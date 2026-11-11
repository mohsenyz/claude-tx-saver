use anyhow::{anyhow, Context, Result};
use axum::{
    extract::State,
    http::{HeaderMap, HeaderName, HeaderValue, Method, Request, StatusCode},
    response::{IntoResponse, Response},
    routing::any,
    Json, Router,
};
use clap::{Parser, ValueEnum};
use futures_util::StreamExt;
use lru::LruCache;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::HashMap,
    net::SocketAddr,
    path::PathBuf,
    sync::{Arc, Mutex},
};

const MAGIC: &[u8] = b"CDP3";
const MAX_METADATA: usize = 1024 * 1024;
const MAX_CHUNK: usize = 32768;

#[derive(Parser, Debug)]
struct Args {
    mode: Mode,
    #[arg(long)]
    port: Option<u16>,
    #[arg(long)]
    listen: Option<String>,
    #[arg(long)]
    token_file: PathBuf,
    #[arg(long)]
    cert: Option<PathBuf>,
    #[arg(long)]
    key: Option<PathBuf>,
    #[arg(long)]
    relay_ca: Option<PathBuf>,
    #[arg(long)]
    relay: Option<String>,
    #[arg(long, default_value = "https://api.anthropic.com")]
    upstream: String,
    #[arg(long, default_value_t = 256)]
    cache_mib: usize,
    #[arg(long, default_value_t = 64)]
    max_body_mib: usize,
    #[arg(long, default_value_t = 0.0)]
    read_timeout: f64,
    #[arg(long)]
    stats: bool,
}
#[derive(Clone, Debug, ValueEnum)]
enum Mode {
    Client,
    Server,
}

#[derive(Serialize, Deserialize, Debug)]
struct Payload {
    version: u8,
    method: String,
    path: String,
    headers: Vec<(String, String)>,
    chunks: Vec<String>,
    sha256: String,
    #[serde(skip)]
    data: HashMap<String, Vec<u8>>,
}
#[derive(Serialize, Deserialize)]
struct WireMeta {
    version: u8,
    method: String,
    path: String,
    headers: Vec<(String, String)>,
    chunks: Vec<String>,
    sha256: String,
    data: Vec<(String, usize)>,
}
#[derive(Serialize, Deserialize)]
struct ResponseMeta {
    version: u8,
    status: u16,
    reason: String,
    headers: Vec<(String, String)>,
}

fn digest(b: &[u8]) -> String {
    hex::encode(Sha256::digest(b))
}
fn chunks(body: &[u8]) -> Vec<Vec<u8>> {
    let mut out = Vec::new();
    let mut start = 0;
    let mut rolling = 0u64;
    let gear: [u64; 256] = std::array::from_fn(|i| {
        let mut h = Sha256::new();
        h.update([i as u8]);
        let d = h.finalize();
        u64::from_be_bytes(d[..8].try_into().unwrap())
    });
    for (i, &b) in body.iter().enumerate() {
        rolling = rolling.rotate_left(1).wrapping_add(gear[b as usize]);
        let n = i + 1 - start;
        if n >= 2048 && ((rolling & 8191) == 0 || n >= 32768) {
            out.push(body[start..=i].to_vec());
            start = i + 1;
            rolling = 0;
        }
    }
    if start < body.len() {
        out.push(body[start..].to_vec());
    }
    out
}
fn pack(p: &Payload) -> Result<Vec<u8>> {
    // Metadata lengths must use the same order as the bytes below. Iterating
    // the HashMap here makes multi-chunk envelopes nondeterministic.
    let entries: Vec<_> = p
        .chunks
        .iter()
        .filter_map(|k| p.data.get(k).map(|v| (k.clone(), v.len())))
        .collect();
    let m = WireMeta {
        version: p.version,
        method: p.method.clone(),
        path: p.path.clone(),
        headers: p.headers.clone(),
        chunks: p.chunks.clone(),
        sha256: p.sha256.clone(),
        data: entries.clone(),
    };
    let h = serde_json::to_vec(&m)?;
    let mut raw = (h.len() as u32).to_be_bytes().to_vec();
    raw.extend(h);
    for (k, _) in &entries {
        raw.extend(p.data.get(k).expect("metadata/data mismatch"));
    }
    let c = zstd::encode_all(raw.as_slice(), 6)?;
    let mut out = MAGIC.to_vec();
    out.extend(c);
    Ok(out)
}
fn unpack(input: &[u8]) -> Result<Payload> {
    if !input.starts_with(MAGIC) {
        return Err(anyhow!("unsupported wire format"));
    }
    let raw = zstd::decode_all(&input[4..])?;
    if raw.len() < 4 {
        return Err(anyhow!("truncated envelope"));
    }
    let n = u32::from_be_bytes(raw[..4].try_into().unwrap()) as usize;
    if n > MAX_METADATA || 4 + n > raw.len() {
        return Err(anyhow!("invalid metadata"));
    }
    let m: WireMeta = serde_json::from_slice(&raw[4..4 + n])?;
    let mut pos = 4 + n;
    let mut data = HashMap::new();
    for (k, len) in m.data {
        if len == 0 || len > MAX_CHUNK || pos + len > raw.len() {
            return Err(anyhow!("invalid chunk"));
        }
        data.insert(k, raw[pos..pos + len].to_vec());
        pos += len;
    }
    if pos != raw.len() {
        return Err(anyhow!("trailing bytes"));
    }
    Ok(Payload {
        version: m.version,
        method: m.method,
        path: m.path,
        headers: m.headers,
        chunks: m.chunks,
        sha256: m.sha256,
        data,
    })
}

#[derive(Clone)]
struct App {
    token: String,
    client: Client,
    upstream: String,
    cache: Arc<Mutex<ChunkCache>>,
    max_body: usize,
    known: Arc<Mutex<LruCache<String, ()>>>,
}

/// Relay chunk store bounded by total bytes, so chunks orphaned by context
/// compaction age out instead of growing memory forever.
struct ChunkCache {
    lru: LruCache<String, Vec<u8>>,
    bytes: usize,
    cap: usize,
}
impl ChunkCache {
    fn new(cap: usize) -> Self {
        Self {
            lru: LruCache::unbounded(),
            bytes: 0,
            cap,
        }
    }
    fn get(&mut self, k: &str) -> Option<Vec<u8>> {
        self.lru.get(k).cloned()
    }
    fn put(&mut self, k: String, v: Vec<u8>) {
        self.bytes += v.len();
        if let Some(old) = self.lru.put(k, v) {
            self.bytes -= old.len();
        }
        while self.bytes > self.cap {
            match self.lru.pop_lru() {
                Some((_, old)) => self.bytes -= old.len(),
                None => break,
            }
        }
    }
}
fn headers(req: &HeaderMap, preserve: bool) -> Vec<(String, String)> {
    let hop = [
        "connection",
        "keep-alive",
        "proxy-authenticate",
        "proxy-authorization",
        "te",
        "trailer",
        "transfer-encoding",
        "upgrade",
        "host",
    ];
    req.iter()
        .filter_map(|(k, v)| {
            let n = k.as_str().to_ascii_lowercase();
            if (!preserve && n == "content-length") || hop.contains(&n.as_str()) {
                None
            } else {
                Some((k.to_string(), v.to_str().unwrap_or("").to_string()))
            }
        })
        .collect()
}
fn make_headers(pairs: &[(String, String)]) -> HeaderMap {
    let mut h = HeaderMap::new();
    for (k, v) in pairs {
        if let (Ok(n), Ok(x)) = (
            HeaderName::from_bytes(k.as_bytes()),
            HeaderValue::from_str(v),
        ) {
            h.append(n, x);
        }
    }
    h
}

async fn relay(State(a): State<App>, req: Request<axum::body::Body>) -> Response {
    let (parts, body) = req.into_parts();
    let expected = format!("Bearer {}", a.token);
    if parts
        .headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        != Some(expected.as_str())
    {
        return (StatusCode::UNAUTHORIZED, "Unauthorized").into_response();
    }
    let bytes = match axum::body::to_bytes(body, a.max_body * 2).await {
        Ok(b) => b,
        Err(_) => return (StatusCode::PAYLOAD_TOO_LARGE, "body too large").into_response(),
    };
    let mut p = match unpack(&bytes) {
        Ok(x) => x,
        Err(e) => {
            eprintln!("invalid relay envelope: {e:#}");
            return (StatusCode::BAD_REQUEST, "Invalid relay request").into_response();
        }
    };
    if p.version != 3 {
        eprintln!("unsupported relay version: {}", p.version);
        return (StatusCode::BAD_REQUEST, "Invalid relay request").into_response();
    }
    let mut bodyv = Vec::new();
    for k in &p.chunks {
        let v = p
            .data
            .get(k)
            .cloned()
            .or_else(|| a.cache.lock().unwrap().get(k));
        match v {
            Some(v) => bodyv.extend(v),
            None => {
                return (
                    StatusCode::CONFLICT,
                    Json(serde_json::json!({"missing":[k]})),
                )
                    .into_response()
            }
        }
    }
    if digest(&bodyv) != p.sha256 {
        eprintln!(
            "relay body digest mismatch: expected={} actual={} chunks={} bytes={}",
            p.sha256,
            digest(&bodyv),
            p.chunks.len(),
            bodyv.len()
        );
        return (StatusCode::BAD_REQUEST, "Invalid relay request").into_response();
    }
    {
        let mut c = a.cache.lock().unwrap();
        for (k, v) in p.data.drain() {
            c.put(k, v);
        }
    }
    let method = Method::from_bytes(p.method.as_bytes()).unwrap_or(Method::GET);
    let url = format!("{}{}", a.upstream.trim_end_matches('/'), p.path);
    let r = a
        .client
        .request(method, url)
        .headers(make_headers(&p.headers))
        .body(bodyv)
        .send()
        .await;
    let r = match r {
        Ok(r) => r,
        Err(_) => {
            return (
                StatusCode::BAD_GATEWAY,
                "Upstream connection failed; request was not retried",
            )
                .into_response()
        }
    };
    let status = r.status();
    let rh = headers(r.headers(), true);
    let mut out = (
        StatusCode::OK,
        [("content-type", "application/octet-stream")],
    )
        .into_response();
    let meta = serde_json::to_vec(&ResponseMeta {
        version: 3,
        status: status.as_u16(),
        reason: status.canonical_reason().unwrap_or("").into(),
        headers: rh,
    })
    .unwrap();
    let mut framed = (meta.len() as u32).to_be_bytes().to_vec();
    framed.extend(meta);
    // Stream the upstream body as it arrives. Buffering it left the link
    // silent for the whole generation, and middleboxes drop TCP flows idle
    // for ~100s, so long responses (compaction, big outputs) always failed.
    let head = futures_util::stream::once(async move { Ok(bytes::Bytes::from(framed)) });
    *out.body_mut() = axum::body::Body::from_stream(head.chain(r.bytes_stream()));
    out
}

/// Split a streamed relay response into its metadata frame and the rest of
/// the body stream, without waiting for the body to finish.
async fn read_frame<S>(mut s: S) -> Option<(ResponseMeta, bytes::Bytes, S)>
where
    S: futures_util::Stream<Item = reqwest::Result<bytes::Bytes>> + Unpin,
{
    let mut buf = Vec::new();
    loop {
        if buf.len() >= 4 {
            let n = u32::from_be_bytes(buf[..4].try_into().unwrap()) as usize;
            if n > MAX_METADATA {
                return None;
            }
            if buf.len() >= 4 + n {
                let m = serde_json::from_slice(&buf[4..4 + n]).ok()?;
                return Some((m, bytes::Bytes::copy_from_slice(&buf[4 + n..]), s));
            }
        }
        buf.extend(s.next().await?.ok()?);
    }
}

async fn client_forward(State(a): State<App>, req: Request<axum::body::Body>) -> Response {
    let (parts, body) = req.into_parts();
    let body = match axum::body::to_bytes(body, a.max_body).await {
        Ok(b) => b,
        Err(_) => return StatusCode::PAYLOAD_TOO_LARGE.into_response(),
    };
    let ps = chunks(&body);
    let manifest: Vec<String> = ps.iter().map(|x| digest(x)).collect();
    let local: HashMap<_, _> = manifest.iter().cloned().zip(ps).collect();
    let delta: HashMap<_, _> = {
        let known = a.known.lock().unwrap();
        local
            .iter()
            .filter(|(k, _)| !known.contains(*k))
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect()
    };
    let mut p = Payload {
        version: 3,
        method: parts.method.to_string(),
        path: parts
            .uri
            .path_and_query()
            .map(|x| x.as_str())
            .unwrap_or("/")
            .into(),
        headers: headers(&parts.headers, true),
        chunks: manifest.clone(),
        sha256: digest(&body),
        // Only chunks the relay has not acknowledged. A stale view (relay
        // restart or eviction) yields 409 and the full set is resent below.
        data: delta,
    };
    for attempt in 0..2 {
        let wire = match pack(&p) {
            Ok(x) => x,
            Err(_) => return StatusCode::BAD_GATEWAY.into_response(),
        };
        // Connect-phase failures (reset/EOF during TCP or TLS setup) mean the
        // relay never saw the request, so retrying cannot duplicate a call.
        let mut tries = 0;
        let r = loop {
            let r = a
                .client
                .post(&a.upstream)
                .header("authorization", format!("Bearer {}", a.token))
                .body(wire.clone())
                .send()
                .await;
            match r {
                Err(e) if e.is_connect() && tries < 5 => {
                    tries += 1;
                    eprintln!("relay connect failed (retry {tries}/5): {e}");
                    tokio::time::sleep(std::time::Duration::from_millis(250 << tries)).await;
                }
                r => break r,
            }
        };
        let r = match r {
            Ok(x) => x,
            Err(e) => {
                eprintln!("relay connection failed: {e:?}");
                return (
                    StatusCode::BAD_GATEWAY,
                    "Relay connection failed; request was not retried",
                )
                    .into_response();
            }
        };
        let status = r.status();
        if status == StatusCode::CONFLICT && attempt == 0 {
            // The relay reports only the first missing chunk and discards
            // the partial upload, so resend everything and forget the stale view.
            eprintln!("relay cache miss; resending full chunk set");
            a.known.lock().unwrap().clear();
            p.data = local.clone();
            continue;
        }
        if status != StatusCode::OK {
            eprintln!("relay transport returned HTTP {status}");
            return (StatusCode::BAD_GATEWAY, "Relay transport failed").into_response();
        }
        let (m, first, rest) = match read_frame(r.bytes_stream()).await {
            Some(x) => x,
            None => {
                eprintln!("relay response framing failed");
                return StatusCode::BAD_GATEWAY.into_response();
            }
        };
        let mut out = Response::builder().status(m.status);
        for (k, v) in m.headers {
            if let (Ok(n), Ok(x)) = (
                HeaderName::from_bytes(k.as_bytes()),
                HeaderValue::from_str(&v),
            ) {
                out = out.header(n, x);
            }
        }
        {
            let mut known = a.known.lock().unwrap();
            for k in manifest {
                known.put(k, ());
            }
        }
        let body = futures_util::stream::once(async move { Ok(first) }).chain(rest);
        return out.body(axum::body::Body::from_stream(body)).unwrap();
    }
    StatusCode::BAD_GATEWAY.into_response()
}

#[tokio::main]
async fn main() -> Result<()> {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let args = Args::parse();
    let token = std::fs::read_to_string(&args.token_file)
        .context("read token")?
        .trim()
        .to_string();
    if token.len() < 32 {
        return Err(anyhow!("token must contain at least 32 characters"));
    }
    let mut builder = reqwest::Client::builder()
        .danger_accept_invalid_certs(false)
        .tcp_keepalive(std::time::Duration::from_secs(30))
        // Middleboxes on the client path kill flows idle for ~100s; reqwest's
        // 90s default reuses connections that are already dead.
        .pool_idle_timeout(std::time::Duration::from_secs(30));
    if let Some(ca) = args.relay_ca {
        builder =
            builder.add_root_certificate(reqwest::Certificate::from_pem(&std::fs::read(ca)?)?);
    }
    let client = builder.build()?;
    let server = matches!(args.mode, Mode::Server);
    let app = App {
        token,
        client,
        upstream: if server {
            args.upstream
        } else {
            args.relay
                .ok_or_else(|| anyhow!("--relay is required in client mode"))?
        },
        cache: Arc::new(Mutex::new(ChunkCache::new(args.cache_mib * 1024 * 1024))),
        max_body: args.max_body_mib * 1024 * 1024,
        // ponytail: fixed digest count (~ a few hundred MiB of chunks); stale
        // entries only cost one 409 round trip.
        known: Arc::new(Mutex::new(LruCache::new(65536.try_into().unwrap()))),
    };
    let router = if server {
        Router::new().route("/v1/relay", any(relay)).with_state(app)
    } else {
        Router::new().fallback(client_forward).with_state(app)
    };
    let addr: SocketAddr = format!(
        "{}:{}",
        args.listen.unwrap_or_else(|| if server {
            "0.0.0.0".into()
        } else {
            "127.0.0.1".into()
        }),
        args.port.unwrap_or(if server { 8443 } else { 8787 })
    )
    .parse()?;
    if server {
        let cert = args
            .cert
            .ok_or_else(|| anyhow!("server requires --cert and --key"))?;
        let key = args
            .key
            .ok_or_else(|| anyhow!("server requires --cert and --key"))?;
        let config = axum_server::tls_rustls::RustlsConfig::from_pem(
            std::fs::read(cert)?,
            std::fs::read(key)?,
        )
        .await?;
        axum_server::bind_rustls(addr, config)
            .serve(router.into_make_service())
            .await?;
    } else {
        axum::serve(tokio::net::TcpListener::bind(addr).await?, router).await?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cache_evicts_by_bytes() {
        let mut c = ChunkCache::new(10);
        c.put("a".into(), vec![0; 4]);
        c.put("b".into(), vec![0; 4]);
        c.put("a".into(), vec![0; 4]); // replace, no double count
        assert_eq!(c.bytes, 8);
        c.get("a");
        c.put("c".into(), vec![0; 4]); // evicts LRU "b"
        assert!(c.get("b").is_none() && c.get("a").is_some() && c.get("c").is_some());
        assert_eq!(c.bytes, 8);
    }

    #[test]
    fn partial_envelope_roundtrip() {
        let body: Vec<u8> = (0..200_000u32)
            .flat_map(|i| (i * 7919).to_le_bytes())
            .collect();
        let ps = chunks(&body);
        assert!(ps.len() > 3);
        let manifest: Vec<String> = ps.iter().map(|x| digest(x)).collect();
        // Send only every other chunk, as the delta path does.
        let data: HashMap<_, _> = manifest
            .iter()
            .cloned()
            .zip(ps.clone())
            .step_by(2)
            .collect();
        let p = Payload {
            version: 3,
            method: "POST".into(),
            path: "/v1/messages".into(),
            headers: vec![],
            chunks: manifest.clone(),
            sha256: digest(&body),
            data,
        };
        let u = unpack(&pack(&p).unwrap()).unwrap();
        let mut cache = ChunkCache::new(usize::MAX);
        for (k, v) in manifest.iter().zip(&ps).skip(1).step_by(2) {
            cache.put(k.clone(), v.clone());
        }
        let rebuilt: Vec<u8> = u
            .chunks
            .iter()
            .flat_map(|k| u.data.get(k).cloned().or_else(|| cache.get(k)).unwrap())
            .collect();
        assert_eq!(digest(&rebuilt), u.sha256);
    }
}
