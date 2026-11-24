//! noti-relay: a dumb, closed, in-memory relay for end-to-end encrypted blobs.
//!
//! Security properties:
//! - Only channels listed in the channels file exist (no open registration).
//! - Every request is HMAC-signed with a role key; timestamp window + nonce replay cache.
//! - Payloads are opaque ciphertext; nothing is written to disk but the channels file.
//! - Per-IP auth-failure lockout, per-channel send rate limit, size and queue caps, TTL.
//! - Optional file API (`--files-root`): the paired phone can upload, list, delete files. The body
//!   is streamed to disk; its SHA-256 is signed up front and verified when the stream ends.

use axum::{
    body::{Body, Bytes},
    extract::{ConnectInfo, DefaultBodyLimit, Path as UrlPath, Query, State},
    http::{HeaderMap, Method, StatusCode, Uri},
    routing::{get, post, put},
    Json, Router,
};
use http_body_util::BodyExt;
use proto::{Role, MAX_BODY, MAX_SKEW_SECS};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::{HashMap, VecDeque},
    net::{IpAddr, SocketAddr},
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use tokio::{io::AsyncWriteExt, sync::{Notify, Semaphore}};

const QUEUE_CAP: usize = 5;
const TTL: Duration = Duration::from_secs(24 * 3600);
const SENDS_PER_MIN: usize = 120;
const MAX_POLLERS: usize = 2;
const MAX_DEVS: usize = 8;
const DEV_IDLE: Duration = Duration::from_secs(7 * 24 * 3600);
/// Name of the placeholder queue that holds messages sent before any laptop has ever polled.
const PENDING_DEV: &str = "";
const MAX_WAIT: u64 = 30;
const FAIL_LIMIT: u32 = 10;
const FAIL_WINDOW: Duration = Duration::from_secs(600);
const NONCE_TTL: Duration = Duration::from_secs(2 * MAX_SKEW_SECS as u64 + 10);
const MAX_NONCES: usize = 4096;
const MAX_TRACKED_IPS: usize = 10_000;
const UPLOAD_CONCURRENCY: usize = 2;
const UPLOAD_IDLE: Duration = Duration::from_secs(30);
const UPLOAD_TOTAL: Duration = Duration::from_secs(20 * 60);

struct FilesCfg {
    root: PathBuf,
    base_url: String,
    slots: Arc<Semaphore>,
}

struct ChanKeys {
    phone: [u8; 32],
    laptop: [u8; 32],
}

/// One laptop's ring buffer. Every paired laptop has its own, so a laptop that is off or slow
/// never loses (or duplicates) messages because of another one.
struct Dev {
    msgs: VecDeque<(u64, Instant, String)>,
    next_seq: u64,
    notify: Arc<Notify>,
    pollers: usize,
    last_seen: Instant,
}

impl Dev {
    fn new(now: Instant) -> Self {
        // Time-based start keeps seq monotonic across relay restarts.
        let ms = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_millis() as u64;
        Dev { msgs: VecDeque::new(), next_seq: ms, notify: Arc::new(Notify::new()), pollers: 0, last_seen: now }
    }
}

/// Per-channel state: replay/rate-limit bookkeeping plus one `Dev` per laptop.
struct Queue {
    nonces: HashMap<String, Instant>,
    sends: VecDeque<Instant>,
    devs: HashMap<String, Dev>,
}

impl Queue {
    fn new() -> Self {
        Queue { nonces: HashMap::new(), sends: VecDeque::new(), devs: HashMap::new() }
    }
    fn expire(&mut self, now: Instant) {
        for d in self.devs.values_mut() {
            while d.msgs.front().is_some_and(|m| now.duration_since(m.1) > TTL) {
                d.msgs.pop_front();
            }
        }
        self.devs.retain(|_, d| d.pollers > 0 || now.duration_since(d.last_seen) < DEV_IDLE);
        self.nonces.retain(|_, t| now.duration_since(*t) < NONCE_TTL);
    }
}

struct App {
    channels_path: PathBuf,
    chans: Mutex<HashMap<String, ChanKeys>>,
    queues: Mutex<HashMap<String, Queue>>,
    fails: Mutex<HashMap<IpAddr, (u32, Instant)>>,
    files: Option<FilesCfg>,
}

type Shared = Arc<App>;

fn parse_key(s: &str) -> Option<[u8; 32]> {
    hex::decode(s).ok()?.try_into().ok()
}

/// File format, one channel per line: `<channel hex> <phone key hex> <laptop key hex>`
fn load_channels(path: &Path) -> HashMap<String, ChanKeys> {
    let mut out = HashMap::new();
    let Ok(text) = std::fs::read_to_string(path) else { return out };
    for line in text.lines() {
        let p: Vec<&str> = line.split_whitespace().collect();
        if p.len() != 3 || p[0].len() != 32 {
            continue;
        }
        if let (Some(a), Some(b)) = (parse_key(p[1]), parse_key(p[2])) {
            out.insert(p[0].to_string(), ChanKeys { phone: a, laptop: b });
        }
    }
    out
}

fn now_secs() -> i64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() as i64
}

fn client_ip(peer: SocketAddr, h: &HeaderMap) -> IpAddr {
    // Trust X-Forwarded-For only from the local reverse proxy; take the entry it appended.
    if peer.ip().is_loopback() {
        if let Some(ip) = h
            .get("x-forwarded-for")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.rsplit(',').next())
            .and_then(|v| v.trim().parse().ok())
        {
            return ip;
        }
    }
    peer.ip()
}

fn hdr<'a>(h: &'a HeaderMap, k: &str) -> Option<&'a str> {
    h.get(k).and_then(|v| v.to_str().ok())
}

impl App {
    fn record_fail(&self, ip: IpAddr) {
        let mut f = self.fails.lock().unwrap();
        let now = Instant::now();
        if f.len() > MAX_TRACKED_IPS {
            f.retain(|_, (_, t)| now.duration_since(*t) < FAIL_WINDOW);
        }
        let e = f.entry(ip).or_insert((0, now));
        if now.duration_since(e.1) > FAIL_WINDOW {
            *e = (0, now);
        }
        e.0 += 1;
    }

    fn banned(&self, ip: IpAddr) -> bool {
        let f = self.fails.lock().unwrap();
        f.get(&ip)
            .is_some_and(|(n, t)| *n >= FAIL_LIMIT && Instant::now().duration_since(*t) < FAIL_WINDOW)
    }

    /// Returns the channel id on success. Unknown channel and bad signature are indistinguishable.
    fn authenticate(
        &self,
        ip: IpAddr,
        h: &HeaderMap,
        method: &Method,
        uri: &Uri,
        body: &[u8],
        role: Role,
    ) -> Result<String, StatusCode> {
        self.authenticate_hashed(ip, h, method, uri, &hex::encode(Sha256::digest(body)), role)
    }

    /// Like `authenticate`, with the body's SHA-256 (hex) given instead of the body itself.
    fn authenticate_hashed(
        &self,
        ip: IpAddr,
        h: &HeaderMap,
        method: &Method,
        uri: &Uri,
        body_sha256: &str,
        role: Role,
    ) -> Result<String, StatusCode> {
        if self.banned(ip) {
            return Err(StatusCode::TOO_MANY_REQUESTS);
        }
        let fail = |s: StatusCode| {
            self.record_fail(ip);
            Err(s)
        };
        let (Some(chan), Some(ts), Some(nonce), Some(sig)) =
            (hdr(h, "x-chan"), hdr(h, "x-ts"), hdr(h, "x-nonce"), hdr(h, "x-sig"))
        else {
            return fail(StatusCode::UNAUTHORIZED);
        };
        let Ok(ts) = ts.parse::<i64>() else { return fail(StatusCode::UNAUTHORIZED) };
        if nonce.len() > 64 || sig.len() > 128 {
            return fail(StatusCode::UNAUTHORIZED);
        }
        let key = {
            let c = self.chans.lock().unwrap();
            match c.get(chan) {
                Some(k) => match role {
                    Role::Phone => k.phone,
                    Role::Laptop => k.laptop,
                },
                None => {
                    drop(c);
                    return fail(StatusCode::UNAUTHORIZED);
                }
            }
        };
        let pq = uri.path_and_query().map(|p| p.as_str()).unwrap_or("/");
        let input = proto::signing_input_hashed(method.as_str(), pq, ts, nonce, body_sha256);
        if !proto::verify(&key, &input, sig) {
            return fail(StatusCode::UNAUTHORIZED);
        }
        if (now_secs() - ts).abs() > MAX_SKEW_SECS {
            // Authentic but stale/skewed: no lockout penalty, but reject.
            return Err(StatusCode::UNAUTHORIZED);
        }
        let mut qs = self.queues.lock().unwrap();
        let q = qs.entry(chan.to_string()).or_insert_with(Queue::new);
        let now = Instant::now();
        q.expire(now);
        if q.nonces.contains_key(nonce) || q.nonces.len() >= MAX_NONCES {
            return Err(StatusCode::UNAUTHORIZED);
        }
        q.nonces.insert(nonce.to_string(), now);
        Ok(chan.to_string())
    }
}

#[derive(Serialize)]
struct SendResp {
    seq: u64,
}

async fn send(
    State(app): State<Shared>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Json<SendResp>, StatusCode> {
    let ip = client_ip(peer, &headers);
    let chan = app.authenticate(ip, &headers, &method, &uri, &body, Role::Phone)?;
    if body.is_empty() || body.len() > MAX_BODY || !body.iter().all(|b| b.is_ascii_graphic()) {
        return Err(StatusCode::BAD_REQUEST);
    }
    let data = String::from_utf8(body.to_vec()).map_err(|_| StatusCode::BAD_REQUEST)?;
    let mut qs = app.queues.lock().unwrap();
    let q = qs.get_mut(&chan).ok_or(StatusCode::INTERNAL_SERVER_ERROR)?;
    let now = Instant::now();
    while q.sends.front().is_some_and(|t| now.duration_since(*t) > Duration::from_secs(60)) {
        q.sends.pop_front();
    }
    if q.sends.len() >= SENDS_PER_MIN {
        return Err(StatusCode::TOO_MANY_REQUESTS);
    }
    q.sends.push_back(now);
    if q.devs.is_empty() {
        q.devs.insert(PENDING_DEV.to_string(), Dev::new(now));
    }
    let mut seq = 0;
    for d in q.devs.values_mut() {
        seq = d.next_seq;
        d.next_seq += 1;
        d.msgs.push_back((seq, now, data.clone()));
        while d.msgs.len() > QUEUE_CAP {
            d.msgs.pop_front();
        }
        d.notify.notify_waiters();
    }
    Ok(Json(SendResp { seq }))
}

#[derive(Deserialize)]
struct PollQ {
    after: Option<u64>,
    wait: Option<u64>,
    dev: Option<String>,
}

#[derive(Serialize)]
struct Msg {
    seq: u64,
    data: String,
}

#[derive(Serialize)]
struct PollResp {
    messages: Vec<Msg>,
}

struct PollerGuard {
    app: Shared,
    chan: String,
    dev: String,
}
impl Drop for PollerGuard {
    fn drop(&mut self) {
        if let Some(d) = self.app.queues.lock().unwrap().get_mut(&self.chan).and_then(|q| q.devs.get_mut(&self.dev)) {
            d.pollers = d.pollers.saturating_sub(1);
            d.last_seen = Instant::now();
        }
    }
}

fn valid_dev(s: &str) -> bool {
    (1..=32).contains(&s.len()) && s.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

/// `after` doubles as the acknowledgement: everything <= after is deleted.
async fn poll(
    State(app): State<Shared>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    Query(pq): Query<PollQ>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
) -> Result<Json<PollResp>, StatusCode> {
    let ip = client_ip(peer, &headers);
    let chan = app.authenticate(ip, &headers, &method, &uri, b"", Role::Laptop)?;
    let dev = pq.dev.unwrap_or_else(|| "default".into());
    if !valid_dev(&dev) {
        return Err(StatusCode::BAD_REQUEST);
    }
    let after = pq.after.unwrap_or(0);
    let wait = Duration::from_secs(pq.wait.unwrap_or(0).min(MAX_WAIT));

    let notify = {
        let mut qs = app.queues.lock().unwrap();
        let q = qs.get_mut(&chan).ok_or(StatusCode::INTERNAL_SERVER_ERROR)?;
        let now = Instant::now();
        if !q.devs.contains_key(&dev) {
            if q.devs.len() >= MAX_DEVS {
                return Err(StatusCode::FORBIDDEN);
            }
            // The first laptop inherits anything sent before any laptop had polled.
            let d = q.devs.remove(PENDING_DEV).unwrap_or_else(|| Dev::new(now));
            q.devs.insert(dev.clone(), d);
        }
        let d = q.devs.get_mut(&dev).unwrap();
        if d.pollers >= MAX_POLLERS {
            return Err(StatusCode::TOO_MANY_REQUESTS);
        }
        d.pollers += 1;
        d.last_seen = now;
        d.notify.clone()
    };
    let _guard = PollerGuard { app: app.clone(), chan: chan.clone(), dev: dev.clone() };

    let collect = |app: &App| -> Vec<Msg> {
        let mut qs = app.queues.lock().unwrap();
        let Some(d) = qs.get_mut(&chan).and_then(|q| q.devs.get_mut(&dev)) else { return vec![] };
        while d.msgs.front().is_some_and(|m| m.0 <= after) {
            d.msgs.pop_front();
        }
        d.msgs.iter().take(50).map(|m| Msg { seq: m.0, data: m.2.clone() }).collect()
    };

    // Register for wakeups before the first check so a send in between is not lost.
    let notified = notify.notified();
    tokio::pin!(notified);
    notified.as_mut().enable();
    let mut messages = collect(&app);
    if messages.is_empty() && !wait.is_zero() {
        let _ = tokio::time::timeout(wait, notified).await;
        messages = collect(&app);
    }
    Ok(Json(PollResp { messages }))
}

// ---- file API (phone role) ----

type FileErr = (StatusCode, String);

fn files_cfg(app: &App) -> Result<&FilesCfg, FileErr> {
    app.files.as_ref().ok_or((StatusCode::NOT_FOUND, String::new()))
}

fn plain(s: StatusCode) -> FileErr {
    (s, String::new())
}

fn phone_auth(app: &App, peer: SocketAddr, h: &HeaderMap, m: &Method, uri: &Uri) -> Result<(), FileErr> {
    files_cfg(app)?;
    app.authenticate(client_ip(peer, h), h, m, uri, b"", Role::Phone).map(|_| ()).map_err(plain)
}

#[derive(Serialize)]
struct FileItem {
    #[serde(flatten)]
    entry: store::Entry,
    url: String,
}

#[derive(Serialize)]
struct FileList {
    files: Vec<FileItem>,
}

async fn files_list(
    State(app): State<Shared>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
) -> Result<Json<FileList>, FileErr> {
    phone_auth(&app, peer, &headers, &method, &uri)?;
    let cfg = files_cfg(&app)?;
    let mut entries = store::entries(&cfg.root);
    entries.sort_by(|a, b| b.uploaded.cmp(&a.uploaded));
    let files = entries
        .into_iter()
        .map(|entry| FileItem { url: format!("{}/{}/{}", cfg.base_url.trim_end_matches('/'), entry.id, entry.name), entry })
        .collect();
    Ok(Json(FileList { files }))
}

async fn files_stat(
    State(app): State<Shared>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
) -> Result<Json<store::Stat>, FileErr> {
    phone_auth(&app, peer, &headers, &method, &uri)?;
    Ok(Json(store::stat(&files_cfg(&app)?.root)))
}

async fn files_delete(
    State(app): State<Shared>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    UrlPath(id): UrlPath<String>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
) -> Result<StatusCode, FileErr> {
    phone_auth(&app, peer, &headers, &method, &uri)?;
    store::delete(&files_cfg(&app)?.root, &id).map_err(|e| (StatusCode::NOT_FOUND, e))?;
    Ok(StatusCode::NO_CONTENT)
}

async fn files_clear(
    State(app): State<Shared>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
) -> Result<Json<serde_json::Value>, FileErr> {
    phone_auth(&app, peer, &headers, &method, &uri)?;
    let n = store::clear(&files_cfg(&app)?.root);
    Ok(Json(serde_json::json!({ "deleted": n })))
}

#[derive(Serialize)]
struct PutResp {
    id: String,
    name: String,
    url: String,
    size: u64,
    expires: u64,
}

async fn files_put(
    State(app): State<Shared>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    UrlPath(name): UrlPath<String>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    mut body: Body,
) -> Result<Json<PutResp>, FileErr> {
    let cfg = files_cfg(&app)?;
    let bad = |m: &str| (StatusCode::BAD_REQUEST, m.to_string());
    let expected = hdr(&headers, "x-body-sha256").unwrap_or("").to_ascii_lowercase();
    if expected.len() != 64 || !expected.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(bad("missing x-body-sha256"));
    }
    let size: u64 = hdr(&headers, "content-length").and_then(|v| v.parse().ok()).ok_or_else(|| bad("content-length required"))?;
    app.authenticate_hashed(client_ip(peer, &headers), &headers, &method, &uri, &expected, Role::Phone).map_err(plain)?;
    let _slot = cfg.slots.clone().try_acquire_owned().map_err(|_| plain(StatusCode::TOO_MANY_REQUESTS))?;

    let pending = store::begin(&cfg.root, size, &name).map_err(|e| {
        let code = if e.contains("too large") {
            StatusCode::PAYLOAD_TOO_LARGE
        } else if e.contains("quota") {
            StatusCode::INSUFFICIENT_STORAGE
        } else {
            StatusCode::BAD_REQUEST
        };
        (code, e)
    })?;
    let mut out = tokio::fs::File::create(pending.part_path()).await.map_err(|e| plain_io(&e))?;
    let (mut got, mut hasher, started) = (0u64, Sha256::new(), Instant::now());
    loop {
        if started.elapsed() > UPLOAD_TOTAL {
            return Err(plain(StatusCode::REQUEST_TIMEOUT));
        }
        let frame = match tokio::time::timeout(UPLOAD_IDLE, body.frame()).await {
            Err(_) => return Err(plain(StatusCode::REQUEST_TIMEOUT)),
            Ok(None) => break,
            Ok(Some(Err(_))) => return Err(bad("body error")),
            Ok(Some(Ok(f))) => f,
        };
        let Ok(data) = frame.into_data() else { continue };
        got += data.len() as u64;
        if got > size {
            return Err(bad("body longer than content-length"));
        }
        hasher.update(&data);
        out.write_all(&data).await.map_err(|e| plain_io(&e))?;
    }
    out.flush().await.map_err(|e| plain_io(&e))?;
    drop(out);
    if got != size {
        return Err(bad("size mismatch"));
    }
    if hex::encode(hasher.finalize()) != expected {
        return Err(bad("sha256 mismatch"));
    }
    let done = pending.finish().map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e))?;
    Ok(Json(PutResp {
        url: format!("{}/{}/{}", cfg.base_url.trim_end_matches('/'), done.id, done.name),
        id: done.id,
        name: done.name,
        size,
        expires: done.expires,
    }))
}

fn plain_io(_e: &std::io::Error) -> FileErr {
    (StatusCode::INSUFFICIENT_STORAGE, "storage error".into())
}

async fn health() -> &'static str {
    "ok"
}

async fn background(app: Shared) {
    let mut last_mtime = None;
    loop {
        tokio::time::sleep(Duration::from_secs(10)).await;
        let mtime = std::fs::metadata(&app.channels_path).and_then(|m| m.modified()).ok();
        if mtime != last_mtime {
            last_mtime = mtime;
            let new = load_channels(&app.channels_path);
            app.queues.lock().unwrap().retain(|k, _| new.contains_key(k));
            *app.chans.lock().unwrap() = new;
        }
        let now = Instant::now();
        for q in app.queues.lock().unwrap().values_mut() {
            q.expire(now);
        }
        app.fails.lock().unwrap().retain(|_, (_, t)| now.duration_since(*t) < FAIL_WINDOW);
    }
}

fn router(app: Shared) -> Router {
    Router::new()
        .route("/v1/send", post(send))
        .route("/v1/poll", get(poll))
        .route("/v1/files", get(files_list))
        .route("/v1/files/stat", get(files_stat))
        .route("/v1/files/clear", post(files_clear))
        .route("/v1/files/:name", put(axum::handler::Handler::layer(files_put, DefaultBodyLimit::disable())).delete(files_delete))
        .route("/healthz", get(health))
        .layer(DefaultBodyLimit::max(MAX_BODY + 1024))
        .with_state(app)
}

fn usage() -> ! {
    eprintln!(
        "usage:\n  noti-relay serve [--listen 127.0.0.1:8787] [--channels FILE] [--files-root DIR --files-url URL]\n  noti-relay add [--channels FILE] '<channel> <phone-key> <laptop-key>'\n  noti-relay list [--channels FILE]\n  noti-relay remove [--channels FILE] <channel-prefix>"
    );
    std::process::exit(2)
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let mut listen = "127.0.0.1:8787".to_string();
    let mut channels = PathBuf::from("channels.txt");
    let (mut files_root, mut files_url) = (None::<PathBuf>, None::<String>);
    let mut rest = vec![];
    let mut it = args.iter().skip(1);
    while let Some(a) = it.next() {
        match a.as_str() {
            "--listen" => listen = it.next().unwrap_or_else(|| usage()).clone(),
            "--channels" => channels = it.next().unwrap_or_else(|| usage()).into(),
            "--files-root" => files_root = Some(it.next().unwrap_or_else(|| usage()).into()),
            "--files-url" => files_url = Some(it.next().unwrap_or_else(|| usage()).clone()),
            _ => rest.push(a.clone()),
        }
    }
    match args.first().map(String::as_str) {
        Some("serve") => {
            let files = match (files_root, files_url) {
                (Some(root), Some(base_url)) => Some(FilesCfg { root, base_url, slots: Arc::new(Semaphore::new(UPLOAD_CONCURRENCY)) }),
                (None, None) => None,
                _ => usage(),
            };
            serve(listen, channels, files)
        }
        Some("add") => {
            let mut line = rest.first().unwrap_or_else(|| usage()).clone();
            if line == "-" {
                line.clear();
                std::io::stdin().read_line(&mut line).expect("stdin");
            }
            let p: Vec<&str> = line.split_whitespace().collect();
            if p.len() != 3 || p[0].len() != 32 || parse_key(p[1]).is_none() || parse_key(p[2]).is_none() {
                eprintln!("invalid channel line");
                std::process::exit(1);
            }
            if load_channels(&channels).contains_key(p[0]) {
                eprintln!("channel already exists");
                std::process::exit(1);
            }
            use std::io::Write;
            let mut f = open_private(&channels);
            writeln!(f, "{}", p.join(" ")).expect("write");
            println!("added {}", p[0]);
        }
        Some("list") => {
            for k in load_channels(&channels).keys() {
                println!("{k}");
            }
        }
        Some("remove") => {
            let pre = rest.first().unwrap_or_else(|| usage());
            let text = std::fs::read_to_string(&channels).unwrap_or_default();
            let kept: Vec<&str> = text.lines().filter(|l| !l.starts_with(pre.as_str())).collect();
            std::fs::write(&channels, kept.join("\n") + if kept.is_empty() { "" } else { "\n" }).expect("write");
            println!("removed {} line(s)", text.lines().count() - kept.len());
        }
        _ => usage(),
    }
}

fn open_private(path: &Path) -> std::fs::File {
    use std::os::unix::fs::OpenOptionsExt;
    std::fs::OpenOptions::new().create(true).append(true).mode(0o600).open(path).expect("open channels file")
}

#[tokio::main]
async fn serve_async(listen: String, channels: PathBuf, files: Option<FilesCfg>) {
    let app = Arc::new(App {
        chans: Mutex::new(load_channels(&channels)),
        channels_path: channels,
        queues: Mutex::new(HashMap::new()),
        fails: Mutex::new(HashMap::new()),
        files,
    });
    tokio::spawn(background(app.clone()));
    let l = tokio::net::TcpListener::bind(&listen).await.expect("bind");
    eprintln!("noti-relay listening on {listen}");
    axum::serve(l, router(app).into_make_service_with_connect_info::<SocketAddr>())
        .with_graceful_shutdown(async {
            let _ = tokio::signal::ctrl_c().await;
        })
        .await
        .unwrap();
}

fn serve(listen: String, channels: PathBuf, files: Option<FilesCfg>) {
    serve_async(listen, channels, files)
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::Request;
    use tower::ServiceExt;

    async fn oneshot(r: Router, req: Request<Body>) -> axum::response::Response {
        r.oneshot(req).await.unwrap()
    }

    fn app_with(keys: &proto::Keys) -> Shared {
        let mut m = HashMap::new();
        m.insert(keys.channel_hex(), ChanKeys { phone: keys.auth_phone, laptop: keys.auth_laptop });
        Arc::new(App {
            channels_path: "none".into(),
            chans: Mutex::new(m),
            queues: Mutex::new(HashMap::new()),
            fails: Mutex::new(HashMap::new()),
            files: None,
        })
    }

    fn app_with_files(keys: &proto::Keys, root: &Path) -> Shared {
        let a = app_with(keys);
        let mut a = Arc::try_unwrap(a).ok().unwrap();
        a.files = Some(FilesCfg { root: root.into(), base_url: "https://x.test/f".into(), slots: Arc::new(Semaphore::new(2)) });
        Arc::new(a)
    }

    fn put_req(keys: &proto::Keys, name: &str, data: &[u8], claimed_hash: &str, nonce: &str) -> Request<Body> {
        let t = now_secs();
        let path = format!("/v1/files/{name}");
        let sig = proto::sign(&keys.auth_phone, &proto::signing_input_hashed("PUT", &path, t, nonce, claimed_hash));
        Request::builder()
            .method("PUT")
            .uri(path)
            .header("x-chan", keys.channel_hex())
            .header("x-ts", t.to_string())
            .header("x-nonce", nonce)
            .header("x-sig", sig)
            .header("x-body-sha256", claimed_hash)
            .header("content-length", data.len().to_string())
            .extension(ConnectInfo(SocketAddr::from(([203, 0, 113, 9], 1))))
            .body(Body::from(data.to_vec()))
            .unwrap()
    }

    async fn json(r: axum::response::Response) -> serde_json::Value {
        serde_json::from_slice(&axum::body::to_bytes(r.into_body(), 1 << 20).await.unwrap()).unwrap()
    }

    #[tokio::test]
    async fn file_api_put_list_delete() {
        let keys = proto::derive(&proto::new_secret());
        let root = std::env::temp_dir().join(format!("relay-files-{}", rand_id()));
        let r = router(app_with_files(&keys, &root));
        let data = vec![7u8; 100_000]; // larger than the 16KB JSON body cap
        let h = hex::encode(Sha256::digest(&data));

        let ok = oneshot(r.clone(), put_req(&keys, "my%20file.bin", &data, &h, "p1")).await;
        assert_eq!(ok.status(), 200);
        let v = json(ok).await;
        assert!(v["url"].as_str().unwrap().starts_with("https://x.test/f/"));
        assert_eq!(v["name"], "my_file.bin");
        let id = v["id"].as_str().unwrap().to_string();

        // hash claimed in the signature must match the streamed body
        let bad = oneshot(r.clone(), put_req(&keys, "evil.bin", b"tampered", &h, "p2")).await;
        assert_eq!(bad.status(), 400);
        // replayed nonce
        let rp = oneshot(r.clone(), put_req(&keys, "again.bin", &data, &h, "p1")).await;
        assert_eq!(rp.status(), 401);

        let l = oneshot(r.clone(), req(&keys, Role::Phone, "GET", "/v1/files", "", now_secs(), "l1")).await;
        let v = json(l).await;
        assert_eq!(v["files"].as_array().unwrap().len(), 1);
        assert_eq!(v["files"][0]["size"], 100_000);
        assert_eq!(v["files"][0]["url"], format!("https://x.test/f/{id}/my_file.bin"));

        let st = oneshot(r.clone(), req(&keys, Role::Phone, "GET", "/v1/files/stat", "", now_secs(), "s1")).await;
        assert_eq!(json(st).await["count"], 1);

        // laptop role is not allowed to touch files
        let lap = oneshot(r.clone(), req(&keys, Role::Laptop, "GET", "/v1/files", "", now_secs(), "l2")).await;
        assert_eq!(lap.status(), 401);

        let d = oneshot(r.clone(), req(&keys, Role::Phone, "DELETE", &format!("/v1/files/{id}"), "", now_secs(), "d1")).await;
        assert_eq!(d.status(), 204);
        let d2 = oneshot(r.clone(), req(&keys, Role::Phone, "DELETE", &format!("/v1/files/{id}"), "", now_secs(), "d2")).await;
        assert_eq!(d2.status(), 404);
        let c = oneshot(r.clone(), req(&keys, Role::Phone, "POST", "/v1/files/clear", "", now_secs(), "c1")).await;
        assert_eq!(json(c).await["deleted"], 0);
        let _ = std::fs::remove_dir_all(root);
    }

    #[tokio::test]
    async fn file_api_disabled_without_root() {
        let keys = proto::derive(&proto::new_secret());
        let r = router(app_with(&keys));
        let l = oneshot(r, req(&keys, Role::Phone, "GET", "/v1/files", "", now_secs(), "l1")).await;
        assert_eq!(l.status(), 404);
    }

    fn rand_id() -> u64 {
        SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos() as u64
    }

    fn req(keys: &proto::Keys, role: Role, method: &str, pq: &str, body: &str, ts: i64, nonce: &str) -> Request<Body> {
        let sig = proto::sign(
            keys.auth_key(role),
            &proto::signing_input(method, pq, ts, nonce, body.as_bytes()),
        );
        Request::builder()
            .method(method)
            .uri(pq)
            .header("x-chan", keys.channel_hex())
            .header("x-ts", ts.to_string())
            .header("x-nonce", nonce)
            .header("x-sig", sig)
            .extension(ConnectInfo(SocketAddr::from(([203, 0, 113, 9], 1))))
            .body(Body::from(body.to_string()))
            .unwrap()
    }

    #[tokio::test]
    async fn send_poll_ack_replay_and_roles() {
        let keys = proto::derive(&proto::new_secret());
        let r = router(app_with(&keys));
        let t = now_secs();

        let ok = oneshot(r.clone(), req(&keys, Role::Phone, "POST", "/v1/send", "abc", t, "n1")).await;
        assert_eq!(ok.status(), 200);
        // replay of identical request
        let rp = oneshot(r.clone(), req(&keys, Role::Phone, "POST", "/v1/send", "abc", t, "n1")).await;
        assert_eq!(rp.status(), 401);
        // wrong role key for endpoint
        let wr = oneshot(r.clone(), req(&keys, Role::Laptop, "POST", "/v1/send", "abc", t, "n2")).await;
        assert_eq!(wr.status(), 401);
        // stale timestamp
        let st = oneshot(r.clone(), req(&keys, Role::Phone, "POST", "/v1/send", "abc", t - 3600, "n3")).await;
        assert_eq!(st.status(), 401);

        let p = oneshot(r.clone(), req(&keys, Role::Laptop, "GET", "/v1/poll?after=0", "", t, "n4")).await;
        assert_eq!(p.status(), 200);
        let b = axum::body::to_bytes(p.into_body(), 1 << 20).await.unwrap();
        let v: serde_json::Value = serde_json::from_slice(&b).unwrap();
        assert_eq!(v["messages"][0]["data"], "abc");
        let seq = v["messages"][0]["seq"].as_u64().unwrap();

        let p2 = oneshot(r.clone(), req(&keys, Role::Laptop, "GET", &format!("/v1/poll?after={seq}"), "", t, "n5")).await;
        let b = axum::body::to_bytes(p2.into_body(), 1 << 20).await.unwrap();
        let v: serde_json::Value = serde_json::from_slice(&b).unwrap();
        assert!(v["messages"].as_array().unwrap().is_empty());
    }

    async fn poll_dev(r: &Router, keys: &proto::Keys, dev: &str, after: u64, nonce: &str) -> Vec<(u64, String)> {
        let pq = format!("/v1/poll?after={after}&dev={dev}");
        let p = oneshot(r.clone(), req(keys, Role::Laptop, "GET", &pq, "", now_secs(), nonce)).await;
        assert_eq!(p.status(), 200);
        json(p).await["messages"]
            .as_array()
            .unwrap()
            .iter()
            .map(|m| (m["seq"].as_u64().unwrap(), m["data"].as_str().unwrap().to_string()))
            .collect()
    }

    #[tokio::test]
    async fn each_laptop_has_its_own_ring_queue() {
        let keys = proto::derive(&proto::new_secret());
        let r = router(app_with(&keys));
        let send = |i: usize| {
            let r = r.clone();
            let keys = &keys;
            async move {
                let b = format!("m{i}");
                let s = oneshot(r, req(keys, Role::Phone, "POST", "/v1/send", &b, now_secs(), &format!("s{i}"))).await;
                assert_eq!(s.status(), 200);
            }
        };
        send(0).await; // before any laptop polled: held for the first one
        let a = poll_dev(&r, &keys, "pc-a", 0, "p1").await;
        assert_eq!(a.iter().map(|m| m.1.as_str()).collect::<Vec<_>>(), ["m0"]);
        let b = poll_dev(&r, &keys, "pc-b", 0, "p2").await; // joins later: starts empty
        assert!(b.is_empty());

        for i in 1..=8 {
            send(i).await;
        }
        // pc-a acked m0 above, pc-b never acks; each keeps only its newest 5, independently
        let b = poll_dev(&r, &keys, "pc-b", 0, "p3").await;
        assert_eq!(b.iter().map(|m| m.1.as_str()).collect::<Vec<_>>(), ["m4", "m5", "m6", "m7", "m8"]);
        let a = poll_dev(&r, &keys, "pc-a", a[0].0, "p4").await;
        assert_eq!(a.len(), 5);
        // acking on one does not consume the other's
        poll_dev(&r, &keys, "pc-a", a[4].0, "p5").await;
        assert_eq!(poll_dev(&r, &keys, "pc-b", 0, "p6").await.len(), 5);
        // bad device id
        let bad = oneshot(r.clone(), req(&keys, Role::Laptop, "GET", "/v1/poll?dev=a%2Fb", "", now_secs(), "p7")).await;
        assert_eq!(bad.status(), 400);
    }

    #[tokio::test]
    async fn lockout_after_failures() {
        let keys = proto::derive(&proto::new_secret());
        let other = proto::derive(&proto::new_secret());
        let r = router(app_with(&keys));
        let t = now_secs();
        for i in 0..FAIL_LIMIT {
            let s = oneshot(r.clone(), req(&other, Role::Phone, "POST", "/v1/send", "x", t, &format!("a{i}"))).await;
            assert_eq!(s.status(), 401);
        }
        let s = oneshot(r.clone(), req(&keys, Role::Phone, "POST", "/v1/send", "x", t, "good")).await;
        assert_eq!(s.status(), 429);
    }
}
