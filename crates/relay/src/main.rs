//! noti-relay: a dumb, closed, in-memory relay for end-to-end encrypted blobs.
//!
//! Security properties:
//! - Only channels listed in the channels file exist (no open registration).
//! - Every request is HMAC-signed with a role key; timestamp window + nonce replay cache.
//! - Payloads are opaque ciphertext; nothing is written to disk but the channels file.
//! - Per-IP auth-failure lockout, per-channel send rate limit, size and queue caps, TTL.

use axum::{
    body::Bytes,
    extract::{ConnectInfo, DefaultBodyLimit, Query, State},
    http::{HeaderMap, Method, StatusCode, Uri},
    routing::{get, post},
    Json, Router,
};
use proto::{Role, MAX_BODY, MAX_SKEW_SECS};
use serde::{Deserialize, Serialize};
use std::{
    collections::{HashMap, VecDeque},
    net::{IpAddr, SocketAddr},
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use tokio::sync::Notify;

const QUEUE_CAP: usize = 500;
const TTL: Duration = Duration::from_secs(24 * 3600);
const SENDS_PER_MIN: usize = 120;
const MAX_POLLERS: usize = 2;
const MAX_WAIT: u64 = 30;
const FAIL_LIMIT: u32 = 10;
const FAIL_WINDOW: Duration = Duration::from_secs(600);
const NONCE_TTL: Duration = Duration::from_secs(2 * MAX_SKEW_SECS as u64 + 10);
const MAX_NONCES: usize = 4096;
const MAX_TRACKED_IPS: usize = 10_000;

struct ChanKeys {
    phone: [u8; 32],
    laptop: [u8; 32],
}

struct Queue {
    msgs: VecDeque<(u64, Instant, String)>,
    next_seq: u64,
    notify: Arc<Notify>,
    nonces: HashMap<String, Instant>,
    sends: VecDeque<Instant>,
    pollers: usize,
}

impl Queue {
    fn new() -> Self {
        // Time-based start keeps seq monotonic across relay restarts.
        let ms = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_millis() as u64;
        Queue {
            msgs: VecDeque::new(),
            next_seq: ms,
            notify: Arc::new(Notify::new()),
            nonces: HashMap::new(),
            sends: VecDeque::new(),
            pollers: 0,
        }
    }
    fn expire(&mut self, now: Instant) {
        while self.msgs.front().is_some_and(|m| now.duration_since(m.1) > TTL) {
            self.msgs.pop_front();
        }
        self.nonces.retain(|_, t| now.duration_since(*t) < NONCE_TTL);
    }
}

struct App {
    channels_path: PathBuf,
    chans: Mutex<HashMap<String, ChanKeys>>,
    queues: Mutex<HashMap<String, Queue>>,
    fails: Mutex<HashMap<IpAddr, (u32, Instant)>>,
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
        let input = proto::signing_input(method.as_str(), pq, ts, nonce, body);
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
    let seq = q.next_seq;
    q.next_seq += 1;
    q.msgs.push_back((seq, now, data));
    while q.msgs.len() > QUEUE_CAP {
        q.msgs.pop_front();
    }
    q.notify.notify_waiters();
    Ok(Json(SendResp { seq }))
}

#[derive(Deserialize)]
struct PollQ {
    after: Option<u64>,
    wait: Option<u64>,
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
}
impl Drop for PollerGuard {
    fn drop(&mut self) {
        if let Some(q) = self.app.queues.lock().unwrap().get_mut(&self.chan) {
            q.pollers = q.pollers.saturating_sub(1);
        }
    }
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
    let after = pq.after.unwrap_or(0);
    let wait = Duration::from_secs(pq.wait.unwrap_or(0).min(MAX_WAIT));

    let notify = {
        let mut qs = app.queues.lock().unwrap();
        let q = qs.get_mut(&chan).ok_or(StatusCode::INTERNAL_SERVER_ERROR)?;
        if q.pollers >= MAX_POLLERS {
            return Err(StatusCode::TOO_MANY_REQUESTS);
        }
        q.pollers += 1;
        q.notify.clone()
    };
    let _guard = PollerGuard { app: app.clone(), chan: chan.clone() };

    let collect = |app: &App| -> Vec<Msg> {
        let mut qs = app.queues.lock().unwrap();
        let Some(q) = qs.get_mut(&chan) else { return vec![] };
        while q.msgs.front().is_some_and(|m| m.0 <= after) {
            q.msgs.pop_front();
        }
        q.msgs.iter().take(50).map(|m| Msg { seq: m.0, data: m.2.clone() }).collect()
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
        .route("/healthz", get(health))
        .layer(DefaultBodyLimit::max(MAX_BODY + 1024))
        .with_state(app)
}

fn usage() -> ! {
    eprintln!(
        "usage:\n  noti-relay serve [--listen 127.0.0.1:8787] [--channels FILE]\n  noti-relay add [--channels FILE] '<channel> <phone-key> <laptop-key>'\n  noti-relay list [--channels FILE]\n  noti-relay remove [--channels FILE] <channel-prefix>"
    );
    std::process::exit(2)
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let mut listen = "127.0.0.1:8787".to_string();
    let mut channels = PathBuf::from("channels.txt");
    let mut rest = vec![];
    let mut it = args.iter().skip(1);
    while let Some(a) = it.next() {
        match a.as_str() {
            "--listen" => listen = it.next().unwrap_or_else(|| usage()).clone(),
            "--channels" => channels = it.next().unwrap_or_else(|| usage()).into(),
            _ => rest.push(a.clone()),
        }
    }
    match args.first().map(String::as_str) {
        Some("serve") => serve(listen, channels),
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
async fn serve_async(listen: String, channels: PathBuf) {
    let app = Arc::new(App {
        chans: Mutex::new(load_channels(&channels)),
        channels_path: channels,
        queues: Mutex::new(HashMap::new()),
        fails: Mutex::new(HashMap::new()),
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

fn serve(listen: String, channels: PathBuf) {
    serve_async(listen, channels)
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
        })
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
