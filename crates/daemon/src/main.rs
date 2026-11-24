//! noti-daemon: pairs with the phone and shows relayed notifications on this laptop.

mod platform;

use platform::write_private;
use proto::{Notification, Role};
use serde::{Deserialize, Serialize};
use std::{
    fs,
    path::PathBuf,
    process::Command,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

#[derive(Serialize, Deserialize)]
struct Config {
    relay: String,
    secret_hex: String,
    /// Names this PC's own queue on the relay. Absent in configs from before multi-PC support,
    /// which map to the relay's `default` queue.
    #[serde(default)]
    device: Option<String>,
}

fn config_path() -> PathBuf {
    platform::config_dir().join("config.json")
}

fn state_path() -> PathBuf {
    platform::state_dir().join("after")
}

fn new_device_id() -> String {
    hex::encode(&proto::new_secret()[..6])
}

fn load_config() -> (Config, [u8; 32]) {
    let text = fs::read_to_string(config_path()).unwrap_or_else(|_| {
        eprintln!("not paired; run `noti-daemon pair --relay https://...` first");
        std::process::exit(1)
    });
    let c: Config = serde_json::from_str(&text).expect("bad config");
    let s: [u8; 32] = hex::decode(&c.secret_hex).ok().and_then(|v| v.try_into().ok()).expect("bad secret");
    (c, s)
}

fn pair(relay: &str, ssh: Option<&str>) {
    let relay = relay.trim_end_matches('/');
    if !relay.starts_with("https://") && !relay.starts_with("http://localhost") && !relay.starts_with("http://127.") {
        eprintln!("relay must be https://");
        std::process::exit(1);
    }
    if config_path().exists() {
        eprintln!("already paired ({}); delete it to re-pair", config_path().display());
        std::process::exit(1);
    }
    let secret = proto::new_secret();
    let keys = proto::derive(&secret);
    let cfg = Config { relay: relay.to_string(), secret_hex: hex::encode(secret), device: Some(new_device_id()) };
    write_private(&config_path(), &serde_json::to_string_pretty(&cfg).unwrap());

    let uri = proto::pairing_uri(relay, &secret);
    let line = format!("{} {} {}", keys.channel_hex(), hex::encode(keys.auth_phone), hex::encode(keys.auth_laptop));
    let add = "/usr/local/bin/noti-relay add --channels /var/lib/noti-relay/channels.txt -";
    match ssh {
        Some(host) => {
            use std::io::Write;
            let mut c = Command::new("ssh")
                .args([host, &format!("sudo -u noti {add}")])
                .stdin(std::process::Stdio::piped())
                .spawn()
                .expect("ssh");
            writeln!(c.stdin.take().unwrap(), "{line}").expect("write ssh");
            if !c.wait().map(|s| s.success()).unwrap_or(false) {
                eprintln!("registration over ssh failed");
                let _ = fs::remove_file(config_path());
                std::process::exit(1);
            }
            println!("1) Channel registered on {host}.\n");
        }
        None => println!("1) On the VPS, register this channel:\n\n   echo '{line}' | sudo -u noti {add}\n"),
    }
    println!("2) In the phone app, scan this QR (or paste the link). It contains the secret; do not share it.\n");
    if let Ok(code) = qrcode::QrCode::new(uri.as_bytes()) {
        println!("{}", code.render::<qrcode::render::unicode::Dense1x2>().quiet_zone(true).build());
    }
    println!("{uri}\n\n3) Start receiving: noti-daemon run   (or `noti-daemon install` to start at login)\n   Add another PC later with: noti-daemon share");
}

/// Prints this pairing as a QR/link so another PC can `join` it. Each PC then gets its own queue.
fn share() {
    let (cfg, secret) = load_config();
    let uri = proto::pairing_uri(&cfg.relay, &secret);
    println!("On the other PC run:  noti-daemon join '<link>'\nThe link contains the secret; do not share it.\n");
    if let Ok(code) = qrcode::QrCode::new(uri.as_bytes()) {
        println!("{}", code.render::<qrcode::render::unicode::Dense1x2>().quiet_zone(true).build());
    }
    println!("{uri}");
}

fn join(uri: &str) {
    if config_path().exists() {
        eprintln!("already paired ({}); delete it to join another pairing", config_path().display());
        std::process::exit(1);
    }
    let (relay, secret) = proto::parse_pairing_uri(uri).unwrap_or_else(|e| {
        eprintln!("bad pairing link: {e}");
        std::process::exit(1)
    });
    if !relay.starts_with("https://") {
        eprintln!("relay must be https://");
        std::process::exit(1);
    }
    let cfg = Config { relay, secret_hex: hex::encode(secret), device: Some(new_device_id()) };
    write_private(&config_path(), &serde_json::to_string_pretty(&cfg).unwrap());
    println!("joined. Start receiving: noti-daemon run   (or `noti-daemon install` to start at login)");
}

fn now_secs() -> i64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() as i64
}

#[derive(Deserialize)]
struct PollResp {
    messages: Vec<Msg>,
}
#[derive(Deserialize)]
struct Msg {
    seq: u64,
    data: String,
}

fn icon_dir() -> PathBuf {
    platform::cache_dir().join("icons")
}

fn icon_path(pkg: &str) -> Option<PathBuf> {
    let ok = !pkg.is_empty() && pkg.len() < 128 && pkg.chars().all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '_' || c == '-');
    ok.then(|| icon_dir().join(format!("{pkg}.png")))
}

/// Cache the icon only if it is a small, genuine PNG.
fn store_icon(n: &Notification) {
    let (Some(b64), Some(path)) = (&n.icon, icon_path(&n.pkg)) else { return };
    let Ok(png) = proto::b64_decode(b64) else { return };
    if png.len() > 32 * 1024 || !png.starts_with(b"\x89PNG\r\n\x1a\n") {
        return;
    }
    let _ = fs::create_dir_all(icon_dir());
    let _ = fs::write(path, png);
}

fn show(n: &Notification) {
    let icon = icon_path(&n.pkg).filter(|p| p.exists()).map(|p| p.display().to_string());
    let title = if n.title.is_empty() { n.app.clone() } else { format!("{}: {}", n.app, n.title) };
    platform::show(&title, &n.text, icon.as_deref());
}

fn run() {
    let (cfg, secret) = load_config();
    let keys = proto::derive(&secret);
    let key = keys.auth_key(Role::Laptop);
    let chan = keys.channel_hex();
    let agent = ureq::AgentBuilder::new().timeout(Duration::from_secs(45)).build();
    let mut after: u64 = fs::read_to_string(state_path()).ok().and_then(|s| s.trim().parse().ok()).unwrap_or(0);
    let mut backoff = 1u64;
    let mut seen_ids: Vec<String> = Vec::new();
    eprintln!("noti-daemon: connected to {} (channel {}…, device {})", cfg.relay, &chan[..8], cfg.device.as_deref().unwrap_or("default"));

    loop {
        let pq = match &cfg.device {
            Some(d) => format!("/v1/poll?after={after}&wait=25&dev={d}"),
            None => format!("/v1/poll?after={after}&wait=25"),
        };
        let ts = now_secs();
        let nonce = proto::new_nonce();
        let sig = proto::sign(key, &proto::signing_input("GET", &pq, ts, &nonce, b""));
        let res = agent
            .get(&format!("{}{}", cfg.relay, pq))
            .set("x-chan", &chan)
            .set("x-ts", &ts.to_string())
            .set("x-nonce", &nonce)
            .set("x-sig", &sig)
            .call();
        match res.map_err(|e| e.to_string()).and_then(|r| r.into_json::<PollResp>().map_err(|e| e.to_string())) {
            Ok(r) => {
                backoff = 1;
                for m in r.messages {
                    match proto::open(&keys.enc, &keys.channel, &m.data)
                        .and_then(|p| serde_json::from_slice::<Notification>(&p).map_err(|e| e.to_string()))
                    {
                        Ok(n) => {
                            let dedup = format!("{}:{}:{}", n.id, n.ts, n.text.len());
                            store_icon(&n);
                            if !seen_ids.contains(&dedup) {
                                show(&n);
                                seen_ids.push(dedup);
                                if seen_ids.len() > 200 {
                                    seen_ids.remove(0);
                                }
                            }
                        }
                        Err(e) => eprintln!("dropping undecryptable message {}: {e}", m.seq),
                    }
                    after = after.max(m.seq);
                    write_private(&state_path(), &after.to_string());
                }
            }
            Err(e) => {
                eprintln!("poll error: {e}; retrying in {backoff}s");
                std::thread::sleep(Duration::from_secs(backoff));
                backoff = (backoff * 2).min(60);
            }
        }
    }
}

/// Acts as the phone: handy for verifying the relay path without the app.
fn test_send(title: &str, text: &str) {
    let (cfg, secret) = load_config();
    let keys = proto::derive(&secret);
    let n = Notification {
        id: proto::new_nonce(),
        pkg: "dev.noti.test".into(),
        app: "noti-test".into(),
        title: title.into(),
        text: text.into(),
        ts: now_secs() * 1000,
        icon: None,
    };
    let body = proto::seal(&keys.enc, &keys.channel, &serde_json::to_vec(&n).unwrap());
    let (ts, nonce) = (now_secs(), proto::new_nonce());
    let sig = proto::sign(&keys.auth_phone, &proto::signing_input("POST", "/v1/send", ts, &nonce, body.as_bytes()));
    let r = ureq::post(&format!("{}/v1/send", cfg.relay))
        .set("x-chan", &keys.channel_hex())
        .set("x-ts", &ts.to_string())
        .set("x-nonce", &nonce)
        .set("x-sig", &sig)
        .send_string(&body);
    match r {
        Ok(r) => println!("sent: {}", r.into_string().unwrap_or_default()),
        Err(e) => eprintln!("send failed: {e}"),
    }
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.first().map(String::as_str) {
        Some("pair") => match args.iter().position(|a| a == "--relay").and_then(|i| args.get(i + 1)) {
            Some(r) => pair(r, args.iter().position(|a| a == "--ssh").and_then(|i| args.get(i + 1)).map(String::as_str)),
            None => eprintln!("usage: noti-daemon pair --relay https://notify.example.com [--ssh host]"),
        },
        Some("run") => run(),
        Some("share") => share(),
        Some("join") if args.len() == 2 => join(&args[1]),
        Some("install") => match platform::install_autostart() {
            Ok(m) => println!("{m}"),
            Err(e) => eprintln!("install failed: {e}"),
        },
        Some("test-send") if args.len() == 3 => test_send(&args[1], &args[2]),
        _ => eprintln!("usage: noti-daemon pair --relay <url> [--ssh host] | share | join <link> | run | install | test-send <title> <text>"),
    }
}
