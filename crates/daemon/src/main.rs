//! noti-daemon: pairs with the phone and shows relayed notifications on this laptop.

use proto::{Notification, Role};
use serde::{Deserialize, Serialize};
use std::{
    fs,
    os::unix::fs::PermissionsExt,
    path::PathBuf,
    process::Command,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

#[derive(Serialize, Deserialize)]
struct Config {
    relay: String,
    secret_hex: String,
}

fn dir(base: &str, fallback: &str) -> PathBuf {
    let d = std::env::var_os(base)
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(std::env::var("HOME").expect("HOME")).join(fallback));
    d.join("noti")
}

fn config_path() -> PathBuf {
    dir("XDG_CONFIG_HOME", ".config").join("config.json")
}

fn state_path() -> PathBuf {
    dir("XDG_STATE_HOME", ".local/state").join("after")
}

fn write_private(p: &PathBuf, data: &str) {
    fs::create_dir_all(p.parent().unwrap()).expect("mkdir");
    fs::write(p, data).expect("write");
    fs::set_permissions(p, fs::Permissions::from_mode(0o600)).expect("chmod");
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
    let cfg = Config { relay: relay.to_string(), secret_hex: hex::encode(secret) };
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
    println!("{uri}\n\n3) Start receiving: noti-daemon run");
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

fn escape(s: &str) -> String {
    s.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;")
}

fn icon_dir() -> PathBuf {
    dir("XDG_CACHE_HOME", ".cache").join("icons")
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
    let icon = icon_path(&n.pkg).filter(|p| p.exists()).map(|p| p.display().to_string()).unwrap_or_else(|| "phone".into());
    let title = if n.title.is_empty() { n.app.clone() } else { format!("{}: {}", n.app, n.title) };
    let _ = Command::new("notify-send")
        .args(["-a", "noti", "-t", "10000", "-i", &icon, "--"])
        .arg(escape(&title))
        .arg(escape(&n.text))
        .status();
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
    eprintln!("noti-daemon: connected to {} (channel {}…)", cfg.relay, &chan[..8]);

    loop {
        let pq = format!("/v1/poll?after={after}&wait=25");
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
        Some("test-send") if args.len() == 3 => test_send(&args[1], &args[2]),
        _ => eprintln!("usage: noti-daemon pair --relay <url> | run"),
    }
}
