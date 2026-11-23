//! upload: send a file to the VPS over ssh (auth = your ssh key), print the link,
//! show a QR code, copy to clipboard and log it.

use std::{
    env, fs,
    io::{Read, Write},
    path::PathBuf,
    process::{exit, Command, Stdio},
};

const HELP: &str = "Usage: upload [OPTION] <file>

Uploads a file to the server over ssh and prints a public link (also shown as a QR code,
copied to the clipboard, and logged to ~/.upload_list).

OPTIONS:
    -u <file>    same as `upload <file>` (compatible with the old script)
    -l [n]       show the last n lines of the local log (all if omitted)
    -e           edit the log file
    stat         server storage: total, free, used
    list         browse uploads on the server (newest first, fzf); Enter downloads
    rm           browse uploads (largest first, fzf); Enter deletes after y/n
    clear        delete ALL uploads on the server after y/n
    -h, --help   this help

ENV:
    UPLOAD_HOST  ssh destination (default: upload@anurag3301.dev)
    UPLOAD_LOG   log file (default: ~/.upload_list)

Max 256 MB. Bigger files expire sooner (90 days for tiny files down to 10 days).";

fn die(msg: &str) -> ! {
    eprintln!("upload: {msg}");
    exit(1)
}

fn log_path() -> PathBuf {
    env::var_os("UPLOAD_LOG")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(env::var("HOME").unwrap_or_default()).join(".upload_list"))
}

/// Must match the server's sanitizer so the command we send contains no whitespace or metacharacters.
fn sanitize(name: &str) -> String {
    let s: String = name
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-') { c } else { '_' })
        .collect();
    let s: String = s.trim_start_matches('.').chars().take(100).collect();
    if s.is_empty() {
        "file".into()
    } else {
        s
    }
}

fn date(fmt: &str, at: Option<&str>) -> String {
    let mut c = Command::new("date");
    if let Some(ts) = at {
        c.arg(format!("--date=@{ts}"));
    }
    String::from_utf8_lossy(&c.arg(fmt).output().map(|o| o.stdout).unwrap_or_default()).trim().to_string()
}

fn upload(path: &str) {
    let meta = fs::metadata(path).unwrap_or_else(|_| die("file doesn't exist"));
    if !meta.is_file() {
        die("not a regular file");
    }
    let size = meta.len();
    let file_name = std::path::Path::new(path).file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
    let name = sanitize(&file_name);
    let host = host();

    eprintln!("Uploading {file_name} ({} KiB)", size.div_ceil(1024));
    let mut ssh = Command::new("ssh")
        .args(["-T", "-o", "BatchMode=yes", "-o", "ClearAllForwardings=yes", &host, &format!("put {size} {name}")])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap_or_else(|e| die(&format!("cannot run ssh: {e}")));

    let mut stdin = ssh.stdin.take().unwrap();
    let mut f = fs::File::open(path).unwrap_or_else(|e| die(&e.to_string()));
    let (mut buf, mut sent, mut last_pct) = (vec![0u8; 256 * 1024], 0u64, 101);
    loop {
        let n = f.read(&mut buf).unwrap_or_else(|e| die(&e.to_string()));
        if n == 0 {
            break;
        }
        if stdin.write_all(&buf[..n]).is_err() {
            break; // ssh/server closed early; its error is reported below
        }
        sent += n as u64;
        let pct = (sent * 100 / size.max(1)) as i32;
        if pct != last_pct && size > 1 << 20 {
            eprint!("\r  {pct}%");
            last_pct = pct;
        }
    }
    drop(stdin);
    if size > 1 << 20 {
        eprintln!();
    }
    let out = ssh.wait_with_output().unwrap_or_else(|e| die(&e.to_string()));
    if !out.status.success() {
        die("upload failed (see message above)");
    }
    let text = String::from_utf8_lossy(&out.stdout);
    let mut lines = text.lines();
    let url = lines.next().filter(|u| u.starts_with("https://")).unwrap_or_else(|| die("unexpected server reply")).to_string();
    let expires = lines.next().and_then(|l| l.strip_prefix("expires=")).unwrap_or("").to_string();

    println!("{url}");
    if let Ok(code) = qrcode::QrCode::new(url.as_bytes()) {
        println!("{}", code.render::<qrcode::render::unicode::Dense1x2>().quiet_zone(true).build());
    }
    if !expires.is_empty() {
        eprintln!("expires {}", date("+%F", Some(&expires)));
    }

    let entry = format!("{}    {}    {}    exp {}\n", date("+%d-%m-%y-%H:%M:%S", None), url, file_name, date("+%F", Some(&expires)));
    if let Err(e) = fs::OpenOptions::new().create(true).append(true).open(log_path()).and_then(|mut l| l.write_all(entry.as_bytes())) {
        eprintln!("warning: couldn't write log: {e}");
    }
    clipboard_and_notify(&url);
}

fn clipboard_and_notify(url: &str) {
    let tool = if env::var_os("WAYLAND_DISPLAY").is_some() { vec!["wl-copy"] } else { vec!["xclip", "-selection", "clipboard"] };
    if let Ok(mut c) = Command::new(tool[0]).args(&tool[1..]).stdin(Stdio::piped()).stdout(Stdio::null()).stderr(Stdio::null()).spawn() {
        if let Some(mut s) = c.stdin.take() {
            let _ = s.write_all(url.as_bytes());
        }
        let _ = c.wait();
    }
    let _ = Command::new("notify-send").args(["-t", "5000", "--", "File uploaded", &format!("{url}\ncopied to clipboard")]).status();
}

fn host() -> String {
    env::var("UPLOAD_HOST").unwrap_or_else(|_| "upload@anurag3301.dev".into())
}

/// Runs a command on the server through the restricted key; returns stdout.
fn remote(cmd: &str) -> String {
    let out = Command::new("ssh")
        .args(["-T", "-o", "BatchMode=yes", "-o", "ClearAllForwardings=yes", &host(), cmd])
        .stdin(Stdio::null())
        .output()
        .unwrap_or_else(|e| die(&format!("cannot run ssh: {e}")));
    if !out.status.success() {
        die(&format!("server refused: {}", String::from_utf8_lossy(&out.stderr).trim()));
    }
    String::from_utf8_lossy(&out.stdout).into_owned()
}

fn human(b: u64) -> String {
    let mut v = b as f64;
    for u in ["B", "KiB", "MiB", "GiB", "TiB"] {
        if v < 1024.0 || u == "TiB" {
            return if u == "B" { format!("{b} B") } else { format!("{v:.1} {u}") };
        }
        v /= 1024.0;
    }
    unreachable!()
}

fn confirm(q: &str) -> bool {
    eprint!("{q} [y/N] ");
    let mut a = String::new();
    std::io::stdin().read_line(&mut a).ok();
    matches!(a.trim(), "y" | "Y" | "yes")
}

struct Item {
    id: String,
    name: String,
    size: u64,
    uploaded: u64,
    expires: u64,
}

fn items() -> Vec<Item> {
    remote("list")
        .lines()
        .filter_map(|l| {
            let f: Vec<&str> = l.split('\t').collect();
            Some(Item { id: f.first()?.to_string(), name: f.get(1)?.to_string(), size: f.get(2)?.parse().ok()?, uploaded: f.get(3)?.parse().ok()?, expires: f.get(4)?.parse().ok()? })
        })
        .collect()
}

fn pick(items: &[Item], prompt: &str) -> Option<usize> {
    if items.is_empty() {
        eprintln!("no uploads on the server");
        return None;
    }
    let mut fzf = Command::new("fzf")
        .args(["--prompt", prompt, "--delimiter", "\t", "--with-nth", "2..", "--no-sort", "--tiebreak=index"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap_or_else(|_| die("fzf is required for this command"));
    let mut si = fzf.stdin.take().unwrap();
    for (i, it) in items.iter().enumerate() {
        let _ = writeln!(si, "{i}\t{}\t{:>10}\t{}\texp {}", it.name, human(it.size), date("+%F %H:%M", Some(&it.uploaded.to_string())), date("+%F", Some(&it.expires.to_string())));
    }
    drop(si);
    let out = fzf.wait_with_output().ok()?;
    String::from_utf8_lossy(&out.stdout).split('\t').next()?.trim().parse().ok()
}

fn stat() {
    let kv: std::collections::HashMap<String, u64> = remote("stat").lines().filter_map(|l| l.split_once('=')).map(|(k, v)| (k.to_string(), v.parse().unwrap_or(0))).collect();
    let g = |k: &str| kv.get(k).copied().unwrap_or(0);
    println!("Server disk : {} total, {} free", human(g("total")), human(g("free")));
    println!("Uploads     : {} file(s), {} used (quota {})", g("count"), human(g("used")), human(g("quota")));
}

fn browse_download() {
    let mut v = items();
    v.sort_by(|a, b| b.uploaded.cmp(&a.uploaded));
    let Some(i) = pick(&v, "download> ") else { return };
    let it = &v[i];
    let url = format!("{}/{}/{}", base_url(), it.id, it.name);
    let dest = std::path::Path::new(&it.name);
    if dest.exists() && !confirm(&format!("{} exists, overwrite?", it.name)) {
        return;
    }
    // Downloads are public, so no ssh needed.
    let ok = Command::new("curl").args(["-fL", "--progress-bar", "-o", &it.name, &url]).status().map(|s| s.success()).unwrap_or(false);
    if !ok {
        die("download failed");
    }
    println!("saved {}", it.name);
}

fn base_url() -> String {
    env::var("UPLOAD_BASE_URL").unwrap_or_else(|_| "https://anurag3301.dev/f".into())
}

fn browse_delete() {
    let mut v = items();
    v.sort_by(|a, b| b.size.cmp(&a.size));
    let Some(i) = pick(&v, "delete> ") else { return };
    let it = &v[i];
    if confirm(&format!("Delete {} ({})?", it.name, human(it.size))) {
        print!("{}", remote(&format!("del {}", it.id)));
    }
}

fn clear_all() {
    let v = items();
    if v.is_empty() {
        return eprintln!("no uploads on the server");
    }
    let total: u64 = v.iter().map(|i| i.size).sum();
    if confirm(&format!("Delete ALL {} upload(s) ({})?", v.len(), human(total))) {
        print!("{}", remote("clear"));
    }
}

fn list(n: Option<&str>) {
    let text = fs::read_to_string(log_path()).unwrap_or_default();
    let lines: Vec<&str> = text.lines().collect();
    let take = match n {
        Some(n) => n.parse::<usize>().unwrap_or_else(|_| die("enter a valid integer")),
        None => lines.len(),
    };
    for l in &lines[lines.len().saturating_sub(take)..] {
        println!("{l}");
    }
}

fn main() {
    let a: Vec<String> = env::args().skip(1).collect();
    match a.iter().map(String::as_str).collect::<Vec<_>>()[..] {
        [] | ["-h"] | ["--help"] => println!("{HELP}"),
        ["stat"] => stat(),
        ["list"] | ["ls"] => browse_download(),
        ["rm"] => browse_delete(),
        ["clear"] => clear_all(),
        ["-l"] => list(None),
        ["-l", n] => list(Some(n)),
        ["-e"] => {
            let ed = env::var("EDITOR").unwrap_or_else(|_| "vi".into());
            let _ = Command::new(ed).arg(log_path()).status();
        }
        ["-u", f] | [f] if !f.starts_with('-') || a[0] == "-u" => upload(f),
        _ => die("invalid arguments, run: upload --help"),
    }
}
