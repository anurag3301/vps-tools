//! noti-upload-recv: server side of `upload`.
//!
//! Runs as the forced command of the restricted `upload` ssh user, so access control is
//! simply "is your key in authorized_keys". The client sends `put <size> <name>` as the ssh
//! command and streams the file on stdin. Also provides `gc` to delete expired files.
//!
//! Layout: <root>/files/<id>/<name> plus <root>/files/<id>/.expires (unix seconds).

use rand::{rngs::OsRng, Rng};
use std::{
    fs,
    io::{self, Read, Write},
    path::{Path, PathBuf},
    process::exit,
    time::{SystemTime, UNIX_EPOCH},
};

const MAX_BYTES: u64 = 256 * 1024 * 1024;
const QUOTA_BYTES: u64 = 5 * 1024 * 1024 * 1024;
const MIN_AGE: u64 = 10 * 86400;
const MAX_AGE: u64 = 90 * 86400;
const ID_LEN: usize = 8;
const ALPHABET: &[u8] = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";

/// Bigger files live shorter: 90 days for tiny files down to 10 days at the size limit.
fn retention_secs(size: u64) -> u64 {
    let r = (size as f64 / MAX_BYTES as f64).min(1.0);
    MIN_AGE + ((MAX_AGE - MIN_AGE) as f64 * (1.0 - r).powi(3)) as u64
}

fn sanitize(name: &str) -> String {
    let base = name.rsplit(['/', '\\']).next().unwrap_or("");
    let s: String = base
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

fn now() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs()
}

fn fail(msg: &str) -> ! {
    eprintln!("upload: {msg}");
    exit(1)
}

fn used_bytes(files: &Path) -> u64 {
    let mut total = 0;
    for d in fs::read_dir(files).into_iter().flatten().flatten() {
        for f in fs::read_dir(d.path()).into_iter().flatten().flatten() {
            total += f.metadata().map(|m| m.len()).unwrap_or(0);
        }
    }
    total
}

fn receive(root: &Path, base_url: &str) {
    let cmd = std::env::var("SSH_ORIGINAL_COMMAND").unwrap_or_default();
    let parts: Vec<&str> = cmd.split_whitespace().collect();
    match parts[..] {
        ["stat"] => return stat(root),
        ["list"] => return list(root),
        ["del", id] => return del(root, id),
        ["clear"] => return clear(root),
        _ => {}
    }
    let [verb, size, name] = parts[..] else { fail("usage: put <size> <name> | stat | list | del <id> | clear") };
    if verb != "put" {
        fail("unknown command");
    }
    let size: u64 = size.parse().unwrap_or_else(|_| fail("bad size"));
    if size == 0 {
        fail("empty file");
    }
    if size > MAX_BYTES {
        fail(&format!("file too large (max {} MB)", MAX_BYTES >> 20));
    }
    let name = sanitize(name);

    let files = root.join("files");
    fs::create_dir_all(&files).unwrap_or_else(|e| fail(&format!("storage unavailable: {e}")));
    if used_bytes(&files) + size > QUOTA_BYTES {
        fail("server storage quota reached");
    }

    let (id, dir) = loop {
        let id: String = (0..ID_LEN).map(|_| ALPHABET[OsRng.gen_range(0..ALPHABET.len())] as char).collect();
        let dir = files.join(&id);
        if fs::create_dir(&dir).is_ok() {
            break (id, dir);
        }
    };
    let cleanup = |e: String| -> ! {
        let _ = fs::remove_dir_all(&dir);
        fail(&e)
    };

    let part = dir.join(".part");
    let mut out = fs::File::create(&part).unwrap_or_else(|e| cleanup(e.to_string()));
    // Read exactly `size` bytes, then require EOF so the declared size can't be exceeded.
    let mut stdin = io::stdin().lock();
    let copied = io::copy(&mut (&mut stdin).take(size), &mut out).unwrap_or_else(|e| cleanup(e.to_string()));
    let mut extra = [0u8; 1];
    if copied != size || stdin.read(&mut extra).unwrap_or(0) != 0 {
        cleanup("size mismatch".into());
    }
    out.flush().ok();
    drop(out);

    let expires = now() + retention_secs(size);
    fs::write(dir.join(".expires"), expires.to_string()).unwrap_or_else(|e| cleanup(e.to_string()));
    fs::rename(&part, dir.join(&name)).unwrap_or_else(|e| cleanup(e.to_string()));
    set_public(&dir, &name);

    println!("{}/{}/{}", base_url.trim_end_matches('/'), id, name);
    println!("expires={expires}");
}

struct Entry {
    id: String,
    name: String,
    size: u64,
    uploaded: u64,
    expires: u64,
}

fn entries(root: &Path) -> Vec<Entry> {
    let mut v = Vec::new();
    for d in fs::read_dir(root.join("files")).into_iter().flatten().flatten() {
        let p = d.path();
        let Some(exp) = fs::read_to_string(p.join(".expires")).ok().and_then(|s| s.trim().parse().ok()) else { continue };
        let uploaded = fs::metadata(p.join(".expires"))
            .and_then(|m| m.modified())
            .ok()
            .and_then(|m| m.duration_since(UNIX_EPOCH).ok())
            .map_or(0, |d| d.as_secs());
        for f in fs::read_dir(&p).into_iter().flatten().flatten() {
            let name = f.file_name().to_string_lossy().into_owned();
            if name.starts_with('.') {
                continue;
            }
            let size = f.metadata().map_or(0, |m| m.len());
            v.push(Entry { id: d.file_name().to_string_lossy().into_owned(), name, size, uploaded, expires: exp });
        }
    }
    v
}

/// Tab-separated: id, name, size, uploaded, expires (unix seconds). Names are sanitized so contain no tabs.
fn list(root: &Path) {
    for e in entries(root) {
        println!("{}\t{}\t{}\t{}\t{}", e.id, e.name, e.size, e.uploaded, e.expires);
    }
}

fn valid_id(id: &str) -> bool {
    id.len() == ID_LEN && id.bytes().all(|b| b.is_ascii_alphanumeric())
}

fn del(root: &Path, id: &str) {
    if !valid_id(id) {
        fail("bad id");
    }
    fs::remove_dir_all(root.join("files").join(id)).unwrap_or_else(|_| fail("no such upload"));
    println!("deleted {id}");
}

fn clear(root: &Path) {
    let mut n = 0;
    for d in fs::read_dir(root.join("files")).into_iter().flatten().flatten() {
        if fs::remove_dir_all(d.path()).is_ok() {
            n += 1;
        }
    }
    println!("deleted {n} upload(s)");
}

/// total/free are for the filesystem holding the uploads; used is what uploads occupy.
fn stat(root: &Path) {
    let used: u64 = entries(root).iter().map(|e| e.size).sum();
    let count = entries(root).len();
    let df = std::process::Command::new("df").args(["-B1", "--output=size,avail"]).arg(root).output().ok();
    let text = df.map(|o| String::from_utf8_lossy(&o.stdout).into_owned()).unwrap_or_default();
    let nums: Vec<u64> = text.lines().nth(1).unwrap_or("").split_whitespace().filter_map(|x| x.parse().ok()).collect();
    let (total, free) = (nums.first().copied().unwrap_or(0), nums.get(1).copied().unwrap_or(0));
    println!("total={total}\nfree={free}\nused={used}\nquota={QUOTA_BYTES}\ncount={count}");
}

fn set_public(dir: &Path, name: &str) {
    use std::os::unix::fs::PermissionsExt;
    let _ = fs::set_permissions(dir, fs::Permissions::from_mode(0o755));
    let _ = fs::set_permissions(dir.join(name), fs::Permissions::from_mode(0o644));
}

fn gc(root: &Path) {
    let t = now();
    let mut removed = 0;
    for d in fs::read_dir(root.join("files")).into_iter().flatten().flatten() {
        let p = d.path();
        let exp: Option<u64> = fs::read_to_string(p.join(".expires")).ok().and_then(|s| s.trim().parse().ok());
        // No expiry file means an interrupted upload; drop it after a day.
        let stale = match exp {
            Some(e) => e <= t,
            None => d
                .metadata()
                .and_then(|m| m.modified())
                .ok()
                .and_then(|m| m.elapsed().ok())
                .is_some_and(|a| a.as_secs() > 86400),
        };
        if stale && fs::remove_dir_all(&p).is_ok() {
            removed += 1;
        }
    }
    println!("removed {removed} expired upload(s)");
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let mut root = PathBuf::from("/var/lib/noti-upload");
    let mut base_url = "https://anurag3301.dev/f".to_string();
    let mut sub = "receive";
    let mut it = args.iter();
    while let Some(a) = it.next() {
        match a.as_str() {
            "--root" => root = it.next().unwrap_or_else(|| fail("--root needs a value")).into(),
            "--base-url" => base_url = it.next().unwrap_or_else(|| fail("--base-url needs a value")).clone(),
            "gc" => sub = "gc",
            other => fail(&format!("unknown argument {other}")),
        }
    }
    match sub {
        "gc" => gc(&root),
        _ => receive(&root, &base_url),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn retention_curve() {
        assert!(retention_secs(1) > MAX_AGE - 60);
        assert_eq!(retention_secs(MAX_BYTES), MIN_AGE);
        assert!(retention_secs(10 << 20) > retention_secs(100 << 20));
        assert!(retention_secs(100 << 20) > MIN_AGE);
    }

    #[test]
    fn names_are_sanitized() {
        assert_eq!(sanitize("../../etc/passwd"), "passwd");
        assert_eq!(sanitize(".hidden"), "hidden");
        assert_eq!(sanitize("a b$c.txt"), "a_b_c.txt");
        assert_eq!(sanitize("..."), "file");
        assert_eq!(sanitize(""), "file");
    }
}
