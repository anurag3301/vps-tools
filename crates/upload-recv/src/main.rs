//! noti-upload-recv: server side of `upload`.
//!
//! Runs as the forced command of the restricted `upload` ssh user, so access control is
//! simply "is your key in authorized_keys". The client sends `put <size> <name>` (or
//! stat/list/del/clear) as the ssh command and streams the file on stdin.
//! Also provides `gc` to delete expired files.

use std::{
    fs,
    io::{self, Read, Write},
    path::{Path, PathBuf},
    process::exit,
};

fn fail(msg: &str) -> ! {
    eprintln!("upload: {msg}");
    exit(1)
}

fn receive(root: &Path, base_url: &str) {
    let cmd = std::env::var("SSH_ORIGINAL_COMMAND").unwrap_or_default();
    let parts: Vec<&str> = cmd.split_whitespace().collect();
    match parts[..] {
        ["stat"] => return stat(root),
        ["list"] => return list(root),
        ["del", id] => {
            store::delete(root, id).unwrap_or_else(|e| fail(&e));
            return println!("deleted {id}");
        }
        ["clear"] => return println!("deleted {} upload(s)", store::clear(root)),
        _ => {}
    }
    let [verb, size, name] = parts[..] else { fail("usage: put <size> <name> | stat | list | del <id> | clear") };
    if verb != "put" {
        fail("unknown command");
    }
    let size: u64 = size.parse().unwrap_or_else(|_| fail("bad size"));
    let pending = store::begin(root, size, name).unwrap_or_else(|e| fail(&e));

    let mut out = fs::File::create(pending.part_path()).unwrap_or_else(|e| fail(&e.to_string()));
    // Read exactly `size` bytes, then require EOF so the declared size can't be exceeded.
    let mut stdin = io::stdin().lock();
    let copied = io::copy(&mut (&mut stdin).take(size), &mut out).unwrap_or_else(|e| fail(&e.to_string()));
    let mut extra = [0u8; 1];
    if copied != size || stdin.read(&mut extra).unwrap_or(0) != 0 {
        fail("size mismatch");
    }
    out.flush().ok();
    drop(out);

    let done = pending.finish().unwrap_or_else(|e| fail(&e));
    println!("{}/{}/{}", base_url.trim_end_matches('/'), done.id, done.name);
    println!("expires={}", done.expires);
}

/// Tab-separated: id, name, size, uploaded, expires (unix seconds). Names are sanitized so contain no tabs.
fn list(root: &Path) {
    for e in store::entries(root) {
        println!("{}\t{}\t{}\t{}\t{}", e.id, e.name, e.size, e.uploaded, e.expires);
    }
}

fn stat(root: &Path) {
    let s = store::stat(root);
    println!("total={}\nfree={}\nused={}\nquota={}\ncount={}", s.total, s.free, s.used, s.quota, s.count);
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
        "gc" => println!("removed {} expired upload(s)", store::gc(&root)),
        _ => receive(&root, &base_url),
    }
}
