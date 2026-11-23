//! On-disk store for uploaded files, shared by the ssh receiver and the relay's HTTP API.
//!
//! Layout: <root>/files/<id>/<name> plus <root>/files/<id>/.expires (unix seconds).

use rand::{rngs::OsRng, Rng};
use serde::Serialize;
use std::{
    fs, io,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};

pub const MAX_BYTES: u64 = 256 * 1024 * 1024;
pub const QUOTA_BYTES: u64 = 5 * 1024 * 1024 * 1024;
pub const MIN_AGE: u64 = 10 * 86400;
pub const MAX_AGE: u64 = 90 * 86400;
pub const ID_LEN: usize = 8;
const ALPHABET: &[u8] = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";

/// Bigger files live shorter: 90 days for tiny files down to 10 days at the size limit.
pub fn retention_secs(size: u64) -> u64 {
    let r = (size as f64 / MAX_BYTES as f64).min(1.0);
    MIN_AGE + ((MAX_AGE - MIN_AGE) as f64 * (1.0 - r).powi(3)) as u64
}

pub fn sanitize(name: &str) -> String {
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

pub fn valid_id(id: &str) -> bool {
    id.len() == ID_LEN && id.bytes().all(|b| b.is_ascii_alphanumeric())
}

pub fn now() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs()
}

fn files_dir(root: &Path) -> PathBuf {
    root.join("files")
}

#[derive(Serialize, Clone, Debug)]
pub struct Entry {
    pub id: String,
    pub name: String,
    pub size: u64,
    pub uploaded: u64,
    pub expires: u64,
}

pub fn entries(root: &Path) -> Vec<Entry> {
    let mut v = Vec::new();
    for d in fs::read_dir(files_dir(root)).into_iter().flatten().flatten() {
        let p = d.path();
        let Some(expires) = fs::read_to_string(p.join(".expires")).ok().and_then(|s| s.trim().parse().ok()) else {
            continue;
        };
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
            v.push(Entry { id: d.file_name().to_string_lossy().into_owned(), name, size, uploaded, expires });
        }
    }
    v
}

#[derive(Serialize, Debug)]
pub struct Stat {
    pub total: u64,
    pub free: u64,
    pub used: u64,
    pub quota: u64,
    pub count: u64,
}

/// total/free describe the filesystem holding the uploads; used is what uploads occupy.
pub fn stat(root: &Path) -> Stat {
    let e = entries(root);
    let (mut total, mut free) = (0, 0);
    if let Ok(c) = std::ffi::CString::new(root.as_os_str().as_encoded_bytes()) {
        let mut s: libc::statvfs = unsafe { std::mem::zeroed() };
        if unsafe { libc::statvfs(c.as_ptr(), &mut s) } == 0 {
            total = s.f_blocks as u64 * s.f_frsize as u64;
            free = s.f_bavail as u64 * s.f_frsize as u64;
        }
    }
    Stat { total, free, used: e.iter().map(|x| x.size).sum(), quota: QUOTA_BYTES, count: e.len() as u64 }
}

fn used_bytes(root: &Path) -> u64 {
    let mut total = 0;
    for d in fs::read_dir(files_dir(root)).into_iter().flatten().flatten() {
        for f in fs::read_dir(d.path()).into_iter().flatten().flatten() {
            total += f.metadata().map(|m| m.len()).unwrap_or(0);
        }
    }
    total
}

pub fn delete(root: &Path, id: &str) -> Result<(), String> {
    if !valid_id(id) {
        return Err("bad id".into());
    }
    fs::remove_dir_all(files_dir(root).join(id)).map_err(|_| "no such upload".to_string())
}

pub fn clear(root: &Path) -> usize {
    let mut n = 0;
    for d in fs::read_dir(files_dir(root)).into_iter().flatten().flatten() {
        if fs::remove_dir_all(d.path()).is_ok() {
            n += 1;
        }
    }
    n
}

/// Removes expired uploads, plus interrupted ones (no expiry file) older than a day.
pub fn gc(root: &Path) -> usize {
    let t = now();
    let mut removed = 0;
    for d in fs::read_dir(files_dir(root)).into_iter().flatten().flatten() {
        let p = d.path();
        let exp: Option<u64> = fs::read_to_string(p.join(".expires")).ok().and_then(|s| s.trim().parse().ok());
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
    removed
}

pub struct Done {
    pub id: String,
    pub name: String,
    pub expires: u64,
}

/// An upload in progress. Write the bytes to `part_path()`, then `finish()`.
/// Dropping without finishing removes everything written so far.
pub struct Pending {
    id: String,
    name: String,
    size: u64,
    dir: PathBuf,
    done: bool,
}

pub fn begin(root: &Path, size: u64, name: &str) -> Result<Pending, String> {
    if size == 0 {
        return Err("empty file".into());
    }
    if size > MAX_BYTES {
        return Err(format!("file too large (max {} MB)", MAX_BYTES >> 20));
    }
    let files = files_dir(root);
    fs::create_dir_all(&files).map_err(|e| format!("storage unavailable: {e}"))?;
    if used_bytes(root) + size > QUOTA_BYTES {
        return Err("server storage quota reached".into());
    }
    loop {
        let id: String = (0..ID_LEN).map(|_| ALPHABET[OsRng.gen_range(0..ALPHABET.len())] as char).collect();
        let dir = files.join(&id);
        match fs::create_dir(&dir) {
            Ok(()) => {
                // Group-writable so the relay and the ssh receiver (different users) can both clean up.
                let _ = fs::set_permissions(&dir, fs::Permissions::from_mode(0o775));
                return Ok(Pending { id, name: sanitize(name), size, dir, done: false });
            }
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => continue,
            Err(e) => return Err(format!("storage unavailable: {e}")),
        }
    }
}

impl Pending {
    pub fn part_path(&self) -> PathBuf {
        self.dir.join(".part")
    }
    pub fn size(&self) -> u64 {
        self.size
    }

    pub fn finish(mut self) -> Result<Done, String> {
        let expires = now() + retention_secs(self.size);
        let e = |e: io::Error| e.to_string();
        fs::write(self.dir.join(".expires"), expires.to_string()).map_err(e)?;
        let _ = fs::set_permissions(self.dir.join(".expires"), fs::Permissions::from_mode(0o664));
        let dest = self.dir.join(&self.name);
        fs::rename(self.part_path(), &dest).map_err(e)?;
        let _ = fs::set_permissions(&dest, fs::Permissions::from_mode(0o644));
        self.done = true;
        Ok(Done { id: self.id.clone(), name: self.name.clone(), expires })
    }
}

impl Drop for Pending {
    fn drop(&mut self) {
        if !self.done {
            let _ = fs::remove_dir_all(&self.dir);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp() -> PathBuf {
        let p = std::env::temp_dir().join(format!("store-test-{}", rand::random::<u64>()));
        fs::create_dir_all(&p).unwrap();
        p
    }

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

    #[test]
    fn put_list_delete_and_abort() {
        let root = tmp();
        let p = begin(&root, 5, "x y.txt").unwrap();
        fs::write(p.part_path(), b"hello").unwrap();
        let d = p.finish().unwrap();
        assert_eq!(d.name, "x_y.txt");
        let e = entries(&root);
        assert_eq!((e.len(), e[0].size, e[0].id.as_str()), (1, 5, d.id.as_str()));
        assert_eq!(stat(&root).count, 1);

        drop(begin(&root, 5, "aborted").unwrap());
        assert_eq!(fs::read_dir(root.join("files")).unwrap().count(), 1);

        assert!(delete(&root, "../x").is_err());
        assert!(delete(&root, "zzzzzzzz").is_err());
        delete(&root, &d.id).unwrap();
        assert!(entries(&root).is_empty());
        assert!(begin(&root, MAX_BYTES + 1, "big").is_err());
        fs::remove_dir_all(root).unwrap();
    }
}
