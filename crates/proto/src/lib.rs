//! Shared protocol: key derivation, payload encryption, request signing, pairing URI.
//!
//! One 32-byte secret `K` is shared between phone and laptop at pairing time.
//! The relay never sees `K`; it only learns the channel id and the two
//! request-auth keys, none of which can decrypt or forge a payload.

use base64::{engine::general_purpose::URL_SAFE_NO_PAD as B64, Engine};
use chacha20poly1305::{
    aead::{Aead, KeyInit, OsRng, Payload},
    AeadCore, ChaCha20Poly1305, Key, Nonce,
};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub const MAX_BODY: usize = 16 * 1024;
pub const MAX_SKEW_SECS: i64 = 60;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Role {
    Phone,
    Laptop,
}

impl Role {
    pub fn as_str(self) -> &'static str {
        match self {
            Role::Phone => "phone",
            Role::Laptop => "laptop",
        }
    }
    pub fn parse(s: &str) -> Option<Role> {
        match s {
            "phone" => Some(Role::Phone),
            "laptop" => Some(Role::Laptop),
            _ => None,
        }
    }
}

/// Keys derived from the pairing secret.
pub struct Keys {
    pub channel: [u8; 16],
    pub enc: [u8; 32],
    pub auth_phone: [u8; 32],
    pub auth_laptop: [u8; 32],
}

fn expand<const N: usize>(hk: &Hkdf<Sha256>, info: &str) -> [u8; N] {
    let mut out = [0u8; N];
    hk.expand(info.as_bytes(), &mut out).expect("hkdf length");
    out
}

pub fn new_secret() -> [u8; 32] {
    let mut k = [0u8; 32];
    rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut k);
    k
}

pub fn derive(secret: &[u8; 32]) -> Keys {
    let hk = Hkdf::<Sha256>::new(Some(b"noti-stuff/v1"), secret);
    Keys {
        channel: expand(&hk, "channel"),
        enc: expand(&hk, "enc"),
        auth_phone: expand(&hk, "auth-phone"),
        auth_laptop: expand(&hk, "auth-laptop"),
    }
}

impl Keys {
    pub fn channel_hex(&self) -> String {
        hex::encode(self.channel)
    }
    pub fn auth_key(&self, role: Role) -> &[u8; 32] {
        match role {
            Role::Phone => &self.auth_phone,
            Role::Laptop => &self.auth_laptop,
        }
    }
}

/// Encrypt a payload. Output: base64url(nonce(12) || ciphertext||tag).
/// The channel id is bound as associated data.
pub fn seal(enc: &[u8; 32], channel: &[u8; 16], plaintext: &[u8]) -> String {
    let c = ChaCha20Poly1305::new(Key::from_slice(enc));
    let nonce = ChaCha20Poly1305::generate_nonce(&mut OsRng);
    let ct = c
        .encrypt(&nonce, Payload { msg: plaintext, aad: channel })
        .expect("encrypt");
    let mut out = nonce.to_vec();
    out.extend_from_slice(&ct);
    B64.encode(out)
}

pub fn open(enc: &[u8; 32], channel: &[u8; 16], sealed: &str) -> Result<Vec<u8>, String> {
    let raw = B64.decode(sealed).map_err(|e| e.to_string())?;
    if raw.len() < 12 + 16 {
        return Err("too short".into());
    }
    let (n, ct) = raw.split_at(12);
    ChaCha20Poly1305::new(Key::from_slice(enc))
        .decrypt(Nonce::from_slice(n), Payload { msg: ct, aad: channel })
        .map_err(|_| "decrypt failed".to_string())
}

/// Canonical string that is HMAC'd for request authentication.
pub fn signing_input(method: &str, path_and_query: &str, ts: i64, nonce: &str, body: &[u8]) -> String {
    format!(
        "v1\n{}\n{}\n{}\n{}\n{}",
        method.to_ascii_uppercase(),
        path_and_query,
        ts,
        nonce,
        hex::encode(Sha256::digest(body))
    )
}

pub fn sign(key: &[u8; 32], input: &str) -> String {
    let mut m = <Hmac<Sha256> as Mac>::new_from_slice(key).expect("hmac key");
    m.update(input.as_bytes());
    hex::encode(m.finalize().into_bytes())
}

/// Constant-time verification.
pub fn verify(key: &[u8; 32], input: &str, sig_hex: &str) -> bool {
    let Ok(sig) = hex::decode(sig_hex) else { return false };
    let mut m = <Hmac<Sha256> as Mac>::new_from_slice(key).expect("hmac key");
    m.update(input.as_bytes());
    m.verify_slice(&sig).is_ok()
}

pub fn b64_decode(s: &str) -> Result<Vec<u8>, String> {
    B64.decode(s).map_err(|e| e.to_string())
}

pub fn new_nonce() -> String {
    let mut b = [0u8; 12];
    rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut b);
    hex::encode(b)
}

/// Decrypted notification payload (JSON inside the sealed blob).
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Notification {
    /// Stable id for dedup / replacing updated notifications.
    pub id: String,
    pub pkg: String,
    pub app: String,
    pub title: String,
    pub text: String,
    /// Unix millis when posted on the phone.
    pub ts: i64,
    /// Optional base64url PNG of the app icon; sent occasionally, cached by the receiver.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub icon: Option<String>,
}

/// `noti://pair?u=<relay url>&k=<base64url secret>`
pub fn pairing_uri(relay_url: &str, secret: &[u8; 32]) -> String {
    format!("noti://pair?u={}&k={}", relay_url, B64.encode(secret))
}

pub fn parse_pairing_uri(uri: &str) -> Result<(String, [u8; 32]), String> {
    let q = uri.strip_prefix("noti://pair?").ok_or("not a noti pairing uri")?;
    let (mut u, mut k) = (None, None);
    for kv in q.split('&') {
        match kv.split_once('=') {
            Some(("u", v)) => u = Some(v.to_string()),
            Some(("k", v)) => k = Some(v.to_string()),
            _ => {}
        }
    }
    let k = B64.decode(k.ok_or("missing k")?).map_err(|e| e.to_string())?;
    let k: [u8; 32] = k.try_into().map_err(|_| "bad key length")?;
    Ok((u.ok_or("missing u")?, k))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_and_tamper() {
        let k = derive(&new_secret());
        let s = seal(&k.enc, &k.channel, b"hello");
        assert_eq!(open(&k.enc, &k.channel, &s).unwrap(), b"hello");
        assert!(open(&k.enc, &[0u8; 16], &s).is_err());
        let mut t = s.clone();
        t.replace_range(20..21, if &t[20..21] == "A" { "B" } else { "A" });
        assert!(open(&k.enc, &k.channel, &t).is_err());
    }

    #[test]
    fn signatures() {
        let k = derive(&new_secret());
        let i = signing_input("post", "/v1/send", 1, "n", b"x");
        let s = sign(&k.auth_phone, &i);
        assert!(verify(&k.auth_phone, &i, &s));
        assert!(!verify(&k.auth_laptop, &i, &s));
        assert!(!verify(&k.auth_phone, &signing_input("post", "/v1/send", 1, "n", b"y"), &s));
    }

    #[test]
    fn pairing() {
        let s = new_secret();
        let (u, k) = parse_pairing_uri(&pairing_uri("https://x.dev", &s)).unwrap();
        assert_eq!((u.as_str(), k), ("https://x.dev", s));
    }

    // Reference vector; the Android implementation is checked against these values.
    #[test]
    fn derivation_vector() {
        let k = derive(&[7u8; 32]);
        assert_eq!(k.channel_hex().len(), 32);
        eprintln!("VECTOR channel={} enc={} auth_phone={}", k.channel_hex(), hex::encode(k.enc), hex::encode(k.auth_phone));
    }
}

#[cfg(test)]
mod interop {
    use super::*;
    // Regenerate with: cargo test -p proto interop -- --nocapture
    #[test]
    fn print_interop_vector() {
        let k = derive(&[7u8; 32]);
        let sealed = seal(&k.enc, &k.channel, b"{\"hello\":\"interop\"}");
        let sig = sign(&k.auth_phone, &signing_input("POST", "/v1/send", 1700000000, "abc", sealed.as_bytes()));
        eprintln!("INTEROP chan={} sealed={} sig={}", k.channel_hex(), sealed, sig);
    }
}
