# vps-tools

Small, security-minded tools that run on my VPS (or talk to it):

1. **noti** — end-to-end encrypted notification relay: Android phone → VPS relay → Linux laptop.
2. **upload** — 0x0.st-style file upload authenticated by my ssh key.

## upload

`upload <file>` streams the file over ssh to a restricted `upload` user (forced command
`noti-upload-recv`), which stores it in `/var/lib/noti-upload/files/<id>/<name>`. The site serves it
read-only at `https://anurag3301.dev/f/<id>/<name>` (Flask route, nosniff + sandbox CSP, risky types
forced to download). It prints the link and a QR, copies it, and logs to `~/.upload_list`.

| Command | What |
|---|---|
| `upload <file>` | upload (max 256 MB; retention 90 days for tiny files down to 10 days at the limit) |
| `upload stat` | server total / free / used storage |
| `upload list` | fzf, newest first; Enter downloads |
| `upload rm` | fzf, largest first; Enter deletes after y/n |
| `upload clear` | delete everything after y/n |

Everything except downloading needs the ssh key. Server setup: `deploy/setup-upload.sh`
(copy `noti-upload-recv` and the `noti-upload-gc.*` units to `/tmp` on the VPS first).

## noti

End-to-end encrypted notification relay: Android phone → VPS relay → Linux laptop.

```
phone app ──HTTPS POST (ciphertext)──► relay (VPS, Caddy TLS) ◄──HTTPS long-poll── laptop daemon ──► notify-send
```

| Path | What |
|---|---|
| `crates/proto` | Shared crypto/protocol (HKDF, ChaCha20-Poly1305, HMAC request signing) |
| `crates/relay` | `noti-relay`: closed, in-memory relay (axum) |
| `crates/daemon` | `noti-daemon`: pair / receive / `test-send` |
| `crates/upload` | `upload` client |
| `crates/upload-recv` | `noti-upload-recv`: server-side receiver, list/delete, gc |
| `android/` | Kotlin app (`NotificationListenerService`), no UI framework deps |
| `deploy/` | systemd units, Caddyfile, VPS hardening script |

## Security model
- **E2E:** one 32-byte secret is created on the laptop and handed to the phone via QR. Payloads are ChaCha20-Poly1305 sealed (channel id as AAD). The relay never has the key, so it only sees ciphertext.
- **Closed relay:** only channels listed in `/var/lib/noti-relay/channels.txt` exist. No open registration.
- **Auth:** every request carries `x-chan/x-ts/x-nonce/x-sig` (HMAC-SHA256 over method, path+query, ts, nonce, body hash). Separate keys per role (phone can send, laptop can poll). ±60 s window plus nonce replay cache.
- **Abuse limits:** 16 KB body, 120 sends/min/channel, 500-message queue, 24 h TTL, 10 auth failures → 10 min IP lockout, max 2 pollers per channel.
- **No persistence** of messages; relay runs as an unprivileged `noti` user in a sandboxed systemd unit, loopback-only behind Caddy (port 8443; the main site is untouched).
- The pairing secret on the phone is wrapped by an Android Keystore key; on the laptop it's `~/.config/noti/config.json` (0600).

## Setup
```sh
cargo build --release
# laptop: pair (also registers the channel on the VPS over ssh) and run
noti-daemon pair --relay https://notify.anurag3301.dev:8443 --ssh anurag3301.dev
systemctl --user enable --now noti-daemon
noti-daemon test-send "Hello" "from the CLI"      # acts as the phone
```
Phone: install `noti-debug.apk` (`adb install`), scan the QR, grant *notification access*, set battery to *Unrestricted* (Samsung: Settings → Apps → Noti → Battery).

Android build: `cd android && ANDROID_HOME=~/Android ./gradlew assembleDebug`. Crypto interop with Rust is covered by `./gradlew testDebugUnitTest`.

## Revoke
`ssh vps 'sudo -u noti noti-relay remove --channels /var/lib/noti-relay/channels.txt <channel-prefix>'` (picked up within 10 s), then `rm ~/.config/noti/config.json` and unpair in the app.
