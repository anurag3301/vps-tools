# SETUP.md: instructions for an AI agent

You are setting up **vps-tools** for a user: an E2E-encrypted phone→PC notification relay (`noti`) and an
ssh-authenticated file upload tool (`upload`), plus the website that serves uploaded files. Read the whole file first.
Work step by step, run the checks in each step, and **stop and report if a check fails** instead of improvising.
Never print secrets (pairing links/`secret_hex`/private keys) anywhere except to the user's own terminal, and say so when you do.
Prefer your file-editing tools to shell redirection for editing files, and ask before any destructive action (deleting users, files, resetting firewall rules).

## 0. Ask the user (all at once)

1. **SSH login**: `user@host` (host = domain or IP) of the VPS, e.g. `anurag@anurag3301.dev`. Call it `$LOGIN`, `$HOST`.
2. **Main domain** that serves the site and public file links (default: `$HOST` if it is a domain). Call it `$SITE`.
3. **Notify subdomain** for the relay (default `notify.$SITE`). Call it `$NOTIFY`. Its DNS **A record must point to the VPS** (the user does this at their registrar; check with `dig +short $NOTIFY`).
4. Which machine you are running on (Linux laptop / Windows) and whether this is a fresh VPS or the existing one already running things.

Then test ssh: `ssh -o BatchMode=yes $LOGIN 'id; uname -m; sudo -n true && echo SUDO_OK; ss -tlnp | head -30; sudo ufw status'`.
- If ssh fails: tell the user to fix key auth first (`ssh-copy-id`), and stop.
- If `SUDO_OK` is missing: the user must grant passwordless sudo or run the sudo parts themselves.
- Note which ports are taken. The relay design needs: `443`/`80` for the site (already owned by the website), `8443` for Caddy, optionally `53/tcp` (see step 5). If something already uses 8443, pick another port and substitute it everywhere.

## 1. Get the sources over HTTPS

```sh
mkdir -p ~/repo && cd ~/repo
git clone https://github.com/anurag3301/vps-tools.git
git clone https://github.com/anurag3301/anurag3301.dev.git     # the website (Flask/gunicorn); used on the VPS
```
The website clone is also what must exist **on the VPS** (`~/anurag3301.dev`). Check: `ssh $LOGIN 'cd ~/anurag3301.dev && git pull --ff-only && git log --oneline -1'`.
(`git@github.com:` URLs also work but need the user's GitHub ssh key; use https unless told otherwise.)

## 2. Toolchain and build (laptop)

Install Rust (`curl https://sh.rustup.rs -sSf | sh -s -- -y`; on Windows use rustup-init + Visual Studio Build Tools "Desktop development with C++"). On Linux also install `fzf`, `curl`, `libnotify-bin` (provides `notify-send`) and a clipboard tool (`wl-clipboard` or `xclip`).

```sh
cd ~/repo/vps-tools
cargo test --workspace                      # sanity (Linux)
cargo build --release -p relay -p upload-recv   # server binaries (Linux x86_64/aarch64 only)
cargo build --release -p daemon -p upload       # PC-side tools (Linux or Windows)
```
If the VPS architecture (`uname -m` above) differs from the laptop, build on the VPS instead (`git clone` + the same `cargo build` there).
Install the PC tools: `install -m755 target/release/{noti-daemon,upload} ~/.local/bin/` (Windows: copy the `.exe`s to a folder on PATH).

## 3. Server: base hardening (once per VPS)

Review `deploy/harden-vps.sh`, then copy and run it (it enables ufw for 22/80/443/8443/53, fail2ban, unattended-upgrades).
**Before** running it, confirm ssh key login works in a second session and `PasswordAuthentication no` / `PermitRootLogin no`. Skip it if the user already has a firewall; just make sure the needed ports are open.

## 4. Server: upload store and receiver

```sh
scp target/release/noti-upload-recv deploy/setup-upload.sh deploy/noti-upload-gc.service deploy/noti-upload-gc.timer $LOGIN:/tmp/
ssh $LOGIN 'bash /tmp/setup-upload.sh $(id -un)'
```
This creates group/user `upload`, `/var/lib/noti-upload/files` (setgid, group-writable), puts the login user (and `noti`, if it exists) in group `upload`, installs `/usr/local/bin/noti-upload-recv` and the daily gc timer.
Group changes need a **new ssh session** to apply.

### The website's `/f/<id>/<name>` route
The site (`anurag3301.dev` repo, `app.py`) serves uploads read-only from `UPLOAD_DIR` (default `/var/lib/noti-upload/files`).
- Same repo/site: `ssh $LOGIN 'cd ~/anurag3301.dev && git pull --ff-only && sudo systemctl restart webserver'` (the unit is `webserver.service` running gunicorn on :443; confirm with `systemctl status webserver`). The gunicorn user must be able to read the files dir (world-readable files are 0644; dir 2775).
- A different website: add an equivalent route (GET only, serves `UPLOAD_DIR/<id>/<name>`, validates ids/names with a strict regex, `X-Content-Type-Options: nosniff`, `Content-Security-Policy: sandbox`, risky types forced to download). Read `app.py` for the reference implementation.

The `--base-url` the clients use must equal `https://$SITE/f`.

## 5. Server: relay behind Caddy

1. Install Caddy (`sudo apt install caddy`) and certbot (`sudo apt install certbot`). Stop/disable Caddy's default site on :80/:443 if it conflicts: this setup uses `auto_https off` and only listens on `$NOTIFY:8443` (and `:53`).
2. Certificate for `$NOTIFY` via **webroot** (the site already answers port 80; its webroot is the site's `home/public` dir, so `/.well-known/acme-challenge/` must be served there; check how the site handles port 80, e.g. `deploy/acme_redirect.py` in the website repo):
   ```sh
   sudo certbot certonly --webroot -w ~/anurag3301.dev/home/public -d $NOTIFY
   ```
3. Copy `deploy/caddy-cert-hook.sh` to `/usr/local/sbin/caddy-cert-hook.sh` (edit `L=` to the `$NOTIFY` cert dir, `chmod 755`), run it once, and register it as renew hook: add `renew_hook = /usr/local/sbin/caddy-cert-hook.sh` to `/etc/letsencrypt/renewal/$NOTIFY.conf`. Test with `sudo certbot renew --dry-run`.
4. Install `deploy/Caddyfile` as `/etc/caddy/Caddyfile`, replacing `notify.anurag3301.dev` with `$NOTIFY`. Port 53/tcp is only for office networks that block 8443: check `ss -tlnp | grep ':53 '`; `systemd-resolved` only listens on 127.0.0.53 so it normally does not conflict. If anything else owns it, drop the `:53` address. (`admin off` means **`systemctl restart caddy`**, not reload.)
5. Create the relay user and install the service:
   ```sh
   sudo useradd --system --home-dir /var/lib/noti-relay --shell /usr/sbin/nologin noti
   sudo usermod -aG upload noti
   scp target/release/noti-relay deploy/noti-relay.service $LOGIN:/tmp/
   sudo install -m755 /tmp/noti-relay /usr/local/bin/noti-relay
   # edit --files-url in the unit to https://$SITE/f first
   sudo install -m644 /tmp/noti-relay.service /etc/systemd/system/
   sudo systemctl daemon-reload && sudo systemctl enable --now noti-relay && sudo systemctl restart caddy
   ```
   Redeploying later = copy binary, `install`, `systemctl restart noti-relay`.

## 6. This PC: pair, configure, start

```sh
noti-daemon pair --relay https://$NOTIFY:8443 --ssh $LOGIN     # registers the channel on the VPS via `sudo -u noti noti-relay add`, prints a QR + link
noti-daemon install                                            # Linux: systemd user unit; Windows: HKCU Run key
upload setup $LOGIN                                            # public URL defaults to https://<host>/f; pass a 2nd arg to override
```
If the user's network blocks 8443, set `"relay"` in `~/.config/noti/config.json` (`%APPDATA%\noti\config.json` on Windows) to the `:53` URL.
`pair` prints a QR/link: this is the pairing secret. Only the user should see it.

Additional PCs share the same secret and get their **own queue** (5-message ring each, max 8 per channel):
`noti-daemon share` on a paired PC → `noti-daemon join '<link>'` on the new one (quote the link in PowerShell, it contains `&`) → `noti-daemon install`.

## 7. Verify everything (run all, report a table of PASS/FAIL)

```sh
# website over HTTPS, cert valid
curl -sS -o /dev/null -w '%{http_code}\n' https://$SITE/                       # 200
echo | openssl s_client -connect $SITE:443 -servername $SITE 2>/dev/null | openssl x509 -noout -enddate
# relay up on each port, cert valid
curl -sS https://$NOTIFY:8443/healthz                                          # ok
curl -sS https://$NOTIFY:53/healthz                                            # ok (skip if :53 not configured)
curl -sS -o /dev/null -w '%{http_code}\n' https://$NOTIFY:8443/anything        # 404 (everything but the API is dropped)
# services and firewall
ssh $LOGIN 'systemctl is-active noti-relay caddy webserver noti-upload-gc.timer; sudo ufw status | head -15; sudo fail2ban-client status sshd | head -4'
ssh $LOGIN 'sudo certbot renew --dry-run 2>&1 | tail -3'
# noti end to end (the toast should appear on this PC; for Linux also: systemctl --user is-active noti-daemon)
noti-daemon test-send "setup test" "hello from the setup guide"
journalctl --user -u noti-daemon -n 5 --no-pager        # Linux; Windows: run `noti-daemon run` visibly
# upload end to end
upload stat
echo setup-test > /tmp/setup-test.txt
URL=$(upload /tmp/setup-test.txt 2>/dev/null | head -1); echo $URL
curl -sS $URL                                                                  # setup-test
ssh $LOGIN "noti-upload-recv del $(echo $URL | cut -d/ -f5)"                   # clean up
rm /tmp/setup-test.txt
```
Also confirm: relay listens only on loopback (`ssh $LOGIN 'ss -tlnp | grep 8787'` shows `127.0.0.1`), `channels.txt` is not world-readable (`/var/lib/noti-relay`, mode 0750), and no secret files (`config.json`, `channels.txt`) are tracked by git (`git ls-files | grep -E 'config.json|channels'` is empty).

## 8. What the user still has to do (tell them explicitly)

1. **DNS**: A record for `$NOTIFY` → VPS IP (if not done before step 5).
2. **Phone app**: build/install `noti-debug.apk`:
   `cd android && ANDROID_HOME=~/Android ./gradlew assembleDebug`, then `adb install -r app/build/outputs/apk/debug/app-debug.apk` (or copy the APK to the phone). Open it, **scan the QR** printed by `noti-daemon pair`, grant **Notification access**, and set battery to **Unrestricted** (Samsung: Settings → Apps → Noti → Battery). The phone talks to `:8443`; if their phone network blocks that, they can pair with the `:53` relay URL instead.
3. **Other PCs**: `noti-daemon share` / `join` as above; Windows needs the Rust + VS Build Tools toolchain to build, or copy the cross-compiled `.exe` (`cargo build --release -p daemon -p upload --target x86_64-pc-windows-gnu` needs `gcc-mingw-w64-x86-64`).
4. **Windows `upload`**: needs OpenSSH client, `curl`, `fzf` (`winget install fzf`); run `upload setup $LOGIN`.
5. **Revoke a device/channel**: `ssh $LOGIN 'sudo -u noti noti-relay remove --channels /var/lib/noti-relay/channels.txt <channel-prefix>'`, delete `config.json` on the PC, unpair in the app.

## Notes and pitfalls

- Only `/v1/send`, `/v1/poll`, `/v1/files*` and `/healthz` are forwarded by Caddy; the relay holds only auth keys, never the encryption key, so a compromised VPS cannot read or forge notifications.
- `upload` auth = your normal ssh login (no restricted account). Anyone with that key already has a shell; keep keys passphrase-protected.
- Relay queue: 5-message ring buffer per PC, 24 h TTL, in memory only. Devices self-register on first signed poll (cap 8).
- The HKDF salt `noti-stuff/v1` in `crates/proto` must never change (it would break all existing pairings).
- Windows toasts and autostart are untested on every Windows version; if toasts show as "Windows PowerShell" or without an icon, sign out and back in (Windows caches the app registration).
- Do not use `gh` for github.com if it is logged into another host; use plain `git` over https.
