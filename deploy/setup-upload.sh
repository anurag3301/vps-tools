#!/bin/bash
# Run on the VPS after copying noti-upload-recv and the gc units to /tmp.
# usage: setup-upload.sh "<public key line>"   (repeat the authorized_keys line for each device)
set -euo pipefail
KEY="$1"
id upload >/dev/null 2>&1 || sudo useradd --system --home-dir /var/lib/noti-upload --shell /bin/sh upload
sudo usermod -p '*' upload   # unlocked for key auth, no usable password
sudo install -d -m 0755 -o upload -g upload /var/lib/noti-upload
# files/ is setgid + group-writable so the relay (user noti, group upload) can store and delete too
sudo install -d -m 2775 -o upload -g upload /var/lib/noti-upload/files
sudo find /var/lib/noti-upload/files -mindepth 1 -type d -exec chmod 775 {} +
id noti >/dev/null 2>&1 && sudo usermod -aG upload noti
sudo install -m 0755 /tmp/noti-upload-recv /usr/local/bin/noti-upload-recv
# authorized_keys is root-owned so the upload user can't alter its own access
sudo install -d -m 0755 -o root -g root /var/lib/noti-upload/.ssh
LINE="restrict,command=\"/usr/local/bin/noti-upload-recv --root /var/lib/noti-upload --base-url https://anurag3301.dev/f\" $KEY"
echo "$LINE" | sudo tee -a /var/lib/noti-upload/.ssh/authorized_keys >/dev/null
sudo chown root:root /var/lib/noti-upload/.ssh/authorized_keys && sudo chmod 0644 /var/lib/noti-upload/.ssh/authorized_keys
sudo install -m 0644 /tmp/noti-upload-gc.service /tmp/noti-upload-gc.timer /etc/systemd/system/
sudo systemctl daemon-reload && sudo systemctl enable --now noti-upload-gc.timer
