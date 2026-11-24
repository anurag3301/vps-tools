#!/bin/bash
# Run on the VPS after copying noti-upload-recv and the gc units to /tmp.
# usage: setup-upload.sh <login-user>      e.g. setup-upload.sh anurag
# `upload` clients run `ssh <login-user>@host noti-upload-recv ...`, so that user must be in group `upload`.
set -euo pipefail
LOGIN="$1"
getent group upload >/dev/null || sudo groupadd --system upload
id upload >/dev/null 2>&1 || sudo useradd --system --gid upload --home-dir /var/lib/noti-upload --shell /usr/sbin/nologin upload
sudo install -d -m 0755 -o upload -g upload /var/lib/noti-upload
# files/ is setgid + group-writable so every member of group `upload` (login user, relay, gc) can store and delete
sudo install -d -m 2775 -o upload -g upload /var/lib/noti-upload/files
sudo find /var/lib/noti-upload/files -mindepth 1 -type d -exec chmod 775 {} +
sudo usermod -aG upload "$LOGIN"
id noti >/dev/null 2>&1 && sudo usermod -aG upload noti
sudo install -m 0755 /tmp/noti-upload-recv /usr/local/bin/noti-upload-recv
sudo install -m 0644 /tmp/noti-upload-gc.service /tmp/noti-upload-gc.timer /etc/systemd/system/
sudo systemctl daemon-reload && sudo systemctl enable --now noti-upload-gc.timer
echo "done. $LOGIN must log in again for the new group to apply."
