#!/bin/bash
# Run on the VPS. Adds a default-deny firewall (22/80/443/8443 only), fail2ban for sshd, and auto security updates.
# Verify SSH key login works in a second session before running; ufw is enabled at the end.
set -euo pipefail
sudo apt-get update -qq
sudo apt-get install -y ufw fail2ban unattended-upgrades
sudo ufw default deny incoming
sudo ufw default allow outgoing
sudo ufw allow 22/tcp
sudo ufw allow 80/tcp
sudo ufw allow 443/tcp
sudo ufw allow 8443/tcp  # relay (Caddy)
sudo ufw --force enable
sudo systemctl enable --now fail2ban
sudo dpkg-reconfigure -f noninteractive unattended-upgrades
grep -Ei '^\s*(PasswordAuthentication|PermitRootLogin)' /etc/ssh/sshd_config /etc/ssh/sshd_config.d/* 2>/dev/null || echo "WARN: set PasswordAuthentication no / PermitRootLogin no"
