#!/bin/sh
# certbot renew hook for notify.anurag3301.dev: copy certs where Caddy can read them and reload.
set -e
L=/etc/letsencrypt/live/notify.anurag3301.dev
install -d -m 0750 -o root -g caddy /etc/caddy/certs
install -m 0640 -o root -g caddy $L/fullchain.pem /etc/caddy/certs/fullchain.pem
install -m 0640 -o root -g caddy $L/privkey.pem /etc/caddy/certs/privkey.pem
systemctl reload caddy 2>/dev/null || systemctl restart caddy
