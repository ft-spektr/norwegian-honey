#!/usr/bin/env bash
# One-time Hetzner VPS bootstrap (Ubuntu 24.04).
# Run as root: sudo bash deploy/setup-server.sh
set -euo pipefail

if [[ "${EUID:-}" -ne 0 ]]; then
  echo "Run as root: sudo bash deploy/setup-server.sh"
  exit 1
fi

export DEBIAN_FRONTEND=noninteractive

apt-get update
apt-get install -y ca-certificates curl git ufw

# Docker (official)
if ! command -v docker >/dev/null; then
  install -m 0755 -d /etc/apt/keyrings
  curl -fsSL https://download.docker.com/linux/ubuntu/gpg -o /etc/apt/keyrings/docker.asc
  chmod a+r /etc/apt/keyrings/docker.asc
  echo \
    "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/ubuntu \
    $(. /etc/os-release && echo "${VERSION_CODENAME}") stable" \
    > /etc/apt/sources.list.d/docker.list
  apt-get update
  apt-get install -y docker-ce docker-ce-cli containerd.io docker-compose-plugin
fi

# Firewall: SSH + HTTP + HTTPS only
ufw --force reset
ufw default deny incoming
ufw default allow outgoing
ufw allow OpenSSH
ufw allow 80/tcp
ufw allow 443/tcp
ufw --force enable

mkdir -p /opt/norwegian-honey
echo "Server ready."
echo "Next:"
echo "  1. Clone repo into /opt/norwegian-honey"
echo "  2. cp .env.production.example .env && edit DOMAIN + API keys"
echo "  3. Point DNS A record for your domain to this server's IP"
echo "  4. bash deploy/deploy.sh"
