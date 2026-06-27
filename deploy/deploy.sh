#!/usr/bin/env bash
# Deploy / update Norwegian Honey on the VPS.
# Run from repo root: bash deploy/deploy.sh
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

if [[ ! -f .env ]]; then
  echo "Missing .env — copy .env.production.example to .env and set DOMAIN"
  exit 1
fi

# shellcheck disable=SC1091
set -a
source .env
set +a

if [[ -z "${DOMAIN:-}" ]]; then
  echo "Set DOMAIN in .env (e.g. www736.your-server.de)"
  exit 1
fi

echo "Deploying to https://${DOMAIN}"

docker compose -f docker-compose.yml -f docker-compose.prod.yml up -d --build

echo "Waiting for health..."
for _ in $(seq 1 30); do
  if docker compose exec -T api python -c \
    "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/health')" 2>/dev/null; then
    break
  fi
  sleep 2
done

echo "Local health:"
docker compose exec -T api python -c \
  "import urllib.request; print(urllib.request.urlopen('http://127.0.0.1:8000/health').read().decode())"

echo ""
echo "Public health (after DNS + TLS propagate):"
echo "  curl -s https://${DOMAIN}/health"
echo ""
echo "Canary token:"
echo "  docker compose exec -T api python scripts/generate_canary_token.py --base-url https://${DOMAIN} --count 1"
