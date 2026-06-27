# Deploy Norwegian Honey on Hetzner

## Overview

```
Internet → Caddy (HTTPS :443) → api:8000 (Docker internal)
                                      ↓
                               SQLite /data/canary.db
```

- **Caddy** terminates TLS (Let's Encrypt) and reverse-proxies to FastAPI.
- Port **8000 is not exposed** publicly in production.
- **ngrok is not used** on the VPS — use a real domain instead.

---

## 1. Create the Hetzner server

1. Hetzner Cloud → **Add Server**
2. Image: **Ubuntu 24.04**
3. Type: **CX22** or similar (2 vCPU, 4 GB RAM recommended)
4. Add your SSH key
5. Note the **public IPv4 address**

---

## 2. DNS

Create an **A record** (or use the hostname Hetzner assigned) pointing to the server IP:

```
www736.your-server.de  →  <HETZNER_IP>
```

Hetzner `your-server.de` hostnames are often pre-linked to your server — verify with:

```bash
dig +short www736.your-server.de
```

---

## 3. Bootstrap the server (once)

```bash
ssh root@<HETZNER_IP>

# Option A: clone from git
apt-get update && apt-get install -y git
git clone <your-repo-url> /opt/norwegian-honey
cd /opt/norwegian-honey

# Option B: copy from your machine
# rsync -avz --exclude .venv --exclude data ./ user@<HETZNER_IP>:/opt/norwegian-honey/

sudo bash deploy/setup-server.sh
```

---

## 4. Configure environment

```bash
cd /opt/norwegian-honey
cp .env.production.example .env
nano .env
```

Set at minimum:

```env
DOMAIN=www736.your-server.de
PUBLIC_BASE_URL=https://www736.your-server.de
DEBUG=false
TRUSTED_PROXY_HEADERS=true
ABUSEIPDB_API_KEY=...   # optional
IPINFO_API_KEY=...      # optional
```

---

## 5. Deploy

```bash
bash deploy/deploy.sh
```

Or from your dev machine (if compose context is synced):

```bash
make prod-up
```

Verify:

```bash
curl -s https://www736.your-server.de/health
```

---

## 6. Generate canary tokens (on server)

```bash
docker compose exec api python scripts/generate_canary_token.py \
  --base-url "https://www736.your-server.de" --count 1
```

View hits:

```bash
make canary-logs-docker
# or on server:
docker compose exec -T api python -c "
import sqlite3
db=sqlite3.connect('/data/canary.db')
for r in db.execute('SELECT id, token, client_ip, user_agent, timestamp FROM canary_hits ORDER BY id DESC LIMIT 10'):
    print(r)
"
```

---

## 7. Updates

```bash
cd /opt/norwegian-honey
git pull
bash deploy/deploy.sh
```

---

## OpSec checklist

- [ ] `DEBUG=false` in `.env` (disables `/docs`, `/openapi.json`)
- [ ] `INVESTIGATOR_API_KEY` set — `/analyze` and `/osint` reject unauthenticated requests
- [ ] Canary tokens **registered** before embedding (`make canary-token` or `register_canary_token.py`)
- [ ] Firewall allows only **22, 80, 443** (`setup-server.sh` does this)
- [ ] Rate limiting enabled via custom Caddy image (see below)
- [ ] Do not commit `.env` or `ngrok.local.yml`

---

## Counter-attack hardening

After a scammer discovers the tracking pixel, they may flood endpoints, burn OSINT API quota, or probe for weaknesses. Layers in place:

| Layer | What it does |
|-------|----------------|
| **Caddy rate limits** | Per-IP caps on all paths (see below) |
| **API key** | `/analyze` and `/osint` require `X-API-Key` header |
| **Token registry** | Only pre-registered canary tokens are logged — random floods are ignored |
| **Body size limits** | 1–2 MiB max at app + Caddy |
| **OSINT caps** | Max 10 entities per type per request |
| **Hit retention** | SQLite hits pruned after 90 days (configurable) |
| **No info leaks** | Canary always returns same PNG; OSINT errors are generic; `/health` has no version |
| **Host validation** | `TrustedHostMiddleware` when `DOMAIN` is set |
| **Blocked paths** | `/openapi.json`, `/docs`, `/redoc` return 404 at Caddy |

### Generate API key

```bash
python -c "import secrets; print(secrets.token_urlsafe(32))"
```

Add to `.env` on the server as `INVESTIGATOR_API_KEY=...` and to your local `.env` / `make.env` for Makefile targets.

### Canary workflow (production)

```bash
# From your machine — generates token, registers on VPS, prints embed HTML
make canary-token

# Or manually register an existing token on the server
make prod-canary-register TOKEN=your-token-here
```

Unregistered tokens still get a valid PNG (no error leak) but **produce no log entry**.

---

## Rate limiting

Production Caddy is built with `github.com/mholt/caddy-ratelimit` (`deploy/Dockerfile.caddy`).

Per-client IP limits (per minute):

| Zone | Path | Limit |
|------|------|-------|
| global | all | 120 req |
| analyze | `/analyze/*` | 20 req |
| osint | `/osint/*` | 30 req |
| canary | `/images/*` | 60 req |

Exceeded limits return **HTTP 429** with `Retry-After: 60`.

To tune limits, edit `deploy/Caddyfile` and redeploy:

```bash
bash deploy/deploy.sh
```

First deploy after this change rebuilds the Caddy image (may take 1–2 minutes).

---

## Troubleshooting

| Problem | Fix |
|---------|-----|
| Caddy won't get certificate | DNS not propagated; check `dig spek-tr.no` |
| 401 Unauthorized | Set `INVESTIGATOR_API_KEY` in `.env` and pass `X-API-Key` header |
| 503 Service unavailable | `INVESTIGATOR_API_KEY` missing on server — set in `.env` and redeploy |
| 429 Too Many Requests | Rate limit hit — wait 60s or tune `deploy/Caddyfile` |
| Canary hit not logged | Token not registered — run `make prod-canary-register TOKEN=...` |
| 502 Bad Gateway | `docker compose logs api` — API not healthy |
| Canary hits missing | Confirm `TRUSTED_PROXY_HEADERS=true` |
| Port 8000 conflict | Production compose removes public 8000 binding |

---

## Local vs production

| | Local dev | Hetzner VPS |
|--|-----------|-------------|
| Start | `make dev` | `bash deploy/deploy.sh` |
| HTTPS | ngrok | Caddy + Let's Encrypt |
| Canary URL | ngrok domain | `https://DOMAIN` |
| DB | `./data/canary.db` | Docker volume `canary_data` |
