# Deploy Norwegian Honey

Production guide for a Linux VPS with SSH (Hetzner, DigitalOcean, Vultr, etc.).

## Architecture

```
Internet → Caddy (:443, TLS, rate limits) → api:8000 (Docker internal only)
                                                    ↓
                                         SQLite  /data/canary.db
```

| Component | Role |
|-----------|------|
| **Caddy** | Let's Encrypt TLS, reverse proxy, rate limits, strips spoofed `X-Forwarded-For` |
| **FastAPI** | `/analyze`, `/osint` (API-key protected), `/images`, `/portfolio` (canary traps) |
| **SQLite** | Canary hits + registered tokens (Docker volume `canary_data`) |

Port **8000 is not published** publicly. Only Caddy exposes **80** and **443**.

---

## Prerequisites

- VPS with **SSH** (SFTP-only hosting will not work)
- A domain or subdomain with an **A record** → VPS public IP
- SSH key on the server (`~/.ssh/norwegian-honey` recommended)

Example: `canary.example.com` → `YOUR_VPS_IP`

```bash
dig +short canary.example.com
```

---

## 1. Bootstrap the server (once)

```bash
ssh -i ~/.ssh/norwegian-honey root@YOUR_VPS_IP

apt-get update && apt-get install -y git
git clone https://github.com/YOUR_ORG/norwegian-honey.git /opt/norwegian-honey
cd /opt/norwegian-honey

bash deploy/setup-server.sh    # Docker, UFW (22/80/443), fail2ban
```

---

## 2. Configure `.env` on the VPS

```bash
cd /opt/norwegian-honey
cp .env.production.example .env
nano .env
```

**Required:**

```env
DOMAIN=canary.example.com
INVESTIGATOR_API_KEY=<generate-below>
DEBUG=false
TRUSTED_PROXY_HEADERS=true
```

Generate the API key:

```bash
python3 -c "import secrets; print(secrets.token_urlsafe(32))"
```

Copy the same key to your **local** `.env` so Makefile targets (`make analyze-eml`, etc.) can send `X-API-Key`.

**Canary (defaults are fine):**

```env
CANARY_STORAGE=sqlite
CANARY_SQLITE_PATH=/data/canary.db
CANARY_REQUIRE_REGISTERED_TOKEN=true
CANARY_HIT_RETENTION_DAYS=90
```

**Optional OSINT keys:** `ABUSEIPDB_API_KEY`, `IPINFO_API_KEY`

---

## 3. Deploy / update

On the **VPS**:

```bash
cd /opt/norwegian-honey
git pull
bash deploy/deploy.sh
```

`deploy.sh` checks `DOMAIN` and `INVESTIGATOR_API_KEY`, builds images, starts Caddy + API, and prints health status.

Verify:

```bash
curl -s https://canary.example.com/health
# {"status":"ok"}
```

---

## 4. Configure your laptop (`make.env`)

For remote canary ops from your dev machine:

```bash
cp make.env.example make.env
nano make.env
```

```env
PROD_SSH=root@YOUR_VPS_IP
PROD_SSH_KEY=$(HOME)/.ssh/norwegian-honey
PROD_REMOTE_DIR=/opt/norwegian-honey
```

Load your SSH key once per session:

```bash
ssh-add ~/.ssh/norwegian-honey
```

---

## 5. Canary operations

### Trap types

| Trap | URL | Embed |
|------|-----|-------|
| **Pixel** | `https://DOMAIN/images/{token}.png` | `<img src="..." width="1" height="1" style="display:none" />` |
| **Portfolio** | `https://DOMAIN/portfolio/{token}` | `<a href="...">View portfolio</a>` |

Tokens must be **registered** before hits are logged. Unregistered requests still get the decoy (pixel or page) but produce **no log entry**.

### From your laptop (recommended)

```bash
make canary-token                        # pixel — generate + register on VPS
make canary-token TRAP=portfolio         # portfolio link
make canary-token TRAP=both              # both embed URLs

make prod-canary-register TOKEN=abc123   # register existing token
make canary-hit TOKEN=abc123 TRAP=portfolio
make prod-canary-logs                    # view last 10 hits
make prod-canary-flush                   # delete hits + tokens
make prod-canary-flush KEEP_TOKENS=1     # delete hits only
```

### On the VPS directly

```bash
cd /opt/norwegian-honey

# Generate + register
docker compose exec -T api python scripts/generate_canary_token.py \
  --base-url "https://canary.example.com" --trap portfolio \
  --register-db /data/canary.db

# Register existing token
docker compose exec -T api python scripts/register_canary_token.py \
  'YOUR_TOKEN' --db-path /data/canary.db

# View hits
docker compose exec -T api python -c "
import sqlite3
db = sqlite3.connect('/data/canary.db')
for r in db.execute(
    'SELECT id, trap, token, client_ip, user_agent, timestamp '
    'FROM canary_hits ORDER BY id DESC LIMIT 10'
):
    print(r)
"

# Flush
docker compose exec -T api python scripts/flush_canary_db.py --db-path /data/canary.db
docker compose exec -T api python scripts/flush_canary_db.py --db-path /data/canary.db --keep-tokens
```

---

## 6. Day-to-day commands

### On the VPS

```bash
cd /opt/norwegian-honey
docker compose -f docker-compose.yml -f docker-compose.prod.yml ps
docker compose -f docker-compose.yml -f docker-compose.prod.yml logs -f api
docker compose -f docker-compose.yml -f docker-compose.prod.yml logs -f caddy
docker compose -f docker-compose.yml -f docker-compose.prod.yml down    # stop
```

### From your laptop

```bash
make health PRETTY=1
make analyze-eml EML=suspicious.eml PRETTY=1
make prod-canary-logs
make prod-canary-flush
```

---

## OpSec checklist

- [ ] `DEBUG=false` (disables `/docs`, `/openapi.json`)
- [ ] `INVESTIGATOR_API_KEY` set on VPS **and** local `.env`
- [ ] Canary tokens registered before embedding (`make canary-token`)
- [ ] UFW allows only **22, 80, 443** (`setup-server.sh`)
- [ ] Custom Caddy image with rate limiting (`deploy/Dockerfile.caddy`)
- [ ] `.env`, `make.env`, `ngrok.local.yml` not committed

---

## Counter-attack hardening

| Layer | What it does |
|-------|----------------|
| **Caddy rate limits** | Per-IP caps (see table below) |
| **API key** | `/analyze` and `/osint` require `X-API-Key` |
| **Token registry** | Unregistered canary tokens are ignored (no DB flood) |
| **Body size limits** | 1–2 MiB at app + Caddy |
| **OSINT caps** | Max 10 entities per type per request |
| **Hit retention** | Auto-prune after 90 days (`CANARY_HIT_RETENTION_DAYS`) |
| **No info leaks** | Canary always returns same decoy; generic OSINT errors |
| **Blocked paths** | `/openapi.json`, `/docs`, `/redoc` → 404 at Caddy |
| **Client IP** | Caddy sets `X-Real-IP` from `{client_ip}` (TCP peer on :443) |

---

## Rate limiting

Caddy is built with `github.com/mholt/caddy-ratelimit` (`deploy/Dockerfile.caddy`).

Per-client IP limits (per minute):

| Zone | Path | Limit |
|------|------|-------|
| global | all | 120 req |
| analyze | `/analyze/*` | 20 req |
| osint | `/osint/*` | 30 req |
| canary | `/images/*`, `/portfolio/*` | 60 req |

Exceeded → **HTTP 429** with `Retry-After: 60`.

Tune in `deploy/Caddyfile`, then `bash deploy/deploy.sh`.

---

## Troubleshooting

| Problem | Fix |
|---------|-----|
| Caddy won't get certificate | DNS not propagated — `dig +short canary.example.com` must show VPS IP |
| API container won't start | `docker compose logs api` — often missing `INVESTIGATOR_API_KEY` |
| 401 Unauthorized | Set `INVESTIGATOR_API_KEY` in `.env`; pass `X-API-Key` header |
| 503 Service unavailable | `INVESTIGATOR_API_KEY` missing on server — set and redeploy |
| 429 Too Many Requests | Rate limit — wait 60s or tune `deploy/Caddyfile` |
| 502 Bad Gateway | `docker compose logs api` — API not healthy |
| Canary hit not logged | Token not registered — `make prod-canary-register TOKEN=...` |
| Canary logs `172.18.x.x` or `unknown` | Redeploy — Caddy must use `{client_ip}` in `header_up` directives |
| Chrome hits local, curl hits prod | Use `https://canary.example.com/...` in browser; stop local `docker compose` |
| `deploy.sh` fails SSH from make | `ssh-add ~/.ssh/norwegian-honey` |
| Port 8000 conflict locally | Production compose does not publish 8000; stop local stack |

### Useful diagnostics

```bash
# Container IPs (Docker bridge — not client IPs)
docker network inspect norwegian-honey_default

# Caddy config test (on VPS, inside caddy container)
docker compose exec caddy caddy validate --config /etc/caddy/Caddyfile

# API health inside Docker network
docker compose exec api python -c \
  "import urllib.request; print(urllib.request.urlopen('http://127.0.0.1:8000/health').read())"
```

---

## Local vs production

| | Local dev | Production VPS |
|--|-----------|----------------|
| Start | `make local-dev` or `make local-docker-up` | `bash deploy/deploy.sh` |
| HTTPS | ngrok (optional) | Caddy + Let's Encrypt |
| Public URL | `http://127.0.0.1:8000` or ngrok | `https://DOMAIN` |
| Canary ops | `local-canary-*` | `prod-canary-*` / `make canary-*` |
| DB | `./data/canary.db` or Docker volume | `/data/canary.db` in `canary_data` volume |
| API auth | Optional (`DEBUG=true`) | `INVESTIGATOR_API_KEY` required |

**Important:** Test canary traps against `https://DOMAIN`, not `localhost` or ngrok, if you want hits in the production database with real client IPs.
