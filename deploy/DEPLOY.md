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

- [ ] `DEBUG=false` in `.env` (disables `/docs`)
- [ ] Firewall allows only **22, 80, 443** (`setup-server.sh` does this)
- [ ] Use a **dedicated subdomain** for the canary (e.g. `canary.…`)
- [ ] Consider restricting `/analyze` and `/osint` to your IP in Caddy (optional)
- [ ] Do not commit `.env` or `ngrok.local.yml`

---

## Troubleshooting

| Problem | Fix |
|---------|-----|
| Caddy won't get certificate | DNS not propagated; check `dig www736.your-server.de` |
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
