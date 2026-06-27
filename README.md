# Norwegian Honey

A lightweight, self-hosted investigative toolkit for analyzing phishing and scam emails. Built with **Python 3.11+** and **FastAPI**.

## What it does

| Component | Description |
|-----------|-------------|
| **Header Evaluator** | Parse `.eml` files or raw headers — routing hops, SPF/DKIM/DMARC, anomaly detection |
| **OSINT Aggregator** | Enrich IPs, domains, and emails via ipinfo.io, AbuseIPDB, and WHOIS |
| **Canary Honeypot** | Hidden tracking pixel and portfolio link trap — logs IP, User-Agent, and timestamp |

## Architecture

```
Internet → Caddy (HTTPS, rate limits) → FastAPI (Docker) → SQLite
                │
    /analyze ───┼─── header parsing + DNS auth checks
    /osint   ───┼─── OSINT APIs + TTL cache
    /images  ───┼─── 1×1 tracking pixel
    /portfolio ─┴─── generic HTML decoy page
```

Production uses **Caddy** for automatic HTTPS, per-IP rate limiting, and counter-attack hardening.

## Quick start (production)

```bash
cp make.env.example make.env          # PROD_SSH for remote canary ops
cp .env.example .env                  # INVESTIGATOR_API_KEY for /analyze + /osint
ssh-add ~/.ssh/norwegian-honey        # if your deploy key has a passphrase

make health PRETTY=1
make analyze-eml EML=suspicious.eml PRETTY=1
make canary-token TRAP=portfolio      # generate + register token on VPS
make prod-canary-logs
```

## Local development

```bash
make install
make local-dev                        # http://127.0.0.1:8000
make local-health PRETTY=1
make help-local                       # all local-* targets
```

With `DEBUG=true` in `.env`, `/analyze` and `/osint` work without an API key and docs are at `/docs`.

## Makefile targets

| Command | What |
|---------|------|
| `make help` | Production targets (default) — `https://canary.example.com` |
| `make help-local` | Local dev — `local-*` targets |
| `make help-ngrok` | ngrok tunnel — `ngrok-*` targets |
| `make help-server` | Deploy commands to run on the VPS |

```bash
make analyze-eml EML=phish.eml PRETTY=1       # production
make local-analyze-eml EML=phish.eml PRETTY=1 # localhost
```

## API endpoints

| Method | Path | Auth | Purpose |
|--------|------|------|---------|
| `GET` | `/health` | — | Liveness check |
| `POST` | `/analyze/headers` | API key* | Analyze raw headers or full message |
| `POST` | `/analyze/eml` | API key* | Upload `.eml` file |
| `POST` | `/osint/query` | API key* | OSINT lookup for IPs, domains, emails |
| `POST` | `/osint/from-analysis` | API key* | OSINT on `/analyze` output |
| `GET` | `/images/{token}.png` | — | Hidden tracking pixel |
| `GET` | `/portfolio/{token}` | — | Portfolio link trap (generic HTML) |

\* `X-API-Key` header required in production (`INVESTIGATOR_API_KEY`). Canary paths stay open — mail clients cannot send API keys.

## Canary workflow

Tokens must be **registered** before hits are logged. Unregistered requests still get the decoy response (pixel or page) but produce no log entry.

```bash
# Generate + register on VPS, print embed URL
make canary-token                        # pixel (default)
make canary-token TRAP=portfolio         # portfolio link
make canary-token TRAP=both              # both embed types

# Register an existing token
make prod-canary-register TOKEN=your-token

# Test a trap
make canary-hit TOKEN=your-token TRAP=portfolio

# View hits (production DB via SSH)
make prod-canary-logs

# Flush logs (hits + registered tokens)
make prod-canary-flush
make prod-canary-flush KEEP_TOKENS=1     # hits only, keep tokens
```

**Local equivalents:** `local-canary-token`, `local-canary-hit`, `local-canary-logs`, `local-canary-flush`

**Embed examples:**

```html
<!-- pixel -->
<img src="https://canary.example.com/images/TOKEN.png" width="1" height="1" alt="" style="display:none" />

<!-- portfolio link -->
<a href="https://canary.example.com/portfolio/TOKEN">View portfolio</a>
```

## CLI (no server required)

```bash
make local-cli-eml EML=suspicious.eml
make local-cli-headers HEADERS=headers.txt
python -m app.cli.header_eval --eml suspicious.eml --pretty
```

## Configuration

**Local** — copy `.env.example` to `.env`:

```env
DEBUG=true
INVESTIGATOR_API_KEY=          # optional in dev; required in production
CANARY_SQLITE_PATH=./data/canary.db
CANARY_REQUIRE_REGISTERED_TOKEN=true
ABUSEIPDB_API_KEY=             # optional
IPINFO_API_KEY=                # optional
TRUSTED_PROXY_HEADERS=true     # keep true behind Caddy/ngrok
```

**Production** — copy `.env.production.example` to `.env` on the VPS:

```env
DOMAIN=canary.example.com
INVESTIGATOR_API_KEY=          # generate: python -c "import secrets; print(secrets.token_urlsafe(32))"
DEBUG=false
```

**Remote ops** — copy `make.env.example` to `make.env` (gitignored):

```env
PROD_SSH=root@your-vps-ip
PROD_SSH_KEY=$(HOME)/.ssh/norwegian-honey
PROD_REMOTE_DIR=/opt/norwegian-honey
```

OSINT modules skip gracefully when API keys are missing.

## Local testing with ngrok (optional)

For exposing a **local** server — not needed when production is live:

```bash
make local-dev                  # terminal 1
make ngrok-tunnel               # terminal 2
make ngrok-canary-token
```

See `make help-ngrok`. For real investigations, use `https://canary.example.com` — ngrok tunnels to local Docker and will not log production canary hits.

## Production deployment

```bash
cp .env.production.example .env   # on VPS: set DOMAIN + INVESTIGATOR_API_KEY
bash deploy/deploy.sh
```

Full guide: **[deploy/DEPLOY.md](deploy/DEPLOY.md)**

Requires a **VPS with SSH** — SFTP-only shared hosting will not work.

## Project structure

```
app/
  routers/          # /analyze, /osint, /canary
  services/         # header parsing, OSINT clients, canary storage
  models/           # Pydantic schemas
  cli/              # standalone header analyzer
deploy/             # Caddy, VPS setup & deploy scripts
scripts/            # canary token generator, register, flush
fixtures/           # sample .eml for testing
```

## Typical workflow

1. **Analyze** — `make analyze-eml EML=phish.eml` → hops, auth results, anomalies
2. **OSINT** — `make osint-from-analysis ANALYSIS=out.json` for IP/domain enrichment
3. **Canary** — `make canary-token TRAP=portfolio` → embed in a controlled reply → `make prod-canary-logs`

## OpSec notes

Scammers who discover the canary may try to flood, probe, or abuse your server. Defenses in place:

- **`INVESTIGATOR_API_KEY`** — `/analyze` and `/osint` require `X-API-Key` in production
- **Token registry** — only pre-registered canary tokens are logged
- **Rate limits** — per-IP caps at Caddy (see `deploy/DEPLOY.md`)
- **Body size limits** — 1–2 MiB max on uploads and JSON payloads
- **`DEBUG=false`** in production (disables `/docs` and `/openapi.json`)
- Canary endpoints always return the same decoy — never leak errors or stack traces
- Caddy sets `X-Real-IP` from `{client_ip}` for accurate client logging

Full hardening guide: `deploy/DEPLOY.md`

## License

Private / internal use — adjust as needed for your organization.
