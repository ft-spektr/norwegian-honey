# Norwegian Honey

A lightweight, self-hosted investigative toolkit for analyzing phishing and scam emails. Built with **Python 3.11+** and **FastAPI**.

## What it does

| Component | Description |
|-----------|-------------|
| **Header Evaluator** | Parse `.eml` files or raw headers — routing hops, SPF/DKIM/DMARC, anomaly detection |
| **OSINT Aggregator** | Enrich IPs, domains, and emails via ipinfo.io, AbuseIPDB, and WHOIS |
| **Canary Honeypot** | 1×1 tracking pixel that logs when an email is opened (IP, User-Agent, timestamp) |

## Architecture

```
┌─────────────┐     ┌──────────────────────────────────────┐
│  /analyze   │────▶│  Header parsing + DNS auth checks  │
│  /osint     │────▶│  Async OSINT APIs + TTL cache        │
│  /images/*      │────▶│  Canary traps → SQLite / InfluxDB    │
│  /portfolio/*   │     │                                      │
└─────────────┘     └──────────────────────────────────────┘
```

Production adds **Caddy** for automatic HTTPS, per-IP rate limiting, and counter-attack hardening in front of the API.

## Quick start (production — cloud at spek-tr.no)

```bash
cp make.env.example make.env    # set PROD_SSH for canary logs
# Set INVESTIGATOR_API_KEY in .env (see .env.production.example)
make health PRETTY=1
make analyze-eml EML=suspicious.eml PRETTY=1
make canary-token               # generates + registers token on VPS
make prod-canary-logs
```

## Local development

```bash
make install
make local-dev                  # http://127.0.0.1:8000
make local-health PRETTY=1
make help-local                 # all local-* targets
```

With `DEBUG=true` in `.env`, interactive API docs are at `/docs`.

## Makefile targets

| Command | What |
|---------|------|
| `make help` | **Production** — calls `https://spek-tr.no` (default) |
| `make help-local` | Local dev — `local-*` targets |
| `make help-ngrok` | ngrok tunnel dev — `ngrok-*` targets |
| `make help-server` | Deploy commands to run on the VPS |

```bash
make analyze-eml EML=phish.eml PRETTY=1      # → production
make local-analyze-eml EML=phish.eml PRETTY=1  # → localhost
make canary-token                              # → spek-tr.no embed URL
make prod-canary-logs                          # → SSH to VPS, read DB
```

## API endpoints

| Method | Path | Purpose |
|--------|------|---------|
| `GET` | `/health` | Liveness check |
| `POST` | `/analyze/headers` | Analyze raw headers or full message (JSON) |
| `POST` | `/analyze/eml` | Upload `.eml` file |
| `POST` | `/osint/query` | OSINT lookup for IPs, domains, emails |
| `POST` | `/osint/from-analysis` | OSINT on entities from `/analyze` output |
| `GET` | `/images/{token}.png` | Hidden tracking pixel |
| `GET` | `/portfolio/{token}` | Portfolio link trap (generic HTML page) |

## Makefile shortcuts

Run `make help` for production targets (default). See also `make help-local`.

```bash
make analyze-eml EML=suspicious.eml PRETTY=1
make osint-from-analysis ANALYSIS=analysis.json PRETTY=1
make canary-token
make prod-canary-logs
```

## CLI (no server required)

```bash
make cli-eml EML=suspicious.eml
python -m app.cli.header_eval --eml suspicious.eml --pretty
```

## Configuration

Copy `.env.example` to `.env`:

```env
DEBUG=true
CANARY_SQLITE_PATH=./data/canary.db
ABUSEIPDB_API_KEY=          # optional
IPINFO_API_KEY=             # optional
TRUSTED_PROXY_HEADERS=true  # keep true behind ngrok/Caddy
```

OSINT modules skip gracefully when API keys are missing.

## Local testing with ngrok (optional)

For exposing a **local** server — not needed when production is live at spek-tr.no:

```bash
make local-dev                  # terminal 1
make ngrok-tunnel               # terminal 2
make ngrok-canary-token
```

See `make help-ngrok`.

## Production deployment

Deploy to any Linux VPS with SSH (DigitalOcean, Vultr, etc.):

```bash
cp .env.production.example .env   # set DOMAIN and PUBLIC_BASE_URL
bash deploy/deploy.sh
```

Full guide: **[deploy/DEPLOY.md](deploy/DEPLOY.md)**

```
Internet → Caddy (HTTPS) → FastAPI (Docker) → SQLite
```

Requires a **VPS with SSH** — SFTP-only shared hosting will not work.

## Project structure

```
app/
  routers/          # /analyze, /osint, /canary
  services/         # header parsing, OSINT clients, canary storage
  models/           # Pydantic schemas
  cli/              # standalone header analyzer
deploy/             # Caddy, VPS setup & deploy scripts
scripts/            # canary token generator
fixtures/           # sample .eml for testing
```

## Typical workflow

1. **Analyze** — `make analyze-eml EML=phish.eml` → hops, auth results, anomalies
2. **OSINT** — pipe analysis into `/osint/from-analysis` for IP/domain enrichment
3. **Canary** (optional) — embed tracking pixel in a controlled reply; check `make canary-logs`

## OpSec notes

Scammers who discover the canary may try to flood, probe, or abuse your server. Defenses in place:

- **`INVESTIGATOR_API_KEY`** — `/analyze` and `/osint` require `X-API-Key` in production
- **Token registry** — only pre-registered canary tokens are logged (`make canary-token`)
- **Rate limits** — per-IP caps at Caddy (see `deploy/DEPLOY.md`)
- **Body size limits** — 1–2 MiB max on uploads and JSON payloads
- Set `DEBUG=false` in production (disables `/docs` and `/openapi.json`)
- Run on an isolated VPS; use a dedicated subdomain for the canary
- The pixel endpoint always returns the same PNG — never leaks stack traces or errors
- Only trust `X-Forwarded-For` when behind a known reverse proxy (`TRUSTED_PROXY_HEADERS=true`)

Full hardening guide: `deploy/DEPLOY.md`

## License

Private / internal use — adjust as needed for your organization.
