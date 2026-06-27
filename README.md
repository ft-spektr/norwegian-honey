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
│  /images/*  │────▶│  Canary pixel → SQLite / InfluxDB    │
└─────────────┘     └──────────────────────────────────────┘
```

Production adds **Caddy** for automatic HTTPS in front of the API.

## Quick start

```bash
git clone git@github.com:ft-spektr/norwegian-honey.git
cd norwegian-honey

make install          # venv + dependencies + .env
make dev              # http://127.0.0.1:8000

make health PRETTY=1
make analyze-eml EML=fixtures/sample.eml PRETTY=1
```

With `DEBUG=true` in `.env`, interactive API docs are at `/docs`.

## Docker

```bash
cp .env.example .env
make docker-up
make health
make canary-logs-docker
```

## API endpoints

| Method | Path | Purpose |
|--------|------|---------|
| `GET` | `/health` | Liveness check |
| `POST` | `/analyze/headers` | Analyze raw headers or full message (JSON) |
| `POST` | `/analyze/eml` | Upload `.eml` file |
| `POST` | `/osint/query` | OSINT lookup for IPs, domains, emails |
| `POST` | `/osint/from-analysis` | OSINT on entities from `/analyze` output |
| `GET` | `/images/{token}.png` | Canary tracking pixel |

## Makefile shortcuts

Run `make help` for the full list. Common targets:

```bash
make analyze-eml EML=suspicious.eml PRETTY=1
make osint-from-analysis ANALYSIS=analysis.json PRETTY=1
make canary-token
make canary-logs
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

## Local testing with ngrok

Expose the API to the internet for canary pixel testing:

```bash
cp ngrok.yml.example ngrok.yml    # edit domain if needed
make ngrok-setup                  # create ngrok.local.yml + authtoken
make ngrok-tunnel                 # terminal 2 (while make dev runs)
make canary-token                 # uses domain from ngrok.yml
```

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

- Set `DEBUG=false` in production (disables `/docs`)
- Run on an isolated VPS; use a dedicated subdomain for the canary
- The pixel endpoint always returns the same PNG — never leaks stack traces
- `Authorization` / `Cookie` headers are redacted before logging
- Only trust `X-Forwarded-For` when behind a known reverse proxy (`TRUSTED_PROXY_HEADERS=true`)

## License

Private / internal use — adjust as needed for your organization.
