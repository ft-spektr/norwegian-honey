# Norwegian Honey

A lightweight, self-hosted investigative toolkit for analyzing phishing and scam emails. Built with **Python 3.11+** and **FastAPI**.

## What it does

| Component | Description |
|-----------|-------------|
| **Header Evaluator** | Parse `.eml` files or raw headers — routing hops, SPF/DKIM/DMARC, anomaly detection |
| **OSINT Aggregator** | Enrich IPs, domains, and emails via ipinfo.io, AbuseIPDB, and WHOIS |
| **Threat Score Report** | Combine analysis + OSINT into a 0–100 phishing/spam score with category breakdown |
| **Report Visualizer** | Pandas tables + HTML export for investigation, threat, analysis, and OSINT JSON |
| **Canary Honeypot** | Hidden tracking pixel and portfolio link trap — logs IP, User-Agent, and timestamp |

## Architecture

```
Internet → Caddy (HTTPS, rate limits) → FastAPI (Docker) → SQLite
                │
    /analyze ───┼─── header parsing + DNS auth checks
    /osint   ───┼─── OSINT APIs + TTL cache
    /report  ───┼─── threat score from analysis + OSINT
    /images  ───┼─── 1×1 tracking pixel
    /portfolio ─┴─── generic HTML decoy page
```

Production uses **Caddy** for automatic HTTPS, per-IP rate limiting, and counter-attack hardening.

## Quick start (production)

```bash
cp make.env.example make.env          # PROD_SSH for remote canary ops
cp .env.example .env                  # INVESTIGATOR_API_KEY for /analyze, /osint, /report
ssh-add ~/.ssh/norwegian-honey        # if your deploy key has a passphrase

make prod-health PRETTY=1
make prod-analyze-eml EML=suspicious.eml PRETTY=1
make prod-canary-token TRAP=portfolio      # generate + register token on VPS
make prod-canary-logs
```

## Local development

```bash
make install
make local-dev                        # http://127.0.0.1:8000
make local-health PRETTY=1
make help-local                       # all local-* targets
```

With `DEBUG=true` in `.env`, `/analyze`, `/osint`, and `/report` work without an API key and docs are at `/docs`.

## Makefile targets

Targets are prefixed by **where they run**:

| Prefix | Environment | Examples |
|--------|-------------|----------|
| **`prod-*`** | Production API at `$(PROD_URL)` or VPS via SSH | `prod-analyze-eml`, `prod-canary-logs`, `prod-canary-export` |
| **`local-*`** | Localhost, local Docker/SQLite, or offline CLI | `local-dev`, `local-canary-export`, `local-cli-report` |
| **`prod-up` / `prod-deploy`** | Commands run **on the VPS** | `make prod-deploy` (SSH + git pull) |
| **Unprefixed** | Backward-compatible **aliases for `prod-*`** | `analyze-eml` → `prod-analyze-eml` |

Use an explicit prefix when in doubt — unprefixed names always hit production.

| Command | What |
|---------|------|
| `make help` | Production targets (`prod-*` and aliases) |
| `make help-local` | Local dev — `local-*` targets |
| `make help-ngrok` | ngrok tunnel — `ngrok-*` targets |
| `make help-server` | Deploy commands to run on the VPS |

```bash
make prod-analyze-eml EML=phish.eml PRETTY=1       # production (explicit)
make analyze-eml EML=phish.eml PRETTY=1            # same — alias
make local-analyze-eml EML=phish.eml PRETTY=1      # localhost
make prod-report-from-analysis ANALYSIS=analysis/analysis.json \
  INVESTIGATION=analysis/investigation.json PRETTY=1 OUT=analysis/report.json
make local-cli-report ANALYSIS=analysis.json OUT=report.json
make prod-canary-export OUT=analysis/investigation.json TOKEN=myprofile TRAP=portfolio
make local-visualize REPORT=investigation.json HTML=investigation.html
make json-extract IN=capture.json OUT=clean.json
```

### Saving API output to files

Prefer **`OUT=`** — writes JSON only (no curl recipe, no API key in the file):

```bash
make prod-analyze-eml EML=phish.eml PRETTY=1 OUT=analysis/analysis.json
make prod-osint-from-analysis ANALYSIS=analysis/analysis.json PRETTY=1 OUT=analysis/osint.json
make prod-report-from-analysis ANALYSIS=analysis/analysis.json PRETTY=1 OUT=analysis/report.json
```

Shell redirect (`> file`) also works if recipes are silent; **`OUT=` is preferred**.

Do **not** use `make -n` for captures — that prints the recipe, not the API response.

If an older capture file includes curl/Makefile noise, tools auto-extract JSON via `load_json_document`. To strip noise (and embedded API keys from the recipe):

```bash
make json-extract IN=capture.json OUT=clean.json
```

Do not commit capture files that echo `X-API-Key` in the curl header line.

## API endpoints

| Method | Path | Auth | Purpose |
|--------|------|------|---------|
| `GET` | `/health` | — | Liveness check |
| `POST` | `/analyze/headers` | API key* | Analyze raw headers or full message |
| `POST` | `/analyze/eml` | API key* | Upload `.eml` file |
| `POST` | `/osint/query` | API key* | OSINT lookup for IPs, domains, emails |
| `POST` | `/osint/from-analysis` | API key* | OSINT on `/analyze` output |
| `POST` | `/report/score` | API key* | Threat score from analysis + optional OSINT JSON |
| `POST` | `/report/from-analysis` | API key* | OSINT on analysis, then threat score report |
| `POST` | `/report/canary-investigation` | API key* | Canary hits + IP profiles + optional OSINT/analysis |
| `GET` | `/images/{token}.png` | — | Hidden tracking pixel |
| `GET` | `/portfolio/{token}` | — | Portfolio link trap (generic HTML) |

\* `X-API-Key` header required in production (`INVESTIGATOR_API_KEY`). Canary paths stay open — mail clients cannot send API keys.

## Threat score report

Produces a **0–100 overall score** with verdict (`low` / `moderate` / `high` / `critical`) and findings grouped by category:

| Category | Weight | Signals |
|----------|--------|---------|
| **identity** | 40% | Reply-To mismatch, business name on free webmail, domain-like Gmail local part |
| **headers** | 30% | Anomalies from header analysis (weighted down for recipient MX noise) |
| **authentication** | 15% | SPF/DKIM/DMARC pass/fail from headers |
| **infrastructure** | 15% | AbuseIPDB, ipinfo, WHOIS on sender-relevant entities only |
| **canary** | pattern bonus | When `INVESTIGATION=` is provided — scores suspicious hit patterns (human + cloud follow-up, multi-country), not trap hits alone |

Verdict bands: **low** &lt;30 · **moderate** 30–54 · **high** 55–74 · **critical** ≥75.

Each report includes an **`action_plan`** with prioritized steps (`immediate` / `recommended` / `optional`) tailored to the verdict and findings (including suspicious canary patterns when present).

```bash
# Full pipeline — report endpoint runs OSINT internally and embeds it in the JSON
make prod-analyze-eml EML=suspicious.eml PRETTY=1 OUT=analysis/analysis.json
make prod-report-from-analysis ANALYSIS=analysis/analysis.json \
  INVESTIGATION=analysis/investigation.json PRETTY=1 OUT=analysis/report.json

# Optional: standalone OSINT file (same enrichment as inside report-from-analysis)
make prod-osint-from-analysis ANALYSIS=analysis/analysis.json PRETTY=1 OUT=analysis/osint.json

# Score with pre-built analysis + OSINT files
make prod-report-score ANALYSIS=analysis/analysis.json OSINT=analysis/osint.json PRETTY=1 OUT=analysis/report.json

# CLI only — no server; runs OSINT locally unless --skip-osint
make local-cli-report ANALYSIS=analysis.json OUT=report.json
python -m app.cli.threat_report analysis.json --osint osint.json -o report.json
```

Report output includes `overall_score`, `verdict`, `summary`, `action_plan`, per-category scores, and a flat `findings` list sorted by severity.

## Canary investigation export

Merges **canary hit logs**, **per-IP OSINT profiles**, and optional **analysis** / **threat report** into one JSON artifact for evidence preservation.

```bash
make prod-canary-export TOKEN=myprofile TRAP=portfolio OUT=investigation.json
make local-canary-export TOKEN=myprofile OUT=investigation.json \
  OSINT=canary-osint.json ANALYSIS=analysis.json REPORT=report.json
python scripts/export_canary_investigation.py --db-path ./data/canary.db \
  --token myprofile --trap portfolio --run-osint \
  --analysis analysis.json --threat-report report.json -o investigation.json
```

Each `ip_profiles[]` entry includes hit IDs, user-agents, OSINT data, a `role` (`human_likely` / `automation_likely` / `unknown`), and investigator notes.

### Readable tables (pandas)

Requires `pandas` (installed via `make install`).

```bash
make local-visualize REPORT=investigation.json
make local-visualize REPORT=investigation.json HTML=investigation.html TEXT=investigation.txt
make local-visualize REPORT=report.json          # threat score
make local-visualize REPORT=analysis.json        # header analysis
make local-visualize REPORT=osint.json           # OSINT only
python -m app.cli.visualize_report investigation.json --html investigation.html
```

Auto-detects report type and prints:

| Input | Tables |
|-------|--------|
| `investigation.json` | overview, timeline, IP profiles (+ embedded threat/analysis if present) |
| `report.json` | threat overview, action plan, category scores, findings |
| `analysis.json` | email overview, received hops, anomalies |
| OSINT JSON | IPs, domains |

Use `HTML=` for a browser-friendly export. Mixed curl/JSON capture files are supported (see [Saving API output](#saving-api-output-to-files)).

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

# Export investigation artifact (hits + OSINT + optional analysis/report)
make prod-canary-export TOKEN=myprofile TRAP=portfolio OUT=investigation.json
make local-canary-export TOKEN=myprofile TRAP=portfolio OUT=investigation.json \
  OSINT=canary-osint.json ANALYSIS=analysis.json REPORT=report.json

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
make local-cli-report ANALYSIS=analysis.json OUT=report.json
make local-visualize REPORT=investigation.json HTML=investigation.html
make json-extract IN=capture.json OUT=clean.json
python -m app.cli.header_eval --eml suspicious.eml --pretty
python -m app.cli.threat_report analysis.json --osint osint.json -o report.json
python -m app.cli.visualize_report investigation.json
python scripts/extract_json.py capture.json -o clean.json
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
  routers/          # /analyze, /osint, /report, /canary
  services/         # header parsing, OSINT, threat scorer, canary, report visualizer
  models/           # Pydantic schemas
  core/             # json_document loader (curl-noise tolerant)
  cli/              # header_eval, threat_report, visualize_report
deploy/             # Caddy, VPS setup & deploy scripts
scripts/            # canary tokens, export investigation, extract_json, flush
fixtures/           # sample .eml for testing
```

## Typical workflow

1. **Analyze** — `make prod-analyze-eml EML=phish.eml PRETTY=1 OUT=analysis/analysis.json`
2. **Report** — `make prod-report-from-analysis ANALYSIS=analysis/analysis.json PRETTY=1 OUT=analysis/report.json` (includes OSINT + threat score). Add `INVESTIGATION=analysis/investigation.json` when canary export is available.
3. **OSINT** *(optional)* — `make prod-osint-from-analysis ANALYSIS=analysis/analysis.json PRETTY=1 OUT=analysis/osint.json` if you want a separate OSINT artifact
4. **Canary** — `make prod-canary-token TRAP=portfolio` → embed full `https://` link → `make prod-canary-logs`
5. **Export** — `make prod-canary-export TOKEN=... OUT=analysis/investigation.json` after hits land
6. **Visualize** — `make local-visualize REPORT=analysis/investigation.json HTML=analysis/investigation.html`

## OpSec notes

Scammers who discover the canary may try to flood, probe, or abuse your server. Defenses in place:

- **`INVESTIGATOR_API_KEY`** — `/analyze`, `/osint`, and `/report` require `X-API-Key` in production
- **Token registry** — only pre-registered canary tokens are logged
- **Rate limits** — per-IP caps at Caddy (see `deploy/DEPLOY.md`)
- **Body size limits** — 1–2 MiB max on uploads and JSON payloads
- **`DEBUG=false`** in production (disables `/docs` and `/openapi.json`)
- Canary endpoints always return the same decoy — never leak errors or stack traces
- Caddy sets `X-Real-IP` from `{client_ip}` for accurate client logging

Full hardening guide: `deploy/DEPLOY.md`

## License

Private / internal use — adjust as needed for your organization.
