# Norwegian Honey — local dev & API testing shortcuts
# Usage: make help

.DEFAULT_GOAL := help

BASE_URL   ?= http://127.0.0.1:8000
VENV       ?= .venv
PYTHON     ?= $(VENV)/bin/python
UVICORN    ?= $(VENV)/bin/uvicorn
EML        ?= fixtures/sample.eml
CANARY_DB  ?= ./data/canary.db
TOKEN      ?=
HOST       ?= 127.0.0.1
PORT       ?= $(NGROK_PORT)
NGROK      ?= $(shell command -v ngrok 2>/dev/null || echo $(HOME)/.local/bin/ngrok)
NGROK_API      ?= http://127.0.0.1:4040
NGROK_CONFIG       ?= ngrok.yml
NGROK_LOCAL_CONFIG ?= ngrok.local.yml
NGROK_GLOBAL_CONFIG ?= $(HOME)/.config/ngrok/ngrok.yml
NGROK_TUNNEL       ?= norwegian-honey
# Read domain/port from ngrok.yml (single source of truth)
NGROK_DOMAIN := $(shell grep -E '^\s+domain:' $(NGROK_CONFIG) 2>/dev/null | head -1 | sed 's/.*domain:[[:space:]]*//')
NGROK_PORT   := $(shell grep -E '^\s+addr:' $(NGROK_CONFIG) 2>/dev/null | head -1 | sed 's/.*addr:[[:space:]]*//')
PUBLIC_URL     ?= https://$(NGROK_DOMAIN)
CANARY_BASE_URL ?= $(PUBLIC_URL)
DOCKER_SERVICE   ?= api
DOCKER_CANARY_DB ?= /data/canary.db

# Pipe JSON through json.tool when set: make health PRETTY=1
ifeq ($(PRETTY),1)
  FORMAT = | $(PYTHON) -m json.tool
else
  FORMAT =
endif

.PHONY: help install dev docker-up docker-down docker-logs prod-up prod-down prod-logs prod-deploy \
        health analyze-headers analyze-headers-sample analyze-eml \
        osint-query osint-query-sample osint-from-analysis osint-from-sample \
        canary-token canary-hit canary-demo canary-logs canary-logs-local canary-logs-docker \
        cli-eml cli-headers docs ngrok-install ngrok-setup ngrok-tunnel ngrok-tunnel-ephemeral \
        ngrok-check ngrok-url health-public canary-token-public canary-token-ngrok

help: ## Show this help
	@echo "Norwegian Honey — make targets"
	@echo ""
	@echo "Config (override on CLI):"
	@echo "  BASE_URL=$(BASE_URL)"
	@echo "  PUBLIC_URL=$(PUBLIC_URL)  (from $(NGROK_CONFIG))"
	@echo "  CANARY_BASE_URL=$(CANARY_BASE_URL)  (canary-token embed URL)"
	@echo "  NGROK_TUNNEL=$(NGROK_TUNNEL)"
	@echo "  EML=$(EML)"
	@echo "  CANARY_DB=$(CANARY_DB)"
	@echo "  PRETTY=1          pretty-print JSON responses"
	@echo ""
	@grep -E '^[a-zA-Z0-9_-]+:.*##' $(MAKEFILE_LIST) | \
		awk 'BEGIN {FS = ":.*## "}; {printf "  \033[36m%-24s\033[0m %s\n", $$1, $$2}'

# --- Setup & server ---

install: ## Create venv and install dependencies
	python3 -m venv $(VENV)
	$(PYTHON) -m pip install -r requirements.txt
	@test -f .env || cp .env.example .env
	@echo "Edit .env if needed (DEBUG=true, CANARY_SQLITE_PATH=./data/canary.db)"

dev: ## Run FastAPI locally with reload
	$(UVICORN) app.main:app --host $(HOST) --port $(PORT) --reload

docker-up: ## Start stack with Docker Compose
	docker compose up --build -d

docker-down: ## Stop Docker Compose stack
	docker compose down

docker-logs: ## Tail API container logs
	docker compose logs -f api

prod-up: ## Production deploy (Caddy + HTTPS) — set DOMAIN in .env
	docker compose -f docker-compose.yml -f docker-compose.prod.yml up -d --build

prod-down: ## Stop production stack
	docker compose -f docker-compose.yml -f docker-compose.prod.yml down

prod-logs: ## Tail production logs (api + caddy)
	docker compose -f docker-compose.yml -f docker-compose.prod.yml logs -f api caddy

prod-deploy: ## Run deploy script (build, up, health check)
	bash deploy/deploy.sh

docs: ## Open Swagger UI URL
	@echo "$(BASE_URL)/docs  (requires DEBUG=true in .env)"

# --- Health ---

health: ## GET /health
	curl -s "$(BASE_URL)/health" $(FORMAT)

# --- Analyze ---

analyze-headers: ## POST /analyze/headers (set HEADERS=path to a raw headers file)
	@test -n "$(HEADERS)" || (echo "Usage: make analyze-headers HEADERS=path/to/headers.txt"; exit 1)
	curl -s -X POST "$(BASE_URL)/analyze/headers" \
		-H "Content-Type: application/json" \
		-d "$$($(PYTHON) -c "import json, pathlib; print(json.dumps({'raw_headers': pathlib.Path('$(HEADERS)').read_text()}))")" \
		$(FORMAT)

analyze-headers-sample: ## POST /analyze/headers with built-in phishing sample
	curl -s -X POST "$(BASE_URL)/analyze/headers" \
		-H "Content-Type: application/json" \
		-d '{"raw_headers":"From: scammer@evil-phish.example\nReply-To: collector@different-bad.example\nReturn-Path: <bounce@evil-phish.example>\nSubject: Urgent wire transfer\nAuthentication-Results: mx.example.com; spf=fail; dkim=fail; dmarc=fail\nReceived: from mail.badactor.example ([198.51.100.10]) by mx.example.com; Mon, 1 Jan 2024 11:59:00 +0000\nX-Originating-IP: [203.0.113.99]\n"}' \
		$(FORMAT)

analyze-eml: ## POST /analyze/eml (EML=fixtures/sample.eml)
	curl -s -X POST "$(BASE_URL)/analyze/eml" \
		-F "file=@$(EML)" \
		$(FORMAT)

# --- OSINT ---

osint-query: ## POST /osint/query (IPS= DOMAINS= EMAILS= comma-separated)
	curl -s -X POST "$(BASE_URL)/osint/query" \
		-H "Content-Type: application/json" \
		-d "$$($(PYTHON) -c "import json, os; ips=[x for x in '$(IPS)'.split(',') if x]; domains=[x for x in '$(DOMAINS)'.split(',') if x]; emails=[x for x in '$(EMAILS)'.split(',') if x]; print(json.dumps({'ips': ips, 'domains': domains, 'emails': emails}))")" \
		$(FORMAT)

osint-query-sample: ## POST /osint/query with 8.8.8.8 and example.com
	$(MAKE) osint-query IPS=8.8.8.8 DOMAINS=example.com

osint-from-analysis: ## POST /osint/from-analysis (ANALYSIS=path/to/analysis.json)
	@test -n "$(ANALYSIS)" || (echo "Usage: make osint-from-analysis ANALYSIS=analysis.json"; exit 1)
	curl -s -X POST "$(BASE_URL)/osint/from-analysis" \
		-H "Content-Type: application/json" \
		-d "@$(ANALYSIS)" \
		$(FORMAT)

osint-from-sample: ## Analyze sample headers, then run OSINT on extracted entities
	curl -s -X POST "$(BASE_URL)/analyze/headers" \
		-H "Content-Type: application/json" \
		-d '{"raw_headers":"From: scammer@evil-phish.example\nReply-To: collector@different-bad.example\nAuthentication-Results: mx.example.com; spf=fail; dkim=fail; dmarc=fail\nReceived: from mail.badactor.example ([198.51.100.10]) by mx.example.com; Mon, 1 Jan 2024 11:59:00 +0000\nX-Originating-IP: [203.0.113.99]\n"}' \
	| curl -s -X POST "$(BASE_URL)/osint/from-analysis" \
		-H "Content-Type: application/json" \
		-d @- \
		$(FORMAT)

# --- Canary honeypot ---

canary-token: ## Generate canary token (uses ngrok domain from ngrok.yml)
	$(PYTHON) scripts/generate_canary_token.py --base-url "$(CANARY_BASE_URL)" --count 1

canary-hit: ## Trigger pixel (TOKEN=required; uses CANARY_BASE_URL)
	@test -n "$(TOKEN)" || (echo "Usage: make canary-hit TOKEN=your-token"; exit 1)
	curl -s -H "User-Agent: Makefile-Test/1.0" \
		"$(CANARY_BASE_URL)/images/$(TOKEN).png" \
		-o /dev/null -w "HTTP %{http_code}, %{size_download} bytes\n"

canary-demo: ## Generate token, hit pixel via ngrok, show latest DB row
	@TOKEN="$$($(PYTHON) scripts/generate_canary_token.py --base-url "$(CANARY_BASE_URL)" --count 1 --json \
		| $(PYTHON) -c "import sys,json; print(json.load(sys.stdin)['token'])")"; \
	echo "token: $$TOKEN"; \
	curl -s -H "User-Agent: Makefile-Test/1.0" \
		"$(CANARY_BASE_URL)/images/$$TOKEN.png" \
		-o /dev/null -w "HTTP %{http_code}, %{size_download} bytes\n"; \
	$(MAKE) canary-logs

canary-logs: ## Show last 10 canary hits (auto: docker if running, else local)
	@if docker compose ps --status running -q $(DOCKER_SERVICE) 2>/dev/null | grep -q .; then \
		echo "Reading from Docker ($(DOCKER_CANARY_DB))..."; \
		$(MAKE) canary-logs-docker; \
	else \
		echo "Reading from local ($(CANARY_DB))..."; \
		$(MAKE) canary-logs-local; \
	fi

canary-logs-local: ## Show last 10 canary hits from local SQLite
	@$(PYTHON) -c "import sqlite3, pathlib; \
db_path=pathlib.Path('$(CANARY_DB)'); \
print(f'DB: {db_path.resolve()}'); \
conn=sqlite3.connect(db_path); \
rows=conn.execute('SELECT id, token, client_ip, user_agent, timestamp FROM canary_hits ORDER BY id DESC LIMIT 10').fetchall(); \
print('id|token|client_ip|user_agent|timestamp'); \
[print('|'.join(str(c) if c is not None else '' for c in r)) for r in rows] if rows else print('(no hits)')"

canary-logs-docker: ## Show last 10 canary hits from SQLite inside Docker
	docker compose exec -T $(DOCKER_SERVICE) python -c "\
import sqlite3; \
db=sqlite3.connect('$(DOCKER_CANARY_DB)'); \
rows=db.execute('SELECT id, token, client_ip, user_agent, timestamp FROM canary_hits ORDER BY id DESC LIMIT 10').fetchall(); \
print('id|token|client_ip|user_agent|timestamp'); \
[print('|'.join(str(c) if c is not None else '' for c in r)) for r in rows] or print('(no hits)')"


# --- CLI (no server) ---

cli-eml: ## Analyze .eml via CLI (EML=fixtures/sample.eml)
	$(PYTHON) -m app.cli.header_eval --eml "$(EML)" --pretty

cli-headers: ## Analyze headers file via CLI (HEADERS=required)
	@test -n "$(HEADERS)" || (echo "Usage: make cli-headers HEADERS=path/to/headers.txt"; exit 1)
	$(PYTHON) -m app.cli.header_eval --headers-file "$(HEADERS)" --headers-only --pretty

# --- ngrok (expose local API to the internet) ---
# Edit ngrok.yml for domain/port. Authtoken in ngrok.local.yml (make ngrok-setup).

ngrok-install: ## Install ngrok binary to ~/.local/bin
	@mkdir -p $(HOME)/.local/bin
	curl -sSL "https://bin.equinox.io/c/bNyj1mQVY4c/ngrok-v3-stable-linux-amd64.tgz" -o /tmp/ngrok.tgz
	tar -xzf /tmp/ngrok.tgz -C $(HOME)/.local/bin ngrok
	@echo "Installed: $$($(NGROK) version)"
	@$(MAKE) ngrok-setup

ngrok-setup: ## Create ngrok.local.yml from example (add your authtoken)
	@test -f $(NGROK_LOCAL_CONFIG) || cp ngrok.local.yml.example $(NGROK_LOCAL_CONFIG)
	@echo "Edit $(NGROK_LOCAL_CONFIG) and set authtoken"
	@echo "  https://dashboard.ngrok.com/get-started/your-authtoken"
	@echo "Tunnel config: $(NGROK_CONFIG) -> $(PUBLIC_URL)"

ngrok-check: ## Validate ngrok config files
	@test -x "$(NGROK)" || (echo "ngrok not found — run: make ngrok-install"; exit 1)
	@test -f "$(NGROK_CONFIG)" || (echo "missing $(NGROK_CONFIG)"; exit 1)
	@if [ -f "$(NGROK_LOCAL_CONFIG)" ]; then \
		$(NGROK) config check --config "$(NGROK_LOCAL_CONFIG)" --config "$(NGROK_CONFIG)"; \
	elif [ -f "$(NGROK_GLOBAL_CONFIG)" ]; then \
		$(NGROK) config check --config "$(NGROK_GLOBAL_CONFIG)" --config "$(NGROK_CONFIG)"; \
	else \
		echo "No authtoken config — run: make ngrok-setup"; exit 1; \
	fi

ngrok-tunnel: ## Start tunnel from ngrok.yml (tunnel: $(NGROK_TUNNEL))
	@test -x "$(NGROK)" || (echo "ngrok not found — run: make ngrok-install"; exit 1)
	@echo "Config: $(NGROK_CONFIG)"
	@echo "Public: $(PUBLIC_URL) -> 127.0.0.1:$(NGROK_PORT)"
	@echo "Inspect: $(NGROK_API)"
	@if [ -f "$(NGROK_LOCAL_CONFIG)" ]; then \
		$(NGROK) start --config "$(NGROK_LOCAL_CONFIG)" --config "$(NGROK_CONFIG)" $(NGROK_TUNNEL); \
	elif [ -f "$(NGROK_GLOBAL_CONFIG)" ]; then \
		$(NGROK) start --config "$(NGROK_GLOBAL_CONFIG)" --config "$(NGROK_CONFIG)" $(NGROK_TUNNEL); \
	else \
		echo "No authtoken — run: make ngrok-setup"; exit 1; \
	fi

ngrok-tunnel-ephemeral: ## Ephemeral URL (ignores reserved domain in ngrok.yml)
	@test -x "$(NGROK)" || (echo "ngrok not found — run: make ngrok-install"; exit 1)
	@if [ -f "$(NGROK_LOCAL_CONFIG)" ]; then \
		$(NGROK) http --config "$(NGROK_LOCAL_CONFIG)" $(NGROK_PORT); \
	elif [ -f "$(NGROK_GLOBAL_CONFIG)" ]; then \
		$(NGROK) http --config "$(NGROK_GLOBAL_CONFIG)" $(NGROK_PORT); \
	else \
		echo "No authtoken — run: make ngrok-setup"; exit 1; \
	fi

ngrok-url: ## Print active ngrok HTTPS URL (falls back to PUBLIC_URL)
	@curl -sf $(NGROK_API)/api/tunnels 2>/dev/null \
	| $(PYTHON) -c "import sys,json; d=json.load(sys.stdin); t=next((x for x in d.get('tunnels',[]) if x.get('public_url','').startswith('https')), None); print(t['public_url'] if t else '$(PUBLIC_URL)')" \
	|| echo "$(PUBLIC_URL)"

health-public: ## GET /health via ngrok public URL
	curl -s "$(PUBLIC_URL)/health" $(FORMAT)

canary-token-public: canary-token ## Alias for canary-token (ngrok domain)

canary-token-ngrok: ## Generate canary token using live ngrok tunnel URL
	@URL=$$($(MAKE) -s ngrok-url); \
	$(PYTHON) scripts/generate_canary_token.py --base-url "$$URL" --count 1

