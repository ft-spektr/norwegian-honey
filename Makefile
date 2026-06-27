# Norwegian Honey — Makefile
# Usage: make help | make help-local | make help-ngrok
#
# Default targets call PRODUCTION (set DOMAIN in make.env).
# Local dev and ngrok targets are prefixed local-* / ngrok-*.

.DEFAULT_GOAL := help

# --- Client config (production URL, SSH for remote logs) ---
-include make.env
-include .env

DOMAIN         ?= canary.example.com
PROD_URL       ?= https://$(DOMAIN)
LOCAL_URL      ?= http://127.0.0.1:8000
API_URL        ?= $(PROD_URL)
INVESTIGATOR_API_KEY ?=

# curl auth header for protected /analyze and /osint endpoints
ifneq ($(INVESTIGATOR_API_KEY),)
  API_AUTH = -H "X-API-Key: $(INVESTIGATOR_API_KEY)"
else
  API_AUTH =
endif

PROD_SSH       ?= root@your-vps-ip
PROD_SSH_KEY   ?= $(HOME)/.ssh/norwegian-honey
PROD_SSH_PORT  ?= 22
PROD_REMOTE_DIR ?= /opt/norwegian-honey

# --- Tooling ---
VENV           ?= .venv
PYTHON         ?= $(VENV)/bin/python
UVICORN        ?= $(VENV)/bin/uvicorn
EML            ?= fixtures/sample.eml
CANARY_DB      ?= ./data/canary.db
TOKEN          ?=
TRAP           ?= pixel
HOST           ?= 127.0.0.1
LOCAL_PORT     ?= 8000
DOCKER_SERVICE ?= api
DOCKER_CANARY_DB ?= /data/canary.db

# --- ngrok (local dev only) ---
NGROK              ?= $(shell command -v ngrok 2>/dev/null || echo $(HOME)/.local/bin/ngrok)
NGROK_API          ?= http://127.0.0.1:4040
NGROK_CONFIG       ?= ngrok.yml
NGROK_LOCAL_CONFIG ?= ngrok.local.yml
NGROK_GLOBAL_CONFIG ?= $(HOME)/.config/ngrok/ngrok.yml
NGROK_TUNNEL       ?= norwegian-honey
NGROK_DOMAIN := $(shell grep -E '^\s+domain:' $(NGROK_CONFIG) 2>/dev/null | head -1 | sed 's/.*domain:[[:space:]]*//')
NGROK_PORT   := $(shell grep -E '^\s+addr:' $(NGROK_CONFIG) 2>/dev/null | head -1 | sed 's/.*addr:[[:space:]]*//')
NGROK_URL        ?= https://$(NGROK_DOMAIN)

ifeq ($(PRETTY),1)
  FORMAT = | $(PYTHON) -m json.tool
else
  FORMAT =
endif

KEEP_TOKENS    ?=
CANARY_FLUSH_FLAGS = $(if $(KEEP_TOKENS),--keep-tokens,)

# Run `ssh-add ~/.ssh/norwegian-honey` once per session if your key has a passphrase
SSH_CMD = ssh -o BatchMode=yes -o StrictHostKeyChecking=accept-new \
	-i $(PROD_SSH_KEY) -p $(PROD_SSH_PORT) $(PROD_SSH)

.PHONY: help help-local help-ngrok install \
        health analyze-headers analyze-headers-sample analyze-eml \
        osint-query osint-query-sample osint-from-analysis osint-from-sample \
        report-score report-from-analysis \
        canary-token canary-hit canary-demo canary-logs canary-flush \
        local-dev local-docker-up local-docker-down local-docker-logs \
        local-health local-analyze-headers local-analyze-headers-sample local-analyze-eml \
        local-osint-query local-osint-query-sample local-osint-from-analysis local-osint-from-sample \
        local-report-score local-report-from-analysis local-cli-report \
        local-canary-token local-canary-hit local-canary-demo \
        local-canary-logs local-canary-logs-local local-canary-logs-docker \
        local-canary-flush local-canary-flush-local local-canary-flush-docker \
        local-cli-eml local-cli-headers local-docs \
        prod-canary-logs prod-canary-flush prod-deploy prod-up prod-down prod-logs \
        ngrok-install ngrok-setup ngrok-check ngrok-tunnel ngrok-tunnel-ephemeral ngrok-url \
        ngrok-health ngrok-canary-token

# =============================================================================
# HELP
# =============================================================================

help: ## Production API (default) — targets cloud at $(PROD_URL)
	@echo "Norwegian Honey — production targets  →  $(PROD_URL)"
	@echo "Config: make.env (copy from make.env.example)"
	@echo "Override: make health PROD_URL=https://other.domain"
	@echo "PRETTY=1  pretty-print JSON"
	@echo ""
	@grep -E '^[a-zA-Z0-9_-]+:.*## \[prod\]' $(MAKEFILE_LIST) | \
		awk 'BEGIN {FS = ":.*## \\[prod\\] "}; {printf "  \033[36m%-28s\033[0m %s\n", $$1, $$2}'
	@echo ""
	@echo "Other: make help-local | make help-ngrok | make help-server"

help-local: ## Local dev targets — localhost:$(LOCAL_PORT)
	@echo "Local dev  →  $(LOCAL_URL)"
	@echo ""
	@grep -E '^local-[a-zA-Z0-9_-]+:.*##' $(MAKEFILE_LIST) | \
		sed 's/^local-//' | \
		awk 'BEGIN {FS = ":.*## "}; {printf "  \033[33m%-28s\033[0m %s\n", $$1, $$2}'

help-ngrok: ## ngrok tunnel targets (local dev + public URL)
	@echo "ngrok  →  $(NGROK_URL)"
	@echo ""
	@grep -E '^ngrok-[a-zA-Z0-9_-]+:.*##' $(MAKEFILE_LIST) | \
		sed 's/^ngrok-//' | \
		awk 'BEGIN {FS = ":.*## "}; {printf "  \033[35m%-28s\033[0m %s\n", $$1, $$2}'

help-server: ## Server-side deploy targets (run on VPS)
	@echo "Server deploy (on VPS)"
	@echo ""
	@grep -E '^prod-(up|down|logs|deploy):.*##' $(MAKEFILE_LIST) | \
		awk 'BEGIN {FS = ":.*## "}; {printf "  \033[32m%-28s\033[0m %s\n", $$1, $$2}'

# =============================================================================
# SETUP
# =============================================================================

install: ## [local] Create venv and install dependencies
	python3 -m venv $(VENV)
	$(PYTHON) -m pip install -r requirements.txt
	@test -f .env || cp .env.example .env
	@test -f make.env || cp make.env.example make.env
	@echo "Edit make.env → PROD_URL, PROD_SSH for cloud targets"

# =============================================================================
# PRODUCTION — call cloud API from your machine (default)
# =============================================================================

health: ## [prod] GET /health
	curl -s "$(API_URL)/health" $(FORMAT)

domain-ip:
	dig +short $(DOMAIN)
	dig +short www.$(DOMAIN)
	dig +short api.$(DOMAIN)
	dig +short www.api.$(DOMAIN)
	dig +short www.api.$(DOMAIN)

analyze-headers: ## [prod] POST /analyze/headers (HEADERS=path)
	@test -n "$(HEADERS)" || (echo "Usage: make analyze-headers HEADERS=path/to/headers.txt"; exit 1)
	curl -s -X POST "$(API_URL)/analyze/headers" \
		$(API_AUTH) \
		-H "Content-Type: application/json" \
		-d "$$($(PYTHON) -c "import json, pathlib; print(json.dumps({'raw_headers': pathlib.Path('$(HEADERS)').read_text()}))")" \
		$(FORMAT)

analyze-headers-sample: ## [prod] POST /analyze/headers (built-in sample)
	curl -s -X POST "$(API_URL)/analyze/headers" \
		$(API_AUTH) \
		-H "Content-Type: application/json" \
		-d '{"raw_headers":"From: scammer@evil-phish.example\nReply-To: collector@different-bad.example\nReturn-Path: <bounce@evil-phish.example>\nSubject: Urgent wire transfer\nAuthentication-Results: mx.example.com; spf=fail; dkim=fail; dmarc=fail\nReceived: from mail.badactor.example ([198.51.100.10]) by mx.example.com; Mon, 1 Jan 2024 11:59:00 +0000\nX-Originating-IP: [203.0.113.99]\n"}' \
		$(FORMAT)

analyze-eml: ## [prod] POST /analyze/eml (EML=path)
	curl -s -X POST "$(API_URL)/analyze/eml" \
		$(API_AUTH) \
		-F "file=@$(EML)" \
		$(FORMAT)

osint-query: ## [prod] POST /osint/query (IPS= DOMAINS= EMAILS=)
	curl -s -X POST "$(API_URL)/osint/query" \
		$(API_AUTH) \
		-H "Content-Type: application/json" \
		-d "$$($(PYTHON) -c "import json; ips=[x for x in '$(IPS)'.split(',') if x]; domains=[x for x in '$(DOMAINS)'.split(',') if x]; emails=[x for x in '$(EMAILS)'.split(',') if x]; print(json.dumps({'ips': ips, 'domains': domains, 'emails': emails}))")" \
		$(FORMAT)

osint-query-sample: ## [prod] POST /osint/query (8.8.8.8, example.com)
	$(MAKE) osint-query IPS=8.8.8.8 DOMAINS=example.com

osint-from-analysis: ## [prod] POST /osint/from-analysis (ANALYSIS=file.json)
	@test -n "$(ANALYSIS)" || (echo "Usage: make osint-from-analysis ANALYSIS=analysis.json"; exit 1)
	curl -s -X POST "$(API_URL)/osint/from-analysis" \
		$(API_AUTH) \
		-H "Content-Type: application/json" \
		-d "@$(ANALYSIS)" \
		$(FORMAT)

osint-from-sample: ## [prod] Analyze sample → OSINT pipeline
	curl -s -X POST "$(API_URL)/analyze/headers" \
		$(API_AUTH) \
		-H "Content-Type: application/json" \
		-d '{"raw_headers":"From: scammer@evil-phish.example\nReply-To: collector@different-bad.example\nAuthentication-Results: mx.example.com; spf=fail; dkim=fail; dmarc=fail\nReceived: from mail.badactor.example ([198.51.100.10]) by mx.example.com; Mon, 1 Jan 2024 11:59:00 +0000\nX-Originating-IP: [203.0.113.99]\n"}' \
	| curl -s -X POST "$(API_URL)/osint/from-analysis" \
		$(API_AUTH) \
		-H "Content-Type: application/json" \
		-d @- \
		$(FORMAT)

report-score: ## [prod] POST /report/score (ANALYSIS=file.json OSINT=osint.json optional)
	@test -n "$(ANALYSIS)" || (echo "Usage: make report-score ANALYSIS=analysis.json [OSINT=osint.json]"; exit 1)
	curl -s -X POST "$(API_URL)/report/score" \
		$(API_AUTH) \
		-H "Content-Type: application/json" \
		-d "$$($(PYTHON) -c "import json, pathlib; a=json.loads(pathlib.Path('$(ANALYSIS)').read_text()); o=pathlib.Path('$(OSINT)'); payload={'analysis': a, 'include_source': True}; payload['osint']=json.loads(o.read_text()) if '$(OSINT)' and o.is_file() else None; print(json.dumps(payload))")" \
		$(FORMAT)

report-from-analysis: ## [prod] POST /report/from-analysis — analyze JSON → OSINT → score
	@test -n "$(ANALYSIS)" || (echo "Usage: make report-from-analysis ANALYSIS=analysis.json"; exit 1)
	curl -s -X POST "$(API_URL)/report/from-analysis" \
		$(API_AUTH) \
		-H "Content-Type: application/json" \
		-d "@$(ANALYSIS)" \
		$(FORMAT)

canary-token: ## [prod] Generate canary embed + register on VPS (TRAP=pixel|portfolio|both)
	@OUT="$$($(PYTHON) scripts/generate_canary_token.py --base-url "$(API_URL)" --count 1 --trap $(TRAP) --json)"; \
	echo "$$OUT" | $(PYTHON) -m json.tool; \
	TOKEN="$$($(PYTHON) -c "import json,sys; print(json.loads(sys.argv[1])['token'])" "$$OUT")"; \
	$(MAKE) prod-canary-register TOKEN="$$TOKEN"

canary-register: ## [prod] Register existing TOKEN in local DB
	@test -n "$(TOKEN)" || (echo "Usage: make canary-register TOKEN=your-token"; exit 1)
	$(PYTHON) scripts/register_canary_token.py "$(TOKEN)" --db-path $(CANARY_DB)

prod-canary-register: ## [prod] Register TOKEN on VPS via SSH
	@test -n "$(TOKEN)" || (echo "Usage: make prod-canary-register TOKEN=your-token"; exit 1)
	$(SSH_CMD) "cd $(PROD_REMOTE_DIR) && docker compose exec -T $(DOCKER_SERVICE) \
		python scripts/register_canary_token.py '$(TOKEN)' --db-path $(DOCKER_CANARY_DB)"

canary-hit: ## [prod] Trigger trap (TOKEN= required, TRAP=pixel|portfolio)
	@test -n "$(TOKEN)" || (echo "Usage: make canary-hit TOKEN=your-token [TRAP=pixel|portfolio]"; exit 1)
	@if [ "$(TRAP)" = "portfolio" ]; then \
		URL="$(API_URL)/portfolio/$(TOKEN)"; \
	else \
		URL="$(API_URL)/images/$(TOKEN).png"; \
	fi; \
	curl -s -H "User-Agent: Makefile-Test/1.0" \
		"$$URL" -o /dev/null -w "HTTP %{http_code}, %{size_download} bytes\n"

canary-demo: ## [prod] Generate token, register on VPS, hit trap on cloud (TRAP=pixel|portfolio)
	@TOKEN="$$($(PYTHON) scripts/generate_canary_token.py --base-url "$(API_URL)" --count 1 --trap $(TRAP) --json \
		| $(PYTHON) -c "import sys,json; print(json.load(sys.stdin)['token'])")"; \
	echo "token: $$TOKEN  trap: $(TRAP)"; \
	$(MAKE) prod-canary-register TOKEN="$$TOKEN"; \
	$(MAKE) canary-hit TOKEN="$$TOKEN" TRAP=$(TRAP); \
	echo "Check logs: make prod-canary-logs"

canary-logs: prod-canary-logs ## [prod] Alias — canary hits on server

prod-canary-logs: ## [prod] Canary hits via SSH on VPS
	$(SSH_CMD) "cd $(PROD_REMOTE_DIR) && docker compose exec -T $(DOCKER_SERVICE) python -c \"\
import sqlite3; \
db=sqlite3.connect('$(DOCKER_CANARY_DB)'); \
rows=db.execute('SELECT id, trap, token, client_ip, user_agent, timestamp FROM canary_hits ORDER BY id DESC LIMIT 10').fetchall(); \
print('id|trap|token|client_ip|user_agent|timestamp'); \
[print('|'.join(str(c) if c is not None else '' for c in r)) for r in rows] or print('(no hits)')\""

canary-flush: prod-canary-flush ## [prod] Alias — flush canary DB on server

prod-canary-flush: ## [prod] Flush canary SQLite on VPS (KEEP_TOKENS=1 to keep registered tokens)
	$(SSH_CMD) "cd $(PROD_REMOTE_DIR) && docker compose exec -T $(DOCKER_SERVICE) \
		python scripts/flush_canary_db.py --db-path $(DOCKER_CANARY_DB) $(CANARY_FLUSH_FLAGS)"

# =============================================================================
# LOCAL DEV — run server on localhost
# =============================================================================

local-dev: ## Run uvicorn with reload on $(LOCAL_URL)
	$(UVICORN) app.main:app --host $(HOST) --port $(LOCAL_PORT) --reload

local-docker-up: ## Start local Docker stack (port $(LOCAL_PORT))
	docker compose up --build -d

local-docker-down: ## Stop local Docker stack
	docker compose down

local-docker-logs: ## Tail local API container logs
	docker compose logs -f api

local-health: ## GET /health on localhost
	$(MAKE) health API_URL=$(LOCAL_URL)

local-analyze-headers: ## POST /analyze/headers on localhost
	$(MAKE) analyze-headers API_URL=$(LOCAL_URL) HEADERS="$(HEADERS)"

local-analyze-headers-sample: ## POST /analyze/headers sample on localhost
	$(MAKE) analyze-headers-sample API_URL=$(LOCAL_URL)

local-analyze-eml: ## POST /analyze/eml on localhost
	$(MAKE) analyze-eml API_URL=$(LOCAL_URL) EML="$(EML)"

local-osint-query: ## POST /osint/query on localhost
	$(MAKE) osint-query API_URL=$(LOCAL_URL) IPS="$(IPS)" DOMAINS="$(DOMAINS)" EMAILS="$(EMAILS)"

local-osint-query-sample: ## POST /osint/query sample on localhost
	$(MAKE) osint-query-sample API_URL=$(LOCAL_URL)

local-osint-from-analysis: ## POST /osint/from-analysis on localhost
	$(MAKE) osint-from-analysis API_URL=$(LOCAL_URL) ANALYSIS="$(ANALYSIS)"

local-osint-from-sample: ## Analyze → OSINT on localhost
	$(MAKE) osint-from-sample API_URL=$(LOCAL_URL)

local-report-score: ## POST /report/score on localhost
	$(MAKE) report-score API_URL=$(LOCAL_URL) ANALYSIS="$(ANALYSIS)" OSINT="$(OSINT)"

local-report-from-analysis: ## POST /report/from-analysis on localhost
	$(MAKE) report-from-analysis API_URL=$(LOCAL_URL) ANALYSIS="$(ANALYSIS)"

local-cli-report: ## CLI threat report (ANALYSIS= OUT=report.json, no server)
	@test -n "$(ANALYSIS)" || (echo "Usage: make local-cli-report ANALYSIS=analysis.json [OUT=report.json]"; exit 1)
	$(PYTHON) -m app.cli.threat_report "$(ANALYSIS)" \
		$(if $(OSINT),--osint "$(OSINT)",) \
		$(if $(OUT),-o "$(OUT)",)

local-canary-token: ## Generate + register canary token for localhost (TRAP=pixel|portfolio|both)
	$(PYTHON) scripts/generate_canary_token.py --base-url "$(LOCAL_URL)" --count 1 \
		--trap $(TRAP) --register-db $(CANARY_DB)

local-canary-register: ## Register TOKEN in local DB
	@test -n "$(TOKEN)" || (echo "Usage: make local-canary-register TOKEN=your-token"; exit 1)
	$(PYTHON) scripts/register_canary_token.py "$(TOKEN)" --db-path $(CANARY_DB)

local-canary-hit: ## Trigger trap on localhost (TOKEN=, TRAP=pixel|portfolio)
	@test -n "$(TOKEN)" || (echo "Usage: make local-canary-hit TOKEN=your-token [TRAP=pixel|portfolio]"; exit 1)
	@if [ "$(TRAP)" = "portfolio" ]; then \
		URL="$(LOCAL_URL)/portfolio/$(TOKEN)"; \
	else \
		URL="$(LOCAL_URL)/images/$(TOKEN).png"; \
	fi; \
	curl -s -H "User-Agent: Makefile-Test/1.0" \
		"$$URL" -o /dev/null -w "HTTP %{http_code}, %{size_download} bytes\n"

local-canary-demo: ## Generate token, register, hit trap locally, show DB (TRAP=pixel|portfolio)
	@TOKEN="$$($(PYTHON) scripts/generate_canary_token.py --base-url "$(LOCAL_URL)" --count 1 --trap $(TRAP) --json \
		| $(PYTHON) -c "import sys,json; print(json.load(sys.stdin)['token'])")"; \
	echo "token: $$TOKEN  trap: $(TRAP)"; \
	$(MAKE) local-canary-register TOKEN="$$TOKEN"; \
	$(MAKE) local-canary-hit TOKEN="$$TOKEN" TRAP=$(TRAP); \
	$(MAKE) local-canary-logs

local-canary-logs: ## Canary hits — local docker if running, else local SQLite
	@if docker compose ps --status running -q $(DOCKER_SERVICE) 2>/dev/null | grep -q .; then \
		$(MAKE) local-canary-logs-docker; \
	else \
		$(MAKE) local-canary-logs-local; \
	fi

local-canary-logs-local: ## Canary hits from ./data/canary.db
	@$(PYTHON) -c "import sqlite3, pathlib; \
db=pathlib.Path('$(CANARY_DB)'); print(f'DB: {db.resolve()}'); \
conn=sqlite3.connect(db); \
rows=conn.execute('SELECT id, trap, token, client_ip, user_agent, timestamp FROM canary_hits ORDER BY id DESC LIMIT 10').fetchall(); \
print('id|trap|token|client_ip|user_agent|timestamp'); \
[print('|'.join(str(c) if c is not None else '' for c in r)) for r in rows] if rows else print('(no hits)')"

local-canary-logs-docker: ## Canary hits from local Docker volume
	docker compose exec -T $(DOCKER_SERVICE) python -c "\
import sqlite3; \
db=sqlite3.connect('$(DOCKER_CANARY_DB)'); \
rows=db.execute('SELECT id, trap, token, client_ip, user_agent, timestamp FROM canary_hits ORDER BY id DESC LIMIT 10').fetchall(); \
print('id|trap|token|client_ip|user_agent|timestamp'); \
[print('|'.join(str(c) if c is not None else '' for c in r)) for r in rows] or print('(no hits)')"

local-canary-flush: ## Flush local canary DB — docker if running, else ./data/canary.db
	@if docker compose ps --status running -q $(DOCKER_SERVICE) 2>/dev/null | grep -q .; then \
		$(MAKE) local-canary-flush-docker; \
	else \
		$(MAKE) local-canary-flush-local; \
	fi

local-canary-flush-local: ## Flush ./data/canary.db (KEEP_TOKENS=1 to keep registered tokens)
	$(PYTHON) scripts/flush_canary_db.py --db-path $(CANARY_DB) $(CANARY_FLUSH_FLAGS)

local-canary-flush-docker: ## Flush canary DB in local Docker volume
	docker compose exec -T $(DOCKER_SERVICE) \
		python scripts/flush_canary_db.py --db-path $(DOCKER_CANARY_DB) $(CANARY_FLUSH_FLAGS)

local-cli-eml: ## Analyze .eml offline (no server)
	$(PYTHON) -m app.cli.header_eval --eml "$(EML)" --pretty

local-cli-headers: ## Analyze headers file offline (HEADERS=)
	@test -n "$(HEADERS)" || (echo "Usage: make local-cli-headers HEADERS=path"; exit 1)
	$(PYTHON) -m app.cli.header_eval --headers-file "$(HEADERS)" --headers-only --pretty

local-docs: ## Print local Swagger URL
	@echo "$(LOCAL_URL)/docs  (requires DEBUG=true in .env)"

# =============================================================================
# NGROK — local dev with public tunnel (optional)
# =============================================================================

ngrok-install: ## Install ngrok to ~/.local/bin
	@mkdir -p $(HOME)/.local/bin
	curl -sSL "https://bin.equinox.io/c/bNyj1mQVY4c/ngrok-v3-stable-linux-amd64.tgz" -o /tmp/ngrok.tgz
	tar -xzf /tmp/ngrok.tgz -C $(HOME)/.local/bin ngrok
	@echo "Installed: $$($(NGROK) version)"
	@$(MAKE) ngrok-setup

ngrok-setup: ## Create ngrok.local.yml (add authtoken)
	@test -f $(NGROK_LOCAL_CONFIG) || cp ngrok.local.yml.example $(NGROK_LOCAL_CONFIG)
	@echo "Edit $(NGROK_LOCAL_CONFIG) with your authtoken"
	@echo "Tunnel: $(NGROK_CONFIG) → $(NGROK_URL)"

ngrok-check: ## Validate ngrok config
	@test -x "$(NGROK)" || (echo "run: make ngrok-install"; exit 1)
	@if [ -f "$(NGROK_LOCAL_CONFIG)" ]; then \
		$(NGROK) config check --config "$(NGROK_LOCAL_CONFIG)" --config "$(NGROK_CONFIG)"; \
	elif [ -f "$(NGROK_GLOBAL_CONFIG)" ]; then \
		$(NGROK) config check --config "$(NGROK_GLOBAL_CONFIG)" --config "$(NGROK_CONFIG)"; \
	else echo "run: make ngrok-setup"; exit 1; fi

ngrok-tunnel: ## Start ngrok tunnel (run local-dev in another terminal)
	@test -x "$(NGROK)" || (echo "run: make ngrok-install"; exit 1)
	@echo "$(NGROK_URL) → 127.0.0.1:$(NGROK_PORT)"
	@if [ -f "$(NGROK_LOCAL_CONFIG)" ]; then \
		$(NGROK) start --config "$(NGROK_LOCAL_CONFIG)" --config "$(NGROK_CONFIG)" $(NGROK_TUNNEL); \
	elif [ -f "$(NGROK_GLOBAL_CONFIG)" ]; then \
		$(NGROK) start --config "$(NGROK_GLOBAL_CONFIG)" --config "$(NGROK_CONFIG)" $(NGROK_TUNNEL); \
	else echo "run: make ngrok-setup"; exit 1; fi

ngrok-tunnel-ephemeral: ## Ephemeral ngrok URL (no reserved domain)
	@test -x "$(NGROK)" || (echo "run: make ngrok-install"; exit 1)
	@if [ -f "$(NGROK_LOCAL_CONFIG)" ]; then \
		$(NGROK) http --config "$(NGROK_LOCAL_CONFIG)" $(NGROK_PORT); \
	else $(NGROK) http --config "$(NGROK_GLOBAL_CONFIG)" $(NGROK_PORT); fi

ngrok-url: ## Print active ngrok HTTPS URL
	@curl -sf $(NGROK_API)/api/tunnels 2>/dev/null \
	| $(PYTHON) -c "import sys,json; d=json.load(sys.stdin); t=next((x for x in d.get('tunnels',[]) if x.get('public_url','').startswith('https')), None); print(t['public_url'] if t else '$(NGROK_URL)')" \
	|| echo "$(NGROK_URL)"

ngrok-health: ## GET /health via ngrok URL
	@URL=$$($(MAKE) -s ngrok-url); curl -s "$$URL/health" $(FORMAT)

ngrok-canary-token: ## Generate canary token for ngrok URL
	@URL=$$($(MAKE) -s ngrok-url); \
	$(PYTHON) scripts/generate_canary_token.py --base-url "$$URL" --count 1

# =============================================================================
# SERVER — run ON the VPS
# =============================================================================

prod-up: ## [server] Start production stack (Caddy + API)
	docker compose -f docker-compose.yml -f docker-compose.prod.yml up -d --build

prod-down: ## [server] Stop production stack
	docker compose -f docker-compose.yml -f docker-compose.prod.yml down

prod-logs: ## [server] Tail API + Caddy logs
	docker compose -f docker-compose.yml -f docker-compose.prod.yml logs -f api caddy

prod-deploy: ## [server] Build, start, health check
	bash deploy/deploy.sh
