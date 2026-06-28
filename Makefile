# Norwegian Honey — Makefile
# Usage: make help | make help-local | make help-server | make help-ngrok
#
# Naming:
#   prod-*   → production API at $(PROD_URL) or VPS via SSH
#   local-*  → localhost API, local Docker/SQLite, or offline CLI
#   server   → run ON the VPS (prod-up, prod-deploy, …)
#   ngrok-*  → local dev with public tunnel
#
# Unprefixed names (analyze-eml, canary-token, …) are backward-compatible aliases for prod-*.

HELP_FILE      := $(firstword $(MAKEFILE_LIST))
.DEFAULT_GOAL  := help

# --- Client config (production URL, SSH for remote logs) ---
-include make.env
-include .env

DOMAIN         ?= canary.example.com
PROD_URL       ?= https://$(DOMAIN)
LOCAL_URL      ?= http://127.0.0.1:8000
API_URL        ?= $(PROD_URL)
PROD_API_URL   = $(if $(filter command line,$(origin API_URL)),$(API_URL),$(PROD_URL))
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
# DB trap column uses images|portfolio; Make targets use pixel|portfolio
CANARY_DB_TRAP = $(if $(filter portfolio,$(TRAP)),portfolio,images)
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

.PHONY: help help-local help-ngrok help-server install \
        prod-health prod-analyze-headers prod-analyze-headers-sample prod-analyze-eml \
        prod-osint-query prod-osint-query-sample prod-osint-from-analysis prod-osint-from-sample \
        prod-report-score prod-report-from-analysis prod-canary-token prod-canary-hit prod-canary-demo \
        prod-canary-logs prod-canary-flush prod-canary-export prod-canary-register \
        health analyze-headers analyze-headers-sample analyze-eml \
        osint-query osint-query-sample osint-from-analysis osint-from-sample \
        report-score report-from-analysis canary-token canary-hit canary-demo canary-logs canary-flush \
        local-dev local-docker-up local-docker-down local-docker-logs \
        local-health local-analyze-headers local-analyze-headers-sample local-analyze-eml \
        local-osint-query local-osint-query-sample local-osint-from-analysis local-osint-from-sample \
        local-report-score local-report-from-analysis local-cli-report \
        local-canary-export local-visualize json-extract \
        local-canary-token local-canary-hit local-canary-demo local-canary-register \
        local-canary-logs local-canary-logs-local local-canary-logs-docker \
        local-canary-flush local-canary-flush-local local-canary-flush-docker \
        local-cli-eml local-cli-headers local-docs \
        prod-deploy prod-up prod-down prod-logs \
        ngrok-install ngrok-setup ngrok-check ngrok-tunnel ngrok-tunnel-ephemeral ngrok-url \
        ngrok-health ngrok-canary-token

# =============================================================================
# HELP
# =============================================================================

help: ## Show production targets (prod-* and aliases)
	@echo "Norwegian Honey"
	@echo ""
	@echo "Environments (use explicit prefix to avoid mistakes):"
	@echo "  \033[36mprod-*\033[0m    → $(PROD_URL) API  or  SSH to $(PROD_SSH)"
	@echo "  \033[33mlocal-*\033[0m  → $(LOCAL_URL), ./data/canary.db, offline CLI  (make help-local)"
	@echo "  \033[32mprod-up\033[0m etc → on VPS only  (make help-server)"
	@echo ""
	@echo "Config: make.env + .env   |   PRETTY=1 for JSON formatting"
	@echo "Override API host: make prod-analyze-eml API_URL=https://other.domain"
	@echo ""
	@echo "Production API & remote canary (prod-*):"
	@grep -hE '^prod-[a-zA-Z0-9_-]+:.*## \[prod\]' $(HELP_FILE) | \
		awk 'BEGIN {FS = ":.*## \\[prod\\] "}; {printf "  \033[36m%-30s\033[0m %s\n", $$1, $$2}'
	@echo ""
	@echo "Aliases (same as prod-*):"
	@grep -hE '^[a-z][a-z0-9_-]*: prod-' $(HELP_FILE) | \
		awk 'BEGIN {FS = ": prod-"}; {sub(/ ##.*/, "", $$2); printf "  %-30s → prod-%s\n", $$1, $$2}'
	@echo ""
	@echo "More: make help-local | make help-server | make help-ngrok"

help-local: ## Local dev targets — localhost:$(LOCAL_PORT)
	@echo "Local dev  →  $(LOCAL_URL)  |  offline CLI  |  ./data/canary.db"
	@echo ""
	@grep -hE '^local-[a-zA-Z0-9_-]+:.*##' $(HELP_FILE) | \
		awk 'BEGIN {FS = ":.*## "}; {printf "  \033[33m%-30s\033[0m %s\n", $$1, $$2}'
	@echo ""
	@grep -hE '^(install|json-extract|domain-ip):.*##' $(HELP_FILE) | \
		awk 'BEGIN {FS = ":.*## "}; {printf "  \033[33m%-30s\033[0m %s\n", $$1, $$2}'

help-ngrok: ## ngrok tunnel targets (local dev + public URL)
	@echo "ngrok  →  $(NGROK_URL)"
	@echo ""
	@grep -hE '^ngrok-[a-zA-Z0-9_-]+:.*##' $(HELP_FILE) | \
		awk 'BEGIN {FS = ":.*## "}; {printf "  \033[35m%-30s\033[0m %s\n", $$1, $$2}'

help-server: ## Server-side deploy targets (run on VPS)
	@echo "Run these ON the VPS ($(PROD_REMOTE_DIR)):"
	@echo ""
	@grep -hE '^prod-(up|down|logs|deploy):.*##' $(HELP_FILE) | \
		awk 'BEGIN {FS = ":.*## "}; {printf "  \033[32m%-30s\033[0m %s\n", $$1, $$2}'

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
# PRODUCTION API — curl $(API_URL); use prod-* targets (aliases kept for compat)
# =============================================================================

_health:
	curl -s "$(API_URL)/health" $(FORMAT)

prod-health: ## [prod] GET /health
	@$(MAKE) _health API_URL=$(PROD_API_URL)

health: prod-health ## alias for prod-health

analyze-headers: prod-analyze-headers ## alias
analyze-headers-sample: prod-analyze-headers-sample ## alias
analyze-eml: prod-analyze-eml ## alias
osint-query: prod-osint-query ## alias
osint-query-sample: prod-osint-query-sample ## alias
osint-from-analysis: prod-osint-from-analysis ## alias
osint-from-sample: prod-osint-from-sample ## alias
report-score: prod-report-score ## alias
report-from-analysis: prod-report-from-analysis ## alias
canary-token: prod-canary-token ## alias
canary-hit: prod-canary-hit ## alias
canary-demo: prod-canary-demo ## alias
canary-logs: prod-canary-logs ## alias
canary-flush: prod-canary-flush ## alias

prod-analyze-headers: ## [prod] POST /analyze/headers (HEADERS=path)
	@test -n "$(HEADERS)" || (echo "Usage: make prod-analyze-headers HEADERS=path/to/headers.txt"; exit 1)
	@$(MAKE) _analyze-headers API_URL=$(PROD_API_URL) HEADERS="$(HEADERS)"

_analyze-headers:
	curl -s -X POST "$(API_URL)/analyze/headers" \
		$(API_AUTH) \
		-H "Content-Type: application/json" \
		-d "$$($(PYTHON) -c "import json, pathlib; print(json.dumps({'raw_headers': pathlib.Path('$(HEADERS)').read_text()}))")" \
		$(FORMAT)

prod-analyze-headers-sample: ## [prod] POST /analyze/headers (built-in sample)
	@$(MAKE) _analyze-headers-sample API_URL=$(PROD_API_URL)

_analyze-headers-sample:
	curl -s -X POST "$(API_URL)/analyze/headers" \
		$(API_AUTH) \
		-H "Content-Type: application/json" \
		-d '{"raw_headers":"From: scammer@evil-phish.example\nReply-To: collector@different-bad.example\nReturn-Path: <bounce@evil-phish.example>\nSubject: Urgent wire transfer\nAuthentication-Results: mx.example.com; spf=fail; dkim=fail; dmarc=fail\nReceived: from mail.badactor.example ([198.51.100.10]) by mx.example.com; Mon, 1 Jan 2024 11:59:00 +0000\nX-Originating-IP: [203.0.113.99]\n"}' \
		$(FORMAT)

prod-analyze-eml: ## [prod] POST /analyze/eml (EML=path)
	@test -n "$(EML)" || (echo "Usage: make prod-analyze-eml EML=path/to/mail.eml"; exit 1)
	@$(MAKE) _analyze-eml API_URL=$(PROD_API_URL)

_analyze-eml:
	curl -s -X POST "$(API_URL)/analyze/eml" \
		$(API_AUTH) \
		-F "file=@$(EML)" \
		$(FORMAT)

prod-osint-query: ## [prod] POST /osint/query (IPS= DOMAINS= EMAILS=)
	@$(MAKE) _osint-query API_URL=$(PROD_API_URL)

_osint-query:
	curl -s -X POST "$(API_URL)/osint/query" \
		$(API_AUTH) \
		-H "Content-Type: application/json" \
		-d "$$($(PYTHON) -c "import json; ips=[x for x in '$(IPS)'.split(',') if x]; domains=[x for x in '$(DOMAINS)'.split(',') if x]; emails=[x for x in '$(EMAILS)'.split(',') if x]; print(json.dumps({'ips': ips, 'domains': domains, 'emails': emails}))")" \
		$(FORMAT)

prod-osint-query-sample: ## [prod] POST /osint/query (8.8.8.8, example.com)
	@$(MAKE) prod-osint-query IPS=8.8.8.8 DOMAINS=example.com

prod-osint-from-analysis: ## [prod] POST /osint/from-analysis (ANALYSIS=file.json)
	@test -n "$(ANALYSIS)" || (echo "Usage: make prod-osint-from-analysis ANALYSIS=analysis.json"; exit 1)
	@$(MAKE) _osint-from-analysis API_URL=$(PROD_API_URL)

_osint-from-analysis:
	curl -s -X POST "$(API_URL)/osint/from-analysis" \
		$(API_AUTH) \
		-H "Content-Type: application/json" \
		-d "$$($(PYTHON) -c "import json; from app.core.json_document import load_json_document; print(json.dumps(load_json_document('$(ANALYSIS)')))")" \
		$(FORMAT)

prod-osint-from-sample: ## [prod] Analyze sample → OSINT pipeline
	@$(MAKE) _osint-from-sample API_URL=$(PROD_API_URL)

_osint-from-sample:
	curl -s -X POST "$(API_URL)/analyze/headers" \
		$(API_AUTH) \
		-H "Content-Type: application/json" \
		-d '{"raw_headers":"From: scammer@evil-phish.example\nReply-To: collector@different-bad.example\nAuthentication-Results: mx.example.com; spf=fail; dkim=fail; dmarc=fail\nReceived: from mail.badactor.example ([198.51.100.10]) by mx.example.com; Mon, 1 Jan 2024 11:59:00 +0000\nX-Originating-IP: [203.0.113.99]\n"}' \
	| curl -s -X POST "$(API_URL)/osint/from-analysis" \
		$(API_AUTH) \
		-H "Content-Type: application/json" \
		-d @- \
		$(FORMAT)

prod-report-score: ## [prod] POST /report/score (ANALYSIS=file.json OSINT=osint.json optional)
	@test -n "$(ANALYSIS)" || (echo "Usage: make prod-report-score ANALYSIS=analysis.json [OSINT=osint.json]"; exit 1)
	@$(MAKE) _report-score API_URL=$(PROD_API_URL)

_report-score:
	curl -s -X POST "$(API_URL)/report/score" \
		$(API_AUTH) \
		-H "Content-Type: application/json" \
		-d "$$($(PYTHON) -c "import json, pathlib; from app.core.json_document import load_json_document; a=load_json_document('$(ANALYSIS)'); o=pathlib.Path('$(OSINT)'); payload={'analysis': a, 'include_source': True}; payload['osint']=load_json_document(o) if '$(OSINT)' and o.is_file() else None; print(json.dumps(payload))")" \
		$(FORMAT)

prod-report-from-analysis: ## [prod] POST /report/from-analysis — analyze JSON → OSINT → score
	@test -n "$(ANALYSIS)" || (echo "Usage: make prod-report-from-analysis ANALYSIS=analysis.json"; exit 1)
	@$(MAKE) _report-from-analysis API_URL=$(PROD_API_URL)

_report-from-analysis:
	curl -s -X POST "$(API_URL)/report/from-analysis" \
		$(API_AUTH) \
		-H "Content-Type: application/json" \
		-d "$$($(PYTHON) -c "import json; from app.core.json_document import load_json_document; print(json.dumps(load_json_document('$(ANALYSIS)')))")" \
		$(FORMAT)

prod-canary-token: ## [prod] Generate canary embed + register on VPS (TRAP=pixel|portfolio|both)
	@OUT="$$($(PYTHON) scripts/generate_canary_token.py --base-url "$(PROD_API_URL)" --count 1 --trap $(TRAP) --json)"; \
	echo "$$OUT" | $(PYTHON) -m json.tool; \
	TOKEN="$$($(PYTHON) -c "import json,sys; print(json.loads(sys.argv[1])['token'])" "$$OUT")"; \
	$(MAKE) prod-canary-register TOKEN="$$TOKEN"

prod-canary-register: ## [prod] Register TOKEN on VPS via SSH
	@test -n "$(TOKEN)" || (echo "Usage: make prod-canary-register TOKEN=your-token"; exit 1)
	$(SSH_CMD) "cd $(PROD_REMOTE_DIR) && docker compose exec -T $(DOCKER_SERVICE) \
		python scripts/register_canary_token.py '$(TOKEN)' --db-path $(DOCKER_CANARY_DB)"

prod-canary-hit: ## [prod] Trigger trap (TOKEN= required, TRAP=pixel|portfolio)
	@test -n "$(TOKEN)" || (echo "Usage: make prod-canary-hit TOKEN=your-token [TRAP=pixel|portfolio]"; exit 1)
	@$(MAKE) _canary-hit API_URL=$(PROD_API_URL)

_canary-hit:
	@if [ "$(TRAP)" = "portfolio" ]; then \
		URL="$(API_URL)/portfolio/$(TOKEN)"; \
	else \
		URL="$(API_URL)/images/$(TOKEN).png"; \
	fi; \
	curl -s -H "User-Agent: Makefile-Test/1.0" \
		"$$URL" -o /dev/null -w "HTTP %{http_code}, %{size_download} bytes\n"

prod-canary-demo: ## [prod] Generate token, register on VPS, hit trap on cloud (TRAP=pixel|portfolio)
	@TOKEN="$$($(PYTHON) scripts/generate_canary_token.py --base-url "$(PROD_API_URL)" --count 1 --trap $(TRAP) --json \
		| $(PYTHON) -c "import sys,json; print(json.load(sys.stdin)['token'])")"; \
	echo "token: $$TOKEN  trap: $(TRAP)"; \
	$(MAKE) prod-canary-register TOKEN="$$TOKEN"; \
	$(MAKE) prod-canary-hit TOKEN="$$TOKEN" TRAP=$(TRAP); \
	echo "Check logs: make prod-canary-logs"

prod-canary-logs: ## [prod] Canary hits via SSH on VPS
	$(SSH_CMD) "cd $(PROD_REMOTE_DIR) && docker compose exec -T $(DOCKER_SERVICE) python -c \"\
import sqlite3; \
db=sqlite3.connect('$(DOCKER_CANARY_DB)'); \
rows=db.execute('SELECT id, trap, token, client_ip, user_agent, timestamp FROM canary_hits ORDER BY id DESC LIMIT 10').fetchall(); \
print('id|trap|token|client_ip|user_agent|timestamp'); \
[print('|'.join(str(c) if c is not None else '' for c in r)) for r in rows] or print('(no hits)')\""

prod-canary-flush: ## [prod] Flush canary SQLite on VPS (KEEP_TOKENS=1 to keep registered tokens)
	$(SSH_CMD) "cd $(PROD_REMOTE_DIR) && docker compose exec -T $(DOCKER_SERVICE) \
		python scripts/flush_canary_db.py --db-path $(DOCKER_CANARY_DB) $(CANARY_FLUSH_FLAGS)"

prod-canary-export: ## [prod] Export canary investigation JSON (TOKEN= TRAP= OUT=investigation.json)
	@test -n "$(OUT)" || (echo "Usage: make prod-canary-export OUT=investigation.json [TOKEN=] [TRAP=portfolio|pixel]"; exit 1)
	@mkdir -p "$(dir $(OUT))"
	$(SSH_CMD) "cd $(PROD_REMOTE_DIR) && docker compose exec -T $(DOCKER_SERVICE) \
		python scripts/export_canary_investigation.py --db-path $(DOCKER_CANARY_DB) \
		$(if $(TOKEN),--token '$(TOKEN)',) $(if $(filter command line,$(origin TRAP)),--trap $(CANARY_DB_TRAP),) --run-osint" > "$(OUT)"
	@echo "Wrote $(OUT)"

domain-ip: ## [local] DNS lookup for DOMAIN
	dig +short $(DOMAIN)
	dig +short www.$(DOMAIN)

# =============================================================================
# LOCAL DEV — run server on localhost
# =============================================================================

local-dev: ## [local] Run uvicorn with reload on localhost:$(LOCAL_PORT)
	$(UVICORN) app.main:app --host $(HOST) --port $(LOCAL_PORT) --reload

local-docker-up: ## [local] Start local Docker stack (port $(LOCAL_PORT))
	docker compose up --build -d

local-docker-down: ## [local] Stop local Docker stack
	docker compose down

local-docker-logs: ## [local] Tail local API container logs
	docker compose logs -f api

local-health: ## [local] GET /health on localhost
	@$(MAKE) _health API_URL=$(LOCAL_URL)

local-analyze-headers: ## [local] POST /analyze/headers on localhost
	@$(MAKE) _analyze-headers API_URL=$(LOCAL_URL) HEADERS="$(HEADERS)"

local-analyze-headers-sample: ## [local] POST /analyze/headers sample on localhost
	@$(MAKE) _analyze-headers-sample API_URL=$(LOCAL_URL)

local-analyze-eml: ## [local] POST /analyze/eml on localhost
	@$(MAKE) _analyze-eml API_URL=$(LOCAL_URL)

local-osint-query: ## [local] POST /osint/query on localhost
	@$(MAKE) _osint-query API_URL=$(LOCAL_URL)

local-osint-query-sample: ## [local] POST /osint/query sample on localhost
	@$(MAKE) _osint-query API_URL=$(LOCAL_URL) IPS=8.8.8.8 DOMAINS=example.com

local-osint-from-analysis: ## [local] POST /osint/from-analysis on localhost
	@$(MAKE) _osint-from-analysis API_URL=$(LOCAL_URL)

local-osint-from-sample: ## [local] Analyze → OSINT on localhost
	@$(MAKE) _osint-from-sample API_URL=$(LOCAL_URL)

local-report-score: ## [local] POST /report/score on localhost
	@$(MAKE) _report-score API_URL=$(LOCAL_URL)

local-report-from-analysis: ## [local] POST /report/from-analysis on localhost
	@$(MAKE) _report-from-analysis API_URL=$(LOCAL_URL)

local-cli-report: ## [local] CLI threat report (ANALYSIS= OUT=report.json, no server)
	@test -n "$(ANALYSIS)" || (echo "Usage: make local-cli-report ANALYSIS=analysis.json [OUT=report.json]"; exit 1)
	$(PYTHON) -m app.cli.threat_report "$(ANALYSIS)" \
		$(if $(OSINT),--osint "$(OSINT)",) \
		$(if $(OUT),-o "$(OUT)",)

local-canary-export: ## [local] Export canary investigation from local DB (TOKEN= TRAP= OUT=)
	@test -n "$(OUT)" || (echo "Usage: make local-canary-export OUT=investigation.json [TOKEN=] [TRAP=portfolio|pixel]"; exit 1)
	@mkdir -p "$(dir $(OUT))"
	$(PYTHON) scripts/export_canary_investigation.py --db-path $(CANARY_DB) \
		$(if $(TOKEN),--token "$(TOKEN)",) $(if $(filter command line,$(origin TRAP)),--trap $(CANARY_DB_TRAP),) \
		$(if $(OSINT),--osint "$(OSINT)",--run-osint) \
		$(if $(ANALYSIS),--analysis "$(ANALYSIS)",) \
		$(if $(REPORT),--threat-report "$(REPORT)",) \
		-o "$(OUT)"
	@echo "Wrote $(OUT)"

local-visualize: ## [local] Pandas table view (REPORT=investigation.json [HTML=report.html] [TEXT=report.txt])
	@test -n "$(REPORT)" || (echo "Usage: make local-visualize REPORT=investigation.json [HTML=out.html] [TEXT=out.txt]"; exit 1)
	$(PYTHON) -m app.cli.visualize_report "$(REPORT)" \
		$(if $(HTML),--html "$(HTML)",) \
		$(if $(TEXT),--text "$(TEXT)",)

json-extract: ## [local] Strip curl noise from captured output (IN=file OUT=clean.json)
	@test -n "$(IN)" || (echo "Usage: make json-extract IN=report2.json OUT=clean.json"; exit 1)
	$(PYTHON) scripts/extract_json.py "$(IN)" $(if $(OUT),-o "$(OUT)",)

local-canary-token: ## [local] Generate + register canary token (TRAP=pixel|portfolio|both)
	$(PYTHON) scripts/generate_canary_token.py --base-url "$(LOCAL_URL)" --count 1 \
		--trap $(TRAP) --register-db $(CANARY_DB)

local-canary-register: ## [local] Register TOKEN in local DB
	@test -n "$(TOKEN)" || (echo "Usage: make local-canary-register TOKEN=your-token"; exit 1)
	$(PYTHON) scripts/register_canary_token.py "$(TOKEN)" --db-path $(CANARY_DB)

local-canary-hit: ## [local] Trigger trap on localhost (TOKEN=, TRAP=pixel|portfolio)
	@test -n "$(TOKEN)" || (echo "Usage: make local-canary-hit TOKEN=your-token [TRAP=pixel|portfolio]"; exit 1)
	@$(MAKE) _canary-hit API_URL=$(LOCAL_URL)

local-canary-demo: ## [local] Generate token, register, hit trap locally, show DB (TRAP=pixel|portfolio)
	@TOKEN="$$($(PYTHON) scripts/generate_canary_token.py --base-url "$(LOCAL_URL)" --count 1 --trap $(TRAP) --json \
		| $(PYTHON) -c "import sys,json; print(json.load(sys.stdin)['token'])")"; \
	echo "token: $$TOKEN  trap: $(TRAP)"; \
	$(MAKE) local-canary-register TOKEN="$$TOKEN"; \
	$(MAKE) local-canary-hit TOKEN="$$TOKEN" TRAP=$(TRAP); \
	$(MAKE) local-canary-logs

local-canary-logs: ## [local] Canary hits — local docker if running, else local SQLite
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

local-canary-flush: ## [local] Flush local canary DB — docker if running, else ./data/canary.db
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

local-cli-eml: ## [local] Analyze .eml offline (no server)
	$(PYTHON) -m app.cli.header_eval --eml "$(EML)" --pretty

local-cli-headers: ## [local] Analyze headers file offline (HEADERS=)
	@test -n "$(HEADERS)" || (echo "Usage: make local-cli-headers HEADERS=path"; exit 1)
	$(PYTHON) -m app.cli.header_eval --headers-file "$(HEADERS)" --headers-only --pretty

local-docs: ## [local] Print local Swagger URL
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
