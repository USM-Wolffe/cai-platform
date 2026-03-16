PYTHON ?= python3
PYTEST ?= $(PYTHON) -m pytest
PLATFORM_API_BASE_URL ?= http://127.0.0.1:8000
DEMO_WATCHGUARD_PAYLOAD ?= examples/watchguard/minimal_payload.json
DEMO_PHISHING_EMAIL_PAYLOAD ?= examples/phishing/minimal_payload.json

.DEFAULT_GOAL := help

.PHONY: help install-dev build up down test test-apps api-dev health demo-watchguard demo-phishing-email

help:
	@printf "Available targets:\n"
	@printf "  help         Show this help output.\n"
	@printf "  install-dev  Install the full contributor/dev Python surface for this repo.\n"
	@printf "  build        Build the compose-managed platform-api container image.\n"
	@printf "  up           Start only the local platform-api container.\n"
	@printf "  down         Stop the local platform-api container.\n"
	@printf "  test         Run the current repository test suite.\n"
	@printf "  test-apps    Run only the app-layer test suite.\n"
	@printf "  api-dev      Run platform-api locally without Docker for contributor/dev use.\n"
	@printf "  health       Check the platform-api health endpoint.\n"
	@printf "  demo-watchguard  Run the baseline WatchGuard demo through the host-run orchestrator against platform-api. Requires apps/cai-orchestrator installed in the active Python env.\n"
	@printf "  demo-phishing-email  Run the phishing email demo through the host-run orchestrator against platform-api. Requires apps/cai-orchestrator installed in the active Python env.\n"

install-dev:
	$(PYTHON) -m pip install -e packages/platform-contracts
	$(PYTHON) -m pip install -e packages/platform-core
	$(PYTHON) -m pip install -e packages/platform-adapters
	$(PYTHON) -m pip install -e packages/platform-backends
	$(PYTHON) -m pip install -e 'apps/platform-api[test]'
	$(PYTHON) -m pip install -e 'apps/cai-orchestrator[test]'

build:
	docker compose build platform-api

up:
	docker compose up -d platform-api

down:
	docker compose down

test:
	$(PYTEST) tests

test-apps:
	$(PYTEST) tests/apps

api-dev:
	$(PYTHON) -m platform_api

health:
	$(PYTHON) -c "import json, urllib.request; print(json.dumps(json.loads(urllib.request.urlopen('$(PLATFORM_API_BASE_URL)/health').read().decode()), indent=2, sort_keys=True))"

demo-watchguard:
	PLATFORM_API_BASE_URL='$(PLATFORM_API_BASE_URL)' $(PYTHON) -m cai_orchestrator run-watchguard --title "WatchGuard demo case" --summary "Run the minimal WatchGuard demo slice." --payload-file '$(DEMO_WATCHGUARD_PAYLOAD)'

demo-phishing-email:
	PLATFORM_API_BASE_URL='$(PLATFORM_API_BASE_URL)' $(PYTHON) -m cai_orchestrator run-phishing-email-basic-assessment --title "Phishing email demo case" --summary "Run the phishing email basic assessment slice." --payload-file '$(DEMO_PHISHING_EMAIL_PAYLOAD)'
