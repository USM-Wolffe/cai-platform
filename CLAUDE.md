# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Commands

```bash
# Install all packages in editable mode (run once in a venv)
make install-dev

# Start/stop platform-api and platform-ui in Docker Compose
make build
make up
make down

# Run platform-api locally (no Docker)
make api-dev

# Run the full test suite
make test

# Run only app-layer tests
make test-apps

# Run a single test file
python3 -m pytest tests/backends/test_watchguard_logs_backend.py

# Run a single test by name
python3 -m pytest tests/backends/test_watchguard_logs_backend.py -k "test_normalize"

# Demo runs (requires platform-api running)
make demo-watchguard
make demo-phishing-email

# CAI terminal session (requires [cai] extras installed and platform-api running)
python3 -m cai_orchestrator run-cai-terminal

# Upload WatchGuard workspace ZIP to S3
make upload-workspace ZIP=path/to/file.zip WORKSPACE=<workspace_id>
```

## Architecture

The platform follows a strict layered dependency order:

```
contracts → core → adapters → backends → platform-api
                                       → cai-orchestrator (host-run, optional)
```

**`packages/platform-contracts`** — Shared Pydantic schemas only. No logic. Referenced by all other layers.

**`packages/platform-core`** — Orchestration-neutral business logic (case/run/artifact/approval management). Defines ports (abstract interfaces) that the API layer implements.

**`packages/platform-adapters`** — Vendor input normalization. Translates raw WatchGuard CSV rows or phishing email payloads into normalized contract types. No backend logic here.

**`packages/platform-backends`** — Deterministic backend implementations. Two backends exist: `watchguard_logs` and `phishing_email`. Each backend exposes predefined observations and optional guarded custom queries. Backends depend on contracts, core, and adapters; they do not depend on the apps.

**`apps/platform-api`** — FastAPI HTTP server. Registers both backends in-process. Routes map directly to backend operations. Uses PostgreSQL automatically when `DATABASE_URL` is defined, otherwise in-memory repositories for local dev/tests. Runs containerized on port 8000.

**`apps/cai-orchestrator`** — Host-run CLI app and CAI integration layer. Contains:
- `client.py` — Thin `httpx`-based HTTP client for platform-api
- `cai_tools.py` — Wraps the client as CAI-callable tool functions
- `cai_terminal.py` — Builds CAI `Agent` objects and runs interactive terminal sessions
- `app.py` — CLI entry point with `run-watchguard`, `run-phishing-email-*`, `run-cai-terminal`, `run-phishing-monitor`, `run-ddos-investigate`, `report-collect`, and `report-generate`
- `phishing_agents.py` — Multi-agent phishing investigator pipeline
- `ddos_agents.py` — Hybrid DDoS investigation pipeline over staged WatchGuard workspaces
- `imap_monitor.py` — IMAP polling loop that feeds forwarded emails into the phishing pipeline

## Key Design Decisions

**CAI is optional.** The orchestrator has a `[cai]` extras group. Without it, the HTTP client and CLI flows work standalone. CAI agents are only built when the `cai-framework` package is present.

**Approval gating on custom queries.** The `watchguard-guarded-filtered-rows` and `watchguard-duckdb-workspace-query` routes require an approval step before executing arbitrary query text. The `execute_watchguard_guarded_custom_query()` tool in `cai_tools.py` handles the approval handshake.

**S3 workspace analytics pipeline.** Large WatchGuard log sets (ZIP files with 1.5–10M rows) are uploaded to S3 via `make upload-workspace`, then accessed in-place via DuckDB's `httpfs` extension. The orchestrator's `find_latest_workspace_upload()` and `duckdb_workspace_analytics()` tools drive this path.

**No plugin system.** Adding a new backend requires explicit wiring: define its operations in `platform-backends`, register it in `platform-api`, add HTTP routes, add client methods in `client.py`, wrap as tools in `cai_tools.py`, and expose them in `cai_terminal.py`.

**Tests are boundary-aligned.** `tests/contracts/`, `tests/core/`, `tests/adapters/`, `tests/backends/`, and `tests/apps/` mirror the package structure. Each layer tests only its own surface.

## Environment Variables

| Variable | Default | Purpose |
|---|---|---|
| `PLATFORM_API_BASE_URL` | `http://127.0.0.1:8000` | Where cai-orchestrator finds platform-api |
| `CAI_AGENT_TYPE` | `egs-analist` | Which agent to build (`egs-analist`, `platform_investigation_agent`, `phishing_investigator`, `ddos_investigator`) |
| `CAI_MODEL` | (none) | LiteLLM model string override; supports `bedrock/...` prefixes |
| `WATCHGUARD_S3_BUCKET` | `egslatam-cai-dev` | S3 bucket for workspace ZIP uploads |
| `WATCHGUARD_S3_REGION` | `us-east-2` | AWS region for that bucket |

Copy `.env.example` to `.env` and populate before running the orchestrator.
