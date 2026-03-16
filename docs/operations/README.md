# Operations Docs

Purpose:
- Hold local development notes, operational runbooks, and future environment guidance.

Owns:
- Practical operating guidance for humans and coding agents.

Must not own:
- Canonical architecture rules that belong in contracts or ADRs.

Relation:
- This folder stays empty of deployment code for now by design.

## Current Runtime Model
- `apps/platform-api` is the only compose-managed and containerized app in the repo today.
- The root `compose.yml` and `apps/platform-api/Dockerfile` intentionally cover only `platform-api`.
- `apps/cai-orchestrator` is intentionally host-run as a CLI/app that calls `platform-api`.
- `packages/platform-contracts`, `packages/platform-core`, `packages/platform-adapters`, and `packages/platform-backends` are libraries, not services.
- The current API runtime registers multiple deterministic backends in process: `watchguard_logs` and `phishing_email`.

## Required Prerequisites
- `git`
- Python `3.12+`
- `python3 -m pip`
- a venv-friendly Python install
- Docker Engine
- Docker Compose plugin via `docker compose`

Quick verification:
```bash
git --version
python3 --version
python3 -m pip --version
docker --version
docker compose version
```

## Optional Prerequisites
- CAI support via `python3 -m pip install -e 'apps/cai-orchestrator[cai]'` only if you want `run-cai-terminal`
- AWS CLI only for AWS-side work outside the current local stack
- MCP is not needed for the current stack

## Fresh Linux/EC2 Bootstrap
Canonical minimal bootstrap for the official runtime model:

```bash
git clone <your-repo-url> cai-platform-v2
cd cai-platform-v2

python3 -m venv .venv
. .venv/bin/activate
python3 -m pip install --upgrade pip
python3 -m pip install -e apps/cai-orchestrator
```

Optional CAI support:

```bash
python3 -m pip install -e 'apps/cai-orchestrator[cai]'
```

Notes:
- You do not need AWS CLI, MCP, or a CAI install for the baseline WatchGuard and phishing CLI smoke tests.
- You do not need to install `platform-api` into the host Python environment for the official current runtime model; the API is containerized.
- `make install-dev` remains the full contributor install, not the minimum bootstrap for a fresh host.

## Smoke Test
Copy-pasteable current smoke test:

```bash
. .venv/bin/activate

make build
make up
make health

python3 -m cai_orchestrator run-watchguard \
  --title "WatchGuard smoke case" \
  --summary "Run the baseline WatchGuard smoke test." \
  --payload-file examples/watchguard/minimal_payload.json

python3 -m cai_orchestrator run-phishing-email-basic-assessment \
  --title "Phishing smoke case" \
  --summary "Run the phishing email smoke test." \
  --payload-file examples/phishing/minimal_payload.json
```

Optional CAI terminal smoke path:

```bash
. .venv/bin/activate
set -a && . ./.env.example && set +a

python3 -m cai_orchestrator run-cai-terminal --prompt \
  "Check health, create a defensive_analysis case, attach examples/phishing/minimal_payload.json, create a run for phishing_email, execute phishing_email.basic_assessment, then show the final run."
```

Shorthands and notes:
- `make demo-watchguard` and `make demo-phishing-email` are convenience shorthands for the same host-run orchestrator pattern.
- Those targets still require `apps/cai-orchestrator` to be installed in the active Python environment first.
- `make api-dev` exists for contributor-focused local API work, but the official current operating model keeps `platform-api` on Docker/Compose.

## Environment Note
- `.env.example` is a small reference file for the current runtime surface.
- Commands do not auto-load `.env.example`; export values in your shell if you want them applied.
- `PLATFORM_API_BASE_URL` points the host-run orchestrator or CAI terminal at the current API boundary.

## Intentionally Absent
- No orchestrator service container
- No backend-specific service containers
- No database, queue, or object-store runtime
- No AWS CLI requirement for the local stack
- No MCP requirement for the local stack
- No CAI requirement unless you explicitly want the CAI terminal path
- No recreated `collector`, `analyzer`, or `data-runner` service topology
