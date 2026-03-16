# cai-platform-v2

`cai-platform-v2` is the new v2 investigation platform. It is a separate project from `cai-project` and starts from explicit contracts and package boundaries instead of vendor-shaped runtime code.

CAI is an external dependency in this repo. It is not vendored source here and should only appear through the CAI-facing orchestration app under `apps/cai-orchestrator/`.

## Boundary Summary
- `packages/platform-contracts`: shared schemas and normalized contract types
- `packages/platform-core`: orchestration-neutral platform logic and ports
- `packages/platform-adapters`: vendor and source translation layers
- `packages/platform-backends`: deterministic backend implementations
- `apps/platform-api`: first platform-facing app boundary
- `apps/cai-orchestrator`: CAI-facing orchestration app
- `tests/`: boundary-aligned test layout
- `docs/`: canonical human-readable architecture and contract documentation

## Source Of Truth
- Start with [docs/README.md](docs/README.md).
- Contracts and repo shape follow the shared handoff decisions stored outside this repo.
- Package READMEs explain what each area owns and what it must not own.
- Local runtime and operating notes live in [docs/operations/README.md](docs/operations/README.md).

## Current Baseline
- `packages/platform-contracts` defines the shared platform vocabulary.
- `packages/platform-core` provides orchestration-neutral coordination logic and ports.
- `packages/platform-adapters` and `packages/platform-backends` now contain both the migrated `watchguard_logs` slice and the brand-new `phishing_email` slice.
- The `watchguard_logs` backend now exposes four predefined observations:
  - `watchguard_logs.normalize_and_summarize`
  - `watchguard_logs.filter_denied_events`
  - `watchguard_logs.analytics_bundle_basic`
  - `watchguard_logs.top_talkers_basic`
- The `phishing_email` backend now exposes one predefined observation:
  - `phishing_email.basic_assessment`
- The backend now also exposes one guarded custom query path:
  - `watchguard_logs.guarded_filtered_rows`
- `apps/platform-api` exposes the current deterministic HTTP surface.
- `apps/cai-orchestrator` provides the current thin CAI-facing orchestration flow over `platform-api`.
- Local runtime support is intentionally minimal: one runnable API process, one host-run orchestrator CLI, one API container image, one compose file, and a small root `Makefile`.
- The current operational surface now includes run-status reads, run-artifact listing, artifact-id-based content reads, and one guarded custom query path for the migrated WatchGuard slices.

## Current Runtime Model
- `apps/platform-api` is the only compose-managed and containerized app in the repo today.
- `apps/cai-orchestrator` is intentionally host-run as a CLI/app that talks to `platform-api`; it is not a compose-managed service.
- `packages/platform-contracts`, `packages/platform-core`, `packages/platform-adapters`, and `packages/platform-backends` are installable libraries, not standalone services.
- Multiple backends currently run behind the same in-process API runtime: `watchguard_logs` and `phishing_email` are both registered inside `platform-api`.
- Use [docs/operations/README.md](docs/operations/README.md) as the short canonical reference for local runtime and operator commands.

## Prerequisites
Required for the current official operating model:
- `git`
- Python `3.12+`
- `pip` plus a venv-friendly Python install
- Docker Engine
- Docker Compose plugin via `docker compose`

Optional for the current stack:
- CAI support via `apps/cai-orchestrator[cai]` only if you want `run-cai-terminal`
- AWS CLI only if you separately need AWS-side operations outside this local stack
- MCP is not required

Quick checks on a fresh Linux/EC2 host:
```bash
git --version
python3 --version
python3 -m pip --version
docker --version
docker compose version
```

## Bootstrap On A Fresh Linux/EC2 Host
Use this as the canonical minimal bootstrap for the official current runtime model:

```bash
git clone <your-repo-url> cai-platform-v2
cd cai-platform-v2

python3 -m venv .venv
. .venv/bin/activate
python3 -m pip install --upgrade pip

# Required for the host-run orchestrator CLI
python3 -m pip install -e apps/cai-orchestrator

# Optional: only if you want CAI terminal integration
# python3 -m pip install -e 'apps/cai-orchestrator[cai]'
```

Notes:
- The official current API path uses Docker/Compose; you do not need to install `platform-api` into the host Python environment just to run the current stack.
- `make install-dev` is still useful for contributors, but it is a full repo/dev install, not the minimum smoke-test bootstrap.
- Ensure your shell user can run `docker` and `docker compose` on the host before using the API container path.

## Smoke Test
Use the checked-in demo payloads at [examples/watchguard/minimal_payload.json](/home/seba/work/proyects/cai-platform-v2/examples/watchguard/minimal_payload.json) and [examples/phishing/minimal_payload.json](/home/seba/work/proyects/cai-platform-v2/examples/phishing/minimal_payload.json).

Canonical end-to-end smoke test:

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

Convenience note:
- `make demo-watchguard` and `make demo-phishing-email` are the only Makefile smoke/demo shorthands.
- They still use the host-run orchestrator, so install `apps/cai-orchestrator` in the active Python environment first.
- `run-watchguard` remains the stable baseline CLI shorthand for the WatchGuard normalize/summarize slice, while the API route remains `POST /runs/{run_id}/observations/watchguard-normalize`.

Expected smoke-test result at a high level:
- the orchestrator prints structured JSON
- WatchGuard returns `case.workflow_type = log_investigation` and `run.backend_ref.id = watchguard_logs`
- phishing returns `case.workflow_type = defensive_analysis` and `run.backend_ref.id = phishing_email`
- both flows return deterministic observation results and at least one output artifact

## Optional CAI Terminal Integration
CAI is optional in the current stack. Install it only if you want the CAI terminal path through `apps/cai-orchestrator`.

Useful env names carried forward for operator ergonomics:
- `PLATFORM_API_BASE_URL`
- `CAI_AGENT_TYPE`
- `CAI_MODEL`

Supported agent type in v2:
- `platform_investigation_agent`

Optional CAI smoke path:

```bash
. .venv/bin/activate
python3 -m pip install -e 'apps/cai-orchestrator[cai]'
set -a && . ./.env.example && set +a

python3 -m cai_orchestrator run-cai-terminal --prompt \
  "Check health, create a defensive_analysis case, attach examples/phishing/minimal_payload.json, create a run for phishing_email, execute phishing_email.basic_assessment, then show the final run."
```

Note:
- `.env.example` is a minimal compatibility reference, not an auto-loaded dotenv file in this pass.
- You can also skip exporting env vars and pass `--api-base-url` directly to `run-cai-terminal`.

## Full Contributor Install
If you are contributing to the repo itself rather than only bootstrapping the current stack:

```bash
. .venv/bin/activate
make install-dev
make test
```

The repo still supports `make api-dev` for contributor-focused local API work, but the official current operating model keeps `platform-api` on Docker/Compose.

## Intentionally Absent
- No database
- No queues
- No S3 or object-store integration
- No AWS CLI requirement for the local stack
- No MCP requirement for the local stack
- No CAI requirement unless you explicitly want the CAI terminal path
- No old `collector`, `analyzer`, or `data-runner` services
- No CAI service container
- No production deployment stack
