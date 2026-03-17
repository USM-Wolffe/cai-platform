# platform-api

Purpose:
- Current platform-facing app boundary for cases, artifacts, runs, observations, queries, and approvals.

Owns:
- App composition, thin FastAPI routes, app-local in-memory runtime wiring, and the current deterministic HTTP surface for the platform.

Must not own:
- Core domain rules, backend implementation logic, or CAI orchestration behavior.
- Real persistence engines, background jobs, authentication stacks, or old `cai-project` service topology.

Relation:
- Depends on `platform-core` and `platform-contracts`.
- Should expose platform services without becoming the place where domain truth is invented.

Implemented now:
- `platform_api.app` for app creation and the thin runtime entrypoint
- `platform_api.routes.health`
- `platform_api.routes.cases`
- `platform_api.routes.runs`
- `platform_api.routes.queries`
- `platform_api.routes.artifacts`
- `platform_api.runtime.memory`
- `platform_api.runtime.wiring`
- `platform_api.errors`
- `platform_api.schemas`

Current endpoint surface:
- `GET /health`
- `POST /cases`
- `GET /cases/{case_id}`
- `POST /cases/{case_id}/artifacts/input`
- `POST /runs`
- `GET /runs/{run_id}`
- `POST /runs/{run_id}/observations/watchguard-ingest-workspace-zip`
- `POST /runs/{run_id}/observations/watchguard-normalize`
- `POST /runs/{run_id}/observations/watchguard-filter-denied`
- `POST /runs/{run_id}/observations/watchguard-analytics-basic`
- `POST /runs/{run_id}/observations/watchguard-top-talkers-basic`
- `POST /runs/{run_id}/observations/phishing-email-basic-assessment`
- `POST /runs/{run_id}/queries/watchguard-guarded-filtered-rows`
- `GET /runs/{run_id}/status`
- `GET /runs/{run_id}/artifacts`
- `GET /artifacts/{artifact_id}/content`

Current WatchGuard input shape:
- The preferred realistic input path keeps the API transport stable and sends a JSON payload that wraps a small WatchGuard traffic CSV export slice, for example `{"log_type": "traffic", "csv_rows": ["..."]}`.
- The older semantic `{"records": [...]}` payload remains only as a secondary compatibility path for tests and transition safety.

Current phishing email input shape:
- The phishing email slice keeps the same attach-artifact transport and expects a JSON payload shaped like:
  `{"subject": "...", "sender": {"email": "...", "display_name": "..."}, "reply_to": null | {"email": "...", "display_name": "..."}, "urls": ["..."], "text": "...", "attachments": [{"filename": "...", "content_type": "..."}]}`
- `reply_to` may be `null`, while `urls` and `attachments` stay explicit lists even when empty.

Still intentionally absent:
- CAI orchestration
- real databases or object stores
- generic SQL or free-form query execution
- auth/authz
- background workers
- old `collector` / `analyzer` / `data-runner` style services

Operational note:
- The current readable-content contract is artifact-id based, not old path based.
- The current guarded custom query contract is one explicit filtered-row query shape over normalized WatchGuard traffic rows. It requires an explicit approval decision and does not expose raw SQL or a generic query router.
- For this runtime, input artifact content is the attached payload and derived artifact content is the backend-emitted payload stored alongside the artifact record.
- If a future artifact exists without stored readable content, `GET /artifacts/{artifact_id}/content` should fail clearly rather than inventing content.
- All observation endpoints share a single `ExecuteObservationRequest` shape (`requested_by`, optional `input_artifact_id`). Backend-specific request fields are added as dedicated schemas when a backend actually requires them.
- Backend execution is dispatched through `AppRuntime.execute_observation()`. Routes pass `backend_id` and `operation_kind` as identifiers; they do not import or call backend execution functions directly. Adding a new backend requires registering its executor in `AppRuntime`, not modifying routes.

Runtime:
- Run locally:
  `python3 -m platform_api`
- Console entrypoint:
  `platform-api`
- Environment variables:
  - `PLATFORM_API_HOST` defaults to `0.0.0.0`
  - `PLATFORM_API_PORT` defaults to `8000`
- This is the only compose-managed and containerized app in this pass.
- The root `compose.yml` runs only this service, and the current app-local runtime registers both `watchguard_logs` and `phishing_email` in process.
- Quick health check:
  `curl -i http://localhost:8000/health`
  or
  `make health`

Packaging note:
- A minimal `pyproject.toml` is included so the app can be installed and tested independently with FastAPI and local in-memory runtime wiring only.
