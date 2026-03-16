# platform-backends

Purpose:
- Deterministic backend implementations that satisfy the shared backend and run contracts.

Owns:
- Concrete backend execution packages and backend conformance helpers.
- The current `platform_backends.watchguard_logs` backend that exposes one descriptor, multiple predefined observation execution paths, and one guarded custom query path.
- The current `platform_backends.phishing_email` backend that exposes one descriptor and one predefined phishing assessment observation.

Must not own:
- Canonical case semantics, CAI prompt/runtime code, or vendor-independent core contracts.
- HTTP/process models, hidden persistence, old service topology recreation, or generalized plugin systems.

Relation:
- Depends on `platform-contracts` and `platform-core`.
- Uses adapters without redefining the platform around one vendor.

Implemented now:
- `platform_backends.watchguard_logs.descriptor`
- `platform_backends.watchguard_logs.execute`
- `platform_backends.watchguard_logs.errors`
- `platform_backends.watchguard_logs.models`
- `platform_backends.phishing_email.descriptor`
- `platform_backends.phishing_email.execute`
- `platform_backends.phishing_email.errors`
- `platform_backends.phishing_email.models`
- Four predefined observation paths in `platform_backends.watchguard_logs`:
  - `watchguard_logs.normalize_and_summarize`
  - `watchguard_logs.filter_denied_events`
  - `watchguard_logs.analytics_bundle_basic`
  - `watchguard_logs.top_talkers_basic`
- One predefined observation path in `platform_backends.phishing_email`:
  - `phishing_email.basic_assessment`
- One guarded custom query path in `platform_backends.watchguard_logs`:
  - `watchguard_logs.guarded_filtered_rows`
- The backend descriptor now also declares practical operational capabilities for the migrated slices:
  - `get_run_status`
  - `list_run_artifacts`
  - `read_artifact_content`
- The phishing email slice is intentionally narrow:
  - one explicit structured input artifact shape
  - one local deterministic ruleset
  - one `analysis_output` artifact with a structured summary
  - no guarded query path, no internet lookups, and no generic rule-engine framework
- The guarded custom query slice is intentionally narrow:
  - allowlisted fields only: `src_ip`, `dst_ip`, `action`, `protocol`, `policy`
  - allowlisted operators only: `eq`, `in`
  - explicit result limit with a strict max
  - explicit approval required through the platform contracts/core layer
- The backend now consumes a realistic migrated WatchGuard traffic CSV ingest slice through the adapter, while still tolerating the older semantic records payload as a secondary compatibility path.

Still intentionally absent:
- executable services
- transport handlers
- old `collector` / `analyzer` / `data-runner` replacement layers
- storage engines
- generic SQL, generic drilldown routers, and raw query consoles

Packaging note:
- A minimal `pyproject.toml` is included so backend code can be installed and tested independently while depending on `cai-platform-core`, `cai-platform-contracts`, and `cai-platform-adapters`.
