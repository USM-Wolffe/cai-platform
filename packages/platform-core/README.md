# platform-core

Purpose:
- Orchestration-neutral platform logic and ports.

Owns:
- Core ports, coordination services, and normalized core errors that operate on `platform-contracts`.
- Case creation, explicit artifact attachment, run creation against registered backends, deterministic timeline/decision appends, approval-gating checks, and minimal observation-result publication.

Must not own:
- Vendor parsing, backend protocol clients, CAI runtime code, or transport-specific handlers.
- Persistence engines, API handlers, HTTP models, CLI commands, or workflow-engine behavior.

Relation:
- Depends on `platform-contracts`.
- Is consumed by backends and apps through explicit boundaries.

Implemented modules:
- `platform_core.ports`
- `platform_core.services`
- `platform_core.cases`
- `platform_core.runs`
- `platform_core.artifacts`
- `platform_core.queries`
- `platform_core.approvals`
- `platform_core.audit`
- `platform_core.errors`

Packaging note:
- A minimal `pyproject.toml` is included so `platform-core` can be installed and tested independently, while still depending only on the already-separated `cai-platform-contracts` package.
