# platform-contracts

Purpose:
- Shared platform schemas and normalized contract types.

Owns:
- Contract-level Python types for common values, cases, artifacts, backends, runs, observations, investigations, queries, and approvals.
- The canonical shared vocabulary that future packages must adapt to.

Must not own:
- Business orchestration logic, backend implementations, CAI integration, or transport handlers.

Relation:
- Every other package depends on this boundary.
- This is the first package that should stay stable as the repo grows.

Implemented modules:
- `platform_contracts.common`
- `platform_contracts.cases`
- `platform_contracts.artifacts`
- `platform_contracts.backends`
- `platform_contracts.runs`
- `platform_contracts.observations`
- `platform_contracts.investigations`
- `platform_contracts.queries`
- `platform_contracts.approvals`

Packaging note:
- A minimal `pyproject.toml` is included so this package can be installed and tested independently without inventing wider monorepo tooling yet.
- The package exposes a small `test` extra so the repo can install `platform-contracts` plus `pytest` with one command and run `tests/contracts` without relying on ad hoc `PYTHONPATH` changes.
