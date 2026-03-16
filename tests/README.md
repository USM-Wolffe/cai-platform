# Tests

Purpose:
- Keep test placement aligned with the architecture boundaries of the repo.

Structure:
- `contracts/`: shared contract invariants
- `core/`: core platform behavior
- `adapters/`: vendor/source translation tests
- `backends/`: backend conformance and backend-specific tests
- `apps/`: app-boundary tests

Rule:
- Tests should follow package boundaries, not vendor sprawl.

