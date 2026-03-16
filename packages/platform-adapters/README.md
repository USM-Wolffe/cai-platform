# platform-adapters

Purpose:
- Vendor and source translation layers.

Owns:
- Source-specific normalization, mapping, and translation helpers.
- The current `platform_adapters.watchguard` slice for inspecting a WatchGuard input artifact and normalizing a small WatchGuard traffic CSV export wrapper into a backend-ready shape.
- The current `platform_adapters.phishing_email` slice for validating and normalizing a structured email-like phishing assessment artifact.

Must not own:
- Canonical case state, backend lifecycle truth, or CAI-facing orchestration.
- Backend descriptors, run coordination, persistence, service processes, or old `cai-project` topology.

Relation:
- Depends on shared contracts.
- Can be used by backend implementations without turning the core into a vendor-shaped layer.

Implemented now:
- `platform_adapters.watchguard.errors`
- `platform_adapters.watchguard.types`
- `platform_adapters.watchguard.normalize`
- `platform_adapters.phishing_email.errors`
- `platform_adapters.phishing_email.types`
- `platform_adapters.phishing_email.normalize`

Still intentionally absent:
- full parser frameworks
- S3/storage assumptions
- executable services
- old WatchGuard pipeline recreation

Current WatchGuard slice notes:
- Preferred realistic input path: JSON payload containing `{"log_type": "traffic", "csv_text" | "csv_rows"}`.
- Compatibility path kept secondary for tests and transition safety: semantic `{"records": [...]}` payloads.

Current phishing email slice notes:
- Input path: JSON payload containing `subject`, `sender`, `reply_to`, `urls`, `text`, and `attachments`.
- The adapter lowercases sender/reply-to emails and domains while preserving URLs and attachment metadata for deterministic backend execution.

Packaging note:
- A minimal `pyproject.toml` is included so adapter code can be installed and tested independently while depending only on `cai-platform-contracts`.
