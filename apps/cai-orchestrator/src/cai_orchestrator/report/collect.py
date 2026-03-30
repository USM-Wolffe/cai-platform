"""Collect report data: load case JSON and fetch artifact payloads from platform-api.

Run this while platform-api (Docker) is still running. Produces case-XXXX-report.json
which contains all the artifact content needed for offline PDF generation.
"""

from __future__ import annotations

import json
import os
from pathlib import Path

from cai_orchestrator.client import PlatformApiClient


_CASES_DIR = Path(".egs_cases")


def collect_report_data(
    case_id: str,
    platform_api_base_url: str,
) -> Path:
    """Load case state JSON, fetch all artifact payloads from platform-api, save report JSON.

    Args:
        case_id: The case ID, e.g. "case-0009e49b2476"
        platform_api_base_url: Base URL of the running platform-api instance

    Returns:
        Path to the written case-XXXX-report.json file
    """
    case_path = _CASES_DIR / f"{case_id}.json"
    if not case_path.exists():
        raise FileNotFoundError(f"Case file not found: {case_path}")

    case_state = json.loads(case_path.read_text())

    client = PlatformApiClient(base_url=platform_api_base_url)
    try:
        artifact_payloads: dict[str, object] = {}
        for evidence in case_state.get("evidence_items", []):
            for artifact_id in evidence.get("artifact_refs", []):
                if artifact_id not in artifact_payloads:
                    result = client.read_artifact_content(artifact_id=artifact_id)
                    # The API wraps the payload under "content" for ANALYSIS_OUTPUT artifacts
                    artifact_payloads[artifact_id] = result.get("content") if "content" in result else result
    finally:
        client.close()

    report_data = {**case_state, "artifact_payloads": artifact_payloads}
    out_path = _CASES_DIR / f"{case_id}-report.json"
    out_path.write_text(json.dumps(report_data, indent=2, ensure_ascii=False))
    return out_path
