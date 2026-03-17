"""Minimal config loading for the CAI-facing integration layer."""

from __future__ import annotations

import os
from dataclasses import dataclass


DEFAULT_PLATFORM_API_BASE_URL = "http://127.0.0.1:8000"
DEFAULT_CAI_AGENT_TYPE = "egs-analist"


@dataclass(frozen=True)
class CaiIntegrationSettings:
    """Small config object for the thin CAI integration layer."""

    platform_api_base_url: str = DEFAULT_PLATFORM_API_BASE_URL
    cai_agent_type: str = DEFAULT_CAI_AGENT_TYPE
    cai_model: str | None = None


def load_cai_integration_settings() -> CaiIntegrationSettings:
    """Load only the minimal env surface worth preserving for operator ergonomics."""
    cai_model = (os.getenv("CAI_MODEL", "") or "").strip() or None
    return CaiIntegrationSettings(
        platform_api_base_url=(os.getenv("PLATFORM_API_BASE_URL", DEFAULT_PLATFORM_API_BASE_URL) or "").strip()
        or DEFAULT_PLATFORM_API_BASE_URL,
        cai_agent_type=(os.getenv("CAI_AGENT_TYPE", DEFAULT_CAI_AGENT_TYPE) or "").strip() or DEFAULT_CAI_AGENT_TYPE,
        cai_model=cai_model,
    )
