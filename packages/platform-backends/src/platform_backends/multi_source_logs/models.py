"""Data models for the multi_source_logs backend."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from platform_contracts import Artifact, ObservationResult


@dataclass(frozen=True)
class MultiSourceLogsExecutionOutcome:
    """Return value from execute_predefined_observation."""

    artifacts: list[Artifact]
    observation_result: ObservationResult


@dataclass(frozen=True)
class NormalizedLogRecord:
    """One row in the unified multi-source schema."""

    timestamp: str              # ISO-8601
    event_type: str             # 'failed_logon'|'logon'|'logoff'|'special_privilege_use'|
                                # 'explicit_credential_use'|'sudo_use'|'su_use'|
                                # 'account_locked'|'dns_query'|'http_request'|'unknown'
    source_host: str | None
    dest_host: str | None
    source_ip: str | None
    dest_ip: str | None
    user: str | None
    action: str | None
    status: str | None
    process_name: str | None
    details_json: str           # JSON string of residual/source-specific fields


@dataclass
class MultiSourceDetectionFinding:
    """One detection finding produced by a detection operation."""

    rule_id: str
    category: str   # 'brute_force'|'spray'|'account_locked'|'lateral_movement'|
                    # 'scanning'|'priv_esc'|'dns_anomaly'|'dns_beaconing'|'multi_stage'
    severity: str   # 'high'|'medium'|'low'
    count: int
    evidence: dict[str, Any] = field(default_factory=dict)
    summary: str = ""
