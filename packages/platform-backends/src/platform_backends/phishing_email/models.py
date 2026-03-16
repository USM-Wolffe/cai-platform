"""Small backend-local models for phishing execution outcomes."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from platform_contracts import Artifact, ObservationResult


@dataclass(frozen=True)
class PhishingEmailExecutionOutcome:
    """Normalized outcome for the phishing email predefined observation."""

    artifacts: list[Artifact]
    observation_result: ObservationResult


@dataclass(frozen=True)
class PhishingTriggeredRule:
    """One deterministic phishing rule trigger."""

    rule_id: str
    category: str
    weight: int
    message: str
    evidence: dict[str, Any]


@dataclass(frozen=True)
class SuspiciousUrlRecord:
    """One suspicious URL and the reasons it was flagged."""

    url: str
    reasons: tuple[str, ...]
