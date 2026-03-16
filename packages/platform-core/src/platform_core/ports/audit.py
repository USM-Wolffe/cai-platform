"""Audit boundary for timeline and decision append operations."""

from __future__ import annotations

from typing import Protocol, runtime_checkable

from platform_contracts import DecisionRecord, TimelineEvent


@runtime_checkable
class AuditPort(Protocol):
    """Write-only audit boundary for case-level logs."""

    def append_timeline_event(self, *, case_id: str, event: TimelineEvent) -> None:
        """Record a timeline event for a case."""

    def append_decision_record(self, *, case_id: str, decision: DecisionRecord) -> None:
        """Record a decision entry for a case."""
