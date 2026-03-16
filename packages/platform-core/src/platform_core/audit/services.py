"""Deterministic timeline and decision append helpers."""

from __future__ import annotations

from platform_contracts import Case, DecisionRecord, TimelineEvent
from platform_contracts.common import utc_now
from platform_contracts.common.refs import EntityRef

from platform_core.errors import NotFoundError
from platform_core.ports import AuditPort, CaseRepository


def append_timeline_event_to_case(
    case: Case,
    *,
    kind: str,
    summary: str,
    related_refs: list[EntityRef] | None = None,
) -> tuple[Case, TimelineEvent]:
    """Return a copy of the case with one appended timeline event."""
    event = TimelineEvent(kind=kind, summary=summary, related_refs=related_refs or [])
    updated_case = case.model_copy(
        update={
            "timeline": [*case.timeline, event],
            "updated_at": utc_now(),
        }
    )
    return updated_case, event


def append_timeline_event(
    case_repository: CaseRepository,
    audit_port: AuditPort,
    *,
    case_id: str,
    kind: str,
    summary: str,
    related_refs: list[EntityRef] | None = None,
) -> Case:
    """Append one timeline event to a stored case and emit it through the audit port."""
    case = case_repository.get_case(case_id)
    if case is None:
        raise NotFoundError(f"case '{case_id}' was not found")
    updated_case, event = append_timeline_event_to_case(
        case,
        kind=kind,
        summary=summary,
        related_refs=related_refs,
    )
    saved_case = case_repository.save_case(updated_case)
    audit_port.append_timeline_event(case_id=saved_case.case_id, event=event)
    return saved_case


def record_case_decision(
    case: Case,
    *,
    summary: str,
    rationale: str,
    related_refs: list[EntityRef] | None = None,
) -> tuple[Case, DecisionRecord]:
    """Return a copy of the case with one appended decision record."""
    decision = DecisionRecord(summary=summary, rationale=rationale, related_refs=related_refs or [])
    updated_case = case.model_copy(
        update={
            "decision_log": [*case.decision_log, decision],
            "updated_at": utc_now(),
        }
    )
    return updated_case, decision


def record_decision(
    case_repository: CaseRepository,
    audit_port: AuditPort,
    *,
    case_id: str,
    summary: str,
    rationale: str,
    related_refs: list[EntityRef] | None = None,
) -> Case:
    """Append one decision record to a stored case and emit it through the audit port."""
    case = case_repository.get_case(case_id)
    if case is None:
        raise NotFoundError(f"case '{case_id}' was not found")
    updated_case, decision = record_case_decision(
        case,
        summary=summary,
        rationale=rationale,
        related_refs=related_refs,
    )
    saved_case = case_repository.save_case(updated_case)
    audit_port.append_decision_record(case_id=saved_case.case_id, decision=decision)
    return saved_case
