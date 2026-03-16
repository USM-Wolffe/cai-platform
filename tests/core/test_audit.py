from platform_contracts import EntityKind, EntityRef, WorkflowType

from platform_core import append_timeline_event, create_case, record_decision

from .support import InMemoryCaseRepository, RecordingAuditPort


def test_timeline_and_decision_log_appends_work_deterministically():
    case_repository = InMemoryCaseRepository()
    audit_port = RecordingAuditPort()

    case = create_case(
        case_repository,
        workflow_type=WorkflowType.LOG_INVESTIGATION,
        title="Audit case",
        summary="Case for audit append testing.",
    )
    related_ref = EntityRef(entity_type=EntityKind.ARTIFACT, id="artifact_audit")

    case = append_timeline_event(
        case_repository,
        audit_port,
        case_id=case.case_id,
        kind="triage_started",
        summary="Started triage.",
        related_refs=[related_ref],
    )
    case = record_decision(
        case_repository,
        audit_port,
        case_id=case.case_id,
        summary="Continue investigation",
        rationale="Suspicious evidence remains in scope.",
        related_refs=[related_ref],
    )

    assert len(case.timeline) == 1
    assert case.timeline[0].kind == "triage_started"
    assert case.timeline[0].related_refs[0].id == "artifact_audit"
    assert len(case.decision_log) == 1
    assert case.decision_log[0].summary == "Continue investigation"
    assert len(audit_port.timeline_events) == 1
    assert len(audit_port.decision_records) == 1
