from platform_contracts import (
    Artifact,
    ArtifactKind,
    Case,
    CaseStatus,
    DecisionRecord,
    EntityKind,
    EntityRef,
    TimelineEvent,
    WorkflowType,
)


def test_case_minimum_valid_model_construction():
    artifact = Artifact(
        kind=ArtifactKind.INPUT,
        format="json",
        storage_ref="object://bucket/input.json",
        content_hash="sha256:abc123",
    )

    case = Case(
        client_id="egs-client-acme",
        workflow_type=WorkflowType.LOG_INVESTIGATION,
        status=CaseStatus.OPEN,
        title="Suspicious traffic investigation",
        summary="Initial case created from log triage.",
        artifact_refs=[EntityRef(entity_type=EntityKind.ARTIFACT, id=artifact.artifact_id)],
        timeline=[TimelineEvent(kind="created", summary="Case created")],
        decision_log=[DecisionRecord(summary="Start investigation", rationale="Minimum viable starting point")],
    )

    assert case.case_id.startswith("case_")
    assert case.workflow_type == WorkflowType.LOG_INVESTIGATION
    assert case.artifact_refs[0].entity_type == EntityKind.ARTIFACT
    assert case.timeline[0].event_id.startswith("evt_")
    assert case.decision_log[0].decision_id.startswith("decision_")

