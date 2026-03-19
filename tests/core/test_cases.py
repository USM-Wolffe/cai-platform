from platform_contracts import ArtifactKind, EntityKind, WorkflowType

from platform_core import attach_artifact_ref_to_case, create_case

from .support import InMemoryArtifactRepository, InMemoryCaseRepository, RecordingAuditPort, make_artifact


def test_case_can_be_created_through_core_service_layer():
    case_repository = InMemoryCaseRepository()

    case = create_case(
        case_repository,
        client_id="test-client",
        workflow_type=WorkflowType.LOG_INVESTIGATION,
        title="Core-created case",
        summary="Created through platform-core.",
    )

    assert case.case_id.startswith("case_")
    assert case.workflow_type == WorkflowType.LOG_INVESTIGATION
    assert case_repository.get_case(case.case_id) is not None


def test_artifact_ref_can_be_attached_explicitly():
    case_repository = InMemoryCaseRepository()
    artifact_repository = InMemoryArtifactRepository()
    audit_port = RecordingAuditPort()

    case = create_case(
        case_repository,
        client_id="test-client",
        workflow_type=WorkflowType.LOG_INVESTIGATION,
        title="Attach artifact case",
        summary="Case for artifact attachment.",
    )
    artifact = make_artifact(artifact_id="artifact_attached")
    artifact_repository.add_artifact(artifact)

    updated_case = attach_artifact_ref_to_case(
        case_repository,
        artifact_repository,
        audit_port,
        case_id=case.case_id,
        artifact_id=artifact.artifact_id,
    )

    assert updated_case.artifact_refs[0].entity_type == EntityKind.ARTIFACT
    assert updated_case.artifact_refs[0].id == artifact.artifact_id
    assert updated_case.timeline[0].kind == "artifact_attached"
    assert len(audit_port.timeline_events) == 1
    assert artifact.kind == ArtifactKind.INPUT
