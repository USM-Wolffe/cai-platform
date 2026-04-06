from platform_contracts import EntityKind, EntityRef, ObservationRequest, ObservationResult, ObservationStatus, WorkflowType

import pytest

from platform_contracts import RunStatus
from platform_core import InvalidStateError, complete_run, create_case, create_run_for_case, publish_observation_result

from .support import InMemoryBackendRegistry, InMemoryCaseRepository, InMemoryRunRepository, RecordingAuditPort, make_backend


def test_observation_result_publication_updates_case_and_run_coordination():
    case_repository = InMemoryCaseRepository()
    run_repository = InMemoryRunRepository()
    backend_registry = InMemoryBackendRegistry()
    audit_port = RecordingAuditPort()
    backend_registry.add_backend(make_backend())

    case = create_case(
        case_repository,
        client_id="test-client",
        workflow_type=WorkflowType.LOG_INVESTIGATION,
        title="Observation case",
        summary="Case for observation publication.",
    )
    run = create_run_for_case(
        case_repository,
        run_repository,
        backend_registry,
        audit_port,
        case_id=case.case_id,
        backend_id="backend_logs",
    )

    observation_request = ObservationRequest(
        case_ref=EntityRef(entity_type=EntityKind.CASE, id=case.case_id),
        backend_ref=EntityRef(entity_type=EntityKind.BACKEND, id="backend_logs"),
        run_ref=EntityRef(entity_type=EntityKind.RUN, id=run.run_id),
        operation_kind="execute_predefined_query",
        requested_by="tester",
    )
    observation_result = ObservationResult(
        observation_ref=EntityRef(entity_type=EntityKind.OBSERVATION_REQUEST, id=observation_request.observation_id),
        status=ObservationStatus.SUCCEEDED,
        output_artifact_refs=[EntityRef(entity_type=EntityKind.ARTIFACT, id="artifact_output")],
        structured_summary={"summary": "One result artifact published."},
        raw_result_ref=EntityRef(entity_type=EntityKind.ARTIFACT, id="artifact_raw"),
    )

    updated_case, updated_run = publish_observation_result(
        case_repository,
        run_repository,
        audit_port,
        observation_request=observation_request,
        observation_result=observation_result,
    )

    assert updated_run.status.value == "running"
    assert updated_run.observation_refs[0].id == observation_request.observation_id
    assert {ref.id for ref in updated_run.output_artifact_refs} == {"artifact_output", "artifact_raw"}
    assert {ref.id for ref in updated_case.artifact_refs} == {"artifact_output", "artifact_raw"}
    assert updated_case.timeline[-1].kind == "observation_result_published"
    assert len(audit_port.timeline_events) == 2


def test_complete_run_marks_active_run_completed_and_is_idempotent():
    case_repository = InMemoryCaseRepository()
    run_repository = InMemoryRunRepository()
    backend_registry = InMemoryBackendRegistry()
    audit_port = RecordingAuditPort()
    backend_registry.add_backend(make_backend())

    case = create_case(
        case_repository,
        client_id="test-client",
        workflow_type=WorkflowType.LOG_INVESTIGATION,
        title="Completion case",
        summary="Case for explicit run completion.",
    )
    run = create_run_for_case(
        case_repository,
        run_repository,
        backend_registry,
        audit_port,
        case_id=case.case_id,
        backend_id="backend_logs",
    )

    completed_case, completed_run = complete_run(
        case_repository,
        run_repository,
        audit_port,
        run_id=run.run_id,
        requested_by="tester",
        reason="Manual triage finished.",
    )
    second_case, second_run = complete_run(
        case_repository,
        run_repository,
        audit_port,
        run_id=run.run_id,
        requested_by="tester",
        reason="Manual triage finished.",
    )

    assert completed_run.status == RunStatus.COMPLETED
    assert completed_case.timeline[-1].kind == "run_completed"
    assert "Manual triage finished." in completed_case.timeline[-1].summary
    assert second_run.status == RunStatus.COMPLETED
    assert second_case.case_id == completed_case.case_id


def test_complete_run_rejects_terminal_non_completed_runs():
    case_repository = InMemoryCaseRepository()
    run_repository = InMemoryRunRepository()
    backend_registry = InMemoryBackendRegistry()
    audit_port = RecordingAuditPort()
    backend_registry.add_backend(make_backend())

    case = create_case(
        case_repository,
        client_id="test-client",
        workflow_type=WorkflowType.LOG_INVESTIGATION,
        title="Cancelled case",
        summary="Case for invalid completion transition.",
    )
    run = create_run_for_case(
        case_repository,
        run_repository,
        backend_registry,
        audit_port,
        case_id=case.case_id,
        backend_id="backend_logs",
    )
    run_repository.save_run(run.model_copy(update={"status": RunStatus.CANCELLED}))

    with pytest.raises(InvalidStateError):
        complete_run(
            case_repository,
            run_repository,
            audit_port,
            run_id=run.run_id,
            requested_by="tester",
        )
