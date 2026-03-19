import pytest

from platform_contracts import BackendCapabilityName, WorkflowType

from platform_core import NotFoundError, UnsupportedBackendError, create_case, create_run_for_case

from .support import InMemoryBackendRegistry, InMemoryCaseRepository, InMemoryRunRepository, RecordingAuditPort, make_backend


def test_runs_can_be_created_only_against_known_backends():
    case_repository = InMemoryCaseRepository()
    run_repository = InMemoryRunRepository()
    backend_registry = InMemoryBackendRegistry()
    audit_port = RecordingAuditPort()

    case = create_case(
        case_repository,
        client_id="test-client",
        workflow_type=WorkflowType.LOG_INVESTIGATION,
        title="Run case",
        summary="Case for run creation.",
    )

    with pytest.raises(NotFoundError):
        create_run_for_case(
            case_repository,
            run_repository,
            backend_registry,
            audit_port,
            case_id=case.case_id,
            backend_id="missing_backend",
        )


def test_unsupported_workflow_backend_combinations_fail_clearly():
    case_repository = InMemoryCaseRepository()
    run_repository = InMemoryRunRepository()
    backend_registry = InMemoryBackendRegistry()
    audit_port = RecordingAuditPort()

    case = create_case(
        case_repository,
        client_id="test-client",
        workflow_type=WorkflowType.LOG_INVESTIGATION,
        title="Mismatch case",
        summary="Case for workflow mismatch.",
    )
    backend_registry.add_backend(
        make_backend(
            backend_id="backend_sandbox_only",
            workflow_types=[WorkflowType.SANDBOX_INVESTIGATION],
            capabilities=[BackendCapabilityName.CREATE_RUN],
        )
    )

    with pytest.raises(UnsupportedBackendError):
        create_run_for_case(
            case_repository,
            run_repository,
            backend_registry,
            audit_port,
            case_id=case.case_id,
            backend_id="backend_sandbox_only",
        )
