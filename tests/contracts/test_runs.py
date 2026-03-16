import pytest
from pydantic import ValidationError

from platform_contracts import EntityKind, EntityRef, Run, RunStatus


def test_run_minimum_valid_model_construction():
    run = Run(
        backend_ref=EntityRef(entity_type=EntityKind.BACKEND, id="backend_test"),
        status=RunStatus.CREATED,
        scope={"tenant": "example"},
    )

    assert run.run_id.startswith("run_")
    assert run.status == RunStatus.CREATED
    assert run.backend_ref.entity_type == EntityKind.BACKEND


def test_run_status_distinguishes_success_and_failure_lifecycle():
    assert RunStatus.COMPLETED != RunStatus.FAILED
    assert RunStatus.RUNNING != RunStatus.BLOCKED


def test_failed_run_requires_error_summary():
    with pytest.raises(ValidationError):
        Run(
            backend_ref=EntityRef(entity_type=EntityKind.BACKEND, id="backend_test"),
            status=RunStatus.FAILED,
        )


def test_completed_run_rejects_error_summary():
    with pytest.raises(ValidationError):
        Run(
            backend_ref=EntityRef(entity_type=EntityKind.BACKEND, id="backend_test"),
            status=RunStatus.COMPLETED,
            error_summary="should not exist on successful completion",
        )
