import pytest
from pydantic import ValidationError

from platform_contracts import (
    EntityKind,
    EntityRef,
    ObservationRequest,
    ObservationResult,
    ObservationStatus,
)


def test_observation_request_minimum_valid_model_construction():
    request = ObservationRequest(
        case_ref=EntityRef(entity_type=EntityKind.CASE, id="case_test"),
        backend_ref=EntityRef(entity_type=EntityKind.BACKEND, id="backend_test"),
        run_ref=EntityRef(entity_type=EntityKind.RUN, id="run_test"),
        operation_kind="read_artifact",
        requested_by="tester",
    )

    assert request.observation_id.startswith("observation_")
    assert request.operation_kind == "read_artifact"


def test_observation_result_distinguishes_no_findings_from_execution_failure():
    no_findings = ObservationResult(
        observation_ref=EntityRef(entity_type=EntityKind.OBSERVATION_REQUEST, id="observation_test"),
        status=ObservationStatus.SUCCEEDED_NO_FINDINGS,
        structured_summary={"finding_count": 0, "summary": "No findings."},
    )
    assert no_findings.observation_result_id.startswith("observation_result_")
    assert no_findings.status == ObservationStatus.SUCCEEDED_NO_FINDINGS
    assert no_findings.errors == []

    failed = ObservationResult(
        observation_ref=EntityRef(entity_type=EntityKind.OBSERVATION_REQUEST, id="observation_test"),
        status=ObservationStatus.FAILED,
        structured_summary={"summary": "Execution failed."},
        errors=["backend timeout"],
    )
    assert failed.status == ObservationStatus.FAILED
    assert failed.errors == ["backend timeout"]

    with pytest.raises(ValidationError):
        ObservationResult(
            observation_ref=EntityRef(entity_type=EntityKind.OBSERVATION_REQUEST, id="observation_test"),
            status=ObservationStatus.FAILED,
            structured_summary={"summary": "Execution failed."},
        )


def test_successful_observation_result_rejects_execution_errors():
    with pytest.raises(ValidationError):
        ObservationResult(
            observation_ref=EntityRef(entity_type=EntityKind.OBSERVATION_REQUEST, id="observation_test"),
            status=ObservationStatus.SUCCEEDED,
            structured_summary={"summary": "Execution succeeded."},
            errors=["this should be represented as a failed result"],
        )
