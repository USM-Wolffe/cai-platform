import pytest
from pydantic import ValidationError

from platform_contracts import (
    ApprovalScopeKind,
    ApprovalStatus,
    ArtifactKind,
    EntityKind,
    EntityRef,
    QueryDefinition,
    QueryMode,
    QueryRequest,
    QueryResultContract,
    RiskClass,
)


def test_query_definition_minimum_valid_model_construction():
    query_definition = QueryDefinition(
        query_mode=QueryMode.PREDEFINED,
        query_class="timeline_slice",
        backend_scope="log_backend",
        parameter_schema={"window": {"type": "string"}},
        result_contract=QueryResultContract(
            summary_type="timeline_summary",
            artifact_outputs=[ArtifactKind.QUERY_RESULT],
        ),
        risk_class=RiskClass.LOW,
    )

    assert query_definition.query_definition_id.startswith("querydef_")
    assert query_definition.query_mode == QueryMode.PREDEFINED


def test_query_definition_can_optionally_bind_to_investigation_definition():
    query_definition = QueryDefinition(
        investigation_definition_ref=EntityRef(
            entity_type=EntityKind.INVESTIGATION_DEFINITION,
            id="investigation_test",
        ),
        query_mode=QueryMode.PREDEFINED,
        query_class="timeline_slice",
        backend_scope="log_backend",
        result_contract=QueryResultContract(summary_type="timeline_summary"),
        risk_class=RiskClass.LOW,
    )

    assert query_definition.investigation_definition_ref is not None
    assert query_definition.investigation_definition_ref.entity_type == EntityKind.INVESTIGATION_DEFINITION


def test_query_request_distinguishes_predefined_from_custom_guarded():
    predefined = QueryRequest(
        query_definition_ref=EntityRef(entity_type=EntityKind.QUERY_DEFINITION, id="querydef_test"),
        case_ref=EntityRef(entity_type=EntityKind.CASE, id="case_test"),
        backend_ref=EntityRef(entity_type=EntityKind.BACKEND, id="backend_test"),
        query_mode=QueryMode.PREDEFINED,
        requested_scope="current case window",
        reason="Standard triage step",
        requested_by="tester",
    )
    assert predefined.query_mode == QueryMode.PREDEFINED

    custom = QueryRequest(
        case_ref=EntityRef(entity_type=EntityKind.CASE, id="case_test"),
        backend_ref=EntityRef(entity_type=EntityKind.BACKEND, id="backend_test"),
        query_mode=QueryMode.CUSTOM_GUARDED,
        requested_scope="same backend scope",
        reason="Need a deeper follow-up query",
        requested_by="tester",
        custom_query_text="filter dst_port = 443 and action = allow",
    )
    assert custom.query_mode == QueryMode.CUSTOM_GUARDED
    assert custom.custom_query_text is not None

    with pytest.raises(ValidationError):
        QueryRequest(
            case_ref=EntityRef(entity_type=EntityKind.CASE, id="case_test"),
            backend_ref=EntityRef(entity_type=EntityKind.BACKEND, id="backend_test"),
            query_mode=QueryMode.PREDEFINED,
            requested_scope="missing definition ref",
            reason="Invalid predefined request",
            requested_by="tester",
        )

    with pytest.raises(ValidationError):
        QueryRequest(
            query_definition_ref=EntityRef(entity_type=EntityKind.QUERY_DEFINITION, id="querydef_test"),
            case_ref=EntityRef(entity_type=EntityKind.CASE, id="case_test"),
            backend_ref=EntityRef(entity_type=EntityKind.BACKEND, id="backend_test"),
            query_mode=QueryMode.CUSTOM_GUARDED,
            requested_scope="same backend scope",
            reason="Invalid custom request",
            requested_by="tester",
            custom_query_text="filter action = allow",
        )
