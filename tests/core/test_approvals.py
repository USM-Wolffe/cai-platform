import pytest

from platform_contracts import ApprovalStatus, RiskClass

from platform_core import ApprovalRequiredError, ensure_query_approval, query_requires_approval

from .support import (
    InMemoryBackendRegistry,
    SimpleApprovalPolicy,
    make_approval_for_query,
    make_backend,
    make_custom_query_request,
    make_predefined_query_request,
    make_query_definition,
)


def test_guarded_query_requests_can_be_detected_as_requiring_approval():
    backend_registry = InMemoryBackendRegistry()
    backend_registry.add_backend(make_backend())
    approval_policy = SimpleApprovalPolicy()

    custom_query_request = make_custom_query_request()

    assert query_requires_approval(
        approval_policy,
        backend_registry,
        query_request=custom_query_request,
    )

    high_risk_predefined = make_predefined_query_request()
    assert query_requires_approval(
        approval_policy,
        backend_registry,
        query_request=high_risk_predefined,
        query_definition=make_query_definition(risk_class=RiskClass.HIGH),
    )


def test_missing_or_invalid_approval_is_rejected_when_policy_requires_it():
    backend_registry = InMemoryBackendRegistry()
    backend_registry.add_backend(make_backend())
    approval_policy = SimpleApprovalPolicy()
    query_request = make_custom_query_request()

    with pytest.raises(ApprovalRequiredError):
        ensure_query_approval(
            approval_policy,
            backend_registry,
            query_request=query_request,
        )

    with pytest.raises(ApprovalRequiredError):
        ensure_query_approval(
            approval_policy,
            backend_registry,
            query_request=query_request,
            approval_decision=make_approval_for_query(query_request, status=ApprovalStatus.PENDING),
        )

    evaluation = ensure_query_approval(
        approval_policy,
        backend_registry,
        query_request=query_request,
        approval_decision=make_approval_for_query(query_request, status=ApprovalStatus.APPROVED),
    )

    assert evaluation.requires_approval is True
    assert evaluation.approval_accepted is True
