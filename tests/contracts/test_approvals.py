import pytest
from pydantic import ValidationError

from platform_contracts import (
    ApprovalDecision,
    ApprovalScopeKind,
    ApprovalStatus,
    EntityKind,
    EntityRef,
)


def test_approval_record_can_bind_to_guarded_query_scope():
    approval = ApprovalDecision(
        status=ApprovalStatus.APPROVED,
        scope_kind=ApprovalScopeKind.QUERY_REQUEST,
        scope_ref=EntityRef(entity_type=EntityKind.QUERY_REQUEST, id="queryreq_test"),
        reason="Approved guarded query.",
        approver_kind="human_operator",
    )

    assert approval.approval_id.startswith("approval_")
    assert approval.scope_kind == ApprovalScopeKind.QUERY_REQUEST


def test_approval_record_can_bind_to_guarded_observation_scope():
    approval = ApprovalDecision(
        status=ApprovalStatus.PENDING,
        scope_kind=ApprovalScopeKind.OBSERVATION_REQUEST,
        scope_ref=EntityRef(entity_type=EntityKind.OBSERVATION_REQUEST, id="observation_test"),
        reason="Awaiting approval for guarded observation.",
        approver_kind="policy_engine",
    )

    assert approval.scope_kind == ApprovalScopeKind.OBSERVATION_REQUEST
    assert approval.scope_ref.entity_type == EntityKind.OBSERVATION_REQUEST


def test_approval_record_rejects_scope_kind_mismatch():
    with pytest.raises(ValidationError):
        ApprovalDecision(
            status=ApprovalStatus.APPROVED,
            scope_kind=ApprovalScopeKind.QUERY_REQUEST,
            scope_ref=EntityRef(entity_type=EntityKind.OBSERVATION_REQUEST, id="observation_test"),
            reason="Invalid mismatched approval.",
            approver_kind="human_operator",
        )
