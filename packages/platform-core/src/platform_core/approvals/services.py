"""Minimal approval-gating services."""

from __future__ import annotations

from dataclasses import dataclass

from platform_contracts import ApprovalDecision, QueryDefinition, QueryRequest

from platform_core.errors import ApprovalRequiredError
from platform_core.ports import ApprovalPolicyPort, BackendRegistry
from platform_core.queries import ensure_backend_supports_query_request


@dataclass(frozen=True)
class ApprovalEvaluation:
    """Minimal evaluation result for guarded query execution."""

    requires_approval: bool
    approval_accepted: bool


def query_requires_approval(
    approval_policy: ApprovalPolicyPort,
    backend_registry: BackendRegistry,
    *,
    query_request: QueryRequest,
    query_definition: QueryDefinition | None = None,
) -> bool:
    """Return whether the current query request requires approval."""
    backend = ensure_backend_supports_query_request(
        backend_registry,
        query_request,
        query_definition=query_definition,
    )
    return approval_policy.query_requires_approval(
        query_request=query_request,
        query_definition=query_definition,
        backend=backend,
    )


def ensure_query_approval(
    approval_policy: ApprovalPolicyPort,
    backend_registry: BackendRegistry,
    *,
    query_request: QueryRequest,
    approval_decision: ApprovalDecision | None = None,
    query_definition: QueryDefinition | None = None,
) -> ApprovalEvaluation:
    """Require an acceptable approval when policy marks the query as guarded."""
    backend = ensure_backend_supports_query_request(
        backend_registry,
        query_request,
        query_definition=query_definition,
    )
    requires_approval = approval_policy.query_requires_approval(
        query_request=query_request,
        query_definition=query_definition,
        backend=backend,
    )
    if not requires_approval:
        return ApprovalEvaluation(requires_approval=False, approval_accepted=True)

    approval_accepted = approval_policy.is_approval_acceptable(
        query_request=query_request,
        approval_decision=approval_decision,
        query_definition=query_definition,
        backend=backend,
    )
    if not approval_accepted:
        raise ApprovalRequiredError("query execution requires an acceptable approval decision")

    return ApprovalEvaluation(requires_approval=True, approval_accepted=True)
