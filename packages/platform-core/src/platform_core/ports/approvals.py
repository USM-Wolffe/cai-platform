"""Approval policy boundary."""

from __future__ import annotations

from typing import Protocol, runtime_checkable

from platform_contracts import ApprovalDecision, BackendDescriptor, QueryDefinition, QueryRequest


@runtime_checkable
class ApprovalPolicyPort(Protocol):
    """Minimal policy boundary for guarded execution checks."""

    def query_requires_approval(
        self,
        *,
        query_request: QueryRequest,
        query_definition: QueryDefinition | None,
        backend: BackendDescriptor,
    ) -> bool:
        """Return whether this query request requires approval."""

    def is_approval_acceptable(
        self,
        *,
        query_request: QueryRequest,
        approval_decision: ApprovalDecision | None,
        query_definition: QueryDefinition | None,
        backend: BackendDescriptor,
    ) -> bool:
        """Return whether the provided approval is sufficient for execution."""
