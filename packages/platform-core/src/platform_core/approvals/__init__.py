"""Approval and execution-gating helpers."""

from platform_core.approvals.services import ApprovalEvaluation, ensure_query_approval, query_requires_approval

__all__ = [
    "ApprovalEvaluation",
    "ensure_query_approval",
    "query_requires_approval",
]
