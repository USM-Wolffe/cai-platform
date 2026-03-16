"""Core platform package for cai-platform-v2."""

from platform_core.approvals import ApprovalEvaluation, ensure_query_approval, query_requires_approval
from platform_core.audit import (
    append_timeline_event,
    append_timeline_event_to_case,
    record_case_decision,
    record_decision,
)
from platform_core.cases import attach_artifact_ref_to_case, create_case
from platform_core.errors import (
    ApprovalRequiredError,
    ContractViolationError,
    CoreError,
    InvalidStateError,
    NotFoundError,
    UnsupportedBackendError,
)
from platform_core.ports import (
    ApprovalPolicyPort,
    ArtifactRepository,
    AuditPort,
    BackendRegistry,
    CaseRepository,
    InvestigationDefinitionRepository,
    RunRepository,
)
from platform_core.queries import ensure_backend_supports_query_request, resolve_query_backend
from platform_core.runs import create_run_for_case, publish_observation_result
from platform_core.services import (
    ensure_backend_can_create_run,
    ensure_backend_supports_query_mode,
    ensure_backend_supports_workflow,
    get_backend_or_raise,
)

__all__ = [
    "ApprovalEvaluation",
    "ApprovalPolicyPort",
    "ApprovalRequiredError",
    "ArtifactRepository",
    "AuditPort",
    "BackendRegistry",
    "CaseRepository",
    "ContractViolationError",
    "CoreError",
    "InvalidStateError",
    "InvestigationDefinitionRepository",
    "NotFoundError",
    "RunRepository",
    "UnsupportedBackendError",
    "append_timeline_event",
    "append_timeline_event_to_case",
    "attach_artifact_ref_to_case",
    "create_case",
    "create_run_for_case",
    "ensure_backend_can_create_run",
    "ensure_backend_supports_query_mode",
    "ensure_backend_supports_query_request",
    "ensure_backend_supports_workflow",
    "ensure_query_approval",
    "get_backend_or_raise",
    "publish_observation_result",
    "query_requires_approval",
    "record_case_decision",
    "record_decision",
    "resolve_query_backend",
]
