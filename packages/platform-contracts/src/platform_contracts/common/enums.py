"""Shared enums for the platform contract layer."""

from enum import Enum


class WorkflowType(str, Enum):
    LOG_INVESTIGATION = "log_investigation"
    FORENSIC_INVESTIGATION = "forensic_investigation"
    DEFENSIVE_ANALYSIS = "defensive_analysis"
    SANDBOX_INVESTIGATION = "sandbox_investigation"


class CaseStatus(str, Enum):
    OPEN = "open"
    IN_PROGRESS = "in_progress"
    AWAITING_APPROVAL = "awaiting_approval"
    BLOCKED = "blocked"
    CLOSED = "closed"


class ArtifactKind(str, Enum):
    INPUT = "input"
    NORMALIZED = "normalized"
    QUERY_RESULT = "query_result"
    ANALYSIS_OUTPUT = "analysis_output"
    REPORT = "report"
    EVIDENCE_BUNDLE = "evidence_bundle"
    BINARY_OR_FILE = "binary_or_file"


class BackendCapabilityName(str, Enum):
    CREATE_RUN = "create_run"
    BIND_INPUT_ARTIFACT = "bind_input_artifact"
    EXECUTE_PREDEFINED_QUERY = "execute_predefined_query"
    EXECUTE_CUSTOM_QUERY = "execute_custom_query"
    GET_RUN_STATUS = "get_run_status"
    LIST_RUN_ARTIFACTS = "list_run_artifacts"
    READ_ARTIFACT_CONTENT = "read_artifact_content"


class BackendHealth(str, Enum):
    UNKNOWN = "unknown"
    HEALTHY = "healthy"
    DEGRADED = "degraded"
    UNAVAILABLE = "unavailable"


class RunStatus(str, Enum):
    CREATED = "created"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    BLOCKED = "blocked"
    CANCELLED = "cancelled"


class ObservationStatus(str, Enum):
    SUCCEEDED = "succeeded"
    SUCCEEDED_NO_FINDINGS = "succeeded_no_findings"
    FAILED = "failed"
    BLOCKED = "blocked"


class InvestigationStatus(str, Enum):
    DRAFT = "draft"
    PUBLISHED = "published"
    DEPRECATED = "deprecated"


class QueryMode(str, Enum):
    PREDEFINED = "predefined"
    CUSTOM_GUARDED = "custom_guarded"


class RiskClass(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class ApprovalStatus(str, Enum):
    PENDING = "pending"
    APPROVED = "approved"
    REJECTED = "rejected"
    EXPIRED = "expired"


class ApprovalScopeKind(str, Enum):
    QUERY_REQUEST = "query_request"
    OBSERVATION_REQUEST = "observation_request"


class EntityKind(str, Enum):
    CASE = "case"
    ARTIFACT = "artifact"
    BACKEND = "backend"
    RUN = "run"
    OBSERVATION_REQUEST = "observation_request"
    OBSERVATION_RESULT = "observation_result"
    INVESTIGATION_DEFINITION = "investigation_definition"
    QUERY_DEFINITION = "query_definition"
    QUERY_REQUEST = "query_request"
    APPROVAL_DECISION = "approval_decision"

