"""Shared enums, base models, and reference objects for platform contracts."""

from platform_contracts.common.base import ContractModel, TimestampedModel, generate_opaque_id, utc_now
from platform_contracts.common.enums import (
    ApprovalScopeKind,
    ApprovalStatus,
    ArtifactKind,
    BackendCapabilityName,
    BackendHealth,
    CaseStatus,
    EntityKind,
    InvestigationStatus,
    ObservationStatus,
    QueryMode,
    RiskClass,
    RunStatus,
    WorkflowType,
)
from platform_contracts.common.refs import EntityRef, ExternalReference

__all__ = [
    "ApprovalScopeKind",
    "ApprovalStatus",
    "ArtifactKind",
    "BackendCapabilityName",
    "BackendHealth",
    "CaseStatus",
    "ContractModel",
    "EntityKind",
    "EntityRef",
    "ExternalReference",
    "InvestigationStatus",
    "ObservationStatus",
    "QueryMode",
    "RiskClass",
    "RunStatus",
    "TimestampedModel",
    "WorkflowType",
    "generate_opaque_id",
    "utc_now",
]
