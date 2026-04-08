"""Backend descriptor for the multi_source_logs backend."""

from __future__ import annotations

from platform_contracts import (
    ArtifactKind,
    BackendCapability,
    BackendCapabilityName,
    BackendDescriptor,
    BackendHealth,
    WorkflowType,
)

MULTI_SOURCE_LOGS_BACKEND_ID = "multi_source_logs"
MULTI_SOURCE_LOGS_BACKEND_TYPE = "multi_source_logs"

# Operation constants
MULTI_SOURCE_LOGS_NORMALIZE_OPERATION        = "multi_source_logs.normalize"
MULTI_SOURCE_LOGS_FAILED_AUTH_OPERATION      = "multi_source_logs.failed_auth_detect"
MULTI_SOURCE_LOGS_LATERAL_MOVEMENT_OPERATION = "multi_source_logs.lateral_movement_detect"
MULTI_SOURCE_LOGS_PRIV_ESC_OPERATION         = "multi_source_logs.privilege_escalation_detect"
MULTI_SOURCE_LOGS_DNS_ANOMALY_OPERATION      = "multi_source_logs.dns_anomaly_detect"
MULTI_SOURCE_LOGS_CROSS_SOURCE_OPERATION     = "multi_source_logs.cross_source_correlate"
MULTI_SOURCE_LOGS_ACTIVE_THREATS_OPERATION   = "multi_source_logs.active_threats_detect"


def get_multi_source_logs_backend_descriptor() -> BackendDescriptor:
    """Return the descriptor for the multi_source_logs backend."""
    return BackendDescriptor(
        backend_id=MULTI_SOURCE_LOGS_BACKEND_ID,
        backend_type=MULTI_SOURCE_LOGS_BACKEND_TYPE,
        capabilities=[
            BackendCapability(
                name=BackendCapabilityName.CREATE_RUN,
                description="Create a multi-source log investigation run.",
            ),
            BackendCapability(
                name=BackendCapabilityName.EXECUTE_PREDEFINED_QUERY,
                description="Execute predefined detection operations over normalized log data.",
            ),
            BackendCapability(
                name=BackendCapabilityName.GET_RUN_STATUS,
                description="Read run status for multi-source log runs.",
            ),
            BackendCapability(
                name=BackendCapabilityName.LIST_RUN_ARTIFACTS,
                description="List artifacts attached to or produced by a multi-source log run.",
            ),
            BackendCapability(
                name=BackendCapabilityName.READ_ARTIFACT_CONTENT,
                description="Read stored content for multi-source log artifacts.",
            ),
        ],
        supported_workflow_types=[
            WorkflowType.LOG_INVESTIGATION,
            WorkflowType.FORENSIC_INVESTIGATION,
        ],
        supported_query_classes=[
            MULTI_SOURCE_LOGS_NORMALIZE_OPERATION,
            MULTI_SOURCE_LOGS_FAILED_AUTH_OPERATION,
            MULTI_SOURCE_LOGS_LATERAL_MOVEMENT_OPERATION,
            MULTI_SOURCE_LOGS_PRIV_ESC_OPERATION,
            MULTI_SOURCE_LOGS_DNS_ANOMALY_OPERATION,
            MULTI_SOURCE_LOGS_CROSS_SOURCE_OPERATION,
            MULTI_SOURCE_LOGS_ACTIVE_THREATS_OPERATION,
        ],
        accepted_artifact_kinds=[ArtifactKind.INPUT],
        produced_artifact_kinds=[ArtifactKind.NORMALIZED, ArtifactKind.ANALYSIS_OUTPUT],
        health=BackendHealth.HEALTHY,
        metadata={
            "slice": "initial",
            "service": "multi_source_logs",
        },
    )
