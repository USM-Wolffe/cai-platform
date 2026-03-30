"""Backend descriptor for the first WatchGuard logs slice."""

from __future__ import annotations

from platform_contracts import (
    ArtifactKind,
    BackendCapability,
    BackendCapabilityName,
    BackendDescriptor,
    BackendHealth,
    WorkflowType,
)

WATCHGUARD_LOGS_BACKEND_ID = "watchguard_logs"
WATCHGUARD_LOGS_BACKEND_TYPE = "watchguard_logs"
WATCHGUARD_WORKSPACE_ZIP_INGESTION_QUERY_CLASS = "watchguard_logs.workspace_zip_ingestion"
WATCHGUARD_WORKSPACE_ZIP_INGESTION_OPERATION = "watchguard_logs.workspace_zip_ingestion"
WATCHGUARD_STAGE_WORKSPACE_ZIP_OPERATION = "watchguard_logs.stage_workspace_zip"
WATCHGUARD_DUCKDB_WORKSPACE_ANALYTICS_OPERATION = "watchguard_logs.duckdb_workspace_analytics"
WATCHGUARD_DUCKDB_WORKSPACE_QUERY_CLASS = "watchguard_logs.duckdb_workspace_query"
WATCHGUARD_ANALYTICS_BUNDLE_BASIC_QUERY_CLASS = "watchguard_logs.analytics_bundle_basic"
WATCHGUARD_ANALYTICS_BUNDLE_BASIC_OPERATION = "watchguard_logs.analytics_bundle_basic"
WATCHGUARD_FILTER_DENIED_EVENTS_QUERY_CLASS = "watchguard_logs.filter_denied_events"
WATCHGUARD_FILTER_DENIED_EVENTS_OPERATION = "watchguard_logs.filter_denied_events"
WATCHGUARD_GUARDED_FILTERED_ROWS_QUERY_CLASS = "watchguard_logs.guarded_filtered_rows"
WATCHGUARD_NORMALIZE_SUMMARY_QUERY_CLASS = "watchguard_logs.normalize_summary"
WATCHGUARD_NORMALIZE_SUMMARY_OPERATION = "watchguard_logs.normalize_and_summarize"
WATCHGUARD_TOP_TALKERS_BASIC_QUERY_CLASS = "watchguard_logs.top_talkers_basic"
WATCHGUARD_TOP_TALKERS_BASIC_OPERATION = "watchguard_logs.top_talkers_basic"

# DDoS investigation operations
WATCHGUARD_DDOS_TEMPORAL_ANALYSIS_OPERATION = "watchguard_logs.ddos_temporal_analysis"
WATCHGUARD_DDOS_TOP_DESTINATIONS_OPERATION = "watchguard_logs.ddos_top_destinations"
WATCHGUARD_DDOS_TOP_SOURCES_OPERATION = "watchguard_logs.ddos_top_sources"
WATCHGUARD_DDOS_SEGMENT_ANALYSIS_OPERATION = "watchguard_logs.ddos_segment_analysis"
WATCHGUARD_DDOS_IP_PROFILE_OPERATION = "watchguard_logs.ddos_ip_profile"
WATCHGUARD_DDOS_HOURLY_DISTRIBUTION_OPERATION = "watchguard_logs.ddos_hourly_distribution"
WATCHGUARD_DDOS_PROTOCOL_BREAKDOWN_OPERATION = "watchguard_logs.ddos_protocol_breakdown"


def get_watchguard_logs_backend_descriptor() -> BackendDescriptor:
    """Return the deterministic descriptor for the first WatchGuard log backend slice."""
    return BackendDescriptor(
        backend_id=WATCHGUARD_LOGS_BACKEND_ID,
        backend_type=WATCHGUARD_LOGS_BACKEND_TYPE,
        capabilities=[
            BackendCapability(
                name=BackendCapabilityName.CREATE_RUN,
                description="Create a deterministic WatchGuard log run.",
            ),
            BackendCapability(
                name=BackendCapabilityName.EXECUTE_PREDEFINED_QUERY,
                description="Execute the first predefined WatchGuard normalization observation.",
            ),
            BackendCapability(
                name=BackendCapabilityName.EXECUTE_CUSTOM_QUERY,
                description="Execute the first guarded custom query shape over normalized WatchGuard traffic data.",
            ),
            BackendCapability(
                name=BackendCapabilityName.GET_RUN_STATUS,
                description="Read the current deterministic run status for WatchGuard log runs.",
            ),
            BackendCapability(
                name=BackendCapabilityName.LIST_RUN_ARTIFACTS,
                description="List the artifacts attached to or produced by a WatchGuard log run.",
            ),
            BackendCapability(
                name=BackendCapabilityName.READ_ARTIFACT_CONTENT,
                description="Read stored content for WatchGuard run artifacts that are readable in the current runtime.",
            ),
        ],
        supported_workflow_types=[WorkflowType.LOG_INVESTIGATION],
        supported_query_classes=[
            WATCHGUARD_WORKSPACE_ZIP_INGESTION_QUERY_CLASS,
            WATCHGUARD_NORMALIZE_SUMMARY_QUERY_CLASS,
            WATCHGUARD_FILTER_DENIED_EVENTS_QUERY_CLASS,
            WATCHGUARD_ANALYTICS_BUNDLE_BASIC_QUERY_CLASS,
            WATCHGUARD_TOP_TALKERS_BASIC_QUERY_CLASS,
            WATCHGUARD_GUARDED_FILTERED_ROWS_QUERY_CLASS,
            WATCHGUARD_STAGE_WORKSPACE_ZIP_OPERATION,
            WATCHGUARD_DUCKDB_WORKSPACE_ANALYTICS_OPERATION,
            WATCHGUARD_DUCKDB_WORKSPACE_QUERY_CLASS,
            WATCHGUARD_DDOS_TEMPORAL_ANALYSIS_OPERATION,
            WATCHGUARD_DDOS_TOP_DESTINATIONS_OPERATION,
            WATCHGUARD_DDOS_TOP_SOURCES_OPERATION,
            WATCHGUARD_DDOS_SEGMENT_ANALYSIS_OPERATION,
            WATCHGUARD_DDOS_IP_PROFILE_OPERATION,
            WATCHGUARD_DDOS_HOURLY_DISTRIBUTION_OPERATION,
            WATCHGUARD_DDOS_PROTOCOL_BREAKDOWN_OPERATION,
        ],
        accepted_artifact_kinds=[ArtifactKind.INPUT],
        produced_artifact_kinds=[ArtifactKind.NORMALIZED, ArtifactKind.ANALYSIS_OUTPUT, ArtifactKind.QUERY_RESULT],
        health=BackendHealth.HEALTHY,
        metadata={
            "slice": "initial",
            "vendor": "watchguard",
        },
    )
