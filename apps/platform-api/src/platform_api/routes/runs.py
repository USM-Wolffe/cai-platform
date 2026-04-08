"""Run creation and explicit observation routes."""

from fastapi import APIRouter, Body, Depends, status
from fastapi.responses import JSONResponse
from platform_contracts import EntityKind, EntityRef, ObservationRequest, ObservationStatus
from platform_core import complete_run, create_run_for_case, publish_observation_result

from platform_api.runtime import AppRuntime, get_runtime
from platform_api.schemas import (
    CompleteRunRequest,
    CreateRunRequest,
    ExecuteObservationRequest,
    serialize_run_artifacts,
    serialize_execution_response,
    serialize_run_summary,
    serialize_run_status,
)
from platform_backends.multi_source_logs import (
    MULTI_SOURCE_LOGS_ACTIVE_THREATS_OPERATION,
    MULTI_SOURCE_LOGS_BACKEND_ID,
    MULTI_SOURCE_LOGS_CROSS_SOURCE_OPERATION,
    MULTI_SOURCE_LOGS_DNS_ANOMALY_OPERATION,
    MULTI_SOURCE_LOGS_FAILED_AUTH_OPERATION,
    MULTI_SOURCE_LOGS_LATERAL_MOVEMENT_OPERATION,
    MULTI_SOURCE_LOGS_NORMALIZE_OPERATION,
    MULTI_SOURCE_LOGS_PRIV_ESC_OPERATION,
)
from platform_backends.phishing_email import (
    PHISHING_EMAIL_BACKEND_ID,
    PHISHING_EMAIL_BASIC_ASSESSMENT_OPERATION,
    PHISHING_EMAIL_HEADER_ANALYSIS_OPERATION,
)
from platform_backends.watchguard_logs import (
    WATCHGUARD_ANALYTICS_BUNDLE_BASIC_OPERATION,
    WATCHGUARD_DDOS_HOURLY_DISTRIBUTION_OPERATION,
    WATCHGUARD_DDOS_IP_PROFILE_OPERATION,
    WATCHGUARD_DDOS_PROTOCOL_BREAKDOWN_OPERATION,
    WATCHGUARD_DDOS_SEGMENT_ANALYSIS_OPERATION,
    WATCHGUARD_DDOS_TEMPORAL_ANALYSIS_OPERATION,
    WATCHGUARD_DDOS_TOP_DESTINATIONS_OPERATION,
    WATCHGUARD_DDOS_TOP_SOURCES_OPERATION,
    WATCHGUARD_DUCKDB_WORKSPACE_ANALYTICS_OPERATION,
    WATCHGUARD_FILTER_DENIED_EVENTS_OPERATION,
    WATCHGUARD_LOGS_BACKEND_ID,
    WATCHGUARD_NORMALIZE_SUMMARY_OPERATION,
    WATCHGUARD_STAGE_WORKSPACE_ZIP_OPERATION,
    WATCHGUARD_TOP_TALKERS_BASIC_OPERATION,
    WATCHGUARD_WORKSPACE_ZIP_INGESTION_OPERATION,
)

router = APIRouter(prefix="/runs", tags=["runs"])


@router.post("", status_code=status.HTTP_201_CREATED)
def create_run_endpoint(
    request: CreateRunRequest,
    runtime: AppRuntime = Depends(get_runtime),
) -> dict[str, object]:
    run = create_run_for_case(
        runtime.case_repository,
        runtime.run_repository,
        runtime.backend_registry,
        runtime.audit_port,
        case_id=request.case_id,
        backend_id=request.backend_id,
        scope=request.scope,
        input_artifact_ids=request.input_artifact_ids,
        artifact_repository=runtime.artifact_repository if request.input_artifact_ids else None,
    )
    return serialize_run_summary(
        run=run,
        input_artifacts=runtime.get_run_input_artifacts(run),
        output_artifacts=runtime.get_run_output_artifacts(run),
        observation_results=runtime.list_run_observation_results(run),
    )


@router.get("/{run_id}")
def get_run_endpoint(run_id: str, runtime: AppRuntime = Depends(get_runtime)) -> dict[str, object]:
    run = runtime.get_run_or_raise(run_id)
    return serialize_run_summary(
        run=run,
        input_artifacts=runtime.get_run_input_artifacts(run),
        output_artifacts=runtime.get_run_output_artifacts(run),
        observation_results=runtime.list_run_observation_results(run),
    )


@router.get("/{run_id}/status")
def get_run_status_endpoint(run_id: str, runtime: AppRuntime = Depends(get_runtime)) -> dict[str, object]:
    run = runtime.get_run_or_raise(run_id)
    return serialize_run_status(
        run=run,
        observation_results=runtime.list_run_observation_results(run),
    )


@router.get("/{run_id}/artifacts")
def list_run_artifacts_endpoint(run_id: str, runtime: AppRuntime = Depends(get_runtime)) -> dict[str, object]:
    run = runtime.get_run_or_raise(run_id)
    return serialize_run_artifacts(
        run=run,
        input_artifacts=runtime.get_run_input_artifacts(run),
        output_artifacts=runtime.get_run_output_artifacts(run),
    )


@router.post("/{run_id}/complete")
def complete_run_endpoint(
    run_id: str,
    request: CompleteRunRequest = Body(default_factory=CompleteRunRequest),
    runtime: AppRuntime = Depends(get_runtime),
) -> dict[str, object]:
    case, run = complete_run(
        runtime.case_repository,
        runtime.run_repository,
        runtime.audit_port,
        run_id=run_id,
        requested_by=request.requested_by,
        reason=request.reason,
    )
    response = serialize_run_summary(
        run=run,
        input_artifacts=runtime.get_run_input_artifacts(run),
        output_artifacts=runtime.get_run_output_artifacts(run),
        observation_results=runtime.list_run_observation_results(run),
    )
    response["case"] = case.model_dump(mode="json")
    return response


@router.post("/{run_id}/observations/watchguard-ingest-workspace-zip", response_model=None)
def execute_watchguard_workspace_zip_ingestion_endpoint(
    run_id: str,
    request: ExecuteObservationRequest = Body(default_factory=ExecuteObservationRequest),
    runtime: AppRuntime = Depends(get_runtime),
) -> object:
    return _run_observation(
        run_id=run_id,
        request_body=request,
        runtime=runtime,
        backend_id=WATCHGUARD_LOGS_BACKEND_ID,
        operation_kind=WATCHGUARD_WORKSPACE_ZIP_INGESTION_OPERATION,
    )


@router.post("/{run_id}/observations/watchguard-normalize", response_model=None)
def execute_watchguard_normalize_endpoint(
    run_id: str,
    request: ExecuteObservationRequest = Body(default_factory=ExecuteObservationRequest),
    runtime: AppRuntime = Depends(get_runtime),
) -> object:
    return _run_observation(
        run_id=run_id,
        request_body=request,
        runtime=runtime,
        backend_id=WATCHGUARD_LOGS_BACKEND_ID,
        operation_kind=WATCHGUARD_NORMALIZE_SUMMARY_OPERATION,
    )


@router.post("/{run_id}/observations/watchguard-filter-denied", response_model=None)
def execute_watchguard_filter_denied_endpoint(
    run_id: str,
    request: ExecuteObservationRequest = Body(default_factory=ExecuteObservationRequest),
    runtime: AppRuntime = Depends(get_runtime),
) -> object:
    return _run_observation(
        run_id=run_id,
        request_body=request,
        runtime=runtime,
        backend_id=WATCHGUARD_LOGS_BACKEND_ID,
        operation_kind=WATCHGUARD_FILTER_DENIED_EVENTS_OPERATION,
    )


@router.post("/{run_id}/observations/watchguard-analytics-basic", response_model=None)
def execute_watchguard_analytics_basic_endpoint(
    run_id: str,
    request: ExecuteObservationRequest = Body(default_factory=ExecuteObservationRequest),
    runtime: AppRuntime = Depends(get_runtime),
) -> object:
    return _run_observation(
        run_id=run_id,
        request_body=request,
        runtime=runtime,
        backend_id=WATCHGUARD_LOGS_BACKEND_ID,
        operation_kind=WATCHGUARD_ANALYTICS_BUNDLE_BASIC_OPERATION,
    )


@router.post("/{run_id}/observations/watchguard-top-talkers-basic", response_model=None)
def execute_watchguard_top_talkers_basic_endpoint(
    run_id: str,
    request: ExecuteObservationRequest = Body(default_factory=ExecuteObservationRequest),
    runtime: AppRuntime = Depends(get_runtime),
) -> object:
    return _run_observation(
        run_id=run_id,
        request_body=request,
        runtime=runtime,
        backend_id=WATCHGUARD_LOGS_BACKEND_ID,
        operation_kind=WATCHGUARD_TOP_TALKERS_BASIC_OPERATION,
    )


@router.post("/{run_id}/observations/watchguard-stage-workspace-zip", response_model=None)
def execute_watchguard_stage_workspace_zip_endpoint(
    run_id: str,
    request: ExecuteObservationRequest = Body(default_factory=ExecuteObservationRequest),
    runtime: AppRuntime = Depends(get_runtime),
) -> object:
    return _run_observation(
        run_id=run_id,
        request_body=request,
        runtime=runtime,
        backend_id=WATCHGUARD_LOGS_BACKEND_ID,
        operation_kind=WATCHGUARD_STAGE_WORKSPACE_ZIP_OPERATION,
    )


@router.post("/{run_id}/observations/watchguard-duckdb-workspace-analytics", response_model=None)
def execute_watchguard_duckdb_workspace_analytics_endpoint(
    run_id: str,
    request: ExecuteObservationRequest = Body(default_factory=ExecuteObservationRequest),
    runtime: AppRuntime = Depends(get_runtime),
) -> object:
    return _run_observation(
        run_id=run_id,
        request_body=request,
        runtime=runtime,
        backend_id=WATCHGUARD_LOGS_BACKEND_ID,
        operation_kind=WATCHGUARD_DUCKDB_WORKSPACE_ANALYTICS_OPERATION,
    )


@router.post("/{run_id}/observations/watchguard-ddos-temporal-analysis", response_model=None)
def execute_watchguard_ddos_temporal_analysis_endpoint(
    run_id: str,
    request: ExecuteObservationRequest = Body(default_factory=ExecuteObservationRequest),
    runtime: AppRuntime = Depends(get_runtime),
) -> object:
    return _run_observation(
        run_id=run_id,
        request_body=request,
        runtime=runtime,
        backend_id=WATCHGUARD_LOGS_BACKEND_ID,
        operation_kind=WATCHGUARD_DDOS_TEMPORAL_ANALYSIS_OPERATION,
    )


@router.post("/{run_id}/observations/watchguard-ddos-top-destinations", response_model=None)
def execute_watchguard_ddos_top_destinations_endpoint(
    run_id: str,
    request: ExecuteObservationRequest = Body(default_factory=ExecuteObservationRequest),
    runtime: AppRuntime = Depends(get_runtime),
) -> object:
    return _run_observation(
        run_id=run_id,
        request_body=request,
        runtime=runtime,
        backend_id=WATCHGUARD_LOGS_BACKEND_ID,
        operation_kind=WATCHGUARD_DDOS_TOP_DESTINATIONS_OPERATION,
    )


@router.post("/{run_id}/observations/watchguard-ddos-top-sources", response_model=None)
def execute_watchguard_ddos_top_sources_endpoint(
    run_id: str,
    request: ExecuteObservationRequest = Body(default_factory=ExecuteObservationRequest),
    runtime: AppRuntime = Depends(get_runtime),
) -> object:
    return _run_observation(
        run_id=run_id,
        request_body=request,
        runtime=runtime,
        backend_id=WATCHGUARD_LOGS_BACKEND_ID,
        operation_kind=WATCHGUARD_DDOS_TOP_SOURCES_OPERATION,
    )


@router.post("/{run_id}/observations/watchguard-ddos-segment-analysis", response_model=None)
def execute_watchguard_ddos_segment_analysis_endpoint(
    run_id: str,
    request: ExecuteObservationRequest = Body(default_factory=ExecuteObservationRequest),
    runtime: AppRuntime = Depends(get_runtime),
) -> object:
    return _run_observation(
        run_id=run_id,
        request_body=request,
        runtime=runtime,
        backend_id=WATCHGUARD_LOGS_BACKEND_ID,
        operation_kind=WATCHGUARD_DDOS_SEGMENT_ANALYSIS_OPERATION,
    )


@router.post("/{run_id}/observations/watchguard-ddos-ip-profile", response_model=None)
def execute_watchguard_ddos_ip_profile_endpoint(
    run_id: str,
    request: ExecuteObservationRequest = Body(default_factory=ExecuteObservationRequest),
    runtime: AppRuntime = Depends(get_runtime),
) -> object:
    return _run_observation(
        run_id=run_id,
        request_body=request,
        runtime=runtime,
        backend_id=WATCHGUARD_LOGS_BACKEND_ID,
        operation_kind=WATCHGUARD_DDOS_IP_PROFILE_OPERATION,
    )


@router.post("/{run_id}/observations/watchguard-ddos-hourly-distribution", response_model=None)
def execute_watchguard_ddos_hourly_distribution_endpoint(
    run_id: str,
    request: ExecuteObservationRequest = Body(default_factory=ExecuteObservationRequest),
    runtime: AppRuntime = Depends(get_runtime),
) -> object:
    return _run_observation(
        run_id=run_id,
        request_body=request,
        runtime=runtime,
        backend_id=WATCHGUARD_LOGS_BACKEND_ID,
        operation_kind=WATCHGUARD_DDOS_HOURLY_DISTRIBUTION_OPERATION,
    )


@router.post("/{run_id}/observations/watchguard-ddos-protocol-breakdown", response_model=None)
def execute_watchguard_ddos_protocol_breakdown_endpoint(
    run_id: str,
    request: ExecuteObservationRequest = Body(default_factory=ExecuteObservationRequest),
    runtime: AppRuntime = Depends(get_runtime),
) -> object:
    return _run_observation(
        run_id=run_id,
        request_body=request,
        runtime=runtime,
        backend_id=WATCHGUARD_LOGS_BACKEND_ID,
        operation_kind=WATCHGUARD_DDOS_PROTOCOL_BREAKDOWN_OPERATION,
    )


@router.post("/{run_id}/observations/phishing-email-header-analysis", response_model=None)
def execute_phishing_email_header_analysis_endpoint(
    run_id: str,
    request: ExecuteObservationRequest = Body(default_factory=ExecuteObservationRequest),
    runtime: AppRuntime = Depends(get_runtime),
) -> object:
    return _run_observation(
        run_id=run_id,
        request_body=request,
        runtime=runtime,
        backend_id=PHISHING_EMAIL_BACKEND_ID,
        operation_kind=PHISHING_EMAIL_HEADER_ANALYSIS_OPERATION,
    )


@router.post("/{run_id}/observations/phishing-email-basic-assessment", response_model=None)
def execute_phishing_email_basic_assessment_endpoint(
    run_id: str,
    request: ExecuteObservationRequest = Body(default_factory=ExecuteObservationRequest),
    runtime: AppRuntime = Depends(get_runtime),
) -> object:
    return _run_observation(
        run_id=run_id,
        request_body=request,
        runtime=runtime,
        backend_id=PHISHING_EMAIL_BACKEND_ID,
        operation_kind=PHISHING_EMAIL_BASIC_ASSESSMENT_OPERATION,
    )


@router.post("/{run_id}/observations/multi-source-logs-normalize", response_model=None)
def execute_multi_source_logs_normalize_endpoint(
    run_id: str,
    request: ExecuteObservationRequest = Body(default_factory=ExecuteObservationRequest),
    runtime: AppRuntime = Depends(get_runtime),
) -> object:
    return _run_observation(
        run_id=run_id,
        request_body=request,
        runtime=runtime,
        backend_id=MULTI_SOURCE_LOGS_BACKEND_ID,
        operation_kind=MULTI_SOURCE_LOGS_NORMALIZE_OPERATION,
    )


@router.post("/{run_id}/observations/multi-source-logs-failed-auth-detect", response_model=None)
def execute_multi_source_logs_failed_auth_detect_endpoint(
    run_id: str,
    request: ExecuteObservationRequest = Body(default_factory=ExecuteObservationRequest),
    runtime: AppRuntime = Depends(get_runtime),
) -> object:
    return _run_observation(
        run_id=run_id,
        request_body=request,
        runtime=runtime,
        backend_id=MULTI_SOURCE_LOGS_BACKEND_ID,
        operation_kind=MULTI_SOURCE_LOGS_FAILED_AUTH_OPERATION,
    )


@router.post("/{run_id}/observations/multi-source-logs-lateral-movement-detect", response_model=None)
def execute_multi_source_logs_lateral_movement_detect_endpoint(
    run_id: str,
    request: ExecuteObservationRequest = Body(default_factory=ExecuteObservationRequest),
    runtime: AppRuntime = Depends(get_runtime),
) -> object:
    return _run_observation(
        run_id=run_id,
        request_body=request,
        runtime=runtime,
        backend_id=MULTI_SOURCE_LOGS_BACKEND_ID,
        operation_kind=MULTI_SOURCE_LOGS_LATERAL_MOVEMENT_OPERATION,
    )


@router.post("/{run_id}/observations/multi-source-logs-privilege-escalation-detect", response_model=None)
def execute_multi_source_logs_privilege_escalation_detect_endpoint(
    run_id: str,
    request: ExecuteObservationRequest = Body(default_factory=ExecuteObservationRequest),
    runtime: AppRuntime = Depends(get_runtime),
) -> object:
    return _run_observation(
        run_id=run_id,
        request_body=request,
        runtime=runtime,
        backend_id=MULTI_SOURCE_LOGS_BACKEND_ID,
        operation_kind=MULTI_SOURCE_LOGS_PRIV_ESC_OPERATION,
    )


@router.post("/{run_id}/observations/multi-source-logs-dns-anomaly-detect", response_model=None)
def execute_multi_source_logs_dns_anomaly_detect_endpoint(
    run_id: str,
    request: ExecuteObservationRequest = Body(default_factory=ExecuteObservationRequest),
    runtime: AppRuntime = Depends(get_runtime),
) -> object:
    return _run_observation(
        run_id=run_id,
        request_body=request,
        runtime=runtime,
        backend_id=MULTI_SOURCE_LOGS_BACKEND_ID,
        operation_kind=MULTI_SOURCE_LOGS_DNS_ANOMALY_OPERATION,
    )


@router.post("/{run_id}/observations/multi-source-logs-active-threats-detect", response_model=None)
def execute_multi_source_logs_active_threats_detect_endpoint(
    run_id: str,
    request: ExecuteObservationRequest = Body(default_factory=ExecuteObservationRequest),
    runtime: AppRuntime = Depends(get_runtime),
) -> object:
    return _run_observation(
        run_id=run_id,
        request_body=request,
        runtime=runtime,
        backend_id=MULTI_SOURCE_LOGS_BACKEND_ID,
        operation_kind=MULTI_SOURCE_LOGS_ACTIVE_THREATS_OPERATION,
    )


@router.post("/{run_id}/observations/multi-source-logs-cross-source-correlate", response_model=None)
def execute_multi_source_logs_cross_source_correlate_endpoint(
    run_id: str,
    request: ExecuteObservationRequest = Body(default_factory=ExecuteObservationRequest),
    runtime: AppRuntime = Depends(get_runtime),
) -> object:
    return _run_observation(
        run_id=run_id,
        request_body=request,
        runtime=runtime,
        backend_id=MULTI_SOURCE_LOGS_BACKEND_ID,
        operation_kind=MULTI_SOURCE_LOGS_CROSS_SOURCE_OPERATION,
    )


def _run_observation(
    *,
    run_id: str,
    request_body: ExecuteObservationRequest,
    runtime: AppRuntime,
    backend_id: str,
    operation_kind: str,
) -> object:
    run = runtime.get_run_or_raise(run_id)
    case = runtime.get_case_or_raise_from_run(run)
    input_artifact = runtime.get_observation_input_artifact(run=run, input_artifact_id=request_body.input_artifact_id)
    input_payload = runtime.get_artifact_payload_or_raise(input_artifact.artifact_id)

    observation_request = ObservationRequest(
        case_ref=EntityRef(entity_type=EntityKind.CASE, id=case.case_id),
        backend_ref=EntityRef(entity_type=EntityKind.BACKEND, id=backend_id),
        run_ref=EntityRef(entity_type=EntityKind.RUN, id=run.run_id),
        operation_kind=operation_kind,
        input_artifact_refs=[EntityRef(entity_type=EntityKind.ARTIFACT, id=input_artifact.artifact_id)],
        parameters=request_body.parameters,
        requested_by=request_body.requested_by,
    )
    runtime.record_observation_request(observation_request)

    outcome = runtime.execute_observation(
        run=run,
        input_artifact=input_artifact,
        input_payload=input_payload,
        observation_request=observation_request,
    )

    for artifact in outcome.artifacts:
        runtime.save_derived_artifact(artifact)

    updated_case, updated_run = publish_observation_result(
        runtime.case_repository,
        runtime.run_repository,
        runtime.audit_port,
        observation_request=observation_request,
        observation_result=outcome.observation_result,
    )
    runtime.record_observation_result(outcome.observation_result)

    response_body = serialize_execution_response(
        case=updated_case,
        run=updated_run,
        artifacts=outcome.artifacts,
        observation_result=outcome.observation_result,
    )
    if outcome.observation_result.status == ObservationStatus.FAILED:
        response_body["error"] = {
            "type": "backend_execution_failed",
            "message": outcome.observation_result.errors[0] if outcome.observation_result.errors else "backend execution failed",
        }
        return JSONResponse(status_code=400, content=response_body)

    return response_body
