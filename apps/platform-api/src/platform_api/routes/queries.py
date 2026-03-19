"""Explicit guarded custom query routes for the deterministic platform-api surface."""

from __future__ import annotations

import json

from fastapi import APIRouter, Body, Depends
from platform_contracts import (
    ApprovalDecision,
    ApprovalScopeKind,
    EntityKind,
    EntityRef,
    QueryMode,
    QueryRequest,
)
from platform_core import ensure_query_approval

from platform_api.runtime import AppRuntime, get_runtime
from platform_api.schemas import (
    ExecuteWatchGuardDuckDBQueryRequest,
    ExecuteWatchGuardGuardedCustomQueryRequest,
    serialize_custom_query_response,
)
from platform_backends.watchguard_logs import (
    WATCHGUARD_DUCKDB_WORKSPACE_QUERY_CLASS,
    WATCHGUARD_GUARDED_FILTERED_ROWS_QUERY_CLASS,
    WATCHGUARD_LOGS_BACKEND_ID,
    execute_duckdb_workspace_query,
    execute_guarded_custom_query,
)

router = APIRouter(prefix="/runs", tags=["queries"])


@router.post("/{run_id}/queries/watchguard-guarded-filtered-rows")
def execute_watchguard_guarded_filtered_rows_query_endpoint(
    run_id: str,
    request: ExecuteWatchGuardGuardedCustomQueryRequest = Body(...),
    runtime: AppRuntime = Depends(get_runtime),
) -> dict[str, object]:
    run = runtime.get_run_or_raise(run_id)
    case = runtime.get_case_or_raise_from_run(run)
    input_artifact = runtime.get_observation_input_artifact(run=run, input_artifact_id=request.input_artifact_id)
    input_payload = runtime.get_artifact_payload_or_raise(input_artifact.artifact_id)

    query_request = QueryRequest(
        case_ref=EntityRef(entity_type=EntityKind.CASE, id=case.case_id),
        backend_ref=EntityRef(entity_type=EntityKind.BACKEND, id=WATCHGUARD_LOGS_BACKEND_ID),
        run_ref=EntityRef(entity_type=EntityKind.RUN, id=run.run_id),
        query_mode=QueryMode.CUSTOM_GUARDED,
        parameters={
            "query": request.query,
            "query_class": WATCHGUARD_GUARDED_FILTERED_ROWS_QUERY_CLASS,
            "input_artifact_id": input_artifact.artifact_id,
        },
        requested_scope=WATCHGUARD_GUARDED_FILTERED_ROWS_QUERY_CLASS,
        reason=request.reason,
        requested_by=request.requested_by,
        custom_query_text=json.dumps(request.query, sort_keys=True),
    )
    approval_decision = _build_approval_decision(query_request=query_request, request=request)
    if approval_decision is not None:
        query_request = query_request.model_copy(
            update={
                "approval_ref": EntityRef(
                    entity_type=EntityKind.APPROVAL_DECISION,
                    id=approval_decision.approval_id,
                )
            }
        )

    runtime.record_query_request(query_request)
    if approval_decision is not None:
        runtime.record_approval_decision(approval_decision)

    ensure_query_approval(
        runtime.approval_policy,
        runtime.backend_registry,
        query_request=query_request,
        approval_decision=approval_decision,
    )

    outcome = execute_guarded_custom_query(
        run=run,
        input_artifact=input_artifact,
        input_payload=input_payload,
        query_request=query_request,
    )
    for artifact in outcome.artifacts:
        runtime.save_derived_artifact(artifact)

    updated_case, updated_run = runtime.publish_query_artifacts(
        case=case,
        run=run,
        artifacts=outcome.artifacts,
    )
    return serialize_custom_query_response(
        case=updated_case,
        run=updated_run,
        query_request=query_request,
        approval_decision=approval_decision,
        artifacts=outcome.artifacts,
        query_summary=outcome.query_summary,
    )


@router.post("/{run_id}/queries/watchguard-duckdb-workspace-query")
def execute_watchguard_duckdb_workspace_query_endpoint(
    run_id: str,
    request: ExecuteWatchGuardDuckDBQueryRequest = Body(...),
    runtime: AppRuntime = Depends(get_runtime),
) -> dict[str, object]:
    run = runtime.get_run_or_raise(run_id)
    case = runtime.get_case_or_raise_from_run(run)
    input_artifact = runtime.get_observation_input_artifact(run=run, input_artifact_id=request.input_artifact_id)
    input_payload = runtime.get_artifact_payload_or_raise(input_artifact.artifact_id)

    query_request = QueryRequest(
        case_ref=EntityRef(entity_type=EntityKind.CASE, id=case.case_id),
        backend_ref=EntityRef(entity_type=EntityKind.BACKEND, id=WATCHGUARD_LOGS_BACKEND_ID),
        run_ref=EntityRef(entity_type=EntityKind.RUN, id=run.run_id),
        query_mode=QueryMode.CUSTOM_GUARDED,
        parameters={
            "query": {
                "family": request.family,
                "filters": request.filters,
                "limit": request.limit,
            },
            "query_class": WATCHGUARD_DUCKDB_WORKSPACE_QUERY_CLASS,
            "input_artifact_id": input_artifact.artifact_id,
        },
        requested_scope=WATCHGUARD_DUCKDB_WORKSPACE_QUERY_CLASS,
        reason=request.reason,
        requested_by=request.requested_by,
        custom_query_text=json.dumps({"family": request.family, "filters": request.filters, "limit": request.limit}, sort_keys=True),
    )
    runtime.record_query_request(query_request)

    outcome = execute_duckdb_workspace_query(
        run=run,
        input_artifact=input_artifact,
        input_payload=input_payload,
        query_request=query_request,
    )
    for artifact in outcome.artifacts:
        runtime.save_derived_artifact(artifact)

    updated_case, updated_run = runtime.publish_query_artifacts(
        case=case,
        run=run,
        artifacts=outcome.artifacts,
    )
    return serialize_custom_query_response(
        case=updated_case,
        run=updated_run,
        query_request=query_request,
        approval_decision=None,
        artifacts=outcome.artifacts,
        query_summary=outcome.query_summary,
    )


def _build_approval_decision(
    *,
    query_request: QueryRequest,
    request: ExecuteWatchGuardGuardedCustomQueryRequest,
) -> ApprovalDecision | None:
    if request.approval is None:
        return None
    return ApprovalDecision(
        status=request.approval.status,
        scope_kind=ApprovalScopeKind.QUERY_REQUEST,
        scope_ref=EntityRef(entity_type=EntityKind.QUERY_REQUEST, id=query_request.query_request_id),
        reason=request.approval.reason,
        approver_kind=request.approval.approver_kind,
        approver_ref=request.approval.approver_ref,
    )
