"""Minimal deterministic execution for the first WatchGuard predefined observation."""

from __future__ import annotations

from collections import Counter
import csv
from datetime import datetime, timezone
import gzip
import hashlib
import io
import json
import os
import tarfile
import tempfile
from typing import Any
import zipfile

from platform_adapters.watchguard import (
    WATCHGUARD_ALARM_LOG_TYPE,
    WATCHGUARD_EVENT_LOG_TYPE,
    WATCHGUARD_TRAFFIC_LOG_TYPE,
    WATCHGUARD_WORKSPACE_S3_ZIP_SOURCE_KIND,
    WatchGuardAdapterError,
    filter_denied_watchguard_batch,
    inspect_watchguard_input_artifact,
    normalize_watchguard_log_payload,
    parse_workspace_s3_zip_reference,
)
from platform_contracts import (
    Artifact,
    ArtifactKind,
    EntityKind,
    EntityRef,
    ObservationRequest,
    ObservationResult,
    ObservationStatus,
    QueryRequest,
    Run,
)
from platform_core import ContractViolationError

from platform_backends.watchguard_logs.descriptor import (
    WATCHGUARD_ANALYTICS_BUNDLE_BASIC_OPERATION,
    WATCHGUARD_DDOS_HOURLY_DISTRIBUTION_OPERATION,
    WATCHGUARD_DDOS_IP_PROFILE_OPERATION,
    WATCHGUARD_DDOS_PROTOCOL_BREAKDOWN_OPERATION,
    WATCHGUARD_DDOS_SEGMENT_ANALYSIS_OPERATION,
    WATCHGUARD_DDOS_TEMPORAL_ANALYSIS_OPERATION,
    WATCHGUARD_DDOS_TOP_DESTINATIONS_OPERATION,
    WATCHGUARD_DDOS_TOP_SOURCES_OPERATION,
    WATCHGUARD_DUCKDB_WORKSPACE_ANALYTICS_OPERATION,
    WATCHGUARD_DUCKDB_WORKSPACE_QUERY_CLASS,
    WATCHGUARD_FILTER_DENIED_EVENTS_OPERATION,
    WATCHGUARD_GUARDED_FILTERED_ROWS_QUERY_CLASS,
    WATCHGUARD_LOGS_BACKEND_ID,
    WATCHGUARD_NORMALIZE_SUMMARY_OPERATION,
    WATCHGUARD_STAGE_WORKSPACE_ZIP_OPERATION,
    WATCHGUARD_TOP_TALKERS_BASIC_OPERATION,
    WATCHGUARD_WORKSPACE_ZIP_INGESTION_OPERATION,
)
from platform_backends.watchguard_logs.errors import (
    InvalidWatchGuardQueryError,
    UnsupportedWatchGuardObservationError,
    WatchGuardLogsBackendError,
)
from platform_backends.watchguard_logs.models import (
    WatchGuardCustomQueryOutcome,
    WatchGuardExecutionOutcome,
    WatchGuardGuardedFilter,
    WatchGuardGuardedQuerySpec,
)

GUARDED_QUERY_ALLOWED_FIELDS = {"src_ip", "dst_ip", "action", "protocol", "policy"}
GUARDED_QUERY_ALLOWED_OPS = {"eq", "in"}
GUARDED_QUERY_MAX_LIMIT = 50
GUARDED_QUERY_DEFAULT_LIMIT = 20
GUARDED_QUERY_MAX_FILTERS = 5
GUARDED_QUERY_MAX_IN_VALUES = 10
WATCHGUARD_INGESTION_FAMILIES = (
    WATCHGUARD_TRAFFIC_LOG_TYPE,
    WATCHGUARD_EVENT_LOG_TYPE,
    WATCHGUARD_ALARM_LOG_TYPE,
)


def execute_predefined_observation(
    *,
    run: Run,
    input_artifact: Artifact,
    input_payload: object,
    observation_request: ObservationRequest,
) -> WatchGuardExecutionOutcome:
    """Execute a predefined WatchGuard observation and normalize the outcome."""
    _STAGING_MANIFEST_OPERATIONS = {
        WATCHGUARD_STAGE_WORKSPACE_ZIP_OPERATION,
        WATCHGUARD_DUCKDB_WORKSPACE_ANALYTICS_OPERATION,
        WATCHGUARD_DDOS_TEMPORAL_ANALYSIS_OPERATION,
        WATCHGUARD_DDOS_TOP_DESTINATIONS_OPERATION,
        WATCHGUARD_DDOS_TOP_SOURCES_OPERATION,
        WATCHGUARD_DDOS_SEGMENT_ANALYSIS_OPERATION,
        WATCHGUARD_DDOS_IP_PROFILE_OPERATION,
        WATCHGUARD_DDOS_HOURLY_DISTRIBUTION_OPERATION,
        WATCHGUARD_DDOS_PROTOCOL_BREAKDOWN_OPERATION,
    }
    try:
        _validate_observation_request(run=run, observation_request=observation_request)
        if observation_request.operation_kind not in _STAGING_MANIFEST_OPERATIONS:
            inspect_watchguard_input_artifact(input_artifact)
        if observation_request.operation_kind == WATCHGUARD_WORKSPACE_ZIP_INGESTION_OPERATION:
            return _execute_workspace_zip_ingestion(
                run=run,
                input_artifact=input_artifact,
                input_payload=input_payload,
                observation_request=observation_request,
            )
        if observation_request.operation_kind == WATCHGUARD_STAGE_WORKSPACE_ZIP_OPERATION:
            return _execute_stage_workspace_zip(
                run=run,
                input_artifact=input_artifact,
                input_payload=input_payload,
                observation_request=observation_request,
            )
        if observation_request.operation_kind == WATCHGUARD_DUCKDB_WORKSPACE_ANALYTICS_OPERATION:
            return _execute_duckdb_workspace_analytics(
                run=run,
                input_artifact=input_artifact,
                input_payload=input_payload,
                observation_request=observation_request,
            )
        if observation_request.operation_kind == WATCHGUARD_DDOS_TEMPORAL_ANALYSIS_OPERATION:
            return _execute_ddos_temporal_analysis(
                run=run,
                input_artifact=input_artifact,
                input_payload=input_payload,
                observation_request=observation_request,
            )
        if observation_request.operation_kind == WATCHGUARD_DDOS_TOP_DESTINATIONS_OPERATION:
            return _execute_ddos_top_destinations(
                run=run,
                input_artifact=input_artifact,
                input_payload=input_payload,
                observation_request=observation_request,
            )
        if observation_request.operation_kind == WATCHGUARD_DDOS_TOP_SOURCES_OPERATION:
            return _execute_ddos_top_sources(
                run=run,
                input_artifact=input_artifact,
                input_payload=input_payload,
                observation_request=observation_request,
            )
        if observation_request.operation_kind == WATCHGUARD_DDOS_SEGMENT_ANALYSIS_OPERATION:
            return _execute_ddos_segment_analysis(
                run=run,
                input_artifact=input_artifact,
                input_payload=input_payload,
                observation_request=observation_request,
            )
        if observation_request.operation_kind == WATCHGUARD_DDOS_IP_PROFILE_OPERATION:
            return _execute_ddos_ip_profile(
                run=run,
                input_artifact=input_artifact,
                input_payload=input_payload,
                observation_request=observation_request,
            )
        if observation_request.operation_kind == WATCHGUARD_DDOS_HOURLY_DISTRIBUTION_OPERATION:
            return _execute_ddos_hourly_distribution(
                run=run,
                input_artifact=input_artifact,
                input_payload=input_payload,
                observation_request=observation_request,
            )
        if observation_request.operation_kind == WATCHGUARD_DDOS_PROTOCOL_BREAKDOWN_OPERATION:
            return _execute_ddos_protocol_breakdown(
                run=run,
                input_artifact=input_artifact,
                input_payload=input_payload,
                observation_request=observation_request,
            )
        normalized_batch = normalize_watchguard_log_payload(input_payload)
        result_batch = _build_result_batch(
            normalized_batch=normalized_batch,
            operation_kind=observation_request.operation_kind,
        )
        output_artifact = _build_output_artifact(
            run=run,
            observation_request=observation_request,
            result_batch=result_batch,
        )
        status = (
            ObservationStatus.SUCCEEDED
            if result_batch.record_count > 0
            else ObservationStatus.SUCCEEDED_NO_FINDINGS
        )
        structured_summary = _build_structured_summary(
            operation_kind=observation_request.operation_kind,
            result_batch=result_batch,
        )
        observation_result = ObservationResult(
            observation_ref=EntityRef(entity_type=EntityKind.OBSERVATION_REQUEST, id=observation_request.observation_id),
            status=status,
            output_artifact_refs=[
                EntityRef(entity_type=EntityKind.ARTIFACT, id=output_artifact.artifact_id),
            ],
            structured_summary=structured_summary,
            provenance={
                "backend_id": WATCHGUARD_LOGS_BACKEND_ID,
                "operation_kind": observation_request.operation_kind,
                "input_shape": result_batch.input_shape,
                "log_type": result_batch.log_type,
            },
        )
        return WatchGuardExecutionOutcome(
            artifacts=[output_artifact],
            observation_result=observation_result,
        )
    except (WatchGuardAdapterError, WatchGuardLogsBackendError, ContractViolationError) as exc:
        return WatchGuardExecutionOutcome(
            artifacts=[],
            observation_result=ObservationResult(
                observation_ref=EntityRef(
                    entity_type=EntityKind.OBSERVATION_REQUEST,
                    id=observation_request.observation_id,
                ),
                status=ObservationStatus.FAILED,
                structured_summary={"summary": "WatchGuard predefined observation failed."},
                errors=[str(exc)],
                provenance={
                    "backend_id": WATCHGUARD_LOGS_BACKEND_ID,
                    "operation_kind": observation_request.operation_kind,
                },
            ),
        )


def execute_guarded_custom_query(
    *,
    run: Run,
    input_artifact: Artifact,
    input_payload: object,
    query_request: QueryRequest,
) -> WatchGuardCustomQueryOutcome:
    """Execute the first guarded custom query slice over normalized WatchGuard traffic rows."""
    _validate_query_request(run=run, query_request=query_request)
    inspect_watchguard_input_artifact(input_artifact)
    normalized_batch = normalize_watchguard_log_payload(input_payload)
    query_spec = _parse_guarded_query_spec(query_request)
    filtered_rows, matched_row_count = _execute_guarded_filtered_rows_query(
        result_batch=normalized_batch,
        query_spec=query_spec,
    )
    artifact_payload = _build_guarded_query_artifact_payload(
        result_batch=normalized_batch,
        query_spec=query_spec,
        rows=filtered_rows,
        matched_row_count=matched_row_count,
    )
    artifact = _build_guarded_query_artifact(
        run=run,
        query_request=query_request,
        artifact_payload=artifact_payload,
    )
    return WatchGuardCustomQueryOutcome(
        artifacts=[artifact],
        query_summary={
            "query_class": WATCHGUARD_GUARDED_FILTERED_ROWS_QUERY_CLASS,
            "record_count": matched_row_count,
            "returned_row_count": len(filtered_rows),
            "limit": query_spec.limit,
            "truncated": matched_row_count > query_spec.limit,
            "top_row": (filtered_rows[0] if filtered_rows else None),
            "summary": _build_guarded_query_summary(
                matched_row_count=matched_row_count,
                returned_row_count=len(filtered_rows),
                limit=query_spec.limit,
            ),
        },
    )


def execute_duckdb_workspace_query(
    *,
    run: Run,
    input_artifact: Artifact,
    input_payload: object,
    query_request: QueryRequest,
) -> WatchGuardCustomQueryOutcome:
    """Execute a guarded DuckDB query over staged WatchGuard CSV files in S3.

    The input artifact must be a staging manifest produced by stage_workspace_zip.
    The query_request.parameters must include a 'query' dict with:
      family: 'traffic' | 'event' | 'alarm'
      filters: list of {field, op, value}
      limit: int (max 500)
    """
    if query_request.backend_ref.id != WATCHGUARD_LOGS_BACKEND_ID:
        raise InvalidWatchGuardQueryError("query backend is not watchguard_logs")
    if query_request.requested_scope != WATCHGUARD_DUCKDB_WORKSPACE_QUERY_CLASS:
        raise InvalidWatchGuardQueryError(
            f"unsupported requested_scope '{query_request.requested_scope}' for DuckDB workspace queries"
        )

    staging = _parse_staging_manifest(input_payload)
    raw_query = query_request.parameters.get("query")
    if not isinstance(raw_query, dict):
        raise InvalidWatchGuardQueryError("DuckDB workspace query must include a 'query' mapping in parameters")

    family = raw_query.get("family", WATCHGUARD_TRAFFIC_LOG_TYPE)
    if family not in WATCHGUARD_INGESTION_FAMILIES:
        raise InvalidWatchGuardQueryError(
            f"DuckDB workspace query 'family' must be one of: {', '.join(WATCHGUARD_INGESTION_FAMILIES)}"
        )
    raw_filters = raw_query.get("filters", [])
    if not isinstance(raw_filters, list):
        raise InvalidWatchGuardQueryError("DuckDB workspace query 'filters' must be a list")
    limit = int(raw_query.get("limit", GUARDED_QUERY_DEFAULT_LIMIT))
    if limit < 1 or limit > _DUCKDB_MAX_LIMIT:
        raise InvalidWatchGuardQueryError(f"DuckDB workspace query limit must be between 1 and {_DUCKDB_MAX_LIMIT}")

    rows, matched_count = _run_duckdb_filtered_query(
        bucket=staging["bucket"],
        staging_prefix=staging["staging_prefix"],
        family=family,
        raw_filters=raw_filters,
        limit=limit,
    )

    artifact_payload: dict[str, Any] = {
        "query_class": WATCHGUARD_DUCKDB_WORKSPACE_QUERY_CLASS,
        "workspace": staging["workspace"],
        "staging_prefix": staging["staging_prefix"],
        "family": family,
        "filters": raw_filters,
        "limit": limit,
        "matched_row_count": matched_count,
        "returned_row_count": len(rows),
        "truncated": matched_count > limit,
        "rows": rows,
    }
    serialized = json.dumps(artifact_payload, sort_keys=True)
    content_hash = hashlib.sha256(serialized.encode("utf-8")).hexdigest()
    artifact = Artifact(
        kind=ArtifactKind.QUERY_RESULT,
        subtype="watchguard.duckdb_workspace_query",
        format="json",
        storage_ref=(
            f"backend://watchguard_logs/runs/{run.run_id}/"
            f"queries/{query_request.query_request_id}/duckdb_workspace_query.json"
        ),
        content_hash=f"sha256:{content_hash}",
        produced_by_backend_ref=EntityRef(entity_type=EntityKind.BACKEND, id=WATCHGUARD_LOGS_BACKEND_ID),
        produced_by_run_ref=EntityRef(entity_type=EntityKind.RUN, id=run.run_id),
        summary=(
            f"DuckDB query over {family} logs: {len(rows)} rows returned "
            f"(matched {matched_count}, limit {limit})."
        ),
        metadata=artifact_payload,
    )
    return WatchGuardCustomQueryOutcome(
        artifacts=[artifact],
        query_summary={
            "query_class": WATCHGUARD_DUCKDB_WORKSPACE_QUERY_CLASS,
            "family": family,
            "matched_row_count": matched_count,
            "returned_row_count": len(rows),
            "limit": limit,
            "truncated": matched_count > limit,
        },
    )


def _execute_stage_workspace_zip(
    *,
    run: Run,
    input_artifact: Artifact,
    input_payload: object,
    observation_request: ObservationRequest,
) -> WatchGuardExecutionOutcome:
    """Download the workspace ZIP from S3 to a temp file, extract TARs → CSVs, upload to S3 staging."""
    reference = parse_workspace_s3_zip_reference(input_payload)
    upload_id = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    staging_prefix = f"workspaces/{reference.workspace}/staging/{upload_id}"

    with tempfile.TemporaryDirectory() as tmp_dir:
        zip_path = os.path.join(tmp_dir, "raw.zip")
        _download_s3_object_to_file(reference.bucket, reference.object_key, zip_path)
        stats = _stage_zip_to_s3(
            zip_path=zip_path,
            bucket=reference.bucket,
            staging_prefix=staging_prefix,
            workspace=reference.workspace,
        )

    manifest_payload: dict[str, Any] = {
        "source": "workspace_staging",
        "workspace": reference.workspace,
        "upload_id": upload_id,
        "staging_prefix": staging_prefix,
        "bucket": reference.bucket,
        "origin_s3_uri": reference.s3_uri,
        "families": stats["families"],
        "date_range": stats["date_range"],
        "total_csv_files": stats["total_csv_files"],
        "family_counts": stats["family_counts"],
    }
    manifest_artifact = Artifact(
        kind=ArtifactKind.ANALYSIS_OUTPUT,
        subtype="watchguard.workspace_staging_manifest",
        format="json",
        storage_ref=(
            f"backend://watchguard_logs/runs/{run.run_id}/"
            f"observations/{observation_request.observation_id}/staging_manifest.json"
        ),
        content_hash=_content_hash_for_payload(manifest_payload),
        produced_by_backend_ref=EntityRef(entity_type=EntityKind.BACKEND, id=WATCHGUARD_LOGS_BACKEND_ID),
        produced_by_run_ref=EntityRef(entity_type=EntityKind.RUN, id=run.run_id),
        produced_by_observation_ref=EntityRef(
            entity_type=EntityKind.OBSERVATION_REQUEST,
            id=observation_request.observation_id,
        ),
        summary=(
            f"Staged workspace ZIP to s3://{reference.bucket}/{staging_prefix} — "
            f"{stats['total_csv_files']} CSV files across {len(stats['families'])} families."
        ),
        metadata=manifest_payload,
    )
    total_files = stats["total_csv_files"]
    status = ObservationStatus.SUCCEEDED if total_files > 0 else ObservationStatus.SUCCEEDED_NO_FINDINGS
    observation_result = ObservationResult(
        observation_ref=EntityRef(entity_type=EntityKind.OBSERVATION_REQUEST, id=observation_request.observation_id),
        status=status,
        output_artifact_refs=[EntityRef(entity_type=EntityKind.ARTIFACT, id=manifest_artifact.artifact_id)],
        structured_summary={
            "workspace": reference.workspace,
            "staging_prefix": staging_prefix,
            "bucket": reference.bucket,
            "upload_id": upload_id,
            "total_csv_files": total_files,
            "families": stats["families"],
            "date_range": stats["date_range"],
            "family_counts": stats["family_counts"],
            "summary": (
                f"Staged {total_files} CSV files from workspace ZIP to "
                f"s3://{reference.bucket}/{staging_prefix}."
            ),
        },
        provenance={
            "backend_id": WATCHGUARD_LOGS_BACKEND_ID,
            "operation_kind": observation_request.operation_kind,
            "origin_s3_uri": reference.s3_uri,
            "staging_prefix": staging_prefix,
        },
    )
    return WatchGuardExecutionOutcome(artifacts=[manifest_artifact], observation_result=observation_result)


def _execute_duckdb_workspace_analytics(
    *,
    run: Run,
    input_artifact: Artifact,
    input_payload: object,
    observation_request: ObservationRequest,
) -> WatchGuardExecutionOutcome:
    """Run DuckDB analytics over staged CSV files in S3. Returns aggregations only — no raw rows."""
    staging = _parse_staging_manifest(input_payload)
    analytics = _run_duckdb_analytics(
        bucket=staging["bucket"],
        staging_prefix=staging["staging_prefix"],
        families=staging.get("families", list(WATCHGUARD_INGESTION_FAMILIES)),
    )

    analytics_payload: dict[str, Any] = _jsonify({
        "source": "duckdb_workspace_analytics",
        "workspace": staging["workspace"],
        "staging_prefix": staging["staging_prefix"],
        "upload_id": staging.get("upload_id", ""),
        **analytics,
    })
    artifact = Artifact(
        kind=ArtifactKind.ANALYSIS_OUTPUT,
        subtype="watchguard.duckdb_workspace_analytics",
        format="json",
        storage_ref=(
            f"backend://watchguard_logs/runs/{run.run_id}/"
            f"observations/{observation_request.observation_id}/duckdb_workspace_analytics.json"
        ),
        content_hash=_content_hash_for_payload(analytics_payload),
        produced_by_backend_ref=EntityRef(entity_type=EntityKind.BACKEND, id=WATCHGUARD_LOGS_BACKEND_ID),
        produced_by_run_ref=EntityRef(entity_type=EntityKind.RUN, id=run.run_id),
        produced_by_observation_ref=EntityRef(
            entity_type=EntityKind.OBSERVATION_REQUEST,
            id=observation_request.observation_id,
        ),
        summary=f"DuckDB analytics over staged WatchGuard logs at {staging['staging_prefix']}.",
        metadata=analytics_payload,
    )
    traffic_count = analytics.get("traffic", {}).get("total_rows", 0)
    status = ObservationStatus.SUCCEEDED if traffic_count > 0 else ObservationStatus.SUCCEEDED_NO_FINDINGS
    observation_result = ObservationResult(
        observation_ref=EntityRef(entity_type=EntityKind.OBSERVATION_REQUEST, id=observation_request.observation_id),
        status=status,
        output_artifact_refs=[EntityRef(entity_type=EntityKind.ARTIFACT, id=artifact.artifact_id)],
        structured_summary={
            "workspace": staging["workspace"],
            "staging_prefix": staging["staging_prefix"],
            "traffic_total_rows": traffic_count,
            "alarm_total_rows": analytics.get("alarm", {}).get("total_rows", 0),
            "event_total_rows": analytics.get("event", {}).get("total_rows", 0),
            "summary": (
                f"DuckDB analytics completed: {traffic_count} traffic rows, "
                f"{analytics.get('alarm', {}).get('total_rows', 0)} alarm rows."
            ),
        },
        provenance={
            "backend_id": WATCHGUARD_LOGS_BACKEND_ID,
            "operation_kind": observation_request.operation_kind,
            "staging_prefix": staging["staging_prefix"],
        },
    )
    return WatchGuardExecutionOutcome(artifacts=[artifact], observation_result=observation_result)


def _ddos_make_artifact(
    *,
    run: Run,
    observation_request: ObservationRequest,
    payload: dict[str, Any],
    subtype: str,
    summary: str,
) -> Artifact:
    serialized = json.dumps(payload, sort_keys=True)
    content_hash = hashlib.sha256(serialized.encode("utf-8")).hexdigest()
    return Artifact(
        kind=ArtifactKind.ANALYSIS_OUTPUT,
        subtype=subtype,
        format="json",
        storage_ref=(
            f"backend://watchguard_logs/runs/{run.run_id}/"
            f"observations/{observation_request.observation_id}/{subtype.replace('.', '_')}.json"
        ),
        content_hash=f"sha256:{content_hash}",
        produced_by_backend_ref=EntityRef(entity_type=EntityKind.BACKEND, id=WATCHGUARD_LOGS_BACKEND_ID),
        produced_by_run_ref=EntityRef(entity_type=EntityKind.RUN, id=run.run_id),
        produced_by_observation_ref=EntityRef(
            entity_type=EntityKind.OBSERVATION_REQUEST,
            id=observation_request.observation_id,
        ),
        summary=summary,
        metadata=payload,
    )


def _ddos_make_outcome(
    *,
    run: Run,
    observation_request: ObservationRequest,
    payload: dict[str, Any],
    subtype: str,
    summary: str,
    structured_summary: dict[str, Any],
) -> "WatchGuardExecutionOutcome":
    artifact = _ddos_make_artifact(
        run=run,
        observation_request=observation_request,
        payload=payload,
        subtype=subtype,
        summary=summary,
    )
    observation_result = ObservationResult(
        observation_ref=EntityRef(
            entity_type=EntityKind.OBSERVATION_REQUEST,
            id=observation_request.observation_id,
        ),
        status=ObservationStatus.SUCCEEDED,
        output_artifact_refs=[EntityRef(entity_type=EntityKind.ARTIFACT, id=artifact.artifact_id)],
        structured_summary=structured_summary,
        provenance={
            "backend_id": WATCHGUARD_LOGS_BACKEND_ID,
            "operation_kind": observation_request.operation_kind,
        },
    )
    return WatchGuardExecutionOutcome(artifacts=[artifact], observation_result=observation_result)


def _execute_ddos_temporal_analysis(
    *,
    run: Run,
    input_artifact: Artifact,
    input_payload: object,
    observation_request: ObservationRequest,
) -> "WatchGuardExecutionOutcome":
    staging = _parse_staging_manifest(input_payload)
    result = _run_duckdb_ddos_temporal_analysis(
        bucket=staging["bucket"],
        staging_prefix=staging["staging_prefix"],
    )
    payload = {
        "source": "ddos_temporal_analysis",
        "workspace": staging["workspace"],
        "staging_prefix": staging["staging_prefix"],
        **result,
    }
    return _ddos_make_outcome(
        run=run,
        observation_request=observation_request,
        payload=payload,
        subtype="watchguard.ddos_temporal_analysis",
        summary=f"DDoS temporal analysis: {result.get('total_events', 0)} events over {len(result.get('by_day', []))} days. Peak day: {result.get('peak_day')}.",
        structured_summary={
            "total_events": result.get("total_events", 0),
            "peak_day": result.get("peak_day"),
            "peak_events": result.get("peak_events", 0),
            "date_range": result.get("date_range"),
        },
    )


def _execute_ddos_top_destinations(
    *,
    run: Run,
    input_artifact: Artifact,
    input_payload: object,
    observation_request: ObservationRequest,
) -> "WatchGuardExecutionOutcome":
    staging = _parse_staging_manifest(input_payload)
    result = _run_duckdb_ddos_top_destinations(
        bucket=staging["bucket"],
        staging_prefix=staging["staging_prefix"],
    )
    payload = {
        "source": "ddos_top_destinations",
        "workspace": staging["workspace"],
        "staging_prefix": staging["staging_prefix"],
        **result,
    }
    top = result.get("destinations", [{}])[0] if result.get("destinations") else {}
    return _ddos_make_outcome(
        run=run,
        observation_request=observation_request,
        payload=payload,
        subtype="watchguard.ddos_top_destinations",
        summary=f"Top destinations: {len(result.get('destinations', []))} IPs. #1: {top.get('dst_ip')} ({top.get('pct', 0):.1f}% of traffic).",
        structured_summary={
            "total_events": result.get("total_events", 0),
            "top_destination": top.get("dst_ip"),
            "top_destination_pct": top.get("pct"),
            "destination_count": len(result.get("destinations", [])),
        },
    )


def _execute_ddos_top_sources(
    *,
    run: Run,
    input_artifact: Artifact,
    input_payload: object,
    observation_request: ObservationRequest,
) -> "WatchGuardExecutionOutcome":
    staging = _parse_staging_manifest(input_payload)
    result = _run_duckdb_ddos_top_sources(
        bucket=staging["bucket"],
        staging_prefix=staging["staging_prefix"],
    )
    payload = {
        "source": "ddos_top_sources",
        "workspace": staging["workspace"],
        "staging_prefix": staging["staging_prefix"],
        **result,
    }
    top = result.get("sources", [{}])[0] if result.get("sources") else {}
    top_seg = result.get("segments", [{}])[0] if result.get("segments") else {}
    return _ddos_make_outcome(
        run=run,
        observation_request=observation_request,
        payload=payload,
        subtype="watchguard.ddos_top_sources",
        summary=f"Top sources: {len(result.get('sources', []))} IPs in {len(result.get('segments', []))} /16 segments. Dominant segment: {top_seg.get('segment')} ({top_seg.get('pct', 0):.1f}%).",
        structured_summary={
            "total_events": result.get("total_events", 0),
            "top_source": top.get("src_ip"),
            "top_source_pct": top.get("pct"),
            "dominant_segment": top_seg.get("segment"),
            "dominant_segment_pct": top_seg.get("pct"),
            "segment_count": len(result.get("segments", [])),
        },
    )


def _execute_ddos_segment_analysis(
    *,
    run: Run,
    input_artifact: Artifact,
    input_payload: object,
    observation_request: ObservationRequest,
) -> "WatchGuardExecutionOutcome":
    staging = _parse_staging_manifest(input_payload)
    segment = observation_request.parameters.get("segment", "")
    if not segment:
        raise UnsupportedWatchGuardObservationError(
            "ddos_segment_analysis requires 'segment' in observation parameters (e.g. '159.60.0.0/16')"
        )
    result = _run_duckdb_ddos_segment_analysis(
        bucket=staging["bucket"],
        staging_prefix=staging["staging_prefix"],
        segment=segment,
    )
    payload = {
        "source": "ddos_segment_analysis",
        "workspace": staging["workspace"],
        "staging_prefix": staging["staging_prefix"],
        **result,
    }
    return _ddos_make_outcome(
        run=run,
        observation_request=observation_request,
        payload=payload,
        subtype="watchguard.ddos_segment_analysis",
        summary=f"Segment {segment}: {result.get('total_events', 0)} events ({result.get('allow_events', 0)} allow / {result.get('deny_events', 0)} deny).",
        structured_summary={
            "segment": segment,
            "total_events": result.get("total_events", 0),
            "allow_events": result.get("allow_events", 0),
            "deny_events": result.get("deny_events", 0),
        },
    )


def _execute_ddos_ip_profile(
    *,
    run: Run,
    input_artifact: Artifact,
    input_payload: object,
    observation_request: ObservationRequest,
) -> "WatchGuardExecutionOutcome":
    staging = _parse_staging_manifest(input_payload)
    ip = observation_request.parameters.get("ip", "")
    if not ip:
        raise UnsupportedWatchGuardObservationError(
            "ddos_ip_profile requires 'ip' in observation parameters (e.g. '223.123.92.149')"
        )
    result = _run_duckdb_ddos_ip_profile(
        bucket=staging["bucket"],
        staging_prefix=staging["staging_prefix"],
        ip=ip,
    )
    payload = {
        "source": "ddos_ip_profile",
        "workspace": staging["workspace"],
        "staging_prefix": staging["staging_prefix"],
        **result,
    }
    return _ddos_make_outcome(
        run=run,
        observation_request=observation_request,
        payload=payload,
        subtype="watchguard.ddos_ip_profile",
        summary=f"IP {ip}: {result.get('total_events', 0)} events ({result.get('allow_events', 0)} allow / {result.get('deny_events', 0)} deny). Active {result.get('first_seen')} to {result.get('last_seen')}.",
        structured_summary={
            "ip": ip,
            "total_events": result.get("total_events", 0),
            "allow_events": result.get("allow_events", 0),
            "deny_events": result.get("deny_events", 0),
            "first_seen": result.get("first_seen"),
            "last_seen": result.get("last_seen"),
        },
    )


def _execute_ddos_hourly_distribution(
    *,
    run: Run,
    input_artifact: Artifact,
    input_payload: object,
    observation_request: ObservationRequest,
) -> "WatchGuardExecutionOutcome":
    staging = _parse_staging_manifest(input_payload)
    date = observation_request.parameters.get("date", "")
    if not date:
        raise UnsupportedWatchGuardObservationError(
            "ddos_hourly_distribution requires 'date' in observation parameters (e.g. '2025-10-16')"
        )
    result = _run_duckdb_ddos_hourly_distribution(
        bucket=staging["bucket"],
        staging_prefix=staging["staging_prefix"],
        date=date,
    )
    payload = {
        "source": "ddos_hourly_distribution",
        "workspace": staging["workspace"],
        "staging_prefix": staging["staging_prefix"],
        **result,
    }
    return _ddos_make_outcome(
        run=run,
        observation_request=observation_request,
        payload=payload,
        subtype="watchguard.ddos_hourly_distribution",
        summary=f"Hourly distribution for {date}: peak at hour {result.get('peak_hour')} with {result.get('peak_events', 0)} events. Pattern: {result.get('pattern')}.",
        structured_summary={
            "date": date,
            "peak_hour": result.get("peak_hour"),
            "peak_events": result.get("peak_events", 0),
            "pattern": result.get("pattern"),
            "total_events": result.get("total_events", 0),
        },
    )


def _execute_workspace_zip_ingestion(
    *,
    run: Run,
    input_artifact: Artifact,
    input_payload: object,
    observation_request: ObservationRequest,
) -> WatchGuardExecutionOutcome:
    reference = parse_workspace_s3_zip_reference(input_payload)
    root_bytes = _download_s3_object(reference.bucket, reference.object_key)
    discovered_files = _discover_workspace_files(root_bytes=root_bytes, root_name=reference.object_key)
    family_payloads = _build_family_payloads(reference=reference, discovered_files=discovered_files)
    manifest_payload = _build_ingestion_manifest(reference=reference, discovered_files=discovered_files, family_payloads=family_payloads)

    artifacts = [
        _build_workspace_manifest_artifact(
            run=run,
            observation_request=observation_request,
            manifest_payload=manifest_payload,
        )
    ]
    for family in WATCHGUARD_INGESTION_FAMILIES:
        payload = family_payloads.get(family)
        if payload is None:
            continue
        artifacts.append(
            _build_workspace_family_artifact(
                run=run,
                observation_request=observation_request,
                log_family=family,
                artifact_payload=payload,
            )
        )

    total_records = sum(int(payload["record_count"]) for payload in family_payloads.values())
    status = ObservationStatus.SUCCEEDED if total_records > 0 else ObservationStatus.SUCCEEDED_NO_FINDINGS
    observation_result = ObservationResult(
        observation_ref=EntityRef(entity_type=EntityKind.OBSERVATION_REQUEST, id=observation_request.observation_id),
        status=status,
        output_artifact_refs=[EntityRef(entity_type=EntityKind.ARTIFACT, id=artifact.artifact_id) for artifact in artifacts],
        structured_summary={
            "workspace": reference.workspace,
            "source_kind": WATCHGUARD_WORKSPACE_S3_ZIP_SOURCE_KIND,
            "s3_uri": reference.s3_uri,
            "artifact_count": len(artifacts),
            "family_counts": manifest_payload["family_counts"],
            "summary": (
                f"Ingested workspace ZIP from {reference.s3_uri} and classified "
                f"{total_records} rows across {len(family_payloads)} WatchGuard families."
            ),
        },
        provenance={
            "backend_id": WATCHGUARD_LOGS_BACKEND_ID,
            "operation_kind": observation_request.operation_kind,
            "source_kind": WATCHGUARD_WORKSPACE_S3_ZIP_SOURCE_KIND,
            "workspace": reference.workspace,
            "s3_uri": reference.s3_uri,
        },
    )
    return WatchGuardExecutionOutcome(artifacts=artifacts, observation_result=observation_result)


def _validate_observation_request(*, run: Run, observation_request: ObservationRequest) -> None:
    if observation_request.operation_kind not in {
        WATCHGUARD_WORKSPACE_ZIP_INGESTION_OPERATION,
        WATCHGUARD_NORMALIZE_SUMMARY_OPERATION,
        WATCHGUARD_FILTER_DENIED_EVENTS_OPERATION,
        WATCHGUARD_ANALYTICS_BUNDLE_BASIC_OPERATION,
        WATCHGUARD_TOP_TALKERS_BASIC_OPERATION,
        WATCHGUARD_STAGE_WORKSPACE_ZIP_OPERATION,
        WATCHGUARD_DUCKDB_WORKSPACE_ANALYTICS_OPERATION,
        WATCHGUARD_DDOS_TEMPORAL_ANALYSIS_OPERATION,
        WATCHGUARD_DDOS_TOP_DESTINATIONS_OPERATION,
        WATCHGUARD_DDOS_TOP_SOURCES_OPERATION,
        WATCHGUARD_DDOS_SEGMENT_ANALYSIS_OPERATION,
        WATCHGUARD_DDOS_IP_PROFILE_OPERATION,
        WATCHGUARD_DDOS_HOURLY_DISTRIBUTION_OPERATION,
        WATCHGUARD_DDOS_PROTOCOL_BREAKDOWN_OPERATION,
    }:
        raise UnsupportedWatchGuardObservationError(
            f"unsupported operation_kind '{observation_request.operation_kind}'"
        )
    if observation_request.run_ref.id != run.run_id:
        raise ContractViolationError("observation_request.run_ref must match the target run")
    if run.backend_ref.id != WATCHGUARD_LOGS_BACKEND_ID:
        raise UnsupportedWatchGuardObservationError("run backend is not watchguard_logs")


def _validate_query_request(*, run: Run, query_request: QueryRequest) -> None:
    if query_request.backend_ref.id != WATCHGUARD_LOGS_BACKEND_ID:
        raise InvalidWatchGuardQueryError("query backend is not watchguard_logs")
    if query_request.run_ref is None or query_request.run_ref.id != run.run_id:
        raise ContractViolationError("query_request.run_ref must match the target run")
    if run.backend_ref.id != WATCHGUARD_LOGS_BACKEND_ID:
        raise InvalidWatchGuardQueryError("run backend is not watchguard_logs")
    if query_request.requested_scope != WATCHGUARD_GUARDED_FILTERED_ROWS_QUERY_CLASS:
        raise InvalidWatchGuardQueryError(
            f"unsupported requested_scope '{query_request.requested_scope}' for guarded WatchGuard queries"
        )


def _build_result_batch(*, normalized_batch, operation_kind: str):
    if operation_kind == WATCHGUARD_FILTER_DENIED_EVENTS_OPERATION:
        return filter_denied_watchguard_batch(normalized_batch)
    return normalized_batch


def _build_output_artifact(
    *,
    run: Run,
    observation_request: ObservationRequest,
    result_batch,
) -> Artifact:
    artifact_payload = _build_output_artifact_payload(
        operation_kind=observation_request.operation_kind,
        result_batch=result_batch,
    )
    serialized_batch = json.dumps(artifact_payload, sort_keys=True)
    content_hash = hashlib.sha256(serialized_batch.encode("utf-8")).hexdigest()
    return Artifact(
        kind=_artifact_kind(observation_request.operation_kind),
        subtype=_artifact_subtype(observation_request.operation_kind),
        format="json",
        storage_ref=_artifact_storage_ref(
            run_id=run.run_id,
            observation_id=observation_request.observation_id,
            operation_kind=observation_request.operation_kind,
        ),
        content_hash=f"sha256:{content_hash}",
        produced_by_backend_ref=EntityRef(entity_type=EntityKind.BACKEND, id=WATCHGUARD_LOGS_BACKEND_ID),
        produced_by_run_ref=EntityRef(entity_type=EntityKind.RUN, id=run.run_id),
        produced_by_observation_ref=EntityRef(
            entity_type=EntityKind.OBSERVATION_REQUEST,
            id=observation_request.observation_id,
        ),
        summary=_build_summary(
            operation_kind=observation_request.operation_kind,
            record_count=result_batch.record_count,
        ),
        metadata=artifact_payload,
    )


def _build_output_artifact_payload(*, operation_kind: str, result_batch) -> dict[str, object]:
    if operation_kind == WATCHGUARD_ANALYTICS_BUNDLE_BASIC_OPERATION:
        return _build_analytics_bundle_basic(result_batch)
    if operation_kind == WATCHGUARD_TOP_TALKERS_BASIC_OPERATION:
        return _build_top_talkers_basic(result_batch)
    return {
        "records": [record.__dict__ for record in result_batch.records],
        "record_count": result_batch.record_count,
        "action_counts": result_batch.action_counts,
        "input_shape": result_batch.input_shape,
        "log_type": result_batch.log_type,
        "operation_kind": operation_kind,
    }


def _build_analytics_bundle_basic(result_batch) -> dict[str, object]:
    action_counts = _sorted_count_dict(record.action for record in result_batch.records)
    top_source_ips = _build_ranked_values(
        ((record.src_ip, "ip") for record in result_batch.records if record.src_ip),
    )
    top_destination_ips = _build_ranked_values(
        ((record.dst_ip, "ip") for record in result_batch.records if record.dst_ip),
    )
    protocol_breakdown = _build_ranked_values(
        ((record.protocol, "protocol") for record in result_batch.records if record.protocol),
    )
    time_range = _build_time_range(record.timestamp for record in result_batch.records)

    return {
        "input_shape": result_batch.input_shape,
        "log_type": result_batch.log_type,
        "record_count": result_batch.record_count,
        "time_range": time_range,
        "action_counts": action_counts,
        "top_source_ips": top_source_ips,
        "top_destination_ips": top_destination_ips,
        "protocol_breakdown": protocol_breakdown,
        "operation_kind": WATCHGUARD_ANALYTICS_BUNDLE_BASIC_OPERATION,
    }


def _build_top_talkers_basic(result_batch) -> dict[str, object]:
    top_source_ips = _build_ranked_values(
        ((record.src_ip, "ip") for record in result_batch.records if record.src_ip),
    )
    top_destination_ips = _build_ranked_values(
        ((record.dst_ip, "ip") for record in result_batch.records if record.dst_ip),
    )
    top_source_destination_pairs = _build_ranked_pairs(
        (
            (record.src_ip, record.dst_ip)
            for record in result_batch.records
            if record.src_ip and record.dst_ip
        ),
    )

    return {
        "input_shape": result_batch.input_shape,
        "log_type": result_batch.log_type,
        "record_count": result_batch.record_count,
        "top_source_ips": top_source_ips,
        "top_destination_ips": top_destination_ips,
        "top_source_destination_pairs": top_source_destination_pairs,
        "operation_kind": WATCHGUARD_TOP_TALKERS_BASIC_OPERATION,
    }


def _parse_guarded_query_spec(query_request: QueryRequest) -> WatchGuardGuardedQuerySpec:
    query_spec = query_request.parameters.get("query")
    if not isinstance(query_spec, dict):
        raise InvalidWatchGuardQueryError("guarded WatchGuard query must include a 'query' mapping in parameters")

    filters = query_spec.get("filters")
    if not isinstance(filters, list) or not filters:
        raise InvalidWatchGuardQueryError("guarded WatchGuard query must include at least one filter")
    if len(filters) > GUARDED_QUERY_MAX_FILTERS:
        raise InvalidWatchGuardQueryError(
            f"guarded WatchGuard query supports at most {GUARDED_QUERY_MAX_FILTERS} filters"
        )

    limit = query_spec.get("limit", GUARDED_QUERY_DEFAULT_LIMIT)
    if not isinstance(limit, int) or limit < 1:
        raise InvalidWatchGuardQueryError("guarded WatchGuard query limit must be a positive integer")
    if limit > GUARDED_QUERY_MAX_LIMIT:
        raise InvalidWatchGuardQueryError(f"guarded WatchGuard query limit must be <= {GUARDED_QUERY_MAX_LIMIT}")

    parsed_filters: list[WatchGuardGuardedFilter] = []
    for index, raw_filter in enumerate(filters):
        if not isinstance(raw_filter, dict):
            raise InvalidWatchGuardQueryError(f"guarded WatchGuard filter at index {index} must be a mapping")
        field = raw_filter.get("field")
        op = raw_filter.get("op")
        raw_value = raw_filter.get("value")

        if field not in GUARDED_QUERY_ALLOWED_FIELDS:
            allowed = ", ".join(sorted(GUARDED_QUERY_ALLOWED_FIELDS))
            raise InvalidWatchGuardQueryError(
                f"guarded WatchGuard filter field '{field}' is not allowed; expected one of: {allowed}"
            )
        if op not in GUARDED_QUERY_ALLOWED_OPS:
            allowed = ", ".join(sorted(GUARDED_QUERY_ALLOWED_OPS))
            raise InvalidWatchGuardQueryError(
                f"guarded WatchGuard filter op '{op}' is not allowed; expected one of: {allowed}"
            )

        if op == "eq":
            if not isinstance(raw_value, str) or not raw_value.strip():
                raise InvalidWatchGuardQueryError(
                    f"guarded WatchGuard filter at index {index} requires a non-empty string value for op 'eq'"
                )
            parsed_value: str | tuple[str, ...] = _normalize_guarded_query_value(field, raw_value)
        else:
            if (
                not isinstance(raw_value, list)
                or not raw_value
                or len(raw_value) > GUARDED_QUERY_MAX_IN_VALUES
                or not all(isinstance(item, str) and item.strip() for item in raw_value)
            ):
                raise InvalidWatchGuardQueryError(
                    f"guarded WatchGuard filter at index {index} requires 1..{GUARDED_QUERY_MAX_IN_VALUES} non-empty string values for op 'in'"
                )
            parsed_value = tuple(_normalize_guarded_query_value(field, item) for item in raw_value)

        parsed_filters.append(
            WatchGuardGuardedFilter(
                field=field,
                op=op,
                value=parsed_value,
            )
        )

    return WatchGuardGuardedQuerySpec(filters=tuple(parsed_filters), limit=limit)


def _normalize_guarded_query_value(field: str, value: str) -> str:
    normalized = value.strip()
    if field in {"action", "protocol"}:
        return normalized.lower()
    return normalized


def _execute_guarded_filtered_rows_query(*, result_batch, query_spec: WatchGuardGuardedQuerySpec) -> tuple[list[dict[str, Any]], int]:
    matched_records = [
        record
        for record in result_batch.records
        if all(_record_matches_filter(record, query_filter) for query_filter in query_spec.filters)
    ]
    sorted_records = sorted(matched_records, key=_guarded_query_sort_key)
    returned_records = sorted_records[: query_spec.limit]
    rows = [_serialize_guarded_query_row(record) for record in returned_records]
    return rows, len(sorted_records)


def _record_matches_filter(record, query_filter: WatchGuardGuardedFilter) -> bool:
    record_value = getattr(record, query_filter.field)
    if record_value is None:
        return False
    if query_filter.op == "eq":
        return record_value == query_filter.value
    return record_value in query_filter.value


def _guarded_query_sort_key(record) -> tuple[object, ...]:
    return (
        record.timestamp,
        record.src_ip,
        record.dst_ip,
        record.action,
        record.protocol,
        record.policy or "",
        record.src_port if record.src_port is not None else -1,
        record.dst_port if record.dst_port is not None else -1,
        record.question or "",
        record.record_type or "",
    )


def _serialize_guarded_query_row(record) -> dict[str, Any]:
    return {
        "timestamp": record.timestamp,
        "src_ip": record.src_ip,
        "dst_ip": record.dst_ip,
        "action": record.action,
        "protocol": record.protocol,
        "policy": record.policy,
        "src_port": record.src_port,
        "dst_port": record.dst_port,
        "question": record.question,
        "record_type": record.record_type,
    }


def _build_guarded_query_artifact_payload(
    *,
    result_batch,
    query_spec: WatchGuardGuardedQuerySpec,
    rows: list[dict[str, Any]],
    matched_row_count: int,
) -> dict[str, Any]:
    return {
        "query_class": WATCHGUARD_GUARDED_FILTERED_ROWS_QUERY_CLASS,
        "input_shape": result_batch.input_shape,
        "log_type": result_batch.log_type,
        "filters": [_serialize_guarded_filter(item) for item in query_spec.filters],
        "limit": query_spec.limit,
        "matched_row_count": matched_row_count,
        "returned_row_count": len(rows),
        "truncated": matched_row_count > query_spec.limit,
        "rows": rows,
    }


def _serialize_guarded_filter(query_filter: WatchGuardGuardedFilter) -> dict[str, Any]:
    value: Any = query_filter.value
    if isinstance(value, tuple):
        value = list(value)
    return {
        "field": query_filter.field,
        "op": query_filter.op,
        "value": value,
    }


def _build_guarded_query_artifact(
    *,
    run: Run,
    query_request: QueryRequest,
    artifact_payload: dict[str, Any],
) -> Artifact:
    serialized_payload = json.dumps(artifact_payload, sort_keys=True)
    content_hash = hashlib.sha256(serialized_payload.encode("utf-8")).hexdigest()
    return Artifact(
        kind=ArtifactKind.QUERY_RESULT,
        subtype="watchguard.guarded_filtered_rows",
        format="json",
        storage_ref=(
            f"backend://watchguard_logs/runs/{run.run_id}/"
            f"queries/{query_request.query_request_id}/guarded_filtered_rows.json"
        ),
        content_hash=f"sha256:{content_hash}",
        produced_by_backend_ref=EntityRef(entity_type=EntityKind.BACKEND, id=WATCHGUARD_LOGS_BACKEND_ID),
        produced_by_run_ref=EntityRef(entity_type=EntityKind.RUN, id=run.run_id),
        summary=_build_guarded_query_summary(
            matched_row_count=artifact_payload["matched_row_count"],
            returned_row_count=artifact_payload["returned_row_count"],
            limit=artifact_payload["limit"],
        ),
        metadata=artifact_payload,
    )


def _build_guarded_query_summary(*, matched_row_count: int, returned_row_count: int, limit: int) -> str:
    return (
        "Returned "
        f"{returned_row_count} WatchGuard rows for the guarded custom query "
        f"(matched {matched_row_count}, limit {limit})."
    )


def _build_ranked_values(values, *, top_n: int = 5) -> list[dict[str, object]]:
    counter: Counter[str] = Counter()
    value_key: str | None = None
    for value, key_name in values:
        counter[value] += 1
        value_key = key_name

    if not counter or value_key is None:
        return []

    ranked = sorted(counter.items(), key=lambda item: (-item[1], item[0]))
    return [{value_key: value, "count": count} for value, count in ranked[:top_n]]


def _build_ranked_pairs(pairs, *, top_n: int = 5) -> list[dict[str, object]]:
    counter: Counter[tuple[str, str]] = Counter()
    for src_ip, dst_ip in pairs:
        counter[(src_ip, dst_ip)] += 1

    ranked = sorted(counter.items(), key=lambda item: (-item[1], item[0][0], item[0][1]))
    return [
        {"src_ip": src_ip, "dst_ip": dst_ip, "count": count}
        for (src_ip, dst_ip), count in ranked[:top_n]
    ]


def _sorted_count_dict(values) -> dict[str, int]:
    counter = Counter(values)
    return {key: counter[key] for key in sorted(counter)}


def _build_time_range(timestamps) -> dict[str, str | None]:
    parsed = []
    for timestamp in timestamps:
        parsed_dt = _parse_normalized_timestamp(timestamp)
        if parsed_dt is not None:
            parsed.append(parsed_dt)
    if not parsed:
        return {"ts_min": None, "ts_max": None}
    return {
        "ts_min": _format_timestamp(min(parsed)),
        "ts_max": _format_timestamp(max(parsed)),
    }


def _parse_normalized_timestamp(value: str) -> datetime | None:
    normalized = value.strip()
    if not normalized:
        return None
    try:
        return datetime.fromisoformat(normalized.replace("Z", "+00:00")).astimezone(timezone.utc)
    except ValueError:
        return None


def _format_timestamp(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def _build_structured_summary(*, operation_kind: str, result_batch) -> dict[str, object]:
    if operation_kind == WATCHGUARD_ANALYTICS_BUNDLE_BASIC_OPERATION:
        analytics_bundle = _build_analytics_bundle_basic(result_batch)
        return {
            "record_count": analytics_bundle["record_count"],
            "input_shape": analytics_bundle["input_shape"],
            "log_type": analytics_bundle["log_type"],
            "action_counts": analytics_bundle["action_counts"],
            "top_source_ip": (analytics_bundle["top_source_ips"][0] if analytics_bundle["top_source_ips"] else None),
            "top_destination_ip": (
                analytics_bundle["top_destination_ips"][0] if analytics_bundle["top_destination_ips"] else None
            ),
            "top_protocol": (
                analytics_bundle["protocol_breakdown"][0] if analytics_bundle["protocol_breakdown"] else None
            ),
            "summary": _build_summary(
                operation_kind=operation_kind,
                record_count=result_batch.record_count,
            ),
        }
    if operation_kind == WATCHGUARD_TOP_TALKERS_BASIC_OPERATION:
        top_talkers = _build_top_talkers_basic(result_batch)
        return {
            "record_count": top_talkers["record_count"],
            "input_shape": top_talkers["input_shape"],
            "log_type": top_talkers["log_type"],
            "top_source_ip": (top_talkers["top_source_ips"][0] if top_talkers["top_source_ips"] else None),
            "top_destination_ip": (
                top_talkers["top_destination_ips"][0] if top_talkers["top_destination_ips"] else None
            ),
            "top_pair": (
                top_talkers["top_source_destination_pairs"][0]
                if top_talkers["top_source_destination_pairs"]
                else None
            ),
            "summary": _build_summary(
                operation_kind=operation_kind,
                record_count=result_batch.record_count,
            ),
        }

    return {
        "record_count": result_batch.record_count,
        "action_counts": result_batch.action_counts,
        "input_shape": result_batch.input_shape,
        "log_type": result_batch.log_type,
        "denied_record_count": (
            result_batch.record_count
            if operation_kind == WATCHGUARD_FILTER_DENIED_EVENTS_OPERATION
            else None
        ),
        "summary": _build_summary(
            operation_kind=operation_kind,
            record_count=result_batch.record_count,
        ),
    }


def _artifact_kind(operation_kind: str) -> ArtifactKind:
    if operation_kind in {
        WATCHGUARD_ANALYTICS_BUNDLE_BASIC_OPERATION,
        WATCHGUARD_TOP_TALKERS_BASIC_OPERATION,
    }:
        return ArtifactKind.ANALYSIS_OUTPUT
    return ArtifactKind.NORMALIZED


def _artifact_subtype(operation_kind: str) -> str:
    if operation_kind == WATCHGUARD_ANALYTICS_BUNDLE_BASIC_OPERATION:
        return "watchguard.analytics_bundle_basic"
    if operation_kind == WATCHGUARD_TOP_TALKERS_BASIC_OPERATION:
        return "watchguard.top_talkers_basic"
    if operation_kind == WATCHGUARD_FILTER_DENIED_EVENTS_OPERATION:
        return "watchguard.denied_events"
    return "watchguard.log_summary"


def _artifact_storage_ref(*, run_id: str, observation_id: str, operation_kind: str) -> str:
    if operation_kind == WATCHGUARD_ANALYTICS_BUNDLE_BASIC_OPERATION:
        filename = "analytics_bundle_basic.json"
    elif operation_kind == WATCHGUARD_TOP_TALKERS_BASIC_OPERATION:
        filename = "top_talkers_basic.json"
    else:
        filename = "normalized.json"
    return (
        f"backend://watchguard_logs/runs/{run_id}/"
        f"observations/{observation_id}/{filename}"
    )


def _build_summary(*, operation_kind: str, record_count: int) -> str:
    if operation_kind == WATCHGUARD_WORKSPACE_ZIP_INGESTION_OPERATION:
        return f"Ingested {record_count} WatchGuard rows from a workspace ZIP in S3."
    if operation_kind == WATCHGUARD_ANALYTICS_BUNDLE_BASIC_OPERATION:
        return f"Built a basic WatchGuard analytics bundle from {record_count} log records."
    if operation_kind == WATCHGUARD_TOP_TALKERS_BASIC_OPERATION:
        return f"Built a basic WatchGuard top-talkers summary from {record_count} log records."
    if operation_kind == WATCHGUARD_FILTER_DENIED_EVENTS_OPERATION:
        return f"Filtered {record_count} denied WatchGuard log records."
    return f"Normalized {record_count} WatchGuard log records."


def _download_s3_object(bucket: str, object_key: str) -> bytes:
    try:
        import boto3
    except ImportError as exc:  # pragma: no cover
        raise WatchGuardLogsBackendError("boto3 is required to ingest workspace ZIPs from S3") from exc

    client = boto3.client("s3")
    response = client.get_object(Bucket=bucket, Key=object_key)
    body = response.get("Body")
    if body is None:
        raise WatchGuardLogsBackendError(f"s3://{bucket}/{object_key} returned no body")
    content = body.read()
    if not isinstance(content, bytes) or not content:
        raise WatchGuardLogsBackendError(f"s3://{bucket}/{object_key} is empty")
    return content


def _discover_workspace_files(*, root_bytes: bytes, root_name: str) -> list[dict[str, Any]]:
    discovered: list[dict[str, Any]] = []
    _collect_archive_entries(
        data=root_bytes,
        path=root_name,
        compression_chain=[],
        discovered=discovered,
    )
    return discovered


def _collect_archive_entries(
    *,
    data: bytes,
    path: str,
    compression_chain: list[str],
    discovered: list[dict[str, Any]],
) -> None:
    normalized_path = path.replace("\\", "/")

    if normalized_path.lower().endswith(".zip"):
        try:
            with zipfile.ZipFile(io.BytesIO(data)) as archive:
                for member in archive.infolist():
                    if member.is_dir():
                        continue
                    _collect_archive_entries(
                        data=archive.read(member),
                        path=f"{normalized_path}!{member.filename}",
                        compression_chain=[*compression_chain, "zip"],
                        discovered=discovered,
                    )
        except zipfile.BadZipFile as exc:
            raise WatchGuardLogsBackendError(f"invalid ZIP content encountered at '{normalized_path}'") from exc
        return

    if normalized_path.lower().endswith(".tar"):
        try:
            with tarfile.open(fileobj=io.BytesIO(data), mode="r:*") as archive:
                for member in archive.getmembers():
                    if not member.isfile():
                        continue
                    extracted = archive.extractfile(member)
                    if extracted is None:
                        continue
                    _collect_archive_entries(
                        data=extracted.read(),
                        path=f"{normalized_path}!{member.name}",
                        compression_chain=[*compression_chain, "tar"],
                        discovered=discovered,
                    )
        except tarfile.TarError as exc:
            raise WatchGuardLogsBackendError(f"invalid TAR content encountered at '{normalized_path}'") from exc
        return

    if normalized_path.lower().endswith(".gz"):
        try:
            decompressed = gzip.decompress(data)
        except OSError as exc:
            raise WatchGuardLogsBackendError(f"invalid GZ content encountered at '{normalized_path}'") from exc
        decompressed_path = normalized_path[:-3]
        _collect_archive_entries(
            data=decompressed,
            path=decompressed_path,
            compression_chain=[*compression_chain, "gz"],
            discovered=discovered,
        )
        return

    if not normalized_path.lower().endswith((".csv", ".txt")):
        return

    classification = _classify_workspace_entry(normalized_path)
    if classification is None:
        return

    text = data.decode("utf-8", errors="replace")
    if not text.strip():
        return

    discovered.append(
        {
            "log_family": classification["log_family"],
            "date": classification["date"],
            "source_path_in_archive": normalized_path,
            "compression_chain": list(compression_chain),
            "text": text,
        }
    )


def _classify_workspace_entry(path: str) -> dict[str, str] | None:
    cleaned_path = path.replace("!", "/")
    segments = [segment for segment in cleaned_path.split("/") if segment]
    for index, segment in enumerate(segments[:-1]):
        if segment not in WATCHGUARD_INGESTION_FAMILIES:
            continue
        if index + 1 >= len(segments):
            continue
        date_part = segments[index + 1]
        if _is_date_segment(date_part):
            return {"log_family": segment, "date": date_part}
    return None


def _is_date_segment(value: str) -> bool:
    if len(value) != 10:
        return False
    try:
        datetime.strptime(value, "%Y-%m-%d")
    except ValueError:
        return False
    return True


def _build_family_payloads(
    *,
    reference,
    discovered_files: list[dict[str, Any]],
) -> dict[str, dict[str, Any]]:
    grouped_files: dict[str, list[dict[str, Any]]] = {family: [] for family in WATCHGUARD_INGESTION_FAMILIES}
    for item in discovered_files:
        grouped_files[item["log_family"]].append(item)

    payloads: dict[str, dict[str, Any]] = {}
    for family, items in grouped_files.items():
        if not items:
            continue
        if family == WATCHGUARD_TRAFFIC_LOG_TYPE:
            payloads[family] = _build_traffic_family_payload(reference=reference, files=items)
        else:
            payloads[family] = _build_text_family_payload(reference=reference, log_family=family, files=items)
    return payloads


def _build_traffic_family_payload(*, reference, files: list[dict[str, Any]]) -> dict[str, Any]:
    csv_rows: list[str] = []
    source_files: list[dict[str, Any]] = []
    date_counts: Counter[str] = Counter()

    for item in files:
        rows = _extract_csv_rows(item["text"])
        if not rows:
            continue
        csv_rows.extend(rows)
        source_files.append(_serialize_source_file(item=item, row_count=len(rows)))
        date_counts[item["date"]] += len(rows)

    if not csv_rows:
        raise WatchGuardLogsBackendError("workspace ZIP ingestion did not produce any traffic CSV rows")

    return {
        "source": "workspace_zip_ingestion",
        "workspace": reference.workspace,
        "source_kind": WATCHGUARD_WORKSPACE_S3_ZIP_SOURCE_KIND,
        "s3_uri": reference.s3_uri,
        "upload_prefix": reference.upload_prefix,
        "log_type": WATCHGUARD_TRAFFIC_LOG_TYPE,
        "csv_rows": csv_rows,
        "record_count": len(csv_rows),
        "source_files": source_files,
        "date_counts": {key: date_counts[key] for key in sorted(date_counts)},
    }


def _build_text_family_payload(*, reference, log_family: str, files: list[dict[str, Any]]) -> dict[str, Any]:
    rows: list[dict[str, Any]] = []
    source_files: list[dict[str, Any]] = []
    date_counts: Counter[str] = Counter()

    for item in files:
        extracted_rows = _extract_text_rows(item["text"])
        if not extracted_rows:
            continue
        rows.extend(
            {
                "timestamp": _extract_timestamp_from_row(row),
                "message": row,
                "date": item["date"],
                "source_path_in_archive": item["source_path_in_archive"],
            }
            for row in extracted_rows
        )
        source_files.append(_serialize_source_file(item=item, row_count=len(extracted_rows)))
        date_counts[item["date"]] += len(extracted_rows)

    return {
        "source": "workspace_zip_ingestion",
        "workspace": reference.workspace,
        "source_kind": WATCHGUARD_WORKSPACE_S3_ZIP_SOURCE_KIND,
        "s3_uri": reference.s3_uri,
        "upload_prefix": reference.upload_prefix,
        "log_family": log_family,
        "rows": rows,
        "record_count": len(rows),
        "source_files": source_files,
        "date_counts": {key: date_counts[key] for key in sorted(date_counts)},
    }


def _extract_csv_rows(text: str) -> list[str]:
    rows: list[str] = []
    for line in text.splitlines():
        stripped = line.strip()
        if stripped:
            rows.append(stripped)
    return rows


def _extract_text_rows(text: str) -> list[str]:
    return [line.strip() for line in text.splitlines() if line.strip()]


def _extract_timestamp_from_row(row: str) -> str | None:
    first_cell = next(csv.reader([row]), [""])[0].strip()
    if not first_cell:
        return None
    try:
        return datetime.fromisoformat(first_cell.replace("Z", "+00:00")).astimezone(timezone.utc).isoformat(
            timespec="seconds"
        ).replace("+00:00", "Z")
    except ValueError:
        return None


def _serialize_source_file(*, item: dict[str, Any], row_count: int) -> dict[str, Any]:
    return {
        "date": item["date"],
        "row_count": row_count,
        "source_path_in_archive": item["source_path_in_archive"],
        "compression_chain": item["compression_chain"],
    }


def _build_ingestion_manifest(*, reference, discovered_files: list[dict[str, Any]], family_payloads: dict[str, dict[str, Any]]) -> dict[str, Any]:
    family_counts = {
        family: {
            "file_count": sum(1 for item in discovered_files if item["log_family"] == family),
            "record_count": int(family_payloads.get(family, {}).get("record_count", 0)),
        }
        for family in WATCHGUARD_INGESTION_FAMILIES
    }
    return {
        "source": "workspace_zip_ingestion",
        "workspace": reference.workspace,
        "source_kind": WATCHGUARD_WORKSPACE_S3_ZIP_SOURCE_KIND,
        "s3_uri": reference.s3_uri,
        "bucket": reference.bucket,
        "object_key": reference.object_key,
        "upload_prefix": reference.upload_prefix,
        "discovered_file_count": len(discovered_files),
        "family_counts": family_counts,
        "source_files": [
            {
                "log_family": item["log_family"],
                "date": item["date"],
                "source_path_in_archive": item["source_path_in_archive"],
                "compression_chain": item["compression_chain"],
            }
            for item in discovered_files
        ],
    }


def _build_workspace_manifest_artifact(
    *,
    run: Run,
    observation_request: ObservationRequest,
    manifest_payload: dict[str, Any],
) -> Artifact:
    return Artifact(
        kind=ArtifactKind.ANALYSIS_OUTPUT,
        subtype="watchguard.workspace_zip_manifest",
        format="json",
        storage_ref=(
            f"backend://watchguard_logs/runs/{run.run_id}/"
            f"observations/{observation_request.observation_id}/workspace_zip_manifest.json"
        ),
        content_hash=_content_hash_for_payload(manifest_payload),
        produced_by_backend_ref=EntityRef(entity_type=EntityKind.BACKEND, id=WATCHGUARD_LOGS_BACKEND_ID),
        produced_by_run_ref=EntityRef(entity_type=EntityKind.RUN, id=run.run_id),
        produced_by_observation_ref=EntityRef(
            entity_type=EntityKind.OBSERVATION_REQUEST,
            id=observation_request.observation_id,
        ),
        summary="Captured the deterministic manifest for a workspace ZIP ingestion.",
        metadata=manifest_payload,
    )


def _build_workspace_family_artifact(
    *,
    run: Run,
    observation_request: ObservationRequest,
    log_family: str,
    artifact_payload: dict[str, Any],
) -> Artifact:
    filename = f"{log_family}.json"
    return Artifact(
        kind=ArtifactKind.NORMALIZED,
        subtype=f"watchguard.workspace_zip.{log_family}",
        format="json",
        storage_ref=(
            f"backend://watchguard_logs/runs/{run.run_id}/"
            f"observations/{observation_request.observation_id}/{filename}"
        ),
        content_hash=_content_hash_for_payload(artifact_payload),
        produced_by_backend_ref=EntityRef(entity_type=EntityKind.BACKEND, id=WATCHGUARD_LOGS_BACKEND_ID),
        produced_by_run_ref=EntityRef(entity_type=EntityKind.RUN, id=run.run_id),
        produced_by_observation_ref=EntityRef(
            entity_type=EntityKind.OBSERVATION_REQUEST,
            id=observation_request.observation_id,
        ),
        summary=f"Materialized {artifact_payload['record_count']} {log_family} rows from a workspace ZIP.",
        metadata=artifact_payload,
    )


def _jsonify(obj: Any) -> Any:
    """Recursively convert non-JSON-serializable types (datetime, date) to ISO strings."""
    import datetime as _dt

    if isinstance(obj, (_dt.datetime, _dt.date)):
        return obj.isoformat()
    if isinstance(obj, dict):
        return {k: _jsonify(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_jsonify(v) for v in obj]
    return obj


def _content_hash_for_payload(payload: dict[str, Any]) -> str:
    serialized_payload = json.dumps(_jsonify(payload), sort_keys=True)
    digest = hashlib.sha256(serialized_payload.encode("utf-8")).hexdigest()
    return f"sha256:{digest}"


# ── DDoS DuckDB analytics ────────────────────────────────────────────────────


def _run_duckdb_ddos_temporal_analysis(*, bucket: str, staging_prefix: str) -> dict[str, Any]:
    """Events per day with % variation. Identifies peak day and cyclical patterns."""
    con = _duckdb_connect_with_s3(bucket)
    files = _list_staging_csvs(bucket=bucket, staging_prefix=staging_prefix, family=WATCHGUARD_TRAFFIC_LOG_TYPE)
    if not files:
        con.close()
        return {"by_day": [], "peak_day": None, "peak_events": 0, "total_events": 0, "date_range": {"from": None, "to": None}, "pattern": "no_data"}

    names_sql = ", ".join(f"'{c}'" for c in _TRAFFIC_COLUMNS)
    con.execute(
        f"CREATE OR REPLACE VIEW traffic_logs AS "
        f"SELECT * FROM read_csv({files!r}, names=[{names_sql}], header=false, null_padding=true, ignore_errors=true)"
    )
    rows = con.execute(
        "SELECT strftime(timestamp::DATE, '%Y-%m-%d') as day, COUNT(*) as cnt "
        "FROM traffic_logs WHERE timestamp IS NOT NULL "
        "GROUP BY day ORDER BY day"
    ).fetchall()
    con.close()

    if not rows:
        return {"by_day": [], "peak_day": None, "peak_events": 0, "total_events": 0, "date_range": {"from": None, "to": None}, "pattern": "no_data"}

    by_day = []
    prev_cnt = None
    for day, cnt in rows:
        variation = round((cnt - prev_cnt) / prev_cnt * 100, 2) if prev_cnt else None
        by_day.append({"date": day, "events": cnt, "variation_pct": variation})
        prev_cnt = cnt

    peak = max(by_day, key=lambda x: x["events"])
    total = sum(r["events"] for r in by_day)
    return {
        "by_day": by_day,
        "peak_day": peak["date"],
        "peak_events": peak["events"],
        "total_events": total,
        "date_range": {"from": by_day[0]["date"], "to": by_day[-1]["date"]},
        "pattern": "cyclic" if len(by_day) >= 7 else "short_period",
    }


def _run_duckdb_ddos_top_destinations(*, bucket: str, staging_prefix: str, top_n: int = 10) -> dict[str, Any]:
    """Top N destination IPs with event count, percentage, and top policy."""
    con = _duckdb_connect_with_s3(bucket)
    files = _list_staging_csvs(bucket=bucket, staging_prefix=staging_prefix, family=WATCHGUARD_TRAFFIC_LOG_TYPE)
    if not files:
        con.close()
        return {"destinations": [], "total_events": 0}

    names_sql = ", ".join(f"'{c}'" for c in _TRAFFIC_COLUMNS)
    con.execute(
        f"CREATE OR REPLACE VIEW traffic_logs AS "
        f"SELECT * FROM read_csv({files!r}, names=[{names_sql}], header=false, null_padding=true, ignore_errors=true)"
    )
    # Materialize into in-memory table so all subsequent queries avoid repeated S3 reads
    con.execute(
        "CREATE OR REPLACE TABLE tl AS "
        "SELECT dst_ip, action, policy FROM traffic_logs WHERE dst_ip IS NOT NULL"
    )
    total = con.execute("SELECT COUNT(*) FROM tl").fetchone()[0]
    rows = con.execute(
        f"SELECT dst_ip, COUNT(*) as cnt, mode(policy) as top_policy, mode(action) as top_action "
        f"FROM tl GROUP BY dst_ip ORDER BY cnt DESC LIMIT {top_n}"
    ).fetchall()
    con.close()

    destinations = [
        {
            "rank": i + 1,
            "dst_ip": r[0],
            "events": r[1],
            "pct": round(r[1] / total * 100, 2) if total else 0,
            "top_policy": r[2],
            "top_action": r[3],
        }
        for i, r in enumerate(rows)
    ]
    return {"destinations": destinations, "total_events": total}


def _run_duckdb_ddos_top_sources(*, bucket: str, staging_prefix: str, top_n: int = 10) -> dict[str, Any]:
    """Top N source IPs with /16 segment grouping and event counts."""
    con = _duckdb_connect_with_s3(bucket)
    files = _list_staging_csvs(bucket=bucket, staging_prefix=staging_prefix, family=WATCHGUARD_TRAFFIC_LOG_TYPE)
    if not files:
        con.close()
        return {"sources": [], "segments": [], "total_events": 0}

    names_sql = ", ".join(f"'{c}'" for c in _TRAFFIC_COLUMNS)
    con.execute(
        f"CREATE OR REPLACE VIEW traffic_logs AS "
        f"SELECT * FROM read_csv({files!r}, names=[{names_sql}], header=false, null_padding=true, ignore_errors=true)"
    )
    # Materialize into in-memory table so all subsequent queries avoid repeated S3 reads
    con.execute(
        "CREATE OR REPLACE TABLE tl AS "
        "SELECT src_ip, action FROM traffic_logs WHERE src_ip IS NOT NULL"
    )
    total = con.execute("SELECT COUNT(*) FROM tl").fetchone()[0]

    # Top individual IPs — single pass with mode()
    ip_rows = con.execute(
        f"SELECT src_ip, COUNT(*) as cnt, mode(action) as top_action "
        f"FROM tl GROUP BY src_ip ORDER BY cnt DESC LIMIT {top_n}"
    ).fetchall()

    # Aggregate by /16 segment using string_split
    seg_rows = con.execute(
        "SELECT "
        "  concat(string_split(src_ip, '.')[1], '.', string_split(src_ip, '.')[2], '.0.0/16') as segment, "
        "  COUNT(*) as cnt, COUNT(DISTINCT src_ip) as ip_count "
        "FROM tl WHERE src_ip LIKE '%.%.%.%' "
        "GROUP BY segment ORDER BY cnt DESC LIMIT 10"
    ).fetchall()
    con.close()

    def _segment(ip: str) -> str:
        parts = ip.split(".")
        return f"{parts[0]}.{parts[1]}.0.0/16" if len(parts) == 4 else ip

    sources = [
        {
            "rank": i + 1,
            "src_ip": r[0],
            "segment_16": _segment(r[0]) if r[0] else None,
            "events": r[1],
            "pct": round(r[1] / total * 100, 2) if total else 0,
            "top_action": r[2],
        }
        for i, r in enumerate(ip_rows)
    ]
    segments = [
        {
            "segment": r[0],
            "events": r[1],
            "pct": round(r[1] / total * 100, 2) if total else 0,
            "ip_count": r[2],
        }
        for r in seg_rows
    ]
    return {"sources": sources, "segments": segments, "total_events": total}


def _run_duckdb_ddos_segment_analysis(*, bucket: str, staging_prefix: str, segment: str) -> dict[str, Any]:
    """Detailed analysis for a /16 segment: protocols, ports, policies, allow/deny breakdown."""
    con = _duckdb_connect_with_s3(bucket)
    files = _list_staging_csvs(bucket=bucket, staging_prefix=staging_prefix, family=WATCHGUARD_TRAFFIC_LOG_TYPE)
    if not files:
        con.close()
        return {"segment": segment, "total_events": 0, "allow_events": 0, "deny_events": 0, "top_dst_ports": [], "top_policies": [], "top_dst_ips": []}

    names_sql = ", ".join(f"'{c}'" for c in _TRAFFIC_COLUMNS)
    con.execute(
        f"CREATE OR REPLACE VIEW traffic_logs AS "
        f"SELECT * FROM read_csv({files!r}, names=[{names_sql}], header=false, null_padding=true, ignore_errors=true)"
    )

    # Build the /16 prefix filter from segment notation (e.g. "159.60.0.0/16" → prefix "159.60.")
    prefix = ".".join(segment.split(".")[:2]) + "."
    # Materialize filtered rows into in-memory table — one S3 read, fast subsequent queries
    con.execute(
        f"CREATE OR REPLACE TABLE seg_data AS "
        f"SELECT src_ip, action, dst_ip, dst_port, protocol, policy, timestamp "
        f"FROM traffic_logs WHERE src_ip LIKE '{prefix}%'"
    )

    total = con.execute("SELECT COUNT(*) FROM seg_data").fetchone()[0]
    allow = con.execute(
        "SELECT COUNT(*) FROM seg_data WHERE lower(action) IN ('allow', 'allowed', 'permit', 'permitted')"
    ).fetchone()[0]
    deny = con.execute(
        "SELECT COUNT(*) FROM seg_data WHERE lower(action) IN ('deny', 'denied', 'block', 'blocked')"
    ).fetchone()[0]

    port_rows = con.execute(
        "SELECT dst_port, protocol, COUNT(*) as cnt FROM seg_data "
        "WHERE dst_port IS NOT NULL GROUP BY dst_port, protocol ORDER BY cnt DESC LIMIT 10"
    ).fetchall()
    policy_rows = con.execute(
        "SELECT policy, COUNT(*) as cnt FROM seg_data "
        "WHERE policy IS NOT NULL GROUP BY policy ORDER BY cnt DESC LIMIT 10"
    ).fetchall()
    dst_rows = con.execute(
        "SELECT dst_ip, COUNT(*) as cnt FROM seg_data "
        "WHERE dst_ip IS NOT NULL GROUP BY dst_ip ORDER BY cnt DESC LIMIT 10"
    ).fetchall()

    time_range = con.execute(
        "SELECT MIN(timestamp), MAX(timestamp) FROM seg_data WHERE timestamp IS NOT NULL"
    ).fetchone()
    con.close()

    return {
        "segment": segment,
        "total_events": total,
        "allow_events": allow,
        "deny_events": deny,
        "top_dst_ports": [{"port": r[0], "protocol": r[1], "events": r[2]} for r in port_rows],
        "top_policies": [{"policy": r[0], "events": r[1]} for r in policy_rows],
        "top_dst_ips": [{"dst_ip": r[0], "events": r[1]} for r in dst_rows],
        "date_range": {
            "from": time_range[0].isoformat() if time_range[0] else None,
            "to": time_range[1].isoformat() if time_range[1] else None,
        },
    }


def _run_duckdb_ddos_ip_profile(*, bucket: str, staging_prefix: str, ip: str) -> dict[str, Any]:
    """Full profile for a single IP: timeline, ports, policies, allow/deny breakdown."""
    con = _duckdb_connect_with_s3(bucket)
    files = _list_staging_csvs(bucket=bucket, staging_prefix=staging_prefix, family=WATCHGUARD_TRAFFIC_LOG_TYPE)
    if not files:
        con.close()
        return {"ip": ip, "total_events": 0, "allow_events": 0, "deny_events": 0, "top_dst_ports": [], "top_policies": [], "top_dst_ips": [], "first_seen": None, "last_seen": None}

    names_sql = ", ".join(f"'{c}'" for c in _TRAFFIC_COLUMNS)
    con.execute(
        f"CREATE OR REPLACE VIEW traffic_logs AS "
        f"SELECT * FROM read_csv({files!r}, names=[{names_sql}], header=false, null_padding=true, ignore_errors=true)"
    )
    # Materialize filtered rows into in-memory table — one S3 read, fast subsequent queries
    con.execute(
        f"CREATE OR REPLACE TABLE ip_data AS "
        f"SELECT src_ip, action, dst_ip, dst_port, protocol, policy, timestamp "
        f"FROM traffic_logs WHERE src_ip = '{ip}'"
    )

    total = con.execute("SELECT COUNT(*) FROM ip_data").fetchone()[0]
    allow = con.execute(
        "SELECT COUNT(*) FROM ip_data WHERE lower(action) IN ('allow', 'allowed', 'permit', 'permitted')"
    ).fetchone()[0]
    deny = con.execute(
        "SELECT COUNT(*) FROM ip_data WHERE lower(action) IN ('deny', 'denied', 'block', 'blocked')"
    ).fetchone()[0]

    port_rows = con.execute(
        "SELECT dst_port, protocol, action, COUNT(*) as cnt FROM ip_data "
        "WHERE dst_port IS NOT NULL GROUP BY dst_port, protocol, action ORDER BY cnt DESC LIMIT 10"
    ).fetchall()
    policy_rows = con.execute(
        "SELECT policy, COUNT(*) as cnt FROM ip_data "
        "WHERE policy IS NOT NULL GROUP BY policy ORDER BY cnt DESC LIMIT 10"
    ).fetchall()
    dst_rows = con.execute(
        "SELECT dst_ip, COUNT(*) as cnt FROM ip_data "
        "WHERE dst_ip IS NOT NULL GROUP BY dst_ip ORDER BY cnt DESC LIMIT 10"
    ).fetchall()
    time_range = con.execute(
        "SELECT MIN(timestamp), MAX(timestamp) FROM ip_data WHERE timestamp IS NOT NULL"
    ).fetchone()
    con.close()

    return {
        "ip": ip,
        "total_events": total,
        "allow_events": allow,
        "deny_events": deny,
        "first_seen": time_range[0].isoformat() if time_range and time_range[0] else None,
        "last_seen": time_range[1].isoformat() if time_range and time_range[1] else None,
        "top_dst_ports": [{"port": r[0], "protocol": r[1], "action": r[2], "events": r[3]} for r in port_rows],
        "top_policies": [{"policy": r[0], "events": r[1]} for r in policy_rows],
        "top_dst_ips": [{"dst_ip": r[0], "events": r[1]} for r in dst_rows],
    }


def _run_duckdb_ddos_hourly_distribution(*, bucket: str, staging_prefix: str, date: str) -> dict[str, Any]:
    """Events per hour for a given date. Identifies peak hour and business-hours pattern."""
    con = _duckdb_connect_with_s3(bucket)
    files = _list_staging_csvs(bucket=bucket, staging_prefix=staging_prefix, family=WATCHGUARD_TRAFFIC_LOG_TYPE)
    if not files:
        con.close()
        return {"date": date, "by_hour": [], "peak_hour": None, "peak_events": 0, "total_events": 0, "pattern": "no_data"}

    names_sql = ", ".join(f"'{c}'" for c in _TRAFFIC_COLUMNS)
    con.execute(
        f"CREATE OR REPLACE VIEW traffic_logs AS "
        f"SELECT * FROM read_csv({files!r}, names=[{names_sql}], header=false, null_padding=true, ignore_errors=true)"
    )
    rows = con.execute(
        f"SELECT hour(timestamp::TIMESTAMP) as hr, COUNT(*) as cnt "
        f"FROM traffic_logs "
        f"WHERE timestamp IS NOT NULL AND strftime(timestamp::DATE, '%Y-%m-%d') = '{date}' "
        f"GROUP BY hr ORDER BY hr"
    ).fetchall()
    con.close()

    if not rows:
        return {"date": date, "by_hour": [], "peak_hour": None, "peak_events": 0, "total_events": 0, "pattern": "no_data"}

    by_hour = [{"hour": r[0], "events": r[1]} for r in rows]
    peak = max(by_hour, key=lambda x: x["events"])
    total = sum(r["events"] for r in by_hour)

    # Heuristic: business-hours if peak is between 8-18
    pattern = "business_hours" if 8 <= peak["hour"] <= 18 else "off_hours"
    return {
        "date": date,
        "by_hour": by_hour,
        "peak_hour": peak["hour"],
        "peak_events": peak["events"],
        "total_events": total,
        "pattern": pattern,
    }


def _run_duckdb_ddos_protocol_breakdown(*, bucket: str, staging_prefix: str) -> dict[str, Any]:
    """Protocol distribution across all traffic: event count + percentage per protocol."""
    con = _duckdb_connect_with_s3(bucket)
    files = _list_staging_csvs(bucket=bucket, staging_prefix=staging_prefix, family=WATCHGUARD_TRAFFIC_LOG_TYPE)
    if not files:
        con.close()
        return {"protocols": [], "total_events": 0}

    names_sql = ", ".join(f"'{c}'" for c in _TRAFFIC_COLUMNS)
    con.execute(
        f"CREATE OR REPLACE VIEW traffic_logs AS "
        f"SELECT * FROM read_csv({files!r}, names=[{names_sql}], header=false, null_padding=true, ignore_errors=true)"
    )
    total = con.execute("SELECT COUNT(*) FROM traffic_logs").fetchone()[0]
    rows = con.execute(
        "SELECT protocol, COUNT(*) AS cnt "
        "FROM traffic_logs WHERE protocol IS NOT NULL "
        "GROUP BY protocol ORDER BY cnt DESC LIMIT 15"
    ).fetchall()
    con.close()

    protocols = [
        {
            "rank": i + 1,
            "protocol": r[0],
            "events": r[1],
            "pct": round(r[1] / total * 100, 2) if total else 0,
        }
        for i, r in enumerate(rows)
    ]
    return {"protocols": protocols, "total_events": total}


def _execute_ddos_protocol_breakdown(
    *,
    run: Run,
    input_artifact: Artifact,
    input_payload: object,
    observation_request: ObservationRequest,
) -> "WatchGuardExecutionOutcome":
    staging = _parse_staging_manifest(input_payload)
    result = _run_duckdb_ddos_protocol_breakdown(
        bucket=staging["bucket"],
        staging_prefix=staging["staging_prefix"],
    )
    payload = {
        "source": "ddos_protocol_breakdown",
        "workspace": staging["workspace"],
        "staging_prefix": staging["staging_prefix"],
        **result,
    }
    top = result.get("protocols", [{}])[0] if result.get("protocols") else {}
    return _ddos_make_outcome(
        run=run,
        observation_request=observation_request,
        payload=payload,
        subtype="watchguard.ddos_protocol_breakdown",
        summary=f"Protocol breakdown: {len(result.get('protocols', []))} protocols. Top: {top.get('protocol')} ({top.get('pct', 0):.1f}%).",
        structured_summary={
            "total_events": result.get("total_events", 0),
            "top_protocol": top.get("protocol"),
            "top_protocol_pct": top.get("pct", 0),
            "protocol_count": len(result.get("protocols", [])),
        },
    )


# ── DuckDB / staging helpers ─────────────────────────────────────────────────

_DUCKDB_MAX_LIMIT = 500
_DUCKDB_S3_REGION = os.environ.get("AWS_DEFAULT_REGION", "us-east-2")

# Column names for each family's CSV (no headers in the real files)
_TRAFFIC_COLUMNS = [
    "timestamp", "action_raw", "firewall_id", "msg_id", "code", "action",
    "policy", "app", "protocol", "src_zone", "dst_zone",
    "src_ip", "src_port", "dst_ip", "dst_port",
    "c15", "c16", "c17", "c18", "c19", "c20", "c21", "c22",
    "dns_type", "dns_name", "c25", "c26", "c27",
    "bytes_sent", "bytes_recv", "status_msg",
]
_ALARM_COLUMNS = [
    "timestamp", "type", "category", "firewall_id", "device_id",
    "process", "severity", "null_field", "msg_id", "code",
    "alarm_type", "notification_method", "local_time", "description",
]
_EVENT_COLUMNS = [
    "timestamp", "type", "category", "firewall_id", "device_id",
    "process", "null_field", "msg_id", "code", "message",
]
_FAMILY_COLUMNS: dict[str, list[str]] = {
    WATCHGUARD_TRAFFIC_LOG_TYPE: _TRAFFIC_COLUMNS,
    WATCHGUARD_ALARM_LOG_TYPE: _ALARM_COLUMNS,
    WATCHGUARD_EVENT_LOG_TYPE: _EVENT_COLUMNS,
}

# Fields allowed in DuckDB guarded queries per family
_DUCKDB_ALLOWED_FIELDS: dict[str, set[str]] = {
    WATCHGUARD_TRAFFIC_LOG_TYPE: {"src_ip", "dst_ip", "action", "protocol", "policy", "src_port", "dst_port"},
    WATCHGUARD_ALARM_LOG_TYPE: {"alarm_type", "src_ip", "timestamp"},
    WATCHGUARD_EVENT_LOG_TYPE: {"type", "timestamp"},
}


def _download_s3_object_to_file(bucket: str, object_key: str, dest_path: str) -> None:
    """Stream-download an S3 object to a local file path (no full-file RAM load)."""
    try:
        import boto3
    except ImportError as exc:
        raise WatchGuardLogsBackendError("boto3 is required for workspace staging") from exc
    boto3.client("s3").download_file(bucket, object_key, dest_path)


def _stage_zip_to_s3(
    *,
    zip_path: str,
    bucket: str,
    staging_prefix: str,
    workspace: str,
) -> dict[str, Any]:
    """Extract workspace ZIP → TAR → CSVs and upload each CSV to S3 staging prefix.

    Returns staging statistics: families found, date_range, total_csv_files, family_counts.
    """
    try:
        import boto3
    except ImportError as exc:
        raise WatchGuardLogsBackendError("boto3 is required for workspace staging") from exc

    s3_client = boto3.client("s3")
    family_counts: dict[str, dict[str, Any]] = {f: {"csv_files": 0, "dates": set()} for f in WATCHGUARD_INGESTION_FAMILIES}
    total_csv_files = 0
    all_dates: list[str] = []

    with zipfile.ZipFile(zip_path, "r") as zf:
        for member in zf.infolist():
            if member.is_dir():
                continue
            normalized = member.filename.replace("\\", "/")
            classification = _classify_workspace_entry(normalized)
            if classification is None:
                continue

            family = classification["log_family"]
            date = classification["date"]

            raw_bytes = zf.read(member)

            if normalized.lower().endswith(".tar"):
                try:
                    with tarfile.open(fileobj=io.BytesIO(raw_bytes), mode="r:*") as tf:
                        for tar_member in tf.getmembers():
                            if not tar_member.isfile():
                                continue
                            if not tar_member.name.lower().endswith((".csv", ".txt")):
                                continue
                            extracted = tf.extractfile(tar_member)
                            if extracted is None:
                                continue
                            csv_data = extracted.read()
                            if not csv_data.strip():
                                continue

                            csv_filename = os.path.basename(tar_member.name.replace("\\", "/"))
                            s3_key = f"{staging_prefix}/{family}/{date}/{csv_filename}"
                            s3_client.put_object(Bucket=bucket, Key=s3_key, Body=csv_data, Tagging="lifecycle=staging")

                            family_counts[family]["csv_files"] += 1
                            family_counts[family]["dates"].add(date)
                            all_dates.append(date)
                            total_csv_files += 1
                except tarfile.TarError:
                    continue
            elif normalized.lower().endswith(".gz"):
                try:
                    csv_data = gzip.decompress(raw_bytes)
                except Exception:
                    continue
                if not csv_data.strip():
                    continue
                # Use the base filename without .gz; append .csv if no text extension
                inner_name = os.path.basename(normalized[:-3])
                if not inner_name.lower().endswith((".csv", ".txt")):
                    inner_name += ".csv"
                s3_key = f"{staging_prefix}/{family}/{date}/{inner_name}"
                s3_client.put_object(Bucket=bucket, Key=s3_key, Body=csv_data, Tagging="lifecycle=staging")
                family_counts[family]["csv_files"] += 1
                family_counts[family]["dates"].add(date)
                all_dates.append(date)
                total_csv_files += 1
            elif normalized.lower().endswith((".csv", ".txt")):
                if not raw_bytes.strip():
                    continue
                csv_filename = os.path.basename(normalized)
                s3_key = f"{staging_prefix}/{family}/{date}/{csv_filename}"
                s3_client.put_object(Bucket=bucket, Key=s3_key, Body=raw_bytes, Tagging="lifecycle=staging")
                family_counts[family]["csv_files"] += 1
                family_counts[family]["dates"].add(date)
                all_dates.append(date)
                total_csv_files += 1

    families_present = [f for f in WATCHGUARD_INGESTION_FAMILIES if family_counts[f]["csv_files"] > 0]
    date_range = {
        "min": min(all_dates) if all_dates else None,
        "max": max(all_dates) if all_dates else None,
    }
    serializable_counts = {
        f: {"csv_files": family_counts[f]["csv_files"], "dates": sorted(family_counts[f]["dates"])}
        for f in WATCHGUARD_INGESTION_FAMILIES
    }
    return {
        "families": families_present,
        "date_range": date_range,
        "total_csv_files": total_csv_files,
        "family_counts": serializable_counts,
    }


def _parse_staging_manifest(payload: object) -> dict[str, Any]:
    """Validate and return the staging manifest dict from an artifact payload."""
    if not isinstance(payload, dict):
        raise WatchGuardLogsBackendError("DuckDB operation requires a staging manifest artifact as input")
    source = payload.get("source")
    if source != "workspace_staging":
        raise WatchGuardLogsBackendError(
            "DuckDB operation requires an artifact with source='workspace_staging' "
            "(output of stage_workspace_zip)"
        )
    required = ("workspace", "staging_prefix", "bucket")
    missing = [k for k in required if not payload.get(k)]
    if missing:
        raise WatchGuardLogsBackendError(
            f"Staging manifest is missing required fields: {', '.join(missing)}"
        )
    return payload  # type: ignore[return-value]


def _duckdb_connect_with_s3(bucket: str) -> "Any":
    """Return a DuckDB connection configured for S3 access via boto3 credentials."""
    try:
        import duckdb
    except ImportError as exc:
        raise WatchGuardLogsBackendError(
            "duckdb is required for workspace analytics. "
            "Install with: pip install duckdb"
        ) from exc
    try:
        import boto3
    except ImportError as exc:
        raise WatchGuardLogsBackendError("boto3 is required for workspace analytics") from exc

    con = duckdb.connect()
    con.execute("INSTALL httpfs; LOAD httpfs;")
    con.execute(f"SET s3_region='{_DUCKDB_S3_REGION}';")

    # Propagate boto3 credentials (works with IAM roles, env vars, ~/.aws/credentials)
    session = boto3.Session()
    creds = session.get_credentials()
    if creds is not None:
        frozen = creds.get_frozen_credentials()
        con.execute(f"SET s3_access_key_id='{frozen.access_key}';")
        con.execute(f"SET s3_secret_access_key='{frozen.secret_key}';")
        if frozen.token:
            con.execute(f"SET s3_session_token='{frozen.token}';")
    return con


def _list_staging_csvs(*, bucket: str, staging_prefix: str, family: str) -> list[str]:
    """List all staged CSV S3 keys for a given family."""
    try:
        import boto3
    except ImportError:
        return []
    s3_client = boto3.client("s3")
    prefix = f"{staging_prefix}/{family}/"
    paginator = s3_client.get_paginator("list_objects_v2")
    keys: list[str] = []
    for page in paginator.paginate(Bucket=bucket, Prefix=prefix):
        for obj in page.get("Contents", []):
            key = obj["Key"]
            if key.endswith((".csv", ".txt")):
                keys.append(f"s3://{bucket}/{key}")
    return keys


def _run_duckdb_analytics(
    *,
    bucket: str,
    staging_prefix: str,
    families: list[str],
) -> dict[str, Any]:
    """Run DuckDB aggregation queries over staged S3 CSVs. Returns a dict keyed by family."""
    con = _duckdb_connect_with_s3(bucket)
    result: dict[str, Any] = {}

    if WATCHGUARD_TRAFFIC_LOG_TYPE in families:
        files = _list_staging_csvs(bucket=bucket, staging_prefix=staging_prefix, family=WATCHGUARD_TRAFFIC_LOG_TYPE)
        if files:
            cols = ", ".join(f"column{i}" for i in range(len(_TRAFFIC_COLUMNS)))
            names_sql = ", ".join(f"'{c}'" for c in _TRAFFIC_COLUMNS)
            view_sql = (
                f"CREATE OR REPLACE VIEW traffic_logs AS "
                f"SELECT * FROM read_csv({files!r}, names=[{names_sql}], header=false, null_padding=true, ignore_errors=true)"
            )
            con.execute(view_sql)
            traffic: dict[str, Any] = {}
            traffic["total_rows"] = con.execute("SELECT COUNT(*) FROM traffic_logs").fetchone()[0]
            traffic["action_counts"] = {
                r[0]: r[1] for r in con.execute(
                    "SELECT action, COUNT(*) as cnt FROM traffic_logs WHERE action IS NOT NULL "
                    "GROUP BY action ORDER BY cnt DESC"
                ).fetchall()
            }
            traffic["top_src_ips"] = [
                {"src_ip": r[0], "count": r[1]} for r in con.execute(
                    "SELECT src_ip, COUNT(*) as cnt FROM traffic_logs WHERE src_ip IS NOT NULL "
                    "GROUP BY src_ip ORDER BY cnt DESC LIMIT 20"
                ).fetchall()
            ]
            traffic["top_dst_ips"] = [
                {"dst_ip": r[0], "count": r[1]} for r in con.execute(
                    "SELECT dst_ip, COUNT(*) as cnt FROM traffic_logs WHERE dst_ip IS NOT NULL "
                    "GROUP BY dst_ip ORDER BY cnt DESC LIMIT 20"
                ).fetchall()
            ]
            traffic["top_src_dst_pairs"] = [
                {"src_ip": r[0], "dst_ip": r[1], "count": r[2]} for r in con.execute(
                    "SELECT src_ip, dst_ip, COUNT(*) as cnt FROM traffic_logs "
                    "WHERE src_ip IS NOT NULL AND dst_ip IS NOT NULL "
                    "GROUP BY src_ip, dst_ip ORDER BY cnt DESC LIMIT 20"
                ).fetchall()
            ]
            traffic["protocol_breakdown"] = [
                {"protocol": r[0], "count": r[1]} for r in con.execute(
                    "SELECT protocol, COUNT(*) as cnt FROM traffic_logs WHERE protocol IS NOT NULL "
                    "GROUP BY protocol ORDER BY cnt DESC LIMIT 10"
                ).fetchall()
            ]
            traffic["deny_count"] = con.execute(
                "SELECT COUNT(*) FROM traffic_logs WHERE lower(action) IN ('deny', 'denied', 'block', 'blocked')"
            ).fetchone()[0]
            time_range = con.execute(
                "SELECT MIN(timestamp), MAX(timestamp) FROM traffic_logs WHERE timestamp IS NOT NULL"
            ).fetchone()
            traffic["time_range"] = {"min": time_range[0], "max": time_range[1]}
            result[WATCHGUARD_TRAFFIC_LOG_TYPE] = traffic

    if WATCHGUARD_ALARM_LOG_TYPE in families:
        files = _list_staging_csvs(bucket=bucket, staging_prefix=staging_prefix, family=WATCHGUARD_ALARM_LOG_TYPE)
        if files:
            names_sql = ", ".join(f"'{c}'" for c in _ALARM_COLUMNS)
            con.execute(
                f"CREATE OR REPLACE VIEW alarm_logs AS "
                f"SELECT * FROM read_csv({files!r}, names=[{names_sql}], header=false, null_padding=true, ignore_errors=true)"
            )
            alarm: dict[str, Any] = {}
            alarm["total_rows"] = con.execute("SELECT COUNT(*) FROM alarm_logs").fetchone()[0]
            alarm["alarm_type_counts"] = {
                r[0]: r[1] for r in con.execute(
                    "SELECT alarm_type, COUNT(*) as cnt FROM alarm_logs WHERE alarm_type IS NOT NULL "
                    "GROUP BY alarm_type ORDER BY cnt DESC LIMIT 20"
                ).fetchall()
            }
            time_range = con.execute(
                "SELECT MIN(timestamp), MAX(timestamp) FROM alarm_logs WHERE timestamp IS NOT NULL"
            ).fetchone()
            alarm["time_range"] = {"min": time_range[0], "max": time_range[1]}
            result[WATCHGUARD_ALARM_LOG_TYPE] = alarm

    if WATCHGUARD_EVENT_LOG_TYPE in families:
        files = _list_staging_csvs(bucket=bucket, staging_prefix=staging_prefix, family=WATCHGUARD_EVENT_LOG_TYPE)
        if files:
            names_sql = ", ".join(f"'{c}'" for c in _EVENT_COLUMNS)
            con.execute(
                f"CREATE OR REPLACE VIEW event_logs AS "
                f"SELECT * FROM read_csv({files!r}, names=[{names_sql}], header=false, null_padding=true, ignore_errors=true)"
            )
            event: dict[str, Any] = {}
            event["total_rows"] = con.execute("SELECT COUNT(*) FROM event_logs").fetchone()[0]
            event["type_counts"] = {
                r[0]: r[1] for r in con.execute(
                    "SELECT type, COUNT(*) as cnt FROM event_logs WHERE type IS NOT NULL "
                    "GROUP BY type ORDER BY cnt DESC LIMIT 10"
                ).fetchall()
            }
            result[WATCHGUARD_EVENT_LOG_TYPE] = event

    con.close()
    return result


def _run_duckdb_filtered_query(
    *,
    bucket: str,
    staging_prefix: str,
    family: str,
    raw_filters: list[dict[str, Any]],
    limit: int,
) -> tuple[list[dict[str, Any]], int]:
    """Run a guarded DuckDB filter query and return (rows, matched_count)."""
    allowed_fields = _DUCKDB_ALLOWED_FIELDS.get(family, set())
    where_clauses: list[str] = []
    for f in raw_filters:
        field = f.get("field", "")
        op = f.get("op", "eq")
        value = f.get("value")
        if field not in allowed_fields:
            raise InvalidWatchGuardQueryError(
                f"DuckDB query field '{field}' is not allowed for family '{family}'. "
                f"Allowed: {', '.join(sorted(allowed_fields))}"
            )
        if op == "eq":
            if not isinstance(value, str):
                raise InvalidWatchGuardQueryError(f"Field '{field}' op 'eq' requires a string value")
            safe_val = value.replace("'", "''")
            where_clauses.append(f"lower({field}) = lower('{safe_val}')")
        elif op == "in":
            if not isinstance(value, list) or not value:
                raise InvalidWatchGuardQueryError(f"Field '{field}' op 'in' requires a non-empty list")
            safe_vals = ", ".join(f"lower('{str(v).replace(chr(39), chr(39)*2)}')" for v in value)
            where_clauses.append(f"lower({field}) IN ({safe_vals})")
        else:
            raise InvalidWatchGuardQueryError(f"DuckDB query op '{op}' is not supported (use 'eq' or 'in')")

    files = _list_staging_csvs(bucket=bucket, staging_prefix=staging_prefix, family=family)
    if not files:
        return [], 0

    con = _duckdb_connect_with_s3(bucket)
    columns = _FAMILY_COLUMNS.get(family, [])
    names_sql = ", ".join(f"'{c}'" for c in columns) if columns else "'c0'"
    view_name = f"{family}_logs_query"
    con.execute(
        f"CREATE OR REPLACE VIEW {view_name} AS "
        f"SELECT * FROM read_csv({files!r}, names=[{names_sql}], header=false, null_padding=true, ignore_errors=true)"
    )

    where_sql = f"WHERE {' AND '.join(where_clauses)}" if where_clauses else ""
    matched_count = con.execute(f"SELECT COUNT(*) FROM {view_name} {where_sql}").fetchone()[0]
    raw_rows = con.execute(
        f"SELECT * FROM {view_name} {where_sql} LIMIT {limit}"
    ).fetchall()
    col_names = [desc[0] for desc in con.execute(f"DESCRIBE {view_name}").fetchall()]
    rows = [dict(zip(col_names, row)) for row in raw_rows]
    con.close()
    return rows, matched_count
