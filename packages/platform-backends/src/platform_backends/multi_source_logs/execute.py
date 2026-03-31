"""Deterministic execution for the multi_source_logs backend."""

from __future__ import annotations

import hashlib
import json
from dataclasses import asdict
from typing import Any

from platform_contracts import (
    Artifact,
    ArtifactKind,
    EntityKind,
    EntityRef,
    ObservationRequest,
    ObservationResult,
    ObservationStatus,
    Run,
)
from platform_core import ContractViolationError

from platform_backends.multi_source_logs.descriptor import (
    MULTI_SOURCE_LOGS_BACKEND_ID,
    MULTI_SOURCE_LOGS_CROSS_SOURCE_OPERATION,
    MULTI_SOURCE_LOGS_DNS_ANOMALY_OPERATION,
    MULTI_SOURCE_LOGS_FAILED_AUTH_OPERATION,
    MULTI_SOURCE_LOGS_LATERAL_MOVEMENT_OPERATION,
    MULTI_SOURCE_LOGS_NORMALIZE_OPERATION,
    MULTI_SOURCE_LOGS_PRIV_ESC_OPERATION,
)
from platform_backends.multi_source_logs.detections import (
    correlate_cross_source,
    detect_dns_anomaly,
    detect_failed_auth,
    detect_lateral_movement,
    detect_privilege_escalation,
)
from platform_backends.multi_source_logs.errors import (
    MultiSourceLogsBackendError,
    UnsupportedMultiSourceLogsOperationError,
)
from platform_backends.multi_source_logs.models import (
    MultiSourceDetectionFinding,
    MultiSourceLogsExecutionOutcome,
    NormalizedLogRecord,
)
from platform_backends.multi_source_logs.normalizer import (
    VALID_SOURCE_TYPES,
    download_s3_lines,
    normalize_log_lines,
)


def execute_predefined_observation(
    *,
    run: Run,
    input_artifact: Artifact,
    input_payload: object,
    observation_request: ObservationRequest,
) -> MultiSourceLogsExecutionOutcome:
    """Dispatch a multi_source_logs observation to the appropriate handler."""
    op = observation_request.operation_kind
    try:
        if op == MULTI_SOURCE_LOGS_NORMALIZE_OPERATION:
            return _execute_normalize(
                run=run,
                input_payload=input_payload,
                observation_request=observation_request,
            )
        if op == MULTI_SOURCE_LOGS_FAILED_AUTH_OPERATION:
            return _execute_detection(
                run=run,
                input_payload=input_payload,
                observation_request=observation_request,
                detect_fn=detect_failed_auth,
                operation=op,
            )
        if op == MULTI_SOURCE_LOGS_LATERAL_MOVEMENT_OPERATION:
            return _execute_detection(
                run=run,
                input_payload=input_payload,
                observation_request=observation_request,
                detect_fn=detect_lateral_movement,
                operation=op,
            )
        if op == MULTI_SOURCE_LOGS_PRIV_ESC_OPERATION:
            return _execute_detection(
                run=run,
                input_payload=input_payload,
                observation_request=observation_request,
                detect_fn=detect_privilege_escalation,
                operation=op,
            )
        if op == MULTI_SOURCE_LOGS_DNS_ANOMALY_OPERATION:
            return _execute_detection(
                run=run,
                input_payload=input_payload,
                observation_request=observation_request,
                detect_fn=detect_dns_anomaly,
                operation=op,
            )
        if op == MULTI_SOURCE_LOGS_CROSS_SOURCE_OPERATION:
            return _execute_cross_source_correlate(
                run=run,
                input_payload=input_payload,
                observation_request=observation_request,
            )
        raise UnsupportedMultiSourceLogsOperationError(
            f"Unknown operation_kind: '{op}' for backend '{MULTI_SOURCE_LOGS_BACKEND_ID}'"
        )
    except (MultiSourceLogsBackendError, ContractViolationError, UnsupportedMultiSourceLogsOperationError) as exc:
        return MultiSourceLogsExecutionOutcome(
            artifacts=[],
            observation_result=ObservationResult(
                observation_ref=EntityRef(
                    entity_type=EntityKind.OBSERVATION_REQUEST,
                    id=observation_request.observation_id,
                ),
                status=ObservationStatus.FAILED,
                errors=[str(exc)],
                warnings=[],
                structured_summary={},
            ),
        )


# ── Normalize ─────────────────────────────────────────────────────────────────

def _execute_normalize(
    *,
    run: Run,
    input_payload: object,
    observation_request: ObservationRequest,
) -> MultiSourceLogsExecutionOutcome:
    source_type, lines = _parse_input_payload(input_payload)
    records = normalize_log_lines(source_type, lines)

    records_as_dicts = [
        {
            "timestamp": r.timestamp,
            "event_type": r.event_type,
            "source_host": r.source_host,
            "dest_host": r.dest_host,
            "source_ip": r.source_ip,
            "dest_ip": r.dest_ip,
            "user": r.user,
            "action": r.action,
            "status": r.status,
            "process_name": r.process_name,
            "details_json": r.details_json,
        }
        for r in records
    ]

    # Compute time range
    timestamps = sorted(r.timestamp for r in records if r.timestamp)
    time_range = {"start": timestamps[0], "end": timestamps[-1]} if timestamps else {}

    artifact_payload: dict[str, Any] = {
        "operation_kind": MULTI_SOURCE_LOGS_NORMALIZE_OPERATION,
        "source_type": source_type,
        "row_count": len(records),
        "time_range": time_range,
        "records": records_as_dicts,
        "summary": f"Normalized {len(records)} {source_type} log records.",
    }

    artifact = _build_output_artifact(
        run=run,
        observation_request=observation_request,
        operation=MULTI_SOURCE_LOGS_NORMALIZE_OPERATION,
        artifact_payload=artifact_payload,
        kind=ArtifactKind.NORMALIZED,
    )

    status = ObservationStatus.SUCCEEDED if records else ObservationStatus.SUCCEEDED_NO_FINDINGS
    return MultiSourceLogsExecutionOutcome(
        artifacts=[artifact],
        observation_result=ObservationResult(
            observation_ref=EntityRef(
                entity_type=EntityKind.OBSERVATION_REQUEST,
                id=observation_request.observation_id,
            ),
            status=status,
            output_artifact_refs=[EntityRef(entity_type=EntityKind.ARTIFACT, id=artifact.artifact_id)],
            errors=[],
            warnings=[],
            structured_summary={
                "source_type": source_type,
                "row_count": len(records),
                "time_range": time_range,
            },
        ),
    )


# ── Detection operations ──────────────────────────────────────────────────────

from typing import Callable  # noqa: E402


def _execute_detection(
    *,
    run: Run,
    input_payload: object,
    observation_request: ObservationRequest,
    detect_fn: Callable[[list[NormalizedLogRecord]], list[MultiSourceDetectionFinding]],
    operation: str,
) -> MultiSourceLogsExecutionOutcome:
    """Generic handler for all single-source detection operations."""
    source_type, lines = _parse_input_payload(input_payload)
    records = normalize_log_lines(source_type, lines)
    findings = detect_fn(records)

    findings_as_dicts = [
        {
            "rule_id": f.rule_id,
            "category": f.category,
            "severity": f.severity,
            "count": f.count,
            "evidence": f.evidence,
            "summary": f.summary,
        }
        for f in findings
    ]

    op_slug = operation.split(".")[-1]
    artifact_payload: dict[str, Any] = {
        "operation_kind": operation,
        "source_type": source_type,
        "findings": findings_as_dicts,
        "finding_count": len(findings),
        "summary": (
            f"{op_slug}: {len(findings)} finding(s) from {len(records)} {source_type} records."
            if findings
            else f"{op_slug}: no findings detected in {len(records)} {source_type} records."
        ),
    }

    artifact = _build_output_artifact(
        run=run,
        observation_request=observation_request,
        operation=operation,
        artifact_payload=artifact_payload,
        kind=ArtifactKind.ANALYSIS_OUTPUT,
    )

    status = ObservationStatus.SUCCEEDED if findings else ObservationStatus.SUCCEEDED_NO_FINDINGS

    # Build structured_summary for cross-source correlation
    structured: dict[str, Any] = {
        "finding_count": len(findings),
        "source_type": source_type,
    }
    if findings:
        # Extract top attacker IP / targeted user for cross-source use
        for f in findings:
            if f.evidence.get("source_ip"):
                structured["source_ip"] = f.evidence["source_ip"]
                break
        for f in findings:
            if f.evidence.get("targeted_user"):
                structured["targeted_user"] = f.evidence["targeted_user"]
                break
        for f in findings:
            if f.evidence.get("affected_users"):
                structured["affected_users"] = f.evidence["affected_users"][:5]
                break
        structured["findings"] = findings_as_dicts[:20]  # cap for summary storage

    return MultiSourceLogsExecutionOutcome(
        artifacts=[artifact],
        observation_result=ObservationResult(
            observation_ref=EntityRef(
                entity_type=EntityKind.OBSERVATION_REQUEST,
                id=observation_request.observation_id,
            ),
            status=status,
            output_artifact_refs=[EntityRef(entity_type=EntityKind.ARTIFACT, id=artifact.artifact_id)],
            errors=[],
            warnings=[],
            structured_summary=structured,
        ),
    )


# ── Cross-source correlation ──────────────────────────────────────────────────

def _execute_cross_source_correlate(
    *,
    run: Run,
    input_payload: object,
    observation_request: ObservationRequest,
) -> MultiSourceLogsExecutionOutcome:
    """Correlate findings from all prior detection observations in this run."""
    # Load all observation results from the runtime via the artifact payload.
    # The input_payload for this operation is the same normalized log payload,
    # but we also read the run's output_artifact_refs to gather prior findings.
    # Since execute.py runs in-process with the runtime, the structured_summary
    # of prior ObservationResults is passed via input_payload as a convenience dict.

    findings_by_operation: dict[str, list[MultiSourceDetectionFinding]] = {}

    # input_payload for cross_source is {"prior_findings": {operation: [finding_dicts]}}
    if isinstance(input_payload, dict) and "prior_findings" in input_payload:
        raw = input_payload["prior_findings"]
        for op, f_dicts in raw.items():
            findings_by_operation[op] = [
                MultiSourceDetectionFinding(
                    rule_id=fd.get("rule_id", ""),
                    category=fd.get("category", ""),
                    severity=fd.get("severity", "low"),
                    count=fd.get("count", 0),
                    evidence=fd.get("evidence", {}),
                    summary=fd.get("summary", ""),
                )
                for fd in (f_dicts or [])
            ]

    correlated = correlate_cross_source(findings_by_operation)
    correlated_dicts = [
        {
            "rule_id": f.rule_id,
            "category": f.category,
            "severity": f.severity,
            "count": f.count,
            "evidence": f.evidence,
            "summary": f.summary,
        }
        for f in correlated
    ]

    artifact_payload: dict[str, Any] = {
        "operation_kind": MULTI_SOURCE_LOGS_CROSS_SOURCE_OPERATION,
        "findings": correlated_dicts,
        "finding_count": len(correlated),
        "summary": (
            f"Cross-source correlation: {len(correlated)} multi-stage indicator(s) detected."
            if correlated
            else "Cross-source correlation: no multi-stage indicators detected."
        ),
    }

    artifact = _build_output_artifact(
        run=run,
        observation_request=observation_request,
        operation=MULTI_SOURCE_LOGS_CROSS_SOURCE_OPERATION,
        artifact_payload=artifact_payload,
        kind=ArtifactKind.ANALYSIS_OUTPUT,
    )

    status = ObservationStatus.SUCCEEDED if correlated else ObservationStatus.SUCCEEDED_NO_FINDINGS
    return MultiSourceLogsExecutionOutcome(
        artifacts=[artifact],
        observation_result=ObservationResult(
            observation_ref=EntityRef(
                entity_type=EntityKind.OBSERVATION_REQUEST,
                id=observation_request.observation_id,
            ),
            status=status,
            output_artifact_refs=[EntityRef(entity_type=EntityKind.ARTIFACT, id=artifact.artifact_id)],
            errors=[],
            warnings=[],
            structured_summary={
                "finding_count": len(correlated),
                "findings": correlated_dicts,
            },
        ),
    )


# ── Input parsing ─────────────────────────────────────────────────────────────

def _parse_input_payload(input_payload: object) -> tuple[str, list[str]]:
    """Validate and extract (source_type, log_lines) from the input artifact payload."""
    if not isinstance(input_payload, dict):
        raise MultiSourceLogsBackendError("input_payload must be a JSON object")

    source_type = input_payload.get("source_type", "")
    if not source_type:
        raise MultiSourceLogsBackendError("input_payload must include 'source_type'")
    if source_type not in VALID_SOURCE_TYPES:
        raise MultiSourceLogsBackendError(
            f"source_type must be one of {sorted(VALID_SOURCE_TYPES)}, got '{source_type}'"
        )

    if "raw_log_lines" in input_payload:
        lines = input_payload["raw_log_lines"]
        if not isinstance(lines, list):
            raise MultiSourceLogsBackendError("raw_log_lines must be a list of strings")
        return source_type, [str(l) for l in lines]

    if "s3_uri" in input_payload:
        s3_uri = input_payload["s3_uri"]
        if not isinstance(s3_uri, str) or not s3_uri.startswith("s3://"):
            raise MultiSourceLogsBackendError(f"s3_uri must be a valid S3 URI, got '{s3_uri}'")
        return source_type, download_s3_lines(s3_uri)

    raise MultiSourceLogsBackendError(
        "input_payload must include either 's3_uri' or 'raw_log_lines'"
    )


# ── Artifact builder ──────────────────────────────────────────────────────────

def _build_output_artifact(
    *,
    run: Run,
    observation_request: ObservationRequest,
    operation: str,
    artifact_payload: dict[str, Any],
    kind: ArtifactKind,
) -> Artifact:
    serialized = json.dumps(artifact_payload, sort_keys=True, default=str)
    content_hash = hashlib.sha256(serialized.encode("utf-8")).hexdigest()
    op_slug = operation.replace(".", "_")
    return Artifact(
        kind=kind,
        subtype=operation,
        format="json",
        storage_ref=(
            f"backend://multi_source_logs/runs/{run.run_id}/"
            f"observations/{observation_request.observation_id}/{op_slug}.json"
        ),
        content_hash=f"sha256:{content_hash}",
        produced_by_backend_ref=EntityRef(
            entity_type=EntityKind.BACKEND, id=MULTI_SOURCE_LOGS_BACKEND_ID
        ),
        produced_by_run_ref=EntityRef(entity_type=EntityKind.RUN, id=run.run_id),
        produced_by_observation_ref=EntityRef(
            entity_type=EntityKind.OBSERVATION_REQUEST,
            id=observation_request.observation_id,
        ),
        summary=artifact_payload.get("summary", ""),
        metadata=artifact_payload,
    )
