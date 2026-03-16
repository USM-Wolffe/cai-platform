"""Minimal deterministic execution for the first WatchGuard predefined observation."""

from __future__ import annotations

from collections import Counter
from datetime import datetime, timezone
import hashlib
import json
from typing import Any

from platform_adapters.watchguard import (
    WatchGuardAdapterError,
    filter_denied_watchguard_batch,
    inspect_watchguard_input_artifact,
    normalize_watchguard_log_payload,
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
    WATCHGUARD_FILTER_DENIED_EVENTS_OPERATION,
    WATCHGUARD_GUARDED_FILTERED_ROWS_QUERY_CLASS,
    WATCHGUARD_LOGS_BACKEND_ID,
    WATCHGUARD_NORMALIZE_SUMMARY_OPERATION,
    WATCHGUARD_TOP_TALKERS_BASIC_OPERATION,
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


def execute_predefined_observation(
    *,
    run: Run,
    input_artifact: Artifact,
    input_payload: object,
    observation_request: ObservationRequest,
) -> WatchGuardExecutionOutcome:
    """Execute a predefined WatchGuard observation and normalize the outcome."""
    try:
        _validate_observation_request(run=run, observation_request=observation_request)
        inspect_watchguard_input_artifact(input_artifact)
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


def _validate_observation_request(*, run: Run, observation_request: ObservationRequest) -> None:
    if observation_request.operation_kind not in {
        WATCHGUARD_NORMALIZE_SUMMARY_OPERATION,
        WATCHGUARD_FILTER_DENIED_EVENTS_OPERATION,
        WATCHGUARD_ANALYTICS_BUNDLE_BASIC_OPERATION,
        WATCHGUARD_TOP_TALKERS_BASIC_OPERATION,
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
    if operation_kind == WATCHGUARD_ANALYTICS_BUNDLE_BASIC_OPERATION:
        return f"Built a basic WatchGuard analytics bundle from {record_count} log records."
    if operation_kind == WATCHGUARD_TOP_TALKERS_BASIC_OPERATION:
        return f"Built a basic WatchGuard top-talkers summary from {record_count} log records."
    if operation_kind == WATCHGUARD_FILTER_DENIED_EVENTS_OPERATION:
        return f"Filtered {record_count} denied WatchGuard log records."
    return f"Normalized {record_count} WatchGuard log records."
