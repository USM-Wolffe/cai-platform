"""WatchGuard input inspection and normalization helpers."""

from __future__ import annotations

import csv
import io
from collections import Counter
from datetime import datetime, timezone
from urllib.parse import urlparse
from typing import Any

from platform_contracts import Artifact, ArtifactKind

from platform_adapters.watchguard.errors import InvalidWatchGuardInputError, UnsupportedWatchGuardArtifactError
from platform_adapters.watchguard.types import (
    NormalizedWatchGuardBatch,
    WatchGuardLogRecord,
    WatchGuardWorkspaceZipReference,
)

SUPPORTED_INPUT_FORMATS = {"json"}
WATCHGUARD_TRAFFIC_LOG_TYPE = "traffic"
WATCHGUARD_EVENT_LOG_TYPE = "event"
WATCHGUARD_ALARM_LOG_TYPE = "alarm"
WATCHGUARD_WORKSPACE_S3_ZIP_SOURCE_KIND = "workspace_s3_zip"
WATCHGUARD_SEMANTIC_RECORDS_INPUT_SHAPE = "semantic_records"
WATCHGUARD_TRAFFIC_CSV_INPUT_SHAPE = "traffic_csv_export"
WATCHGUARD_WORKSPACE_S3_ZIP_INPUT_SHAPE = "workspace_s3_zip_reference"
REQUIRED_RECORD_FIELDS = {"timestamp", "action", "src_ip", "dst_ip"}
DENIED_ACTIONS = {"deny", "denied", "block", "blocked"}


def inspect_watchguard_input_artifact(artifact: Artifact) -> None:
    """Validate that the artifact contract is acceptable for the current WatchGuard slice."""
    if artifact.kind not in {ArtifactKind.INPUT, ArtifactKind.NORMALIZED}:
        raise UnsupportedWatchGuardArtifactError(
            "watchguard_logs only accepts input artifacts or normalized WatchGuard ingestion artifacts"
        )
    if artifact.format not in SUPPORTED_INPUT_FORMATS:
        raise UnsupportedWatchGuardArtifactError(
            f"watchguard_logs only accepts formats: {', '.join(sorted(SUPPORTED_INPUT_FORMATS))}"
        )


def normalize_watchguard_log_payload(payload: Any) -> NormalizedWatchGuardBatch:
    """Normalize either the compatibility records payload or a WatchGuard traffic CSV export wrapper."""
    if not isinstance(payload, dict):
        raise InvalidWatchGuardInputError(
            "watchguard payload must be a mapping containing either 'records' or a traffic CSV wrapper"
        )

    if isinstance(payload.get("records"), list):
        return _normalize_semantic_records_payload(payload)

    if "csv_text" in payload or "csv_rows" in payload:
        return _normalize_traffic_csv_payload(payload)

    raise InvalidWatchGuardInputError(
        "watchguard payload must include either 'records' or {'log_type': 'traffic', 'csv_text' | 'csv_rows'}"
    )


def parse_workspace_s3_zip_reference(payload: Any) -> WatchGuardWorkspaceZipReference:
    """Validate and parse the stable JSON wrapper used for workspace ZIP ingestion."""
    if not isinstance(payload, dict):
        raise InvalidWatchGuardInputError(
            "workspace ZIP payload must be a mapping with source='workspace_s3_zip', workspace, and s3_uri"
        )

    source_kind = payload.get("source")
    if source_kind != WATCHGUARD_WORKSPACE_S3_ZIP_SOURCE_KIND:
        raise InvalidWatchGuardInputError(
            "workspace ZIP payload must include {'source': 'workspace_s3_zip'}"
        )

    workspace = payload.get("workspace")
    if not isinstance(workspace, str) or not workspace.strip():
        raise InvalidWatchGuardInputError("workspace ZIP payload requires a non-empty 'workspace' string")
    workspace = workspace.strip()

    s3_uri = payload.get("s3_uri")
    if not isinstance(s3_uri, str) or not s3_uri.strip():
        raise InvalidWatchGuardInputError("workspace ZIP payload requires a non-empty 's3_uri' string")
    s3_uri = s3_uri.strip()

    bucket, object_key = _parse_s3_uri(s3_uri)
    expected_prefix = f"workspaces/{workspace}/input/uploads/"
    if expected_prefix not in object_key:
        raise InvalidWatchGuardInputError(
            "workspace ZIP s3_uri must point under "
            f"'s3://<bucket>/workspaces/{workspace}/input/uploads/...'"
        )

    upload_prefix = payload.get("upload_prefix")
    normalized_upload_prefix: str | None = None
    if upload_prefix is not None:
        if not isinstance(upload_prefix, str) or not upload_prefix.strip():
            raise InvalidWatchGuardInputError("workspace ZIP payload 'upload_prefix' must be a non-empty string")
        normalized_upload_prefix = upload_prefix.strip().strip("/")
    else:
        zip_name = object_key.rsplit("/", 1)[-1]
        normalized_upload_prefix = object_key[: -len(zip_name)].rstrip("/")

    return WatchGuardWorkspaceZipReference(
        workspace=workspace,
        s3_uri=s3_uri,
        bucket=bucket,
        object_key=object_key,
        upload_prefix=normalized_upload_prefix,
    )


def filter_denied_watchguard_batch(batch: NormalizedWatchGuardBatch) -> NormalizedWatchGuardBatch:
    """Return only the records whose normalized action represents a deny outcome."""
    denied_records = [record for record in batch.records if is_denied_watchguard_action(record.action)]
    action_counts = Counter(record.action for record in denied_records)
    return NormalizedWatchGuardBatch(
        records=denied_records,
        record_count=len(denied_records),
        action_counts=dict(action_counts),
        input_shape=batch.input_shape,
        log_type=batch.log_type,
    )


def is_denied_watchguard_action(action: str) -> bool:
    """Return whether the normalized WatchGuard action represents a deny or blocked outcome."""
    return action.strip().lower() in DENIED_ACTIONS


def _normalize_semantic_records_payload(payload: dict[str, Any]) -> NormalizedWatchGuardBatch:
    raw_records = payload.get("records")
    if not isinstance(raw_records, list):
        raise InvalidWatchGuardInputError("watchguard payload 'records' must be a list")

    normalized_records = [_normalize_semantic_record(index=index, raw_record=record) for index, record in enumerate(raw_records)]
    action_counts = Counter(record.action for record in normalized_records)
    return NormalizedWatchGuardBatch(
        records=normalized_records,
        record_count=len(normalized_records),
        action_counts=dict(action_counts),
        input_shape=WATCHGUARD_SEMANTIC_RECORDS_INPUT_SHAPE,
        log_type=WATCHGUARD_TRAFFIC_LOG_TYPE,
    )


def _normalize_traffic_csv_payload(payload: dict[str, Any]) -> NormalizedWatchGuardBatch:
    log_type = _require_csv_log_type(payload.get("log_type"))
    delimiter = _require_delimiter(payload.get("delimiter"))
    rows = _load_csv_rows(payload, delimiter=delimiter)

    normalized_records = [_normalize_watchguard_csv_row(index=index, row=row) for index, row in enumerate(rows)]
    action_counts = Counter(record.action for record in normalized_records)
    return NormalizedWatchGuardBatch(
        records=normalized_records,
        record_count=len(normalized_records),
        action_counts=dict(action_counts),
        input_shape=WATCHGUARD_TRAFFIC_CSV_INPUT_SHAPE,
        log_type=log_type,
    )


def _normalize_semantic_record(*, index: int, raw_record: Any) -> WatchGuardLogRecord:
    if not isinstance(raw_record, dict):
        raise InvalidWatchGuardInputError(f"watchguard record at index {index} must be a mapping")

    missing_fields = sorted(REQUIRED_RECORD_FIELDS - set(raw_record))
    if missing_fields:
        joined = ", ".join(missing_fields)
        raise InvalidWatchGuardInputError(
            f"watchguard record at index {index} is missing required fields: {joined}"
        )

    return WatchGuardLogRecord(
        timestamp=_require_string(raw_record["timestamp"], field_name="timestamp", index=index),
        action=_require_string(raw_record["action"], field_name="action", index=index).lower(),
        src_ip=_require_string(raw_record["src_ip"], field_name="src_ip", index=index),
        dst_ip=_require_string(raw_record["dst_ip"], field_name="dst_ip", index=index),
        protocol=_coerce_protocol(raw_record.get("protocol")),
        policy=_optional_string(raw_record.get("policy")),
        src_port=_coerce_port(raw_record.get("src_port"), field_name="src_port", index=index),
        dst_port=_coerce_port(raw_record.get("dst_port"), field_name="dst_port", index=index),
        question=_optional_string(raw_record.get("question")),
        record_type=_optional_string(raw_record.get("record_type")),
    )


def _normalize_watchguard_csv_row(*, index: int, row: list[str]) -> WatchGuardLogRecord:
    if len(row) < 15:
        raise InvalidWatchGuardInputError(
            f"watchguard traffic CSV row at index {index} must include at least 15 columns"
        )

    return WatchGuardLogRecord(
        timestamp=_normalize_timestamp(_column(row, 0), index=index),
        action=_normalize_action(_column(row, 5), index=index),
        src_ip=_require_csv_value(_column(row, 11), field_name="src_ip", index=index),
        dst_ip=_require_csv_value(_column(row, 13), field_name="dst_ip", index=index),
        protocol=_normalize_protocol(_column(row, 8)),
        policy=_optional_csv_value(_column(row, 6)),
        src_port=_safe_int(_column(row, 12), field_name="src_port", index=index),
        dst_port=_safe_int(_column(row, 14), field_name="dst_port", index=index),
        record_type=_optional_csv_value(_column(row, 22)),
        question=_optional_csv_value(_column(row, 23)),
    )


def _require_csv_log_type(value: Any) -> str:
    if value != WATCHGUARD_TRAFFIC_LOG_TYPE:
        raise InvalidWatchGuardInputError(
            "the current realistic WatchGuard slice only supports {'log_type': 'traffic'} CSV payloads"
        )
    return WATCHGUARD_TRAFFIC_LOG_TYPE


def _require_delimiter(value: Any) -> str:
    if value is None:
        return ","
    if not isinstance(value, str) or len(value) != 1:
        raise InvalidWatchGuardInputError("watchguard CSV payload 'delimiter' must be a single character when provided")
    return value


def _load_csv_rows(payload: dict[str, Any], *, delimiter: str) -> list[list[str]]:
    if "csv_rows" in payload:
        csv_rows = payload["csv_rows"]
        if not isinstance(csv_rows, list) or not csv_rows or not all(isinstance(row, str) for row in csv_rows):
            raise InvalidWatchGuardInputError("watchguard payload 'csv_rows' must be a non-empty list of CSV row strings")
        content = "\n".join(csv_rows)
    else:
        csv_text = payload.get("csv_text")
        if not isinstance(csv_text, str) or not csv_text.strip():
            raise InvalidWatchGuardInputError("watchguard payload 'csv_text' must be a non-empty string")
        content = csv_text

    reader = csv.reader(io.StringIO(content), delimiter=delimiter)
    rows = [row for row in reader if any(cell.strip() for cell in row)]
    if not rows:
        raise InvalidWatchGuardInputError("watchguard CSV payload did not contain any non-empty rows")
    return rows


def _column(row: list[str], index: int) -> str | None:
    if index >= len(row):
        return None
    value = row[index].strip()
    if not value or value == "\\N":
        return None
    return value


def _normalize_timestamp(value: str | None, *, index: int) -> str:
    raw = _require_csv_value(value, field_name="timestamp", index=index)
    normalized = raw.rstrip("Zz").strip()
    for fmt in (
        "%d/%m/%Y %H:%M",
        "%d/%m/%Y %H:%M:%S",
        "%d/%m/%Y %H:%M:%S.%f",
        "%Y-%m-%d %H:%M:%S",
        "%Y-%m-%d %H:%M:%S.%f",
        "%Y-%m-%dT%H:%M:%S",
        "%Y-%m-%dT%H:%M:%S.%f",
    ):
        try:
            parsed = datetime.strptime(normalized, fmt)
            return parsed.replace(tzinfo=timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")
        except ValueError:
            continue
    raise InvalidWatchGuardInputError(
        f"watchguard traffic CSV row at index {index} has an unsupported timestamp format"
    )


def _normalize_action(value: str | None, *, index: int) -> str:
    action = _require_csv_value(value, field_name="action", index=index).lower()
    return action


def _normalize_protocol(value: str | None) -> str:
    if value is None:
        return "unknown"
    return value.strip().lower()


def _require_csv_value(value: str | None, *, field_name: str, index: int) -> str:
    if value is None or not value.strip():
        raise InvalidWatchGuardInputError(f"watchguard traffic CSV row at index {index} has invalid '{field_name}'")
    return value.strip()


def _optional_csv_value(value: str | None) -> str | None:
    if value is None or not value.strip():
        return None
    return value.strip()


def _require_string(value: Any, *, field_name: str, index: int) -> str:
    if not isinstance(value, str) or not value.strip():
        raise InvalidWatchGuardInputError(f"watchguard record at index {index} has invalid '{field_name}'")
    return value.strip()


def _optional_string(value: Any) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str):
        raise InvalidWatchGuardInputError("watchguard record optional fields must be strings when provided")
    stripped = value.strip()
    return stripped or None


def _coerce_protocol(value: Any) -> str:
    if value is None:
        return "unknown"
    if not isinstance(value, str) or not value.strip():
        raise InvalidWatchGuardInputError("watchguard record has invalid 'protocol'")
    return value.strip().lower()


def _coerce_port(value: Any, *, field_name: str, index: int) -> int | None:
    if value is None:
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        return _safe_int(value, field_name=field_name, index=index)
    raise InvalidWatchGuardInputError(f"watchguard record at index {index} has invalid '{field_name}'")


def _safe_int(value: str | None, *, field_name: str, index: int) -> int | None:
    if value is None:
        return None
    stripped = value.strip()
    if not stripped or stripped == "\\N":
        return None
    try:
        return int(stripped)
    except ValueError as exc:
        raise InvalidWatchGuardInputError(
            f"watchguard traffic CSV row at index {index} has invalid '{field_name}'"
        ) from exc


def _parse_s3_uri(value: str) -> tuple[str, str]:
    parsed = urlparse(value)
    if parsed.scheme != "s3" or not parsed.netloc or not parsed.path:
        raise InvalidWatchGuardInputError("workspace ZIP payload 's3_uri' must be a valid s3://bucket/key URI")
    object_key = parsed.path.lstrip("/")
    if not object_key:
        raise InvalidWatchGuardInputError("workspace ZIP payload 's3_uri' must include an object key")
    return parsed.netloc, object_key
