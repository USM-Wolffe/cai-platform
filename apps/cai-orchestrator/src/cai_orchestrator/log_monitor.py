"""S3 log file polling monitor — mirrors imap_monitor.py for log source ingestion."""

from __future__ import annotations

import json
import os
from dataclasses import dataclass
from datetime import datetime, timezone


@dataclass(frozen=True)
class S3LogRef:
    """Reference to a single S3 log file discovered during polling."""

    s3_uri: str
    source_type: str
    bucket: str
    key: str
    last_modified_iso: str  # ISO-8601 for deduplication


@dataclass(frozen=True)
class LogMonitorSettings:
    """Runtime configuration for the S3 log monitor."""

    s3_bucket: str
    s3_prefix: str
    source_type: str        # 'windows_events'|'linux_auth'|'dns_logs'|'firewall_csv'|'web_proxy'
    poll_interval: int      # seconds, default 60
    state_file_path: str    # JSON tracking last-processed keys


class LogMonitorConfigError(Exception):
    """Raised when required log monitor environment variables are missing or invalid."""


_VALID_SOURCE_TYPES = frozenset({
    "windows_events",
    "linux_auth",
    "dns_logs",
    "firewall_csv",
    "web_proxy",
})


def load_log_monitor_settings() -> LogMonitorSettings:
    """Load log monitor settings from environment variables.

    Required:
        LOG_MONITOR_S3_BUCKET, LOG_MONITOR_S3_PREFIX, LOG_MONITOR_SOURCE_TYPE

    Optional:
        LOG_MONITOR_POLL_INTERVAL (default: 60 seconds)
        LOG_MONITOR_STATE_FILE (default: .log_monitor_state.json)
    """
    missing = [
        k for k in ("LOG_MONITOR_S3_BUCKET", "LOG_MONITOR_S3_PREFIX", "LOG_MONITOR_SOURCE_TYPE")
        if not os.environ.get(k)
    ]
    if missing:
        raise LogMonitorConfigError(f"missing required log monitor environment variables: {', '.join(missing)}")

    source_type = os.environ["LOG_MONITOR_SOURCE_TYPE"]
    if source_type not in _VALID_SOURCE_TYPES:
        raise LogMonitorConfigError(
            f"LOG_MONITOR_SOURCE_TYPE must be one of {sorted(_VALID_SOURCE_TYPES)}, got '{source_type}'"
        )

    try:
        poll_interval = int(os.environ.get("LOG_MONITOR_POLL_INTERVAL", "60"))
    except ValueError:
        raise LogMonitorConfigError("LOG_MONITOR_POLL_INTERVAL must be an integer")

    state_file = os.environ.get("LOG_MONITOR_STATE_FILE", ".log_monitor_state.json")

    return LogMonitorSettings(
        s3_bucket=os.environ["LOG_MONITOR_S3_BUCKET"],
        s3_prefix=os.environ["LOG_MONITOR_S3_PREFIX"].rstrip("/"),
        source_type=source_type,
        poll_interval=poll_interval,
        state_file_path=state_file,
    )


def poll_new_log_files(settings: LogMonitorSettings) -> list[S3LogRef]:
    """List objects under the configured S3 prefix and return newly-seen files.

    Files already in the state file are skipped. The state file is updated
    with newly discovered keys and the current timestamp after each call.
    """
    try:
        import boto3
    except ImportError as exc:
        raise LogMonitorConfigError(
            "boto3 is required for log monitoring. Install it with: pip install boto3"
        ) from exc

    state = _load_state(settings.state_file_path)
    processed_keys: set[str] = set(state.get("last_processed_keys", []))

    s3 = boto3.client("s3")
    prefix = settings.s3_prefix + "/" if settings.s3_prefix and not settings.s3_prefix.endswith("/") else settings.s3_prefix
    paginator = s3.get_paginator("list_objects_v2")

    new_refs: list[S3LogRef] = []
    for page in paginator.paginate(Bucket=settings.s3_bucket, Prefix=prefix):
        for obj in page.get("Contents", []):
            key: str = obj["Key"]
            if key in processed_keys:
                continue
            if key.endswith("/"):
                continue
            last_modified: datetime = obj["LastModified"]
            new_refs.append(S3LogRef(
                s3_uri=f"s3://{settings.s3_bucket}/{key}",
                source_type=settings.source_type,
                bucket=settings.s3_bucket,
                key=key,
                last_modified_iso=last_modified.astimezone(timezone.utc).isoformat(),
            ))
            processed_keys.add(key)

    if new_refs:
        _save_state(settings.state_file_path, {
            "last_processed_keys": sorted(processed_keys),
            "last_run_iso": datetime.now(timezone.utc).isoformat(),
        })

    return new_refs


def _load_state(state_file_path: str) -> dict:
    try:
        with open(state_file_path, encoding="utf-8") as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return {}


def _save_state(state_file_path: str, state: dict) -> None:
    with open(state_file_path, "w", encoding="utf-8") as f:
        json.dump(state, f, indent=2)
