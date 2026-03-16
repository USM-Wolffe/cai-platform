"""Small adapter-local normalized types."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class WatchGuardLogRecord:
    """Normalized single WatchGuard log record used by the first backend slice."""

    timestamp: str
    action: str
    src_ip: str
    dst_ip: str
    protocol: str
    policy: str | None = None
    src_port: int | None = None
    dst_port: int | None = None
    question: str | None = None
    record_type: str | None = None


@dataclass(frozen=True)
class NormalizedWatchGuardBatch:
    """Normalized batch plus deterministic summary counts."""

    records: list[WatchGuardLogRecord]
    record_count: int
    action_counts: dict[str, int]
    input_shape: str
    log_type: str
