"""WatchGuard adapter helpers for the first log backend slice."""

from platform_adapters.watchguard.errors import (
    InvalidWatchGuardInputError,
    UnsupportedWatchGuardArtifactError,
    WatchGuardAdapterError,
)
from platform_adapters.watchguard.normalize import (
    WATCHGUARD_SEMANTIC_RECORDS_INPUT_SHAPE,
    WATCHGUARD_TRAFFIC_CSV_INPUT_SHAPE,
    WATCHGUARD_TRAFFIC_LOG_TYPE,
    filter_denied_watchguard_batch,
    inspect_watchguard_input_artifact,
    is_denied_watchguard_action,
    normalize_watchguard_log_payload,
)
from platform_adapters.watchguard.types import NormalizedWatchGuardBatch, WatchGuardLogRecord

__all__ = [
    "InvalidWatchGuardInputError",
    "NormalizedWatchGuardBatch",
    "UnsupportedWatchGuardArtifactError",
    "WatchGuardAdapterError",
    "WatchGuardLogRecord",
    "WATCHGUARD_SEMANTIC_RECORDS_INPUT_SHAPE",
    "WATCHGUARD_TRAFFIC_CSV_INPUT_SHAPE",
    "WATCHGUARD_TRAFFIC_LOG_TYPE",
    "filter_denied_watchguard_batch",
    "inspect_watchguard_input_artifact",
    "is_denied_watchguard_action",
    "normalize_watchguard_log_payload",
]
