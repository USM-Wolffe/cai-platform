"""WatchGuard adapter helpers for the first log backend slice."""

from platform_adapters.watchguard.errors import (
    InvalidWatchGuardInputError,
    UnsupportedWatchGuardArtifactError,
    WatchGuardAdapterError,
)
from platform_adapters.watchguard.normalize import (
    WATCHGUARD_ALARM_LOG_TYPE,
    WATCHGUARD_EVENT_LOG_TYPE,
    WATCHGUARD_SEMANTIC_RECORDS_INPUT_SHAPE,
    WATCHGUARD_WORKSPACE_S3_ZIP_INPUT_SHAPE,
    WATCHGUARD_WORKSPACE_S3_ZIP_SOURCE_KIND,
    WATCHGUARD_TRAFFIC_CSV_INPUT_SHAPE,
    WATCHGUARD_TRAFFIC_LOG_TYPE,
    filter_denied_watchguard_batch,
    inspect_watchguard_input_artifact,
    is_denied_watchguard_action,
    normalize_watchguard_log_payload,
    parse_workspace_s3_zip_reference,
)
from platform_adapters.watchguard.types import (
    NormalizedWatchGuardBatch,
    WatchGuardLogRecord,
    WatchGuardWorkspaceZipReference,
)

__all__ = [
    "InvalidWatchGuardInputError",
    "NormalizedWatchGuardBatch",
    "UnsupportedWatchGuardArtifactError",
    "WatchGuardAdapterError",
    "WatchGuardLogRecord",
    "WatchGuardWorkspaceZipReference",
    "WATCHGUARD_ALARM_LOG_TYPE",
    "WATCHGUARD_EVENT_LOG_TYPE",
    "WATCHGUARD_SEMANTIC_RECORDS_INPUT_SHAPE",
    "WATCHGUARD_WORKSPACE_S3_ZIP_INPUT_SHAPE",
    "WATCHGUARD_WORKSPACE_S3_ZIP_SOURCE_KIND",
    "WATCHGUARD_TRAFFIC_CSV_INPUT_SHAPE",
    "WATCHGUARD_TRAFFIC_LOG_TYPE",
    "filter_denied_watchguard_batch",
    "inspect_watchguard_input_artifact",
    "is_denied_watchguard_action",
    "normalize_watchguard_log_payload",
    "parse_workspace_s3_zip_reference",
]
