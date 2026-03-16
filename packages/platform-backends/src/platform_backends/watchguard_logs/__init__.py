"""WatchGuard logs backend slice for deterministic WatchGuard observation paths."""

from platform_backends.watchguard_logs.descriptor import (
    WATCHGUARD_ANALYTICS_BUNDLE_BASIC_OPERATION,
    WATCHGUARD_ANALYTICS_BUNDLE_BASIC_QUERY_CLASS,
    WATCHGUARD_FILTER_DENIED_EVENTS_OPERATION,
    WATCHGUARD_FILTER_DENIED_EVENTS_QUERY_CLASS,
    WATCHGUARD_GUARDED_FILTERED_ROWS_QUERY_CLASS,
    WATCHGUARD_LOGS_BACKEND_ID,
    WATCHGUARD_LOGS_BACKEND_TYPE,
    WATCHGUARD_NORMALIZE_SUMMARY_OPERATION,
    WATCHGUARD_NORMALIZE_SUMMARY_QUERY_CLASS,
    WATCHGUARD_TOP_TALKERS_BASIC_OPERATION,
    WATCHGUARD_TOP_TALKERS_BASIC_QUERY_CLASS,
    get_watchguard_logs_backend_descriptor,
)
from platform_backends.watchguard_logs.errors import (
    InvalidWatchGuardQueryError,
    UnsupportedWatchGuardObservationError,
    WatchGuardLogsBackendError,
)
from platform_backends.watchguard_logs.execute import (
    WatchGuardCustomQueryOutcome,
    WatchGuardExecutionOutcome,
    execute_guarded_custom_query,
    execute_predefined_observation,
)

__all__ = [
    "InvalidWatchGuardQueryError",
    "UnsupportedWatchGuardObservationError",
    "WATCHGUARD_ANALYTICS_BUNDLE_BASIC_OPERATION",
    "WATCHGUARD_ANALYTICS_BUNDLE_BASIC_QUERY_CLASS",
    "WATCHGUARD_FILTER_DENIED_EVENTS_OPERATION",
    "WATCHGUARD_FILTER_DENIED_EVENTS_QUERY_CLASS",
    "WATCHGUARD_GUARDED_FILTERED_ROWS_QUERY_CLASS",
    "WATCHGUARD_LOGS_BACKEND_ID",
    "WATCHGUARD_LOGS_BACKEND_TYPE",
    "WATCHGUARD_NORMALIZE_SUMMARY_OPERATION",
    "WATCHGUARD_NORMALIZE_SUMMARY_QUERY_CLASS",
    "WATCHGUARD_TOP_TALKERS_BASIC_OPERATION",
    "WATCHGUARD_TOP_TALKERS_BASIC_QUERY_CLASS",
    "WatchGuardCustomQueryOutcome",
    "WatchGuardExecutionOutcome",
    "WatchGuardLogsBackendError",
    "execute_guarded_custom_query",
    "execute_predefined_observation",
    "get_watchguard_logs_backend_descriptor",
]
