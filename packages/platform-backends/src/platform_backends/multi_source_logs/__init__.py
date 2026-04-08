"""Multi-source logs backend for defensive log analysis without a SIEM."""

from platform_backends.multi_source_logs.descriptor import (
    MULTI_SOURCE_LOGS_ACTIVE_THREATS_OPERATION,
    MULTI_SOURCE_LOGS_BACKEND_ID,
    MULTI_SOURCE_LOGS_BACKEND_TYPE,
    MULTI_SOURCE_LOGS_CROSS_SOURCE_OPERATION,
    MULTI_SOURCE_LOGS_DNS_ANOMALY_OPERATION,
    MULTI_SOURCE_LOGS_FAILED_AUTH_OPERATION,
    MULTI_SOURCE_LOGS_LATERAL_MOVEMENT_OPERATION,
    MULTI_SOURCE_LOGS_NORMALIZE_OPERATION,
    MULTI_SOURCE_LOGS_PRIV_ESC_OPERATION,
    get_multi_source_logs_backend_descriptor,
)
from platform_backends.multi_source_logs.errors import (
    MultiSourceLogsBackendError,
    UnsupportedMultiSourceLogsOperationError,
)
from platform_backends.multi_source_logs.execute import (
    execute_predefined_observation,
)
from platform_backends.multi_source_logs.models import (
    MultiSourceDetectionFinding,
    MultiSourceLogsExecutionOutcome,
    NormalizedLogRecord,
)

__all__ = [
    "MULTI_SOURCE_LOGS_ACTIVE_THREATS_OPERATION",
    "MULTI_SOURCE_LOGS_BACKEND_ID",
    "MULTI_SOURCE_LOGS_BACKEND_TYPE",
    "MULTI_SOURCE_LOGS_CROSS_SOURCE_OPERATION",
    "MULTI_SOURCE_LOGS_DNS_ANOMALY_OPERATION",
    "MULTI_SOURCE_LOGS_FAILED_AUTH_OPERATION",
    "MULTI_SOURCE_LOGS_LATERAL_MOVEMENT_OPERATION",
    "MULTI_SOURCE_LOGS_NORMALIZE_OPERATION",
    "MULTI_SOURCE_LOGS_PRIV_ESC_OPERATION",
    "MultiSourceDetectionFinding",
    "MultiSourceLogsBackendError",
    "MultiSourceLogsExecutionOutcome",
    "NormalizedLogRecord",
    "UnsupportedMultiSourceLogsOperationError",
    "execute_predefined_observation",
    "get_multi_source_logs_backend_descriptor",
]
