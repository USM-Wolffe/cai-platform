"""WatchGuard logs backend-local errors."""


class WatchGuardLogsBackendError(ValueError):
    """Base backend-local error for the first WatchGuard slice."""


class UnsupportedWatchGuardObservationError(WatchGuardLogsBackendError):
    """Raised when the requested observation path is not supported by this slice."""


class InvalidWatchGuardQueryError(WatchGuardLogsBackendError):
    """Raised when a guarded custom query shape is invalid or unsafe for this slice."""
