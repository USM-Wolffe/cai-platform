"""WatchGuard adapter-local errors."""


class WatchGuardAdapterError(ValueError):
    """Base adapter error for invalid or unsupported WatchGuard input."""


class UnsupportedWatchGuardArtifactError(WatchGuardAdapterError):
    """Raised when an artifact contract is unsupported for WatchGuard normalization."""


class InvalidWatchGuardInputError(WatchGuardAdapterError):
    """Raised when the WatchGuard payload shape is invalid."""
