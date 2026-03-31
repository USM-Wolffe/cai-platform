"""Errors for the multi_source_logs backend."""

from __future__ import annotations


class MultiSourceLogsBackendError(Exception):
    """Base error for all multi_source_logs backend failures."""


class UnsupportedMultiSourceLogsOperationError(MultiSourceLogsBackendError):
    """Raised when an unknown operation_kind is dispatched to this backend."""
