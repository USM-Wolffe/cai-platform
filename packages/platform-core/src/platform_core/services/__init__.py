"""Shared backend-facing validation helpers."""

from platform_core.services.backend_registry import (
    ensure_backend_can_create_run,
    ensure_backend_supports_query_mode,
    ensure_backend_supports_workflow,
    get_backend_or_raise,
)

__all__ = [
    "ensure_backend_can_create_run",
    "ensure_backend_supports_query_mode",
    "ensure_backend_supports_workflow",
    "get_backend_or_raise",
]
