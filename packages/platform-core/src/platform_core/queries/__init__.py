"""Query-facing backend validation helpers."""

from platform_core.queries.services import ensure_backend_supports_query_request, resolve_query_backend

__all__ = [
    "ensure_backend_supports_query_request",
    "resolve_query_backend",
]
