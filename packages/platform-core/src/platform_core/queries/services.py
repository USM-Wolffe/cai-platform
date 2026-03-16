"""Query-facing coordination helpers."""

from __future__ import annotations

from platform_contracts import BackendDescriptor, QueryDefinition, QueryRequest

from platform_core.errors import ContractViolationError
from platform_core.ports import BackendRegistry
from platform_core.services import ensure_backend_supports_query_mode, get_backend_or_raise


def resolve_query_backend(backend_registry: BackendRegistry, query_request: QueryRequest) -> BackendDescriptor:
    """Resolve the backend descriptor for a query request."""
    return get_backend_or_raise(backend_registry, query_request.backend_ref.id)


def ensure_backend_supports_query_request(
    backend_registry: BackendRegistry,
    query_request: QueryRequest,
    *,
    query_definition: QueryDefinition | None = None,
) -> BackendDescriptor:
    """Resolve and validate backend support for the query request."""
    backend = resolve_query_backend(backend_registry, query_request)
    ensure_backend_supports_query_mode(backend, query_request.query_mode)

    if query_definition is not None and query_definition.query_mode != query_request.query_mode:
        raise ContractViolationError("query_definition.query_mode must match query_request.query_mode")

    return backend
