"""Registry-backed backend validation helpers."""

from __future__ import annotations

from platform_contracts import (
    BackendCapabilityName,
    BackendDescriptor,
    QueryMode,
    WorkflowType,
)

from platform_core.errors import NotFoundError, UnsupportedBackendError
from platform_core.ports import BackendRegistry


def get_backend_or_raise(backend_registry: BackendRegistry, backend_id: str) -> BackendDescriptor:
    """Resolve one backend descriptor or raise a normalized core error."""
    backend = backend_registry.get_backend(backend_id)
    if backend is None:
        raise NotFoundError(f"backend '{backend_id}' was not found")
    return backend


def ensure_backend_can_create_run(backend: BackendDescriptor) -> None:
    """Require the backend to expose the create-run capability."""
    _ensure_backend_has_capability(backend, BackendCapabilityName.CREATE_RUN)


def ensure_backend_supports_workflow(backend: BackendDescriptor, workflow_type: WorkflowType) -> None:
    """Require the backend to support the requested workflow type."""
    if workflow_type not in backend.supported_workflow_types:
        raise UnsupportedBackendError(
            f"backend '{backend.backend_id}' does not support workflow '{workflow_type.value}'"
        )


def ensure_backend_supports_query_mode(backend: BackendDescriptor, query_mode: QueryMode) -> None:
    """Require the backend to expose the capability needed for the query mode."""
    capability_map = {
        QueryMode.PREDEFINED: BackendCapabilityName.EXECUTE_PREDEFINED_QUERY,
        QueryMode.CUSTOM_GUARDED: BackendCapabilityName.EXECUTE_CUSTOM_QUERY,
    }
    _ensure_backend_has_capability(backend, capability_map[query_mode])


def _ensure_backend_has_capability(backend: BackendDescriptor, capability_name: BackendCapabilityName) -> None:
    if any(capability.name == capability_name for capability in backend.capabilities):
        return
    raise UnsupportedBackendError(
        f"backend '{backend.backend_id}' does not expose capability '{capability_name.value}'"
    )
