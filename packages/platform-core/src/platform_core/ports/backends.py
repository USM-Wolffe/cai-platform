"""Backend registry lookup port."""

from __future__ import annotations

from typing import Protocol, runtime_checkable

from platform_contracts import BackendDescriptor


@runtime_checkable
class BackendRegistry(Protocol):
    """Read-only boundary for resolving backend descriptors."""

    def get_backend(self, backend_id: str) -> BackendDescriptor | None:
        """Return one backend descriptor by id or `None` when it does not exist."""
