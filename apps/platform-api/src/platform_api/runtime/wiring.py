"""Runtime creation and dependency helpers."""

from __future__ import annotations

from fastapi import Request

from platform_api.runtime.memory import AppRuntime, build_default_runtime


def create_runtime() -> AppRuntime:
    """Create a fresh in-memory runtime bundle."""
    return build_default_runtime()


def get_runtime(request: Request) -> AppRuntime:
    """Resolve the in-memory runtime from app state."""
    return request.app.state.runtime
