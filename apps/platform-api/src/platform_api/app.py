"""FastAPI app creation and runtime wiring."""

from __future__ import annotations

import os

from fastapi import FastAPI

from platform_api.errors import register_exception_handlers
from platform_api.routes import api_router
from platform_api.runtime import create_runtime


def create_app() -> FastAPI:
    """Create the first minimal deterministic platform API app."""
    app = FastAPI(title="cai-platform-v2 API", version="0.1.0")
    app.state.runtime = create_runtime()
    register_exception_handlers(app)
    app.include_router(api_router)
    return app


def get_runtime_host() -> str:
    """Return the local runtime host for the API process."""
    return os.getenv("PLATFORM_API_HOST", "0.0.0.0")


def get_runtime_port() -> int:
    """Return the local runtime port for the API process."""
    return int(os.getenv("PLATFORM_API_PORT", "8000"))


def main() -> None:
    """Run the API through a thin Uvicorn entrypoint."""
    import uvicorn

    uvicorn.run(
        "platform_api.app:create_app",
        factory=True,
        host=get_runtime_host(),
        port=get_runtime_port(),
    )
