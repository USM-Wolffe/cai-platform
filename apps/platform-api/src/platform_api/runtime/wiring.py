"""Runtime creation and dependency helpers."""

from __future__ import annotations

import os

from fastapi import Request

from platform_api.runtime.memory import AppRuntime, build_default_runtime


def create_runtime() -> AppRuntime:
    """Create a runtime backed by PostgreSQL if DATABASE_URL is set, otherwise in-memory."""
    database_url = os.environ.get("DATABASE_URL")
    if database_url:
        return _build_postgres_runtime(database_url)
    return build_default_runtime()


def get_runtime(request: Request) -> AppRuntime:
    """Resolve the runtime from app state."""
    return request.app.state.runtime


def _build_postgres_runtime(database_url: str) -> AppRuntime:
    from platform_api.runtime.postgres import (
        PostgresArtifactRepository,
        PostgresCaseRepository,
        PostgresRunRepository,
        apply_schema,
        init_pool,
    )
    from platform_api.runtime.memory import (
        AppRuntime,
        DevelopmentApprovalPolicy,
        InMemoryAuditPort,
        InProcessBackendRegistry,
    )
    from platform_backends.watchguard_logs import get_watchguard_logs_backend_descriptor
    from platform_backends.phishing_email import get_phishing_email_backend_descriptor

    init_pool(database_url)
    apply_schema()

    return AppRuntime(
        case_repository=PostgresCaseRepository(),
        artifact_repository=PostgresArtifactRepository(),
        run_repository=PostgresRunRepository(),
        backend_registry=InProcessBackendRegistry(
            [
                get_watchguard_logs_backend_descriptor(),
                get_phishing_email_backend_descriptor(),
            ]
        ),
        approval_policy=DevelopmentApprovalPolicy(),
        audit_port=InMemoryAuditPort(),
    )
