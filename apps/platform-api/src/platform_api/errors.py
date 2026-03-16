"""Minimal HTTP error mapping for platform-api."""

from __future__ import annotations

from fastapi import FastAPI
from fastapi.responses import JSONResponse
from platform_adapters.phishing_email.errors import PhishingEmailAdapterError
from platform_adapters.watchguard.errors import WatchGuardAdapterError
from platform_backends.phishing_email.errors import PhishingEmailBackendError
from platform_backends.watchguard_logs.errors import WatchGuardLogsBackendError
from platform_core import (
    ApprovalRequiredError,
    ContractViolationError,
    InvalidStateError,
    NotFoundError,
    UnsupportedBackendError,
)


def register_exception_handlers(app: FastAPI) -> None:
    """Register the minimal deterministic HTTP error mapping."""

    @app.exception_handler(NotFoundError)
    async def handle_not_found(_, exc: NotFoundError) -> JSONResponse:
        return _error_response(status_code=404, error_type="not_found", message=str(exc))

    @app.exception_handler(UnsupportedBackendError)
    async def handle_unsupported_backend(_, exc: UnsupportedBackendError) -> JSONResponse:
        return _error_response(status_code=400, error_type="unsupported_backend", message=str(exc))

    @app.exception_handler(InvalidStateError)
    async def handle_invalid_state(_, exc: InvalidStateError) -> JSONResponse:
        return _error_response(status_code=409, error_type="invalid_state", message=str(exc))

    @app.exception_handler(ApprovalRequiredError)
    async def handle_approval_required(_, exc: ApprovalRequiredError) -> JSONResponse:
        return _error_response(status_code=409, error_type="approval_required", message=str(exc))

    @app.exception_handler(ContractViolationError)
    async def handle_contract_violation(_, exc: ContractViolationError) -> JSONResponse:
        return _error_response(status_code=400, error_type="contract_violation", message=str(exc))

    @app.exception_handler(WatchGuardAdapterError)
    async def handle_watchguard_adapter_error(_, exc: WatchGuardAdapterError) -> JSONResponse:
        return _error_response(status_code=400, error_type="invalid_adapter_input", message=str(exc))

    @app.exception_handler(PhishingEmailAdapterError)
    async def handle_phishing_email_adapter_error(_, exc: PhishingEmailAdapterError) -> JSONResponse:
        return _error_response(status_code=400, error_type="invalid_adapter_input", message=str(exc))

    @app.exception_handler(WatchGuardLogsBackendError)
    async def handle_watchguard_backend_error(_, exc: WatchGuardLogsBackendError) -> JSONResponse:
        return _error_response(status_code=400, error_type="backend_execution_error", message=str(exc))

    @app.exception_handler(PhishingEmailBackendError)
    async def handle_phishing_email_backend_error(_, exc: PhishingEmailBackendError) -> JSONResponse:
        return _error_response(status_code=400, error_type="backend_execution_error", message=str(exc))


def _error_response(*, status_code: int, error_type: str, message: str) -> JSONResponse:
    return JSONResponse(
        status_code=status_code,
        content={
            "error": {
                "type": error_type,
                "message": message,
            }
        },
    )
