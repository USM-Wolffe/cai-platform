"""Minimal error model for the CAI-facing orchestrator app."""

from __future__ import annotations

from typing import Any


class CaiOrchestratorError(Exception):
    """Base error for the CAI-facing orchestration layer."""


class MissingCaiDependencyError(CaiOrchestratorError):
    """Raised when CAI-specific wiring is requested without the external CAI dependency."""


class InvalidOperatorInputError(CaiOrchestratorError):
    """Raised when the operator request is too malformed for the first slice."""


class PlatformApiUnavailableError(CaiOrchestratorError):
    """Raised when the platform API cannot be reached."""


class PlatformApiRequestError(CaiOrchestratorError):
    """Raised when the platform API returns a structured non-success response."""

    def __init__(self, *, method: str, path: str, status_code: int, payload: Any) -> None:
        self.method = method
        self.path = path
        self.status_code = status_code
        self.payload = payload
        super().__init__(f"{method} {path} failed with status {status_code}")


class OrchestrationFlowError(CaiOrchestratorError):
    """Raised when one phase of the thin orchestration flow fails."""

    def __init__(
        self,
        *,
        phase: str,
        message: str,
        status_code: int | None = None,
        details: Any = None,
    ) -> None:
        self.phase = phase
        self.status_code = status_code
        self.details = details
        super().__init__(message)
