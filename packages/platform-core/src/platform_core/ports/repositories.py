"""Persistence-agnostic repository ports."""

from __future__ import annotations

from typing import Protocol, runtime_checkable

from platform_contracts import Artifact, Case, InvestigationDefinition, Run


@runtime_checkable
class CaseRepository(Protocol):
    """Minimal persistence boundary for case records."""

    def get_case(self, case_id: str) -> Case | None:
        """Return one case by id or `None` when it does not exist."""

    def save_case(self, case: Case) -> Case:
        """Persist and return the saved case."""


@runtime_checkable
class ArtifactRepository(Protocol):
    """Minimal read boundary for artifact records."""

    def get_artifact(self, artifact_id: str) -> Artifact | None:
        """Return one artifact by id or `None` when it does not exist."""


@runtime_checkable
class RunRepository(Protocol):
    """Minimal persistence boundary for run records."""

    def get_run(self, run_id: str) -> Run | None:
        """Return one run by id or `None` when it does not exist."""

    def save_run(self, run: Run) -> Run:
        """Persist and return the saved run."""


@runtime_checkable
class InvestigationDefinitionRepository(Protocol):
    """Minimal read boundary for investigation definitions."""

    def get_investigation_definition(self, investigation_definition_id: str) -> InvestigationDefinition | None:
        """Return one investigation definition by id or `None` when it does not exist."""
