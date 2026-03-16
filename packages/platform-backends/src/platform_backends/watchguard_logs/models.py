"""Small backend-local models for execution outcomes and guarded query specs."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from platform_contracts import Artifact, ObservationResult


@dataclass(frozen=True)
class WatchGuardExecutionOutcome:
    """Normalized outcome for the first predefined WatchGuard observation."""

    artifacts: list[Artifact]
    observation_result: ObservationResult


@dataclass(frozen=True)
class WatchGuardCustomQueryOutcome:
    """Normalized outcome for the first guarded custom query slice."""

    artifacts: list[Artifact]
    query_summary: dict[str, Any]


@dataclass(frozen=True)
class WatchGuardGuardedFilter:
    """One allowlisted guarded filter clause."""

    field: str
    op: str
    value: str | tuple[str, ...]


@dataclass(frozen=True)
class WatchGuardGuardedQuerySpec:
    """Parsed and validated guarded custom query spec."""

    filters: tuple[WatchGuardGuardedFilter, ...]
    limit: int
