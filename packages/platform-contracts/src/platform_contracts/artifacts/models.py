"""Artifact contract models."""

from __future__ import annotations

from typing import Any

from pydantic import Field, field_validator

from platform_contracts.common.base import TimestampedModel, generate_opaque_id
from platform_contracts.common.enums import ArtifactKind, EntityKind
from platform_contracts.common.refs import EntityRef, ensure_ref_type


class Artifact(TimestampedModel):
    """Durable record for input, normalized evidence, or derived output."""

    artifact_id: str = Field(default_factory=lambda: generate_opaque_id("artifact"), min_length=1)
    kind: ArtifactKind
    subtype: str | None = Field(default=None, min_length=1)
    format: str = Field(min_length=1)
    storage_ref: str = Field(min_length=1)
    content_hash: str = Field(min_length=1)
    produced_by_backend_ref: EntityRef | None = None
    produced_by_run_ref: EntityRef | None = None
    produced_by_observation_ref: EntityRef | None = None
    labels: list[str] = Field(default_factory=list)
    summary: str | None = Field(default=None, min_length=1)
    metadata: dict[str, Any] = Field(default_factory=dict)

    @field_validator("produced_by_backend_ref")
    @classmethod
    def validate_backend_ref(cls, value: EntityRef | None) -> EntityRef | None:
        return ensure_ref_type(value, {EntityKind.BACKEND}, "produced_by_backend_ref")

    @field_validator("produced_by_run_ref")
    @classmethod
    def validate_run_ref(cls, value: EntityRef | None) -> EntityRef | None:
        return ensure_ref_type(value, {EntityKind.RUN}, "produced_by_run_ref")

    @field_validator("produced_by_observation_ref")
    @classmethod
    def validate_observation_ref(cls, value: EntityRef | None) -> EntityRef | None:
        return ensure_ref_type(
            value,
            {EntityKind.OBSERVATION_REQUEST, EntityKind.OBSERVATION_RESULT},
            "produced_by_observation_ref",
        )
