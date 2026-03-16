"""Run contract models."""

from __future__ import annotations

from typing import Any

from pydantic import Field, field_validator, model_validator

from platform_contracts.common.base import TimestampedModel, generate_opaque_id
from platform_contracts.common.enums import EntityKind, RunStatus
from platform_contracts.common.refs import EntityRef, ensure_ref_list_types, ensure_ref_type


class Run(TimestampedModel):
    """Durable execution scope for one backend-specific investigation context."""

    run_id: str = Field(default_factory=lambda: generate_opaque_id("run"), min_length=1)
    backend_ref: EntityRef
    status: RunStatus = RunStatus.CREATED
    case_ref: EntityRef | None = None
    scope: dict[str, Any] = Field(default_factory=dict)
    input_artifact_refs: list[EntityRef] = Field(default_factory=list)
    observation_refs: list[EntityRef] = Field(default_factory=list)
    output_artifact_refs: list[EntityRef] = Field(default_factory=list)
    error_summary: str | None = Field(default=None, min_length=1)
    metadata: dict[str, Any] = Field(default_factory=dict)

    @field_validator("backend_ref")
    @classmethod
    def validate_backend_ref(cls, value: EntityRef) -> EntityRef:
        return ensure_ref_type(value, {EntityKind.BACKEND}, "backend_ref")

    @field_validator("case_ref")
    @classmethod
    def validate_case_ref(cls, value: EntityRef | None) -> EntityRef | None:
        return ensure_ref_type(value, {EntityKind.CASE}, "case_ref")

    @field_validator("input_artifact_refs", "output_artifact_refs")
    @classmethod
    def validate_artifact_refs(cls, value: list[EntityRef]) -> list[EntityRef]:
        return ensure_ref_list_types(value, {EntityKind.ARTIFACT}, "artifact_refs")

    @field_validator("observation_refs")
    @classmethod
    def validate_observation_refs(cls, value: list[EntityRef]) -> list[EntityRef]:
        return ensure_ref_list_types(value, {EntityKind.OBSERVATION_REQUEST}, "observation_refs")

    @model_validator(mode="after")
    def validate_status_shape(self) -> "Run":
        if self.status == RunStatus.FAILED and not self.error_summary:
            raise ValueError("failed runs must include error_summary")
        if self.status == RunStatus.COMPLETED and self.error_summary:
            raise ValueError("completed runs must not include error_summary")
        return self
