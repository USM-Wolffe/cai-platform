"""Observation request and result models."""

from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import Field, field_validator, model_validator

from platform_contracts.common.base import ContractModel, generate_opaque_id, utc_now
from platform_contracts.common.enums import EntityKind, ObservationStatus
from platform_contracts.common.refs import EntityRef, ensure_ref_list_types, ensure_ref_type


class ObservationRequest(ContractModel):
    """Single deterministic action request."""

    observation_id: str = Field(default_factory=lambda: generate_opaque_id("observation"), min_length=1)
    case_ref: EntityRef
    backend_ref: EntityRef
    run_ref: EntityRef
    requested_at: datetime = Field(default_factory=utc_now)
    operation_kind: str = Field(min_length=1)
    input_artifact_refs: list[EntityRef] = Field(default_factory=list)
    parameters: dict[str, Any] = Field(default_factory=dict)
    query_request_ref: EntityRef | None = None
    approval_ref: EntityRef | None = None
    requested_by: str = Field(min_length=1)

    @field_validator("case_ref")
    @classmethod
    def validate_case_ref(cls, value: EntityRef) -> EntityRef:
        return ensure_ref_type(value, {EntityKind.CASE}, "case_ref")

    @field_validator("backend_ref")
    @classmethod
    def validate_backend_ref(cls, value: EntityRef) -> EntityRef:
        return ensure_ref_type(value, {EntityKind.BACKEND}, "backend_ref")

    @field_validator("run_ref")
    @classmethod
    def validate_run_ref(cls, value: EntityRef) -> EntityRef:
        return ensure_ref_type(value, {EntityKind.RUN}, "run_ref")

    @field_validator("input_artifact_refs")
    @classmethod
    def validate_input_artifacts(cls, value: list[EntityRef]) -> list[EntityRef]:
        return ensure_ref_list_types(value, {EntityKind.ARTIFACT}, "input_artifact_refs")

    @field_validator("query_request_ref")
    @classmethod
    def validate_query_request_ref(cls, value: EntityRef | None) -> EntityRef | None:
        return ensure_ref_type(value, {EntityKind.QUERY_REQUEST}, "query_request_ref")

    @field_validator("approval_ref")
    @classmethod
    def validate_approval_ref(cls, value: EntityRef | None) -> EntityRef | None:
        return ensure_ref_type(value, {EntityKind.APPROVAL_DECISION}, "approval_ref")


class ObservationResult(ContractModel):
    """Normalized outcome of a deterministic action."""

    observation_result_id: str = Field(default_factory=lambda: generate_opaque_id("observation_result"), min_length=1)
    observation_ref: EntityRef
    status: ObservationStatus
    completed_at: datetime = Field(default_factory=utc_now)
    output_artifact_refs: list[EntityRef] = Field(default_factory=list)
    structured_summary: dict[str, Any] = Field(default_factory=dict)
    raw_result_ref: EntityRef | None = None
    warnings: list[str] = Field(default_factory=list)
    errors: list[str] = Field(default_factory=list)
    provenance: dict[str, Any] = Field(default_factory=dict)

    @field_validator("observation_ref")
    @classmethod
    def validate_observation_ref(cls, value: EntityRef) -> EntityRef:
        return ensure_ref_type(value, {EntityKind.OBSERVATION_REQUEST}, "observation_ref")

    @field_validator("output_artifact_refs")
    @classmethod
    def validate_output_artifacts(cls, value: list[EntityRef]) -> list[EntityRef]:
        return ensure_ref_list_types(value, {EntityKind.ARTIFACT}, "output_artifact_refs")

    @field_validator("raw_result_ref")
    @classmethod
    def validate_raw_result_ref(cls, value: EntityRef | None) -> EntityRef | None:
        return ensure_ref_type(value, {EntityKind.ARTIFACT}, "raw_result_ref")

    @model_validator(mode="after")
    def validate_status_shape(self) -> "ObservationResult":
        if self.status == ObservationStatus.FAILED and not self.errors:
            raise ValueError("failed observation results must include at least one error")
        if self.status == ObservationStatus.SUCCEEDED and self.errors:
            raise ValueError("successful observation results must not include execution errors")
        if self.status == ObservationStatus.SUCCEEDED_NO_FINDINGS and self.errors:
            raise ValueError("no-findings observation results must not include execution errors")
        return self
