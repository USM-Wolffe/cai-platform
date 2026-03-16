"""Case-level contract models."""

from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import Field, field_validator

from platform_contracts.common.base import ContractModel, TimestampedModel, generate_opaque_id, utc_now
from platform_contracts.common.enums import CaseStatus, EntityKind, WorkflowType
from platform_contracts.common.refs import EntityRef, ExternalReference, ensure_ref_list_types, ensure_ref_type


class TimelineEvent(ContractModel):
    """Timeline entry embedded inside a case record."""

    event_id: str = Field(default_factory=lambda: generate_opaque_id("evt"), min_length=1)
    timestamp: datetime = Field(default_factory=utc_now)
    kind: str = Field(min_length=1)
    summary: str = Field(min_length=1)
    related_refs: list[EntityRef] = Field(default_factory=list)

    @field_validator("related_refs")
    @classmethod
    def validate_related_refs(cls, value: list[EntityRef]) -> list[EntityRef]:
        return ensure_ref_list_types(value, set(EntityKind), "related_refs")


class DecisionRecord(ContractModel):
    """Decision entry embedded inside a case record."""

    decision_id: str = Field(default_factory=lambda: generate_opaque_id("decision"), min_length=1)
    timestamp: datetime = Field(default_factory=utc_now)
    summary: str = Field(min_length=1)
    rationale: str = Field(min_length=1)
    related_refs: list[EntityRef] = Field(default_factory=list)

    @field_validator("related_refs")
    @classmethod
    def validate_related_refs(cls, value: list[EntityRef]) -> list[EntityRef]:
        return ensure_ref_list_types(value, set(EntityKind), "related_refs")


class Case(TimestampedModel):
    """Canonical durable record for one investigation case."""

    case_id: str = Field(default_factory=lambda: generate_opaque_id("case"), min_length=1)
    workflow_type: WorkflowType
    status: CaseStatus = CaseStatus.OPEN
    title: str = Field(min_length=1)
    summary: str = Field(min_length=1)
    investigation_definition_ref: EntityRef | None = None
    current_stage_id: str | None = Field(default=None, min_length=1)
    artifact_refs: list[EntityRef] = Field(default_factory=list)
    run_refs: list[EntityRef] = Field(default_factory=list)
    timeline: list[TimelineEvent] = Field(default_factory=list)
    decision_log: list[DecisionRecord] = Field(default_factory=list)
    labels: list[str] = Field(default_factory=list)
    external_refs: list[ExternalReference] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)

    @field_validator("investigation_definition_ref")
    @classmethod
    def validate_investigation_ref(cls, value: EntityRef | None) -> EntityRef | None:
        return ensure_ref_type(value, {EntityKind.INVESTIGATION_DEFINITION}, "investigation_definition_ref")

    @field_validator("artifact_refs")
    @classmethod
    def validate_artifact_refs(cls, value: list[EntityRef]) -> list[EntityRef]:
        return ensure_ref_list_types(value, {EntityKind.ARTIFACT}, "artifact_refs")

    @field_validator("run_refs")
    @classmethod
    def validate_run_refs(cls, value: list[EntityRef]) -> list[EntityRef]:
        return ensure_ref_list_types(value, {EntityKind.RUN}, "run_refs")
