"""Query definition and request models."""

from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import Field, field_validator, model_validator

from platform_contracts.common.base import ContractModel, generate_opaque_id, utc_now
from platform_contracts.common.enums import ArtifactKind, EntityKind, QueryMode, RiskClass
from platform_contracts.common.refs import EntityRef, ensure_ref_type


class QueryResultContract(ContractModel):
    """Expected normalized shape of a query result."""

    summary_type: str = Field(min_length=1)
    artifact_outputs: list[ArtifactKind] = Field(default_factory=list)
    supports_raw_result_ref: bool = True


class QueryDefinition(ContractModel):
    """Versioned allowed query shape."""

    query_definition_id: str = Field(default_factory=lambda: generate_opaque_id("querydef"), min_length=1)
    version: str = Field(default="1.0.0")
    investigation_definition_ref: EntityRef | None = None
    query_mode: QueryMode
    query_class: str = Field(min_length=1)
    backend_scope: str = Field(min_length=1)
    parameter_schema: dict[str, Any] = Field(default_factory=dict)
    result_contract: QueryResultContract
    risk_class: RiskClass
    approval_policy_ref: str | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)

    @field_validator("investigation_definition_ref")
    @classmethod
    def validate_investigation_definition_ref(cls, value: EntityRef | None) -> EntityRef | None:
        return ensure_ref_type(
            value,
            {EntityKind.INVESTIGATION_DEFINITION},
            "investigation_definition_ref",
        )


class QueryRequest(ContractModel):
    """Concrete request to execute a query definition or guarded custom query."""

    query_request_id: str = Field(default_factory=lambda: generate_opaque_id("queryreq"), min_length=1)
    query_definition_ref: EntityRef | None = None
    case_ref: EntityRef
    backend_ref: EntityRef
    run_ref: EntityRef | None = None
    query_mode: QueryMode
    parameters: dict[str, Any] = Field(default_factory=dict)
    requested_scope: str = Field(min_length=1)
    requested_at: datetime = Field(default_factory=utc_now)
    reason: str = Field(min_length=1)
    approval_ref: EntityRef | None = None
    requested_by: str = Field(min_length=1)
    custom_query_text: str | None = None

    @field_validator("query_definition_ref")
    @classmethod
    def validate_query_definition_ref(cls, value: EntityRef | None) -> EntityRef | None:
        return ensure_ref_type(value, {EntityKind.QUERY_DEFINITION}, "query_definition_ref")

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
    def validate_run_ref(cls, value: EntityRef | None) -> EntityRef | None:
        return ensure_ref_type(value, {EntityKind.RUN}, "run_ref")

    @field_validator("approval_ref")
    @classmethod
    def validate_approval_ref(cls, value: EntityRef | None) -> EntityRef | None:
        return ensure_ref_type(value, {EntityKind.APPROVAL_DECISION}, "approval_ref")

    @model_validator(mode="after")
    def validate_query_mode_requirements(self) -> "QueryRequest":
        if self.query_mode == QueryMode.PREDEFINED and self.query_definition_ref is None:
            raise ValueError("predefined query requests must include query_definition_ref")
        if self.query_mode == QueryMode.PREDEFINED and self.custom_query_text:
            raise ValueError("predefined query requests must not include custom_query_text")
        if self.query_mode == QueryMode.CUSTOM_GUARDED and self.query_definition_ref is not None:
            raise ValueError("custom_guarded query requests must not include query_definition_ref")
        if self.query_mode == QueryMode.CUSTOM_GUARDED and not self.custom_query_text:
            raise ValueError("custom_guarded query requests must include custom_query_text")
        return self
