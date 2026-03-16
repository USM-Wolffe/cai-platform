"""Approval contract models."""

from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import Field, field_validator, model_validator

from platform_contracts.common.base import ContractModel, generate_opaque_id, utc_now
from platform_contracts.common.enums import ApprovalScopeKind, ApprovalStatus, EntityKind
from platform_contracts.common.refs import EntityRef, ensure_ref_type


class ApprovalDecision(ContractModel):
    """Durable record of approval for a guarded action."""

    approval_id: str = Field(default_factory=lambda: generate_opaque_id("approval"), min_length=1)
    status: ApprovalStatus
    scope_kind: ApprovalScopeKind
    scope_ref: EntityRef
    reason: str = Field(min_length=1)
    approver_kind: str = Field(min_length=1)
    approver_ref: str | None = None
    issued_at: datetime = Field(default_factory=utc_now)
    expires_at: datetime | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)

    @field_validator("scope_ref")
    @classmethod
    def validate_scope_ref(cls, value: EntityRef) -> EntityRef:
        return ensure_ref_type(
            value,
            {EntityKind.QUERY_REQUEST, EntityKind.OBSERVATION_REQUEST},
            "scope_ref",
        )

    @model_validator(mode="after")
    def validate_scope_binding(self) -> "ApprovalDecision":
        if self.scope_kind == ApprovalScopeKind.QUERY_REQUEST and self.scope_ref.entity_type != EntityKind.QUERY_REQUEST:
            raise ValueError("query_request approvals must reference a query_request scope_ref")
        if (
            self.scope_kind == ApprovalScopeKind.OBSERVATION_REQUEST
            and self.scope_ref.entity_type != EntityKind.OBSERVATION_REQUEST
        ):
            raise ValueError("observation_request approvals must reference an observation_request scope_ref")
        if self.expires_at is not None and self.expires_at <= self.issued_at:
            raise ValueError("expires_at must be later than issued_at")
        return self
