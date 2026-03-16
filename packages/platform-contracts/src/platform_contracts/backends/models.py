"""Backend contract models."""

from __future__ import annotations

from typing import Any

from pydantic import Field, field_validator

from platform_contracts.common.base import ContractModel, generate_opaque_id
from platform_contracts.common.enums import (
    ArtifactKind,
    BackendCapabilityName,
    BackendHealth,
    WorkflowType,
)


class BackendCapability(ContractModel):
    """Declared capability offered by a backend."""

    name: BackendCapabilityName
    description: str | None = None
    supports_async: bool = False
    requires_approval: bool = False


class BackendDescriptor(ContractModel):
    """Deterministic backend descriptor."""

    backend_id: str = Field(default_factory=lambda: generate_opaque_id("backend"), min_length=1)
    backend_type: str = Field(min_length=1)
    contract_version: str = Field(default="1.0")
    capabilities: list[BackendCapability] = Field(default_factory=list)
    supported_workflow_types: list[WorkflowType] = Field(default_factory=list)
    supported_query_classes: list[str] = Field(default_factory=list)
    accepted_artifact_kinds: list[ArtifactKind] = Field(default_factory=list)
    produced_artifact_kinds: list[ArtifactKind] = Field(default_factory=list)
    health: BackendHealth = BackendHealth.UNKNOWN
    metadata: dict[str, Any] = Field(default_factory=dict)

    @field_validator("capabilities")
    @classmethod
    def validate_unique_capabilities(cls, value: list[BackendCapability]) -> list[BackendCapability]:
        names = [item.name for item in value]
        if len(names) != len(set(names)):
            raise ValueError("capabilities must not contain duplicate names")
        return value
