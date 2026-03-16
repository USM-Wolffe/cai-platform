"""Investigation definition models."""

from __future__ import annotations

from typing import Any

from pydantic import Field

from platform_contracts.common.base import ContractModel, generate_opaque_id
from platform_contracts.common.enums import ArtifactKind, InvestigationStatus, WorkflowType


class InvestigationStage(ContractModel):
    """One stage inside a versioned investigation definition."""

    stage_id: str = Field(min_length=1)
    name: str = Field(min_length=1)
    purpose: str = Field(min_length=1)
    expected_inputs: list[str] = Field(default_factory=list)
    allowed_query_classes: list[str] = Field(default_factory=list)
    completion_criteria: list[str] = Field(default_factory=list)


class InvestigationDefinition(ContractModel):
    """Versioned workflow/playbook definition."""

    investigation_definition_id: str = Field(
        default_factory=lambda: generate_opaque_id("investigation"),
        min_length=1,
    )
    version: str = Field(default="1.0.0")
    name: str = Field(min_length=1)
    workflow_type: WorkflowType
    status: InvestigationStatus = InvestigationStatus.DRAFT
    entry_requirements: list[str] = Field(default_factory=list)
    stages: list[InvestigationStage] = Field(min_length=1)
    allowed_query_classes: list[str] = Field(default_factory=list)
    required_artifact_kinds: list[ArtifactKind] = Field(default_factory=list)
    default_observation_kinds: list[str] = Field(default_factory=list)
    completion_requirements: list[str] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)
