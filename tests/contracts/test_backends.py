import pytest
from pydantic import ValidationError

from platform_contracts import (
    ArtifactKind,
    BackendCapability,
    BackendCapabilityName,
    BackendDescriptor,
    BackendHealth,
    WorkflowType,
)


def test_backend_descriptor_minimum_valid_model_construction():
    descriptor = BackendDescriptor(
        backend_type="log_backend",
        capabilities=[
            BackendCapability(
                name=BackendCapabilityName.CREATE_RUN,
                description="Create a backend run.",
            ),
            BackendCapability(
                name=BackendCapabilityName.EXECUTE_PREDEFINED_QUERY,
                description="Run a predefined query.",
            ),
        ],
        supported_workflow_types=[WorkflowType.LOG_INVESTIGATION],
        supported_query_classes=["timeline_slice"],
        accepted_artifact_kinds=[ArtifactKind.INPUT],
        produced_artifact_kinds=[ArtifactKind.NORMALIZED, ArtifactKind.QUERY_RESULT],
        health=BackendHealth.HEALTHY,
    )

    assert descriptor.backend_id.startswith("backend_")
    assert descriptor.health == BackendHealth.HEALTHY
    assert descriptor.capabilities[0].name == BackendCapabilityName.CREATE_RUN


def test_backend_descriptor_rejects_duplicate_capabilities():
    with pytest.raises(ValidationError):
        BackendDescriptor(
            backend_type="log_backend",
            capabilities=[
                BackendCapability(name=BackendCapabilityName.CREATE_RUN),
                BackendCapability(name=BackendCapabilityName.CREATE_RUN),
            ],
        )
