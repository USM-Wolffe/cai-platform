"""Backend descriptor for the first phishing email slice."""

from __future__ import annotations

from platform_contracts import (
    ArtifactKind,
    BackendCapability,
    BackendCapabilityName,
    BackendDescriptor,
    BackendHealth,
    WorkflowType,
)

PHISHING_EMAIL_BACKEND_ID = "phishing_email"
PHISHING_EMAIL_BACKEND_TYPE = "phishing_email"
PHISHING_EMAIL_BASIC_ASSESSMENT_QUERY_CLASS = "phishing_email.basic_assessment"
PHISHING_EMAIL_BASIC_ASSESSMENT_OPERATION = "phishing_email.basic_assessment"


def get_phishing_email_backend_descriptor() -> BackendDescriptor:
    """Return the deterministic descriptor for the phishing email backend slice."""
    return BackendDescriptor(
        backend_id=PHISHING_EMAIL_BACKEND_ID,
        backend_type=PHISHING_EMAIL_BACKEND_TYPE,
        capabilities=[
            BackendCapability(
                name=BackendCapabilityName.CREATE_RUN,
                description="Create a deterministic phishing email assessment run.",
            ),
            BackendCapability(
                name=BackendCapabilityName.EXECUTE_PREDEFINED_QUERY,
                description="Execute the predefined phishing email basic assessment.",
            ),
            BackendCapability(
                name=BackendCapabilityName.GET_RUN_STATUS,
                description="Read deterministic phishing email run status.",
            ),
            BackendCapability(
                name=BackendCapabilityName.LIST_RUN_ARTIFACTS,
                description="List the artifacts attached to or produced by a phishing email run.",
            ),
            BackendCapability(
                name=BackendCapabilityName.READ_ARTIFACT_CONTENT,
                description="Read stored content for phishing email artifacts in the current runtime.",
            ),
        ],
        supported_workflow_types=[WorkflowType.DEFENSIVE_ANALYSIS],
        supported_query_classes=[PHISHING_EMAIL_BASIC_ASSESSMENT_QUERY_CLASS],
        accepted_artifact_kinds=[ArtifactKind.INPUT],
        produced_artifact_kinds=[ArtifactKind.ANALYSIS_OUTPUT],
        health=BackendHealth.HEALTHY,
        metadata={
            "slice": "initial",
            "service": "phishing_email",
        },
    )
