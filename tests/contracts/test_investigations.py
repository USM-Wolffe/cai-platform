from platform_contracts import (
    ArtifactKind,
    InvestigationDefinition,
    InvestigationStage,
    InvestigationStatus,
    WorkflowType,
)


def test_investigation_definition_minimum_valid_model_construction():
    definition = InvestigationDefinition(
        name="Generic log triage",
        workflow_type=WorkflowType.LOG_INVESTIGATION,
        status=InvestigationStatus.PUBLISHED,
        stages=[
            InvestigationStage(
                stage_id="triage",
                name="Triage",
                purpose="Establish the initial scope.",
                expected_inputs=["input evidence"],
                allowed_query_classes=["timeline_slice"],
                completion_criteria=["baseline scope captured"],
            )
        ],
        required_artifact_kinds=[ArtifactKind.INPUT],
    )

    assert definition.investigation_definition_id.startswith("investigation_")
    assert definition.status == InvestigationStatus.PUBLISHED
    assert definition.stages[0].stage_id == "triage"

