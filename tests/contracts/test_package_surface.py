from platform_contracts import (
    ApprovalDecision,
    Artifact,
    BackendCapability,
    BackendDescriptor,
    Case,
    InvestigationDefinition,
    ObservationRequest,
    ObservationResult,
    QueryDefinition,
    QueryRequest,
    Run,
)


def test_top_level_package_exports_expected_contract_models():
    exported_models = {
        ApprovalDecision,
        Artifact,
        BackendCapability,
        BackendDescriptor,
        Case,
        InvestigationDefinition,
        ObservationRequest,
        ObservationResult,
        QueryDefinition,
        QueryRequest,
        Run,
    }

    assert len(exported_models) == 11
