from platform_contracts import (
    ArtifactKind,
    CaseStatus,
    ContractModel,
    QueryMode,
    RiskClass,
    RunStatus,
    WorkflowType,
)


def test_required_workflow_types_exist():
    assert WorkflowType.LOG_INVESTIGATION.value == "log_investigation"
    assert WorkflowType.FORENSIC_INVESTIGATION.value == "forensic_investigation"
    assert WorkflowType.DEFENSIVE_ANALYSIS.value == "defensive_analysis"
    assert WorkflowType.SANDBOX_INVESTIGATION.value == "sandbox_investigation"


def test_required_enum_values_exist():
    assert QueryMode.PREDEFINED.value == "predefined"
    assert QueryMode.CUSTOM_GUARDED.value == "custom_guarded"
    assert RunStatus.COMPLETED.value == "completed"
    assert RunStatus.FAILED.value == "failed"
    assert CaseStatus.OPEN.value == "open"
    assert RiskClass.HIGH.value == "high"


def test_artifact_kinds_remain_generic():
    values = {item.value for item in ArtifactKind}
    assert values == {
        "input",
        "normalized",
        "query_result",
        "analysis_output",
        "report",
        "evidence_bundle",
        "binary_or_file",
    }
    assert all("watchguard" not in value for value in values)
    assert all("anyrun" not in value for value in values)


def test_contract_models_expose_schema_version():
    model = ContractModel()
    assert model.schema_version == "1.0"
