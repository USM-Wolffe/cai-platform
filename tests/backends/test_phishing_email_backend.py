import pytest

from platform_contracts import (
    ArtifactKind,
    BackendCapabilityName,
    EntityKind,
    EntityRef,
    ObservationRequest,
    ObservationStatus,
    WorkflowType,
)
from platform_core import UnsupportedBackendError, create_case, create_run_for_case

from platform_backends.phishing_email import (
    PHISHING_EMAIL_BACKEND_ID,
    PHISHING_EMAIL_BASIC_ASSESSMENT_OPERATION,
    execute_predefined_observation,
    get_phishing_email_backend_descriptor,
)

from .support import InMemoryCaseRepository, InMemoryRunRepository, RecordingAuditPort, make_input_artifact


def _make_demo_payload() -> dict[str, object]:
    return {
        "subject": "Urgent action required: verify now",
        "sender": {
            "email": "security.alerts@gmail.com",
            "display_name": "Security Support",
        },
        "reply_to": {
            "email": "billing@corp-payments.example",
            "display_name": "Billing Desk",
        },
        "urls": ["http://198.51.100.7/login?verify=1"],
        "text": "Immediately update your account. Payment required today.",
        "attachments": [
            {"filename": "invoice.zip", "content_type": "application/zip"},
        ],
    }


def _make_benign_payload() -> dict[str, object]:
    return {
        "subject": "Quarterly planning notes",
        "sender": {
            "email": "teammate@example.com",
            "display_name": "Teammate",
        },
        "reply_to": {
            "email": "teammate@example.com",
            "display_name": "Teammate",
        },
        "urls": ["https://portal.example.com/team-notes"],
        "text": "Please review the attached planning notes before tomorrow's meeting.",
        "attachments": [
            {"filename": "planning-notes.pdf", "content_type": "application/pdf"},
        ],
    }


class StaticBackendRegistry:
    def __init__(self) -> None:
        self._descriptor = get_phishing_email_backend_descriptor()

    def get_backend(self, backend_id: str):
        if backend_id == self._descriptor.backend_id:
            return self._descriptor.model_copy(deep=True)
        return None


def test_descriptor_declares_the_phishing_backend_deterministically():
    descriptor = get_phishing_email_backend_descriptor()

    assert descriptor.backend_id == PHISHING_EMAIL_BACKEND_ID
    assert [capability.name for capability in descriptor.capabilities] == [
        BackendCapabilityName.CREATE_RUN,
        BackendCapabilityName.EXECUTE_PREDEFINED_QUERY,
        BackendCapabilityName.GET_RUN_STATUS,
        BackendCapabilityName.LIST_RUN_ARTIFACTS,
        BackendCapabilityName.READ_ARTIFACT_CONTENT,
    ]
    assert descriptor.supported_workflow_types == [WorkflowType.DEFENSIVE_ANALYSIS]
    assert descriptor.supported_query_classes == ["phishing_email.basic_assessment"]
    assert descriptor.accepted_artifact_kinds == [ArtifactKind.INPUT]
    assert descriptor.produced_artifact_kinds == [ArtifactKind.ANALYSIS_OUTPUT]


def test_backend_rejects_unsupported_workflow_clearly_through_core_run_creation():
    case_repository = InMemoryCaseRepository()
    run_repository = InMemoryRunRepository()
    audit_port = RecordingAuditPort()
    backend_registry = StaticBackendRegistry()

    case = create_case(
        case_repository,
        client_id="test-client",
        workflow_type=WorkflowType.LOG_INVESTIGATION,
        title="Unsupported workflow case",
        summary="Case to confirm workflow rejection.",
    )

    with pytest.raises(UnsupportedBackendError):
        create_run_for_case(
            case_repository,
            run_repository,
            backend_registry,
            audit_port,
            case_id=case.case_id,
            backend_id=PHISHING_EMAIL_BACKEND_ID,
        )


def test_demo_payload_triggers_expected_rules_and_high_risk_output():
    case_repository = InMemoryCaseRepository()
    run_repository = InMemoryRunRepository()
    audit_port = RecordingAuditPort()
    backend_registry = StaticBackendRegistry()
    input_artifact = make_input_artifact()

    case = create_case(
        case_repository,
        client_id="test-client",
        workflow_type=WorkflowType.DEFENSIVE_ANALYSIS,
        title="Phishing assessment case",
        summary="Case for phishing assessment.",
    )
    run = create_run_for_case(
        case_repository,
        run_repository,
        backend_registry,
        audit_port,
        case_id=case.case_id,
        backend_id=PHISHING_EMAIL_BACKEND_ID,
    )
    observation_request = ObservationRequest(
        case_ref=EntityRef(entity_type=EntityKind.CASE, id=case.case_id),
        backend_ref=EntityRef(entity_type=EntityKind.BACKEND, id=PHISHING_EMAIL_BACKEND_ID),
        run_ref=EntityRef(entity_type=EntityKind.RUN, id=run.run_id),
        operation_kind=PHISHING_EMAIL_BASIC_ASSESSMENT_OPERATION,
        input_artifact_refs=[EntityRef(entity_type=EntityKind.ARTIFACT, id=input_artifact.artifact_id)],
        requested_by="tester",
    )

    outcome = execute_predefined_observation(
        run=run,
        input_artifact=input_artifact,
        input_payload=_make_demo_payload(),
        observation_request=observation_request,
    )

    assert len(outcome.artifacts) == 1
    artifact = outcome.artifacts[0]
    assert artifact.kind == ArtifactKind.ANALYSIS_OUTPUT
    assert artifact.subtype == "phishing_email.basic_assessment"
    assert artifact.metadata["risk_level"] == "high"
    assert artifact.metadata["risk_score"] == 16  # 12 base + 4 correlation bonus (6 signals >= 5)
    assert artifact.metadata["signal_count"] == 7  # 6 base + multi_signal_correlation
    assert [rule["rule_id"] for rule in artifact.metadata["triggered_rules"]] == [
        "sender_reply_to_mismatch",
        "trusted_display_name_from_free_mail",
        "urgent_language",
        "credential_or_payment_theme",
        "suspicious_url_patterns",
        "suspicious_attachment_extension",
        "multi_signal_correlation",
    ]
    assert artifact.metadata["suspicious_urls"][0]["url"] == "http://198.51.100.7/login?verify=1"
    assert artifact.metadata["suspicious_urls"][0]["reasons"] == [
        "uses a non-https scheme",
        "uses an IP-literal host",
        "contains 'login' in the path or query",
        "contains 'verify' in the path or query",
    ]
    assert outcome.observation_result.status == ObservationStatus.SUCCEEDED
    assert outcome.observation_result.structured_summary["risk_level"] == "high"
    assert outcome.observation_result.structured_summary["triggered_rule_ids"] == [
        "sender_reply_to_mismatch",
        "trusted_display_name_from_free_mail",
        "urgent_language",
        "credential_or_payment_theme",
        "suspicious_url_patterns",
        "suspicious_attachment_extension",
        "multi_signal_correlation",
    ]


def test_benign_payload_returns_no_findings_deterministically():
    case_repository = InMemoryCaseRepository()
    run_repository = InMemoryRunRepository()
    audit_port = RecordingAuditPort()
    backend_registry = StaticBackendRegistry()
    input_artifact = make_input_artifact()

    case = create_case(
        case_repository,
        client_id="test-client",
        workflow_type=WorkflowType.DEFENSIVE_ANALYSIS,
        title="Benign phishing case",
        summary="Case for no-findings semantics.",
    )
    run = create_run_for_case(
        case_repository,
        run_repository,
        backend_registry,
        audit_port,
        case_id=case.case_id,
        backend_id=PHISHING_EMAIL_BACKEND_ID,
    )
    observation_request = ObservationRequest(
        case_ref=EntityRef(entity_type=EntityKind.CASE, id=case.case_id),
        backend_ref=EntityRef(entity_type=EntityKind.BACKEND, id=PHISHING_EMAIL_BACKEND_ID),
        run_ref=EntityRef(entity_type=EntityKind.RUN, id=run.run_id),
        operation_kind=PHISHING_EMAIL_BASIC_ASSESSMENT_OPERATION,
        input_artifact_refs=[EntityRef(entity_type=EntityKind.ARTIFACT, id=input_artifact.artifact_id)],
        requested_by="tester",
    )

    outcome = execute_predefined_observation(
        run=run,
        input_artifact=input_artifact,
        input_payload=_make_benign_payload(),
        observation_request=observation_request,
    )

    assert len(outcome.artifacts) == 1
    assert outcome.artifacts[0].metadata["risk_level"] == "none"
    assert outcome.artifacts[0].metadata["risk_score"] == 0
    assert outcome.artifacts[0].metadata["signal_count"] == 0
    assert outcome.artifacts[0].metadata["triggered_rules"] == []
    assert outcome.observation_result.status == ObservationStatus.SUCCEEDED_NO_FINDINGS
    assert outcome.observation_result.structured_summary == {
        "risk_level": "none",
        "risk_score": 0,
        "signal_count": 0,
        "triggered_rule_ids": [],
        "suspicious_url_count": 0,
        "summary": "No phishing signals were detected in the provided email artifact.",
    }


def test_invalid_payload_returns_normalized_failure_semantics():
    case_repository = InMemoryCaseRepository()
    run_repository = InMemoryRunRepository()
    audit_port = RecordingAuditPort()
    backend_registry = StaticBackendRegistry()
    input_artifact = make_input_artifact()

    case = create_case(
        case_repository,
        client_id="test-client",
        workflow_type=WorkflowType.DEFENSIVE_ANALYSIS,
        title="Invalid phishing case",
        summary="Case for invalid input.",
    )
    run = create_run_for_case(
        case_repository,
        run_repository,
        backend_registry,
        audit_port,
        case_id=case.case_id,
        backend_id=PHISHING_EMAIL_BACKEND_ID,
    )
    observation_request = ObservationRequest(
        case_ref=EntityRef(entity_type=EntityKind.CASE, id=case.case_id),
        backend_ref=EntityRef(entity_type=EntityKind.BACKEND, id=PHISHING_EMAIL_BACKEND_ID),
        run_ref=EntityRef(entity_type=EntityKind.RUN, id=run.run_id),
        operation_kind=PHISHING_EMAIL_BASIC_ASSESSMENT_OPERATION,
        input_artifact_refs=[EntityRef(entity_type=EntityKind.ARTIFACT, id=input_artifact.artifact_id)],
        requested_by="tester",
    )

    outcome = execute_predefined_observation(
        run=run,
        input_artifact=input_artifact,
        input_payload={
            "subject": "Broken payload",
            "sender": {"email": "sender@example.com"},
            "reply_to": None,
            "urls": [],
            "text": "Body",
            "attachments": "invoice.zip",
        },
        observation_request=observation_request,
    )

    assert outcome.artifacts == []
    assert outcome.observation_result.status == ObservationStatus.FAILED
    assert "'attachments' must be a list" in outcome.observation_result.errors[0]
