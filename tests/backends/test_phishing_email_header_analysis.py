"""Tests for the phishing_email header_analysis backend operation."""

from __future__ import annotations

import pytest

from platform_adapters.phishing_email_mime.types import (
    AuthenticationResult,
    NormalizedMimeEmail,
    ReceivedHop,
)
from platform_adapters.phishing_email.types import PhishingEmailAttachment, PhishingEmailParty
from platform_backends.phishing_email.header_rules import evaluate_header_rules
from platform_contracts import (
    EntityKind,
    EntityRef,
    ObservationRequest,
    ObservationStatus,
    WorkflowType,
)
from platform_core import create_case, create_run_for_case

from platform_backends.phishing_email import (
    PHISHING_EMAIL_BACKEND_ID,
    PHISHING_EMAIL_HEADER_ANALYSIS_OPERATION,
    execute_header_analysis_observation,
    get_phishing_email_backend_descriptor,
)

from .support import InMemoryCaseRepository, InMemoryRunRepository, RecordingAuditPort, make_input_artifact


# ── helpers ──────────────────────────────────────────────────────────────────

class StaticBackendRegistry:
    def __init__(self) -> None:
        self._descriptor = get_phishing_email_backend_descriptor()

    def get_backend(self, backend_id: str):
        if backend_id == self._descriptor.backend_id:
            return self._descriptor.model_copy(deep=True)
        return None


def _make_normalized(
    *,
    auth: AuthenticationResult | None = None,
    received: list[ReceivedHop] | None = None,
) -> NormalizedMimeEmail:
    return NormalizedMimeEmail(
        subject="Test",
        sender=PhishingEmailParty(email="sender@example.com", domain="example.com"),
        reply_to=None,
        urls=(),
        text="Body",
        attachments=(),
        input_shape="structured_email_v2",
        message_id=None,
        date=None,
        html_body=None,
        plain_text_body="Body",
        received_chain=tuple(received or []),
        authentication_results=auth,
        x_originating_ip=None,
        x_mailer=None,
        all_headers={},
    )


def _make_v2_payload(
    *,
    auth: dict | None = None,
    received_chain: list[dict] | None = None,
) -> dict:
    return {
        "input_shape": "structured_email_v2",
        "subject": "Test",
        "sender": {"email": "sender@example.com", "domain": "example.com"},
        "reply_to": None,
        "urls": [],
        "text": "Body",
        "attachments": [],
        "authentication_results": auth,
        "received_chain": received_chain or [],
        "html_body": None,
        "plain_text_body": "Body",
        "message_id": None,
        "date": None,
        "x_originating_ip": None,
        "x_mailer": None,
        "all_headers": {},
    }


def _run_header_analysis(payload: dict):
    case_repo = InMemoryCaseRepository()
    run_repo = InMemoryRunRepository()
    audit = RecordingAuditPort()
    registry = StaticBackendRegistry()
    artifact = make_input_artifact()

    case = create_case(case_repo, client_id="test-client",
        workflow_type=WorkflowType.DEFENSIVE_ANALYSIS, title="T", summary="S")
    run = create_run_for_case(case_repo, run_repo, registry, audit, case_id=case.case_id, backend_id=PHISHING_EMAIL_BACKEND_ID)
    obs = ObservationRequest(
        case_ref=EntityRef(entity_type=EntityKind.CASE, id=case.case_id),
        backend_ref=EntityRef(entity_type=EntityKind.BACKEND, id=PHISHING_EMAIL_BACKEND_ID),
        run_ref=EntityRef(entity_type=EntityKind.RUN, id=run.run_id),
        operation_kind=PHISHING_EMAIL_HEADER_ANALYSIS_OPERATION,
        input_artifact_refs=[EntityRef(entity_type=EntityKind.ARTIFACT, id=artifact.artifact_id)],
        requested_by="tester",
    )
    return execute_header_analysis_observation(
        run=run, input_artifact=artifact, input_payload=payload, observation_request=obs
    )


# ── header_rules unit tests ───────────────────────────────────────────────────

def test_spf_fail_triggers_rule():
    normalized = _make_normalized(auth=AuthenticationResult(spf="fail", dkim="pass", dmarc="pass", raw="spf=fail"))
    rules = evaluate_header_rules(normalized)
    rule_ids = [r.rule_id for r in rules]
    assert "spf_fail" in rule_ids


def test_spf_softfail_triggers_rule():
    normalized = _make_normalized(auth=AuthenticationResult(spf="softfail", dkim=None, dmarc=None, raw="spf=softfail"))
    rules = evaluate_header_rules(normalized)
    rule_ids = [r.rule_id for r in rules]
    assert "spf_fail" in rule_ids


def test_dkim_fail_triggers_rule():
    normalized = _make_normalized(auth=AuthenticationResult(spf="pass", dkim="fail", dmarc="pass", raw="dkim=fail"))
    rules = evaluate_header_rules(normalized)
    rule_ids = [r.rule_id for r in rules]
    assert "dkim_fail" in rule_ids


def test_dmarc_fail_triggers_rule():
    normalized = _make_normalized(auth=AuthenticationResult(spf="pass", dkim="pass", dmarc="fail", raw="dmarc=fail"))
    rules = evaluate_header_rules(normalized)
    rule_ids = [r.rule_id for r in rules]
    assert "dmarc_fail" in rule_ids


def test_all_auth_pass_no_auth_rules():
    normalized = _make_normalized(auth=AuthenticationResult(spf="pass", dkim="pass", dmarc="pass", raw="ok"))
    rules = evaluate_header_rules(normalized)
    rule_ids = [r.rule_id for r in rules]
    assert "spf_fail" not in rule_ids
    assert "dkim_fail" not in rule_ids
    assert "dmarc_fail" not in rule_ids


def test_short_received_chain_triggers_rule():
    normalized = _make_normalized(received=[])
    rules = evaluate_header_rules(normalized)
    rule_ids = [r.rule_id for r in rules]
    assert "short_received_chain" in rule_ids


def test_two_hop_chain_no_short_chain_rule():
    hops = [
        ReceivedHop(from_host="a.example", by_host="b.example", with_protocol="SMTP", timestamp=None, raw=""),
        ReceivedHop(from_host="b.example", by_host="mx.corp.example", with_protocol="SMTP", timestamp=None, raw=""),
    ]
    normalized = _make_normalized(received=hops)
    rules = evaluate_header_rules(normalized)
    rule_ids = [r.rule_id for r in rules]
    assert "short_received_chain" not in rule_ids


def test_first_hop_ip_literal_triggers_rule():
    hops = [ReceivedHop(from_host="198.51.100.7", by_host="mx.corp.example", with_protocol="SMTP", timestamp=None, raw="")]
    normalized = _make_normalized(received=hops)
    rules = evaluate_header_rules(normalized)
    rule_ids = [r.rule_id for r in rules]
    assert "first_hop_ip_literal" in rule_ids


def test_first_hop_hostname_no_ip_literal_rule():
    hops = [ReceivedHop(from_host="mail.legit.example", by_host="mx.corp.example", with_protocol="SMTP", timestamp=None, raw="")]
    normalized = _make_normalized(received=hops)
    rules = evaluate_header_rules(normalized)
    rule_ids = [r.rule_id for r in rules]
    assert "first_hop_ip_literal" not in rule_ids


def test_received_chain_loop_triggers_rule():
    hops = [
        ReceivedHop(from_host="a.example", by_host="loop.example", with_protocol="SMTP", timestamp=None, raw=""),
        ReceivedHop(from_host="b.example", by_host="loop.example", with_protocol="SMTP", timestamp=None, raw=""),
    ]
    normalized = _make_normalized(received=hops)
    rules = evaluate_header_rules(normalized)
    rule_ids = [r.rule_id for r in rules]
    assert "received_chain_loop" in rule_ids


def test_no_chain_loop_when_hosts_unique():
    hops = [
        ReceivedHop(from_host="a.example", by_host="hop1.example", with_protocol="SMTP", timestamp=None, raw=""),
        ReceivedHop(from_host="hop1.example", by_host="hop2.example", with_protocol="SMTP", timestamp=None, raw=""),
    ]
    normalized = _make_normalized(received=hops)
    rules = evaluate_header_rules(normalized)
    rule_ids = [r.rule_id for r in rules]
    assert "received_chain_loop" not in rule_ids


# ── execute_header_analysis_observation integration ───────────────────────────

def test_clean_v2_payload_returns_no_findings():
    payload = _make_v2_payload(
        auth={"spf": "pass", "dkim": "pass", "dmarc": "pass", "raw": "ok"},
        received_chain=[
            {"from_host": "a.example", "by_host": "b.example", "with_protocol": "SMTP", "timestamp": None, "raw": ""},
            {"from_host": "b.example", "by_host": "mx.corp.example", "with_protocol": "SMTP", "timestamp": None, "raw": ""},
        ],
    )
    outcome = _run_header_analysis(payload)
    assert outcome.observation_result.status == ObservationStatus.SUCCEEDED_NO_FINDINGS
    assert outcome.artifacts[0].subtype == "phishing_email.header_analysis"
    assert outcome.artifacts[0].metadata["risk_score"] == 0


def test_spf_dmarc_fail_payload_returns_high_risk():
    payload = _make_v2_payload(
        auth={"spf": "fail", "dkim": "fail", "dmarc": "fail", "raw": "fails"},
        received_chain=[],
    )
    outcome = _run_header_analysis(payload)
    assert outcome.observation_result.status == ObservationStatus.SUCCEEDED
    score = outcome.artifacts[0].metadata["risk_score"]
    # spf_fail=3, dkim_fail=3, dmarc_fail=4, short_received_chain=1 → 11
    assert score >= 10
    rule_ids = [r["rule_id"] for r in outcome.artifacts[0].metadata["triggered_rules"]]
    assert "spf_fail" in rule_ids
    assert "dmarc_fail" in rule_ids


def test_header_analysis_fails_for_v1_input():
    v1_payload = {
        "subject": "Test",
        "sender": {"email": "a@b.com", "display_name": "A"},
        "reply_to": None,
        "urls": [],
        "text": "Test",
        "attachments": [],
    }
    outcome = _run_header_analysis(v1_payload)
    assert outcome.observation_result.status == ObservationStatus.FAILED
    assert "structured_email_v2" in outcome.observation_result.errors[0]


def test_header_analysis_fails_for_wrong_operation_kind():
    from platform_backends.phishing_email import PHISHING_EMAIL_BASIC_ASSESSMENT_OPERATION

    case_repo = InMemoryCaseRepository()
    run_repo = InMemoryRunRepository()
    audit = RecordingAuditPort()
    registry = StaticBackendRegistry()
    artifact = make_input_artifact()

    case = create_case(case_repo, client_id="test-client",
        workflow_type=WorkflowType.DEFENSIVE_ANALYSIS, title="T", summary="S")
    run = create_run_for_case(case_repo, run_repo, registry, audit, case_id=case.case_id, backend_id=PHISHING_EMAIL_BACKEND_ID)
    obs = ObservationRequest(
        case_ref=EntityRef(entity_type=EntityKind.CASE, id=case.case_id),
        backend_ref=EntityRef(entity_type=EntityKind.BACKEND, id=PHISHING_EMAIL_BACKEND_ID),
        run_ref=EntityRef(entity_type=EntityKind.RUN, id=run.run_id),
        operation_kind=PHISHING_EMAIL_BASIC_ASSESSMENT_OPERATION,  # wrong kind
        input_artifact_refs=[],
        requested_by="tester",
    )
    payload = _make_v2_payload()
    outcome = execute_header_analysis_observation(
        run=run, input_artifact=artifact, input_payload=payload, observation_request=obs
    )
    assert outcome.observation_result.status == ObservationStatus.FAILED
