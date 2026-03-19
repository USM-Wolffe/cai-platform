"""Extended tests for phishing_email backend Phase A fixes."""

from __future__ import annotations

import pytest

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
    PHISHING_EMAIL_BASIC_ASSESSMENT_OPERATION,
    execute_predefined_observation,
    get_phishing_email_backend_descriptor,
)
from platform_backends.phishing_email.execute import (
    FREE_MAIL_DOMAINS,
    _compute_correlation_bonus,
    _derive_observation_status,
    _find_suspicious_attachments,
    _find_suspicious_urls,
)
from platform_backends.phishing_email.models import PhishingTriggeredRule

from .support import InMemoryCaseRepository, InMemoryRunRepository, RecordingAuditPort, make_input_artifact


# ── helpers ──────────────────────────────────────────────────────────────────

class StaticBackendRegistry:
    def __init__(self) -> None:
        self._descriptor = get_phishing_email_backend_descriptor()

    def get_backend(self, backend_id: str):
        if backend_id == self._descriptor.backend_id:
            return self._descriptor.model_copy(deep=True)
        return None


def _make_observation_request(run, case):
    return ObservationRequest(
        case_ref=EntityRef(entity_type=EntityKind.CASE, id=case.case_id),
        backend_ref=EntityRef(entity_type=EntityKind.BACKEND, id=PHISHING_EMAIL_BACKEND_ID),
        run_ref=EntityRef(entity_type=EntityKind.RUN, id=run.run_id),
        operation_kind=PHISHING_EMAIL_BASIC_ASSESSMENT_OPERATION,
        input_artifact_refs=[],
        requested_by="tester",
    )


def _make_run_and_obs(payload):
    case_repo = InMemoryCaseRepository()
    run_repo = InMemoryRunRepository()
    audit = RecordingAuditPort()
    registry = StaticBackendRegistry()
    artifact = make_input_artifact()

    case = create_case(case_repo, client_id="test-client",
        workflow_type=WorkflowType.DEFENSIVE_ANALYSIS, title="T", summary="S")
    run = create_run_for_case(case_repo, run_repo, registry, audit, case_id=case.case_id, backend_id=PHISHING_EMAIL_BACKEND_ID)
    obs = _make_observation_request(run, case)
    outcome = execute_predefined_observation(run=run, input_artifact=artifact, input_payload=payload, observation_request=obs)
    return outcome


# ── A1: descriptor supported_query_classes ───────────────────────────────────

def test_descriptor_supported_query_classes_includes_basic_assessment():
    descriptor = get_phishing_email_backend_descriptor()
    assert "phishing_email.basic_assessment" in descriptor.supported_query_classes


# ── A2: expanded FREE_MAIL_DOMAINS ───────────────────────────────────────────

def test_free_mail_domains_contains_expanded_set():
    required = {"live.com", "msn.com", "yandex.com", "yandex.ru", "mail.com",
                "zoho.com", "fastmail.com", "pm.me", "tutanota.com", "guerrillamail.com"}
    assert required.issubset(FREE_MAIL_DOMAINS)


def test_yandex_domain_triggers_trusted_display_name_rule():
    payload = {
        "subject": "Test",
        "sender": {"email": "billing@yandex.com", "display_name": "Billing Department"},
        "reply_to": None,
        "urls": [],
        "text": "Hello",
        "attachments": [],
    }
    outcome = _make_run_and_obs(payload)
    rule_ids = [r["rule_id"] for r in outcome.artifacts[0].metadata["triggered_rules"]]
    assert "trusted_display_name_from_free_mail" in rule_ids


# ── A3: correlation bonus ─────────────────────────────────────────────────────

def _make_dummy_rule(rule_id: str) -> PhishingTriggeredRule:
    return PhishingTriggeredRule(rule_id=rule_id, category="test", weight=1, message=".", evidence={})


def test_correlation_bonus_zero_for_fewer_than_3_rules():
    rules = [_make_dummy_rule("r1"), _make_dummy_rule("r2")]
    assert _compute_correlation_bonus(rules) == 0


def test_correlation_bonus_2_for_3_rules():
    rules = [_make_dummy_rule(f"r{i}") for i in range(3)]
    assert _compute_correlation_bonus(rules) == 2


def test_correlation_bonus_2_for_4_rules():
    rules = [_make_dummy_rule(f"r{i}") for i in range(4)]
    assert _compute_correlation_bonus(rules) == 2


def test_correlation_bonus_4_for_5_or_more_rules():
    for n in (5, 6, 8):
        rules = [_make_dummy_rule(f"r{i}") for i in range(n)]
        assert _compute_correlation_bonus(rules) == 4, f"failed at n={n}"


def test_correlation_rule_appended_when_3_signals_fire():
    # Minimal payload that reliably fires 3 signals:
    # 1. sender_reply_to_mismatch
    # 2. trusted_display_name_from_free_mail
    # 3. urgent_language
    payload = {
        "subject": "Urgent action required",
        "sender": {"email": "support@gmail.com", "display_name": "Support Team"},
        "reply_to": {"email": "attacker@evil.example", "display_name": "Attacker"},
        "urls": [],
        "text": "Please act now.",
        "attachments": [],
    }
    outcome = _make_run_and_obs(payload)
    rule_ids = [r["rule_id"] for r in outcome.artifacts[0].metadata["triggered_rules"]]
    assert "multi_signal_correlation" in rule_ids


def test_correlation_rule_not_appended_for_1_signal():
    payload = {
        "subject": "Hello",
        "sender": {"email": "alice@gmail.com", "display_name": "Security"},
        "reply_to": None,
        "urls": [],
        "text": "Quarterly meeting notes.",
        "attachments": [],
    }
    outcome = _make_run_and_obs(payload)
    rule_ids = [r["rule_id"] for r in outcome.artifacts[0].metadata["triggered_rules"]]
    assert "multi_signal_correlation" not in rule_ids


# ── A4: MIME mismatch detection ───────────────────────────────────────────────

def test_mime_mismatch_flagged_for_pdf_named_zip():
    # invoice.pdf but served as application/zip → mismatch
    from platform_adapters.phishing_email.types import PhishingEmailAttachment
    attachments = (PhishingEmailAttachment(filename="invoice.pdf", content_type="application/zip"),)
    result = _find_suspicious_attachments(attachments)
    assert len(result) == 1
    assert result[0]["mime_mismatch"] is True
    assert result[0]["filename"] == "invoice.pdf"


def test_mime_no_mismatch_for_correct_pdf():
    from platform_adapters.phishing_email.types import PhishingEmailAttachment
    attachments = (PhishingEmailAttachment(filename="report.pdf", content_type="application/pdf"),)
    result = _find_suspicious_attachments(attachments)
    assert result == []


def test_mime_mismatch_flagged_within_suspicious_extension():
    # file.zip but served as application/pdf → suspicious extension + mismatch
    from platform_adapters.phishing_email.types import PhishingEmailAttachment
    attachments = (PhishingEmailAttachment(filename="payload.zip", content_type="application/pdf"),)
    result = _find_suspicious_attachments(attachments)
    assert len(result) == 1
    assert result[0]["mime_mismatch"] is True


def test_mime_mismatch_attachment_triggers_rule_via_full_execute():
    payload = {
        "subject": "Check invoice",
        "sender": {"email": "billing@corp.example", "display_name": "Billing"},
        "reply_to": None,
        "urls": [],
        "text": "Please review this invoice.",
        "attachments": [{"filename": "invoice.pdf", "content_type": "application/zip"}],
    }
    outcome = _make_run_and_obs(payload)
    rule_ids = [r["rule_id"] for r in outcome.artifacts[0].metadata["triggered_rules"]]
    # The MIME mismatch is inside suspicious_attachment_extension evidence
    assert "suspicious_attachment_extension" in rule_ids
    evidence = next(r["evidence"] for r in outcome.artifacts[0].metadata["triggered_rules"] if r["rule_id"] == "suspicious_attachment_extension")
    assert any(a.get("mime_mismatch") for a in evidence["attachments"])


# ── A5: advanced URL detection ────────────────────────────────────────────────

def test_data_uri_flagged():
    urls = ("data:text/html,<script>alert(1)</script>",)
    result = _find_suspicious_urls(urls)
    assert len(result) == 1
    reasons = result[0].reasons
    assert any("data:" in r for r in reasons)


def test_null_byte_url_flagged():
    urls = ("http://evil.example/page%00?foo=bar",)
    result = _find_suspicious_urls(urls)
    assert len(result) == 1
    reasons = result[0].reasons
    assert any("%00" in r for r in reasons)


def test_high_pct_encoding_url_flagged():
    url = "http://evil.example/%61%62%63%64%65%66%67%68%69"  # 9 encoded sequences
    urls = (url,)
    result = _find_suspicious_urls(urls)
    assert len(result) == 1
    reasons = result[0].reasons
    assert any("encoding" in r for r in reasons)


def test_normal_https_url_not_flagged():
    urls = ("https://www.example.com/dashboard",)
    result = _find_suspicious_urls(urls)
    assert result == []


# ── A7: status guard coherence ────────────────────────────────────────────────

def test_derive_observation_status_no_findings_only_when_both_empty():
    rule = _make_dummy_rule("r1")
    # score=0, rules=[] → SUCCEEDED_NO_FINDINGS
    status = _derive_observation_status(risk_score=0, triggered_rules=[])
    assert status == ObservationStatus.SUCCEEDED_NO_FINDINGS
    # score=0 but rules not empty → SUCCEEDED (guard)
    status = _derive_observation_status(risk_score=0, triggered_rules=[rule])
    assert status == ObservationStatus.SUCCEEDED
    # score>0 → SUCCEEDED
    status = _derive_observation_status(risk_score=3, triggered_rules=[rule])
    assert status == ObservationStatus.SUCCEEDED


def test_benign_payload_still_returns_no_findings():
    payload = {
        "subject": "Quarterly planning notes",
        "sender": {"email": "teammate@example.com", "display_name": "Teammate"},
        "reply_to": {"email": "teammate@example.com", "display_name": "Teammate"},
        "urls": ["https://portal.example.com/team-notes"],
        "text": "Please review the attached planning notes before tomorrow's meeting.",
        "attachments": [{"filename": "planning-notes.pdf", "content_type": "application/pdf"}],
    }
    outcome = _make_run_and_obs(payload)
    assert outcome.observation_result.status == ObservationStatus.SUCCEEDED_NO_FINDINGS
    assert outcome.artifacts[0].metadata["risk_score"] == 0
    assert outcome.artifacts[0].metadata["triggered_rules"] == []
