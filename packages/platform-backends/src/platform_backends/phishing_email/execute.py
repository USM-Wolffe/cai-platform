"""Deterministic execution for the phishing email basic assessment slice."""

from __future__ import annotations

import hashlib
import ipaddress
import json
from typing import Any
from urllib.parse import urlsplit

from platform_adapters.phishing_email import (
    PHISHING_EMAIL_INPUT_SHAPE,
    PhishingEmailAdapterError,
    inspect_phishing_email_input_artifact,
    normalize_phishing_email_payload,
)
from platform_contracts import (
    Artifact,
    ArtifactKind,
    EntityKind,
    EntityRef,
    ObservationRequest,
    ObservationResult,
    ObservationStatus,
    Run,
)
from platform_core import ContractViolationError

from platform_backends.phishing_email.descriptor import (
    PHISHING_EMAIL_BACKEND_ID,
    PHISHING_EMAIL_BASIC_ASSESSMENT_OPERATION,
)
from platform_backends.phishing_email.errors import (
    PhishingEmailBackendError,
    UnsupportedPhishingEmailObservationError,
)
from platform_backends.phishing_email.models import (
    PhishingEmailExecutionOutcome,
    PhishingTriggeredRule,
    SuspiciousUrlRecord,
)

FREE_MAIL_DOMAINS = {
    "gmail.com",
    "outlook.com",
    "hotmail.com",
    "yahoo.com",
    "proton.me",
    "protonmail.com",
    "icloud.com",
    "aol.com",
}
TRUSTED_DISPLAY_NAME_TERMS = (
    "support",
    "security",
    "admin",
    "billing",
    "payroll",
    "helpdesk",
)
URGENCY_TERMS = (
    "urgent",
    "immediately",
    "action required",
    "verify now",
    "suspended",
    "final notice",
    "asap",
)
THEME_PHRASES = (
    "account verification",
    "password reset",
    "payment required",
    "update your account",
)
THEME_KEYWORDS = (
    "login",
    "password",
    "verify",
    "account",
    "reset",
    "payment",
    "invoice",
    "bank",
    "gift card",
)
SUSPICIOUS_URL_SHORTENERS = {"bit.ly", "tinyurl.com", "t.co"}
SUSPICIOUS_URL_TERMS = ("login", "verify", "reset", "update", "invoice", "payment")
SUSPICIOUS_ATTACHMENT_EXTENSIONS = (
    ".html",
    ".htm",
    ".zip",
    ".docm",
    ".xlsm",
    ".js",
    ".exe",
    ".scr",
    ".lnk",
)


def execute_predefined_observation(
    *,
    run: Run,
    input_artifact: Artifact,
    input_payload: object,
    observation_request: ObservationRequest,
) -> PhishingEmailExecutionOutcome:
    """Execute the phishing email basic assessment and normalize the outcome."""
    try:
        _validate_observation_request(run=run, observation_request=observation_request)
        inspect_phishing_email_input_artifact(input_artifact)
        normalized_email = normalize_phishing_email_payload(input_payload)

        triggered_rules, suspicious_urls, matched_terms = _evaluate_rules(normalized_email)
        risk_score = sum(rule.weight for rule in triggered_rules)
        risk_level = _derive_risk_level(risk_score)
        signal_count = len(triggered_rules)
        summary = _build_summary(risk_level=risk_level, signal_count=signal_count, risk_score=risk_score)

        artifact_payload = {
            "operation_kind": PHISHING_EMAIL_BASIC_ASSESSMENT_OPERATION,
            "input_shape": PHISHING_EMAIL_INPUT_SHAPE,
            "email_overview": {
                "subject": normalized_email.subject,
                "sender_email": normalized_email.sender.email,
                "reply_to_email": None if normalized_email.reply_to is None else normalized_email.reply_to.email,
                "url_count": len(normalized_email.urls),
                "attachment_count": len(normalized_email.attachments),
            },
            "risk_level": risk_level,
            "risk_score": risk_score,
            "signal_count": signal_count,
            "triggered_rules": [
                {
                    "rule_id": rule.rule_id,
                    "category": rule.category,
                    "weight": rule.weight,
                    "message": rule.message,
                    "evidence": rule.evidence,
                }
                for rule in triggered_rules
            ],
            "suspicious_urls": [
                {"url": item.url, "reasons": list(item.reasons)}
                for item in suspicious_urls
            ],
            "matched_terms": matched_terms,
            "summary": summary,
        }

        output_artifact = _build_output_artifact(
            run=run,
            observation_request=observation_request,
            artifact_payload=artifact_payload,
        )
        observation_status = (
            ObservationStatus.SUCCEEDED_NO_FINDINGS
            if risk_score == 0
            else ObservationStatus.SUCCEEDED
        )
        observation_result = ObservationResult(
            observation_ref=EntityRef(entity_type=EntityKind.OBSERVATION_REQUEST, id=observation_request.observation_id),
            status=observation_status,
            output_artifact_refs=[
                EntityRef(entity_type=EntityKind.ARTIFACT, id=output_artifact.artifact_id),
            ],
            structured_summary={
                "risk_level": risk_level,
                "risk_score": risk_score,
                "signal_count": signal_count,
                "triggered_rule_ids": [rule.rule_id for rule in triggered_rules],
                "suspicious_url_count": len(suspicious_urls),
                "summary": summary,
            },
            provenance={
                "backend_id": PHISHING_EMAIL_BACKEND_ID,
                "operation_kind": observation_request.operation_kind,
                "input_shape": PHISHING_EMAIL_INPUT_SHAPE,
            },
        )
        return PhishingEmailExecutionOutcome(
            artifacts=[output_artifact],
            observation_result=observation_result,
        )
    except (PhishingEmailAdapterError, PhishingEmailBackendError, ContractViolationError) as exc:
        return PhishingEmailExecutionOutcome(
            artifacts=[],
            observation_result=ObservationResult(
                observation_ref=EntityRef(
                    entity_type=EntityKind.OBSERVATION_REQUEST,
                    id=observation_request.observation_id,
                ),
                status=ObservationStatus.FAILED,
                structured_summary={"summary": "Phishing email basic assessment failed."},
                errors=[str(exc)],
                provenance={
                    "backend_id": PHISHING_EMAIL_BACKEND_ID,
                    "operation_kind": observation_request.operation_kind,
                },
            ),
        )


def _validate_observation_request(*, run: Run, observation_request: ObservationRequest) -> None:
    if observation_request.operation_kind != PHISHING_EMAIL_BASIC_ASSESSMENT_OPERATION:
        raise UnsupportedPhishingEmailObservationError(
            f"unsupported operation_kind '{observation_request.operation_kind}'"
        )
    if observation_request.run_ref.id != run.run_id:
        raise ContractViolationError("observation_request.run_ref must match the target run")
    if run.backend_ref.id != PHISHING_EMAIL_BACKEND_ID:
        raise UnsupportedPhishingEmailObservationError("run backend is not phishing_email")


def _evaluate_rules(normalized_email) -> tuple[list[PhishingTriggeredRule], list[SuspiciousUrlRecord], dict[str, list[str]]]:
    combined_text = f"{normalized_email.subject}\n{normalized_email.text}".lower()
    triggered_rules: list[PhishingTriggeredRule] = []

    if normalized_email.reply_to is not None and normalized_email.reply_to.email != normalized_email.sender.email:
        triggered_rules.append(
            PhishingTriggeredRule(
                rule_id="sender_reply_to_mismatch",
                category="identity",
                weight=3,
                message="Sender and reply-to addresses do not match.",
                evidence={
                    "sender_email": normalized_email.sender.email,
                    "reply_to_email": normalized_email.reply_to.email,
                },
            )
        )

    matched_display_terms = [
        term
        for term in TRUSTED_DISPLAY_NAME_TERMS
        if normalized_email.sender.display_name is not None and term in normalized_email.sender.display_name.lower()
    ]
    if matched_display_terms and normalized_email.sender.domain in FREE_MAIL_DOMAINS:
        triggered_rules.append(
            PhishingTriggeredRule(
                rule_id="trusted_display_name_from_free_mail",
                category="identity",
                weight=2,
                message="Trusted-looking sender display name is using a free-mail domain.",
                evidence={
                    "display_name": normalized_email.sender.display_name,
                    "matched_terms": matched_display_terms,
                    "sender_domain": normalized_email.sender.domain,
                },
            )
        )

    matched_urgency_terms = [term for term in URGENCY_TERMS if term in combined_text]
    if matched_urgency_terms:
        triggered_rules.append(
            PhishingTriggeredRule(
                rule_id="urgent_language",
                category="language",
                weight=1,
                message="Urgent or pressure-based language was detected.",
                evidence={"matched_terms": matched_urgency_terms},
            )
        )

    matched_theme_phrases = [term for term in THEME_PHRASES if term in combined_text]
    matched_theme_keywords = [term for term in THEME_KEYWORDS if term in combined_text]
    if matched_theme_phrases or len(matched_theme_keywords) >= 2:
        triggered_rules.append(
            PhishingTriggeredRule(
                rule_id="credential_or_payment_theme",
                category="theme",
                weight=2,
                message="Credential or payment-related themes were detected.",
                evidence={
                    "matched_phrases": matched_theme_phrases,
                    "matched_keywords": matched_theme_keywords,
                },
            )
        )

    suspicious_urls = _find_suspicious_urls(normalized_email.urls)
    if suspicious_urls:
        triggered_rules.append(
            PhishingTriggeredRule(
                rule_id="suspicious_url_patterns",
                category="url",
                weight=2 if len(suspicious_urls) == 1 else 3,
                message="One or more suspicious URL patterns were detected.",
                evidence={
                    "suspicious_urls": [
                        {"url": item.url, "reasons": list(item.reasons)}
                        for item in suspicious_urls
                    ]
                },
            )
        )

    suspicious_attachments = _find_suspicious_attachments(normalized_email.attachments)
    if suspicious_attachments:
        triggered_rules.append(
            PhishingTriggeredRule(
                rule_id="suspicious_attachment_extension",
                category="attachment",
                weight=2,
                message="Suspicious attachment extensions were detected.",
                evidence={"attachments": suspicious_attachments},
            )
        )

    return (
        triggered_rules,
        suspicious_urls,
        {
            "urgency_terms": matched_urgency_terms,
            "theme_terms": _dedupe_preserve_order([*matched_theme_phrases, *matched_theme_keywords]),
        },
    )


def _find_suspicious_urls(urls: tuple[str, ...]) -> list[SuspiciousUrlRecord]:
    suspicious_urls: list[SuspiciousUrlRecord] = []
    for url in urls:
        reasons: list[str] = []
        parsed = urlsplit(url)
        hostname = (parsed.hostname or "").lower()
        scheme = parsed.scheme.lower()

        if scheme != "https":
            reasons.append("uses a non-https scheme")
        if hostname:
            if _is_ip_literal(hostname):
                reasons.append("uses an IP-literal host")
            if "xn--" in hostname:
                reasons.append("uses a punycode host")
            if hostname in SUSPICIOUS_URL_SHORTENERS:
                reasons.append("uses a shortener host")
        if parsed.username is not None or "@" in parsed.netloc:
            reasons.append("contains userinfo in the URL")

        path_and_query = f"{parsed.path}?{parsed.query}".lower()
        matched_terms = [term for term in SUSPICIOUS_URL_TERMS if term in path_and_query]
        for term in matched_terms:
            reasons.append(f"contains '{term}' in the path or query")

        if reasons:
            suspicious_urls.append(
                SuspiciousUrlRecord(
                    url=url,
                    reasons=tuple(_dedupe_preserve_order(reasons)),
                )
            )
    return suspicious_urls


def _find_suspicious_attachments(attachments) -> list[dict[str, str | None]]:
    suspicious: list[dict[str, str | None]] = []
    for attachment in attachments:
        filename_lower = attachment.filename.lower()
        for extension in SUSPICIOUS_ATTACHMENT_EXTENSIONS:
            if filename_lower.endswith(extension):
                suspicious.append(
                    {
                        "filename": attachment.filename,
                        "content_type": attachment.content_type,
                        "extension": extension,
                    }
                )
                break
    return suspicious


def _build_output_artifact(
    *,
    run: Run,
    observation_request: ObservationRequest,
    artifact_payload: dict[str, Any],
) -> Artifact:
    serialized_payload = json.dumps(artifact_payload, sort_keys=True)
    content_hash = hashlib.sha256(serialized_payload.encode("utf-8")).hexdigest()
    return Artifact(
        kind=ArtifactKind.ANALYSIS_OUTPUT,
        subtype="phishing_email.basic_assessment",
        format="json",
        storage_ref=(
            f"backend://phishing_email/runs/{run.run_id}/"
            f"observations/{observation_request.observation_id}/basic_assessment.json"
        ),
        content_hash=f"sha256:{content_hash}",
        produced_by_backend_ref=EntityRef(entity_type=EntityKind.BACKEND, id=PHISHING_EMAIL_BACKEND_ID),
        produced_by_run_ref=EntityRef(entity_type=EntityKind.RUN, id=run.run_id),
        produced_by_observation_ref=EntityRef(
            entity_type=EntityKind.OBSERVATION_REQUEST,
            id=observation_request.observation_id,
        ),
        summary=artifact_payload["summary"],
        metadata=artifact_payload,
    )


def _derive_risk_level(risk_score: int) -> str:
    if risk_score == 0:
        return "none"
    if risk_score <= 2:
        return "low"
    if risk_score <= 5:
        return "medium"
    return "high"


def _build_summary(*, risk_level: str, signal_count: int, risk_score: int) -> str:
    if risk_score == 0:
        return "No phishing signals were detected in the provided email artifact."
    return (
        f"Detected {signal_count} phishing signals with {risk_level} risk "
        f"(score {risk_score})."
    )


def _is_ip_literal(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
    except ValueError:
        return False
    return True


def _dedupe_preserve_order(values: list[str]) -> list[str]:
    deduped: list[str] = []
    for value in values:
        if value not in deduped:
            deduped.append(value)
    return deduped
