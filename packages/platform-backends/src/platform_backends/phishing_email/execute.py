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
    PHISHING_EMAIL_HEADER_ANALYSIS_OPERATION,
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
    "live.com",
    "msn.com",
    "yandex.com",
    "yandex.ru",
    "mail.com",
    "zoho.com",
    "fastmail.com",
    "pm.me",
    "tutanota.com",
    "guerrillamail.com",
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
    "act now",
    "account suspended",
    "limited time",
    "expires today",
    "verify immediately",
    "confirm now",
    "click here immediately",
)
THEME_PHRASES = (
    "account verification",
    "password reset",
    "payment required",
    "update your account",
    "wire transfer",
    "gift card",
    "crypto payment",
    "bank account",
    "confirm your identity",
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
    "wire",
    "transfer",
    "crypto",
    "bitcoin",
    "credential",
)
MIME_EXTENSION_EXPECTATIONS: dict[str, set[str]] = {
    ".pdf": {"application/pdf"},
    ".doc": {"application/msword"},
    ".docx": {"application/vnd.openxmlformats-officedocument.wordprocessingml.document"},
    ".xls": {"application/vnd.ms-excel"},
    ".xlsx": {"application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"},
    ".zip": {"application/zip", "application/x-zip-compressed"},
    ".png": {"image/png"},
    ".jpg": {"image/jpeg"},
    ".jpeg": {"image/jpeg"},
    ".html": {"text/html"},
    ".htm": {"text/html"},
    ".txt": {"text/plain"},
}
SUSPICIOUS_URL_SHORTENERS = {"bit.ly", "tinyurl.com", "t.co"}
# These schemes are legitimate non-web references used inside MIME emails; do not flag them.
BENIGN_URL_SCHEMES = {"cid", "mailto", "tel", "sms", "fax", "callto"}
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
        observation_status = _derive_observation_status(risk_score=risk_score, triggered_rules=triggered_rules)
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


def execute_header_analysis_observation(
    *,
    run: Run,
    input_artifact: Artifact,
    input_payload: object,
    observation_request: ObservationRequest,
) -> PhishingEmailExecutionOutcome:
    """Execute header-based phishing analysis on a structured_email_v2 input."""
    from platform_adapters.phishing_email_mime.normalize import normalize_mime_email_bytes
    from platform_adapters.phishing_email_mime.types import NormalizedMimeEmail
    from platform_backends.phishing_email.header_rules import evaluate_header_rules

    try:
        if observation_request.operation_kind != PHISHING_EMAIL_HEADER_ANALYSIS_OPERATION:
            raise UnsupportedPhishingEmailObservationError(
                f"unsupported operation_kind '{observation_request.operation_kind}'"
            )
        if observation_request.run_ref.id != run.run_id:
            raise ContractViolationError("observation_request.run_ref must match the target run")
        if run.backend_ref.id != PHISHING_EMAIL_BACKEND_ID:
            raise UnsupportedPhishingEmailObservationError("run backend is not phishing_email")

        if not isinstance(input_payload, dict):
            raise PhishingEmailBackendError("header_analysis requires a dict input_payload")

        # Accept a pre-parsed NormalizedMimeEmail dict (structured_email_v2) or raw bytes string
        input_shape = input_payload.get("input_shape", "")
        if input_shape != "structured_email_v2":
            raise PhishingEmailBackendError(
                f"header_analysis requires input_shape 'structured_email_v2', got '{input_shape}'"
            )

        normalized = _payload_to_normalized_mime_email(input_payload)
        triggered_rules = evaluate_header_rules(normalized)
        risk_score = sum(rule.weight for rule in triggered_rules)
        risk_level = _derive_risk_level(risk_score)
        signal_count = len(triggered_rules)
        summary = _build_summary(risk_level=risk_level, signal_count=signal_count, risk_score=risk_score)

        artifact_payload = {
            "operation_kind": PHISHING_EMAIL_HEADER_ANALYSIS_OPERATION,
            "input_shape": "structured_email_v2",
            "authentication_results": (
                None
                if normalized.authentication_results is None
                else {
                    "spf": normalized.authentication_results.spf,
                    "dkim": normalized.authentication_results.dkim,
                    "dmarc": normalized.authentication_results.dmarc,
                }
            ),
            "received_chain_length": len(normalized.received_chain),
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
            "summary": summary,
        }

        serialized_payload = json.dumps(artifact_payload, sort_keys=True)
        content_hash = hashlib.sha256(serialized_payload.encode("utf-8")).hexdigest()
        output_artifact = Artifact(
            kind=ArtifactKind.ANALYSIS_OUTPUT,
            subtype="phishing_email.header_analysis",
            format="json",
            storage_ref=(
                f"backend://phishing_email/runs/{run.run_id}/"
                f"observations/{observation_request.observation_id}/header_analysis.json"
            ),
            content_hash=f"sha256:{content_hash}",
            produced_by_backend_ref=EntityRef(entity_type=EntityKind.BACKEND, id=PHISHING_EMAIL_BACKEND_ID),
            produced_by_run_ref=EntityRef(entity_type=EntityKind.RUN, id=run.run_id),
            produced_by_observation_ref=EntityRef(
                entity_type=EntityKind.OBSERVATION_REQUEST,
                id=observation_request.observation_id,
            ),
            summary=summary,
            metadata=artifact_payload,
        )
        observation_status = _derive_observation_status(risk_score=risk_score, triggered_rules=triggered_rules)
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
                "summary": summary,
            },
            provenance={
                "backend_id": PHISHING_EMAIL_BACKEND_ID,
                "operation_kind": observation_request.operation_kind,
                "input_shape": "structured_email_v2",
            },
        )
        return PhishingEmailExecutionOutcome(
            artifacts=[output_artifact],
            observation_result=observation_result,
        )
    except (PhishingEmailBackendError, ContractViolationError) as exc:
        return PhishingEmailExecutionOutcome(
            artifacts=[],
            observation_result=ObservationResult(
                observation_ref=EntityRef(
                    entity_type=EntityKind.OBSERVATION_REQUEST,
                    id=observation_request.observation_id,
                ),
                status=ObservationStatus.FAILED,
                structured_summary={"summary": "Phishing email header analysis failed."},
                errors=[str(exc)],
                provenance={
                    "backend_id": PHISHING_EMAIL_BACKEND_ID,
                    "operation_kind": observation_request.operation_kind,
                },
            ),
        )


def _payload_to_normalized_mime_email(payload: dict) -> object:
    """Convert a structured_email_v2 dict payload to a NormalizedMimeEmail.

    If the payload contains a 'raw_eml_bytes_hex' key it re-parses from raw bytes;
    otherwise it reconstructs from the dict fields (the wire format for pre-parsed emails).
    """
    from platform_adapters.phishing_email_mime.normalize import normalize_mime_email_bytes
    from platform_adapters.phishing_email_mime.types import (
        AuthenticationResult,
        NormalizedMimeEmail,
        ReceivedHop,
    )
    from platform_adapters.phishing_email.types import PhishingEmailAttachment, PhishingEmailParty

    raw_hex = payload.get("raw_eml_bytes_hex")
    if raw_hex:
        return normalize_mime_email_bytes(bytes.fromhex(raw_hex))

    # Reconstruct from pre-serialized v2 dict
    def _party(d) -> PhishingEmailParty | None:
        if d is None:
            return None
        return PhishingEmailParty(
            email=d.get("email", ""),
            domain=d.get("domain", d.get("email", "").split("@")[-1] if "@" in d.get("email", "") else ""),
            display_name=d.get("display_name"),
        )

    def _attachment(d) -> PhishingEmailAttachment:
        return PhishingEmailAttachment(filename=d.get("filename", ""), content_type=d.get("content_type"))

    def _hop(d) -> ReceivedHop:
        return ReceivedHop(
            from_host=d.get("from_host"),
            by_host=d.get("by_host"),
            with_protocol=d.get("with_protocol"),
            timestamp=d.get("timestamp"),
            raw=d.get("raw", ""),
        )

    def _auth(d) -> AuthenticationResult | None:
        if d is None:
            return None
        return AuthenticationResult(
            spf=d.get("spf"),
            dkim=d.get("dkim"),
            dmarc=d.get("dmarc"),
            raw=d.get("raw"),
        )

    sender_raw = payload.get("sender") or {}
    reply_to_raw = payload.get("reply_to")
    return NormalizedMimeEmail(
        subject=payload.get("subject", ""),
        sender=_party(sender_raw) or PhishingEmailParty(email="", domain=""),
        reply_to=_party(reply_to_raw),
        urls=tuple(payload.get("urls") or []),
        text=payload.get("text", ""),
        attachments=tuple(_attachment(a) for a in (payload.get("attachments") or [])),
        input_shape="structured_email_v2",
        message_id=payload.get("message_id"),
        date=payload.get("date"),
        html_body=payload.get("html_body"),
        plain_text_body=payload.get("plain_text_body"),
        received_chain=tuple(_hop(h) for h in (payload.get("received_chain") or [])),
        authentication_results=_auth(payload.get("authentication_results")),
        x_originating_ip=payload.get("x_originating_ip"),
        x_mailer=payload.get("x_mailer"),
        all_headers=payload.get("all_headers") or {},
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

    correlation_bonus = _compute_correlation_bonus(triggered_rules)
    if correlation_bonus > 0:
        triggered_rules.append(
            PhishingTriggeredRule(
                rule_id="multi_signal_correlation",
                category="correlation",
                weight=correlation_bonus,
                message=f"Multiple independent phishing signals ({len(triggered_rules) - 1}) were correlated.",
                evidence={"signal_count_before_bonus": len(triggered_rules) - 1},
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

        # Skip legitimate MIME-internal and non-web schemes (embedded images, mailto links, etc.)
        if scheme in BENIGN_URL_SCHEMES:
            continue

        if scheme == "data":
            reasons.append("uses a data: URI (potential HTML/JS embedding)")
        elif scheme != "https":
            reasons.append("uses a non-https scheme")
        if "%00" in url:
            reasons.append("contains null byte (%00) in URL")
        pct_encoded_count = url.count("%")
        if pct_encoded_count > 4:
            reasons.append(f"high URL-encoding ratio ({pct_encoded_count} encoded sequences)")
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


def _find_suspicious_attachments(attachments) -> list[dict[str, object]]:
    suspicious: list[dict[str, object]] = []
    for attachment in attachments:
        filename_lower = attachment.filename.lower()
        entry: dict[str, object] | None = None
        for extension in SUSPICIOUS_ATTACHMENT_EXTENSIONS:
            if filename_lower.endswith(extension):
                entry = {
                    "filename": attachment.filename,
                    "content_type": attachment.content_type,
                    "extension": extension,
                    "mime_mismatch": False,
                }
                break
        if entry is None:
            # Check for MIME mismatch even on non-suspicious extensions
            for ext, expected_types in MIME_EXTENSION_EXPECTATIONS.items():
                if filename_lower.endswith(ext) and attachment.content_type is not None:
                    ct_base = attachment.content_type.split(";")[0].strip().lower()
                    if ct_base not in expected_types:
                        entry = {
                            "filename": attachment.filename,
                            "content_type": attachment.content_type,
                            "extension": ext,
                            "mime_mismatch": True,
                        }
                        break
        else:
            # Also check MIME mismatch for suspicious-extension attachments
            ext = str(entry["extension"])
            if ext in MIME_EXTENSION_EXPECTATIONS and attachment.content_type is not None:
                ct_base = attachment.content_type.split(";")[0].strip().lower()
                if ct_base not in MIME_EXTENSION_EXPECTATIONS[ext]:
                    entry["mime_mismatch"] = True
        if entry is not None:
            suspicious.append(entry)
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


def _compute_correlation_bonus(triggered_rules: list[PhishingTriggeredRule]) -> int:
    """Return a correlation bonus weight based on how many independent signals fired."""
    n = len(triggered_rules)
    if n >= 5:
        return 4
    if n >= 3:
        return 2
    return 0


def _derive_observation_status(*, risk_score: int, triggered_rules: list[PhishingTriggeredRule]) -> ObservationStatus:
    """Return SUCCEEDED_NO_FINDINGS only when both score and rule list are empty."""
    if risk_score == 0 and len(triggered_rules) == 0:
        return ObservationStatus.SUCCEEDED_NO_FINDINGS
    return ObservationStatus.SUCCEEDED
