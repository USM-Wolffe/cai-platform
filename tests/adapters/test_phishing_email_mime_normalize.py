"""Tests for the phishing_email_mime MIME parser adapter."""

from __future__ import annotations

import textwrap

from platform_adapters.phishing_email_mime import (
    PHISHING_EMAIL_MIME_INPUT_SHAPE,
    normalize_mime_email_bytes,
    normalize_mime_email_string,
)
from platform_adapters.phishing_email_mime.normalize import (
    _extract_urls_from_html,
    _parse_party,
)


# ── helpers ──────────────────────────────────────────────────────────────────

def _make_simple_eml(
    *,
    subject: str = "Test subject",
    from_: str = "Sender Name <sender@example.com>",
    reply_to: str | None = None,
    body: str = "Hello there.",
    received: list[str] | None = None,
    auth_results: str | None = None,
    extra_headers: str = "",
) -> bytes:
    lines = [
        f"From: {from_}",
        f"Subject: {subject}",
        "MIME-Version: 1.0",
        "Content-Type: text/plain; charset=utf-8",
    ]
    if reply_to:
        lines.append(f"Reply-To: {reply_to}")
    if auth_results:
        lines.append(f"Authentication-Results: {auth_results}")
    for r in reversed(received or []):
        lines.append(f"Received: {r}")
    if extra_headers:
        lines.append(extra_headers.strip())
    lines.append("")
    lines.append(body)
    return "\n".join(lines).encode("utf-8")


# ── basic parsing ─────────────────────────────────────────────────────────────

def test_normalize_bytes_parses_subject_and_sender():
    raw = _make_simple_eml(subject="Hello World", from_="Alice <alice@corp.example>")
    normalized = normalize_mime_email_bytes(raw)
    assert normalized.subject == "Hello World"
    assert normalized.sender.email == "alice@corp.example"
    assert normalized.sender.domain == "corp.example"
    assert normalized.sender.display_name == "Alice"


def test_normalize_string_equivalent_to_bytes():
    raw = _make_simple_eml(subject="String test")
    normalized_bytes = normalize_mime_email_bytes(raw)
    normalized_str = normalize_mime_email_string(raw.decode("utf-8"))
    assert normalized_bytes.subject == normalized_str.subject
    assert normalized_bytes.sender.email == normalized_str.sender.email


def test_input_shape_is_v2():
    raw = _make_simple_eml()
    normalized = normalize_mime_email_bytes(raw)
    assert normalized.input_shape == PHISHING_EMAIL_MIME_INPUT_SHAPE
    assert normalized.input_shape == "structured_email_v2"


def test_reply_to_parsed_when_present():
    raw = _make_simple_eml(
        from_="Alice <alice@corp.example>",
        reply_to="Attacker <evil@hacker.example>",
    )
    normalized = normalize_mime_email_bytes(raw)
    assert normalized.reply_to is not None
    assert normalized.reply_to.email == "evil@hacker.example"
    assert normalized.reply_to.display_name == "Attacker"


def test_reply_to_is_none_when_absent():
    raw = _make_simple_eml(from_="Alice <alice@corp.example>")
    normalized = normalize_mime_email_bytes(raw)
    assert normalized.reply_to is None


def test_plain_text_body_extracted():
    raw = _make_simple_eml(body="Click here to verify your account.")
    normalized = normalize_mime_email_bytes(raw)
    assert normalized.plain_text_body is not None
    assert "verify your account" in normalized.plain_text_body


# ── Received chain parsing ────────────────────────────────────────────────────

def test_received_chain_parsed_single_hop():
    raw = _make_simple_eml(
        received=["from mail.evil.example by mx.corp.example with ESMTP; Mon, 1 Jan 2024 00:00:00 +0000"]
    )
    normalized = normalize_mime_email_bytes(raw)
    assert len(normalized.received_chain) == 1
    hop = normalized.received_chain[0]
    assert hop.from_host == "mail.evil.example"
    assert hop.by_host == "mx.corp.example"
    assert hop.with_protocol == "ESMTP"


def test_received_chain_empty_when_no_headers():
    raw = _make_simple_eml()
    normalized = normalize_mime_email_bytes(raw)
    assert normalized.received_chain == ()


def test_received_chain_multiple_hops():
    raw = _make_simple_eml(
        received=[
            "from hop2.example by hop3.example with SMTP; Tue, 2 Jan 2024 00:00:00 +0000",
            "from hop1.example by hop2.example with SMTP; Tue, 2 Jan 2024 00:00:01 +0000",
        ]
    )
    normalized = normalize_mime_email_bytes(raw)
    assert len(normalized.received_chain) == 2


# ── Authentication-Results parsing ───────────────────────────────────────────

def test_authentication_results_spf_pass():
    auth_str = "mx.corp.example; spf=pass smtp.mailfrom=sender@example.com"
    raw = _make_simple_eml(auth_results=auth_str)
    normalized = normalize_mime_email_bytes(raw)
    assert normalized.authentication_results is not None
    assert normalized.authentication_results.spf == "pass"


def test_authentication_results_dkim_fail():
    auth_str = "mx.corp.example; dkim=fail header.d=example.com"
    raw = _make_simple_eml(auth_results=auth_str)
    normalized = normalize_mime_email_bytes(raw)
    assert normalized.authentication_results is not None
    assert normalized.authentication_results.dkim == "fail"


def test_authentication_results_dmarc_fail():
    auth_str = "mx.corp.example; dmarc=fail action=quarantine"
    raw = _make_simple_eml(auth_results=auth_str)
    normalized = normalize_mime_email_bytes(raw)
    assert normalized.authentication_results is not None
    assert normalized.authentication_results.dmarc == "fail"


def test_authentication_results_none_when_absent():
    raw = _make_simple_eml()
    normalized = normalize_mime_email_bytes(raw)
    assert normalized.authentication_results is None


def test_authentication_results_all_fields():
    auth_str = "mx.corp.example; spf=fail dkim=fail dmarc=fail"
    raw = _make_simple_eml(auth_results=auth_str)
    normalized = normalize_mime_email_bytes(raw)
    assert normalized.authentication_results is not None
    assert normalized.authentication_results.spf == "fail"
    assert normalized.authentication_results.dkim == "fail"
    assert normalized.authentication_results.dmarc == "fail"


# ── URL extraction from HTML ──────────────────────────────────────────────────

def test_extract_urls_from_html_href():
    html = '<a href="http://evil.example/login?verify=1">Click here</a>'
    urls = _extract_urls_from_html(html)
    assert "http://evil.example/login?verify=1" in urls


def test_extract_urls_from_html_deduplicates():
    html = '<a href="https://example.com">Link 1</a><a href="https://example.com">Link 2</a>'
    urls = _extract_urls_from_html(html)
    assert urls.count("https://example.com") == 1


# ── party parsing ─────────────────────────────────────────────────────────────

def test_parse_party_with_display_name():
    party = _parse_party("Billing Department <billing@company.example>")
    assert party.email == "billing@company.example"
    assert party.domain == "company.example"
    assert party.display_name == "Billing Department"


def test_parse_party_bare_address():
    party = _parse_party("user@example.com")
    assert party.email == "user@example.com"
    assert party.domain == "example.com"
    assert party.display_name is None


def test_parse_party_quoted_display_name():
    party = _parse_party('"Security Team" <security@corp.example>')
    assert party.display_name == "Security Team"
    assert party.email == "security@corp.example"
