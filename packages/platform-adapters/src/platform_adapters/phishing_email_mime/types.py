"""Normalized MIME email types for the phishing_email_mime adapter."""

from __future__ import annotations

from dataclasses import dataclass, field

from platform_adapters.phishing_email.types import PhishingEmailAttachment, PhishingEmailParty

PHISHING_EMAIL_MIME_INPUT_SHAPE = "structured_email_v2"


@dataclass(frozen=True)
class ReceivedHop:
    """A single hop in the Received header chain."""

    from_host: str | None
    by_host: str | None
    with_protocol: str | None
    timestamp: str | None
    raw: str


@dataclass(frozen=True)
class AuthenticationResult:
    """Parsed Authentication-Results header values."""

    spf: str | None
    dkim: str | None
    dmarc: str | None
    raw: str | None


@dataclass(frozen=True)
class NormalizedMimeEmail:
    """Normalized phishing email produced by parsing a raw MIME .eml file.

    This is a superset of the structured_email_v1 shape — it includes all v1
    fields plus the full MIME header context needed for header_analysis.
    """

    # structured_email_v1 fields
    subject: str
    sender: PhishingEmailParty
    reply_to: PhishingEmailParty | None
    urls: tuple[str, ...]
    text: str
    attachments: tuple[PhishingEmailAttachment, ...]

    # MIME extras (structured_email_v2)
    input_shape: str  # "structured_email_v2"
    message_id: str | None
    date: str | None
    html_body: str | None
    plain_text_body: str | None
    received_chain: tuple[ReceivedHop, ...]
    authentication_results: AuthenticationResult | None
    x_originating_ip: str | None
    x_mailer: str | None
    all_headers: dict[str, list[str]]
