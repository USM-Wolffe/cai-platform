"""Small adapter-local normalized phishing email types."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class PhishingEmailParty:
    """Normalized sender or reply-to party."""

    email: str
    domain: str
    display_name: str | None = None


@dataclass(frozen=True)
class PhishingEmailAttachment:
    """Normalized attachment metadata."""

    filename: str
    content_type: str | None = None


@dataclass(frozen=True)
class NormalizedPhishingEmail:
    """Normalized phishing-email artifact used by the backend slice."""

    subject: str
    sender: PhishingEmailParty
    reply_to: PhishingEmailParty | None
    urls: tuple[str, ...]
    text: str
    attachments: tuple[PhishingEmailAttachment, ...]
    input_shape: str
