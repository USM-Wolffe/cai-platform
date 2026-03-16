"""Phishing email adapter helpers for the first deterministic phishing slice."""

from platform_adapters.phishing_email.errors import (
    InvalidPhishingEmailInputError,
    PhishingEmailAdapterError,
    UnsupportedPhishingEmailArtifactError,
)
from platform_adapters.phishing_email.normalize import (
    PHISHING_EMAIL_INPUT_SHAPE,
    inspect_phishing_email_input_artifact,
    normalize_phishing_email_payload,
)
from platform_adapters.phishing_email.types import (
    NormalizedPhishingEmail,
    PhishingEmailAttachment,
    PhishingEmailParty,
)

__all__ = [
    "InvalidPhishingEmailInputError",
    "NormalizedPhishingEmail",
    "PHISHING_EMAIL_INPUT_SHAPE",
    "PhishingEmailAdapterError",
    "PhishingEmailAttachment",
    "PhishingEmailParty",
    "UnsupportedPhishingEmailArtifactError",
    "inspect_phishing_email_input_artifact",
    "normalize_phishing_email_payload",
]
