"""MIME-based phishing email adapter (structured_email_v2)."""

from platform_adapters.phishing_email_mime.errors import (
    MimeParseError,
    MissingMimeBodyError,
    PhishingEmailMimeAdapterError,
)
from platform_adapters.phishing_email_mime.normalize import (
    normalize_mime_email_bytes,
    normalize_mime_email_string,
)
from platform_adapters.phishing_email_mime.types import (
    PHISHING_EMAIL_MIME_INPUT_SHAPE,
    AuthenticationResult,
    NormalizedMimeEmail,
    ReceivedHop,
)

__all__ = [
    "AuthenticationResult",
    "MimeParseError",
    "MissingMimeBodyError",
    "NormalizedMimeEmail",
    "PHISHING_EMAIL_MIME_INPUT_SHAPE",
    "PhishingEmailMimeAdapterError",
    "ReceivedHop",
    "normalize_mime_email_bytes",
    "normalize_mime_email_string",
]
