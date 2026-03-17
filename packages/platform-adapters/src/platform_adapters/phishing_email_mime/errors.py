"""Errors for the phishing_email_mime adapter."""

from __future__ import annotations


class PhishingEmailMimeAdapterError(Exception):
    """Base error for the MIME phishing email adapter."""


class MimeParseError(PhishingEmailMimeAdapterError):
    """Raised when raw MIME bytes cannot be parsed into a usable email structure."""


class MissingMimeBodyError(PhishingEmailMimeAdapterError):
    """Raised when no text body can be extracted from the MIME message."""
