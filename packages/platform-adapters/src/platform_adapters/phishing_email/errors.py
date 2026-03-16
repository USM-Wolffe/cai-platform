"""Phishing email adapter errors."""


class PhishingEmailAdapterError(Exception):
    """Base error for phishing email adapter helpers."""


class InvalidPhishingEmailInputError(PhishingEmailAdapterError):
    """Raised when the phishing email payload shape is invalid."""


class UnsupportedPhishingEmailArtifactError(PhishingEmailAdapterError):
    """Raised when the artifact contract is incompatible with the phishing slice."""
