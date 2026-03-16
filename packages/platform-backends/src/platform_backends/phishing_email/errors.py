"""Phishing email backend errors."""


class PhishingEmailBackendError(Exception):
    """Base error for the phishing email backend slice."""


class UnsupportedPhishingEmailObservationError(PhishingEmailBackendError):
    """Raised when the phishing backend receives an unsupported operation."""
