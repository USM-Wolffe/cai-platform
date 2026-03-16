"""Phishing email backend slice for deterministic phishing assessment."""

from platform_backends.phishing_email.descriptor import (
    PHISHING_EMAIL_BACKEND_ID,
    PHISHING_EMAIL_BACKEND_TYPE,
    PHISHING_EMAIL_BASIC_ASSESSMENT_OPERATION,
    PHISHING_EMAIL_BASIC_ASSESSMENT_QUERY_CLASS,
    get_phishing_email_backend_descriptor,
)
from platform_backends.phishing_email.errors import (
    PhishingEmailBackendError,
    UnsupportedPhishingEmailObservationError,
)
from platform_backends.phishing_email.execute import execute_predefined_observation
from platform_backends.phishing_email.models import (
    PhishingEmailExecutionOutcome,
    PhishingTriggeredRule,
    SuspiciousUrlRecord,
)

__all__ = [
    "PHISHING_EMAIL_BACKEND_ID",
    "PHISHING_EMAIL_BACKEND_TYPE",
    "PHISHING_EMAIL_BASIC_ASSESSMENT_OPERATION",
    "PHISHING_EMAIL_BASIC_ASSESSMENT_QUERY_CLASS",
    "PhishingEmailBackendError",
    "PhishingEmailExecutionOutcome",
    "PhishingTriggeredRule",
    "SuspiciousUrlRecord",
    "UnsupportedPhishingEmailObservationError",
    "execute_predefined_observation",
    "get_phishing_email_backend_descriptor",
]
