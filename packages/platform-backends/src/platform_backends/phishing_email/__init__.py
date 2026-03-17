"""Phishing email backend slice for deterministic phishing assessment."""

from platform_backends.phishing_email.descriptor import (
    PHISHING_EMAIL_BACKEND_ID,
    PHISHING_EMAIL_BACKEND_TYPE,
    PHISHING_EMAIL_BASIC_ASSESSMENT_OPERATION,
    PHISHING_EMAIL_BASIC_ASSESSMENT_QUERY_CLASS,
    PHISHING_EMAIL_HEADER_ANALYSIS_OPERATION,
    get_phishing_email_backend_descriptor,
)
from platform_backends.phishing_email.errors import (
    PhishingEmailBackendError,
    UnsupportedPhishingEmailObservationError,
)
from platform_backends.phishing_email.execute import (
    execute_header_analysis_observation,
    execute_predefined_observation,
)
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
    "PHISHING_EMAIL_HEADER_ANALYSIS_OPERATION",
    "PhishingEmailBackendError",
    "PhishingEmailExecutionOutcome",
    "PhishingTriggeredRule",
    "SuspiciousUrlRecord",
    "UnsupportedPhishingEmailObservationError",
    "execute_header_analysis_observation",
    "execute_predefined_observation",
    "get_phishing_email_backend_descriptor",
]
