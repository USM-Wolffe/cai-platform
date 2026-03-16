import pytest

from platform_adapters.phishing_email import (
    PHISHING_EMAIL_INPUT_SHAPE,
    InvalidPhishingEmailInputError,
    normalize_phishing_email_payload,
)


def test_valid_phishing_email_payload_normalizes_successfully():
    normalized = normalize_phishing_email_payload(
        {
            "subject": "Urgent invoice review",
            "sender": {
                "email": "Security.Alert@GMAIL.COM",
                "display_name": "Security Team",
            },
            "reply_to": {
                "email": "ops@Corp-Example.com",
                "display_name": "Operations",
            },
            "urls": [
                "https://portal.example.com/inbox",
                "http://198.51.100.7/login?verify=1",
            ],
            "text": "Please verify your account immediately.",
            "attachments": [
                {"filename": "statement.zip", "content_type": "application/zip"},
                {"filename": "notes.txt"},
            ],
        }
    )

    assert normalized.input_shape == PHISHING_EMAIL_INPUT_SHAPE
    assert normalized.sender.email == "security.alert@gmail.com"
    assert normalized.sender.domain == "gmail.com"
    assert normalized.reply_to is not None
    assert normalized.reply_to.email == "ops@corp-example.com"
    assert normalized.urls == (
        "https://portal.example.com/inbox",
        "http://198.51.100.7/login?verify=1",
    )
    assert normalized.attachments[0].filename == "statement.zip"
    assert normalized.attachments[0].content_type == "application/zip"
    assert normalized.attachments[1].content_type is None


def test_missing_required_fields_fail_clearly():
    with pytest.raises(
        InvalidPhishingEmailInputError,
        match="missing required fields: attachments, reply_to, urls",
    ):
        normalize_phishing_email_payload(
            {
                "subject": "Missing pieces",
                "sender": {"email": "sender@example.com"},
                "text": "Body",
            }
        )


def test_wrong_phishing_email_field_types_fail_clearly():
    with pytest.raises(InvalidPhishingEmailInputError, match="'attachments' must be a list"):
        normalize_phishing_email_payload(
            {
                "subject": "Type mismatch",
                "sender": {"email": "sender@example.com"},
                "reply_to": None,
                "urls": [],
                "text": "Body",
                "attachments": "invoice.zip",
            }
        )
