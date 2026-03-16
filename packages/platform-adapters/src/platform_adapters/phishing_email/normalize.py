"""Phishing email input inspection and normalization helpers."""

from __future__ import annotations

from typing import Any

from platform_contracts import Artifact, ArtifactKind

from platform_adapters.phishing_email.errors import (
    InvalidPhishingEmailInputError,
    UnsupportedPhishingEmailArtifactError,
)
from platform_adapters.phishing_email.types import (
    NormalizedPhishingEmail,
    PhishingEmailAttachment,
    PhishingEmailParty,
)

SUPPORTED_INPUT_FORMATS = {"json"}
PHISHING_EMAIL_INPUT_SHAPE = "structured_email_v1"
REQUIRED_FIELDS = {"subject", "sender", "reply_to", "urls", "text", "attachments"}


def inspect_phishing_email_input_artifact(artifact: Artifact) -> None:
    """Validate that the artifact contract is acceptable for the phishing email slice."""
    if artifact.kind != ArtifactKind.INPUT:
        raise UnsupportedPhishingEmailArtifactError("phishing_email only accepts input artifacts")
    if artifact.format not in SUPPORTED_INPUT_FORMATS:
        raise UnsupportedPhishingEmailArtifactError(
            f"phishing_email only accepts formats: {', '.join(sorted(SUPPORTED_INPUT_FORMATS))}"
        )


def normalize_phishing_email_payload(payload: Any) -> NormalizedPhishingEmail:
    """Normalize the structured phishing email payload."""
    if not isinstance(payload, dict):
        raise InvalidPhishingEmailInputError("phishing email payload must be a mapping")

    missing_fields = sorted(REQUIRED_FIELDS - set(payload))
    if missing_fields:
        joined = ", ".join(missing_fields)
        raise InvalidPhishingEmailInputError(
            f"phishing email payload is missing required fields: {joined}"
        )

    return NormalizedPhishingEmail(
        subject=_require_non_empty_string(payload["subject"], field_name="subject"),
        sender=_normalize_party(payload["sender"], field_name="sender"),
        reply_to=_normalize_optional_party(payload["reply_to"], field_name="reply_to"),
        urls=_normalize_urls(payload["urls"]),
        text=_require_non_empty_string(payload["text"], field_name="text"),
        attachments=_normalize_attachments(payload["attachments"]),
        input_shape=PHISHING_EMAIL_INPUT_SHAPE,
    )


def _normalize_party(value: Any, *, field_name: str) -> PhishingEmailParty:
    if not isinstance(value, dict):
        raise InvalidPhishingEmailInputError(f"'{field_name}' must be a mapping")

    email = _normalize_email(value.get("email"), field_name=f"{field_name}.email")
    display_name = _optional_string(value.get("display_name"), field_name=f"{field_name}.display_name")
    domain = email.rsplit("@", maxsplit=1)[1]
    return PhishingEmailParty(
        email=email,
        domain=domain,
        display_name=display_name,
    )


def _normalize_optional_party(value: Any, *, field_name: str) -> PhishingEmailParty | None:
    if value is None:
        return None
    return _normalize_party(value, field_name=field_name)


def _normalize_urls(value: Any) -> tuple[str, ...]:
    if not isinstance(value, list):
        raise InvalidPhishingEmailInputError("'urls' must be a list")

    normalized_urls: list[str] = []
    for index, item in enumerate(value):
        normalized_urls.append(
            _require_non_empty_string(item, field_name=f"urls[{index}]")
        )
    return tuple(normalized_urls)


def _normalize_attachments(value: Any) -> tuple[PhishingEmailAttachment, ...]:
    if not isinstance(value, list):
        raise InvalidPhishingEmailInputError("'attachments' must be a list")

    normalized: list[PhishingEmailAttachment] = []
    for index, item in enumerate(value):
        if not isinstance(item, dict):
            raise InvalidPhishingEmailInputError(f"attachments[{index}] must be a mapping")
        normalized.append(
            PhishingEmailAttachment(
                filename=_require_non_empty_string(
                    item.get("filename"),
                    field_name=f"attachments[{index}].filename",
                ),
                content_type=_optional_string(
                    item.get("content_type"),
                    field_name=f"attachments[{index}].content_type",
                ),
            )
        )
    return tuple(normalized)


def _normalize_email(value: Any, *, field_name: str) -> str:
    email = _require_non_empty_string(value, field_name=field_name).lower()
    local_part, separator, domain = email.partition("@")
    if separator != "@" or not local_part or not domain:
        raise InvalidPhishingEmailInputError(f"'{field_name}' must be a valid email address")
    return f"{local_part}@{domain}"


def _require_non_empty_string(value: Any, *, field_name: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise InvalidPhishingEmailInputError(f"'{field_name}' must be a non-empty string")
    return value.strip()


def _optional_string(value: Any, *, field_name: str) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str):
        raise InvalidPhishingEmailInputError(f"'{field_name}' must be a string when provided")
    stripped = value.strip()
    return stripped or None
