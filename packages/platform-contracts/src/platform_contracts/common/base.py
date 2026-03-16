"""Base contract models and shared helpers."""

from __future__ import annotations

from datetime import datetime, timezone
from uuid import uuid4

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

SCHEMA_VERSION = "1.0"


def utc_now() -> datetime:
    """Return a timezone-aware UTC timestamp."""
    return datetime.now(timezone.utc)


def generate_opaque_id(prefix: str) -> str:
    """Generate a stable opaque identifier with a type-specific prefix."""
    return f"{prefix}_{uuid4().hex}"


class ContractModel(BaseModel):
    """Strict base model for all shared contract objects."""

    model_config = ConfigDict(extra="forbid", validate_assignment=True, str_strip_whitespace=True)

    schema_version: str = Field(default=SCHEMA_VERSION)

    @field_validator("schema_version")
    @classmethod
    def validate_schema_version(cls, value: str) -> str:
        if not value:
            raise ValueError("schema_version must not be empty")
        return value


class TimestampedModel(ContractModel):
    """Base model for durable records with creation and update timestamps."""

    created_at: datetime = Field(default_factory=utc_now)
    updated_at: datetime = Field(default_factory=utc_now)

    @model_validator(mode="after")
    def validate_timestamp_order(self) -> "TimestampedModel":
        if self.updated_at < self.created_at:
            raise ValueError("updated_at must be greater than or equal to created_at")
        return self
