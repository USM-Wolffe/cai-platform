"""Shared reference objects and validation helpers."""

from __future__ import annotations

from typing import Iterable

from pydantic import Field, field_validator

from platform_contracts.common.base import ContractModel
from platform_contracts.common.enums import EntityKind


class EntityRef(ContractModel):
    """Explicit reference to another durable platform entity."""

    entity_type: EntityKind
    id: str = Field(min_length=1)

    @field_validator("id")
    @classmethod
    def strip_id(cls, value: str) -> str:
        return value.strip()


class ExternalReference(ContractModel):
    """Reference to an external identifier or human-visible system reference."""

    source: str = Field(min_length=1)
    value: str = Field(min_length=1)
    uri: str | None = None

    @field_validator("source", "value")
    @classmethod
    def strip_text(cls, value: str) -> str:
        return value.strip()


def ensure_ref_type(ref: EntityRef | None, allowed: set[EntityKind], field_name: str) -> EntityRef | None:
    """Validate that an optional reference points to an allowed entity kind."""
    if ref is None:
        return None
    if ref.entity_type not in allowed:
        allowed_values = ", ".join(sorted(item.value for item in allowed))
        raise ValueError(f"{field_name} must reference one of: {allowed_values}")
    return ref


def ensure_ref_list_types(
    refs: Iterable[EntityRef],
    allowed: set[EntityKind],
    field_name: str,
) -> list[EntityRef]:
    """Validate that a list of references points only to allowed entity kinds."""
    validated = list(refs)
    for ref in validated:
        ensure_ref_type(ref, allowed, field_name)
    return validated

