"""Artifact lookup helpers for orchestration-neutral core services."""

from __future__ import annotations

from platform_contracts import Artifact, EntityKind, EntityRef

from platform_core.errors import NotFoundError
from platform_core.ports import ArtifactRepository


def get_artifact_or_raise(artifact_repository: ArtifactRepository, artifact_id: str) -> Artifact:
    """Resolve one artifact or raise a normalized core error."""
    artifact = artifact_repository.get_artifact(artifact_id)
    if artifact is None:
        raise NotFoundError(f"artifact '{artifact_id}' was not found")
    return artifact


def build_artifact_ref(artifact: Artifact) -> EntityRef:
    """Build an explicit artifact reference from a durable artifact record."""
    return EntityRef(entity_type=EntityKind.ARTIFACT, id=artifact.artifact_id)
