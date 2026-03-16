"""Artifact inspection routes for the deterministic platform-api surface."""

from fastapi import APIRouter, Depends

from platform_api.runtime import AppRuntime, get_runtime
from platform_api.schemas import serialize_artifact_content

router = APIRouter(prefix="/artifacts", tags=["artifacts"])


@router.get("/{artifact_id}/content")
def get_artifact_content_endpoint(
    artifact_id: str,
    runtime: AppRuntime = Depends(get_runtime),
) -> dict[str, object]:
    artifact, content, content_source = runtime.get_artifact_content_or_raise(artifact_id)
    return serialize_artifact_content(
        artifact=artifact,
        content=content,
        content_source=content_source,
    )
