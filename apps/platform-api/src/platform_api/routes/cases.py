"""Case and artifact routes."""

from fastapi import APIRouter, Depends, status
from platform_contracts import Artifact
from platform_core import attach_artifact_ref_to_case, create_case

from platform_api.runtime import AppRuntime, get_runtime
from platform_api.schemas import (
    AttachInputArtifactRequest,
    CreateCaseRequest,
    serialize_case_summary,
)

router = APIRouter(prefix="/cases", tags=["cases"])


@router.post("", status_code=status.HTTP_201_CREATED)
def create_case_endpoint(
    request: CreateCaseRequest,
    runtime: AppRuntime = Depends(get_runtime),
) -> dict[str, object]:
    case = create_case(
        runtime.case_repository,
        workflow_type=request.workflow_type,
        title=request.title,
        summary=request.summary,
        metadata=request.metadata,
    )
    return serialize_case_summary(case=case, artifacts=[])


@router.get("/{case_id}")
def get_case_endpoint(case_id: str, runtime: AppRuntime = Depends(get_runtime)) -> dict[str, object]:
    case = runtime.get_case_or_raise(case_id)
    return serialize_case_summary(case=case, artifacts=runtime.get_case_artifacts(case))


@router.post("/{case_id}/artifacts/input", status_code=status.HTTP_201_CREATED)
def attach_input_artifact_endpoint(
    case_id: str,
    request: AttachInputArtifactRequest,
    runtime: AppRuntime = Depends(get_runtime),
) -> dict[str, object]:
    artifact = runtime.create_input_artifact(
        payload=request.payload,
        format=request.format,
        summary=request.summary,
        labels=request.labels,
        metadata=request.metadata,
    )
    case = attach_artifact_ref_to_case(
        runtime.case_repository,
        runtime.artifact_repository,
        runtime.audit_port,
        case_id=case_id,
        artifact_id=artifact.artifact_id,
    )
    return {
        "case": case.model_dump(mode="json"),
        "artifact": artifact.model_dump(mode="json"),
    }
