"""Health route."""

from fastapi import APIRouter, Depends

from platform_api.runtime import AppRuntime, get_runtime

router = APIRouter()


@router.get("/health")
def health(runtime: AppRuntime = Depends(get_runtime)) -> dict[str, object]:
    return {
        "status": "ok",
        "backend_ids": runtime.backend_registry.list_backend_ids(),
    }
