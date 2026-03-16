"""API route registration."""

from fastapi import APIRouter

from platform_api.routes.artifacts import router as artifacts_router
from platform_api.routes.cases import router as cases_router
from platform_api.routes.health import router as health_router
from platform_api.routes.queries import router as queries_router
from platform_api.routes.runs import router as runs_router

api_router = APIRouter()
api_router.include_router(health_router)
api_router.include_router(cases_router)
api_router.include_router(runs_router)
api_router.include_router(queries_router)
api_router.include_router(artifacts_router)

__all__ = ["api_router"]
