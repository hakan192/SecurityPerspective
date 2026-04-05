from fastapi import APIRouter

from app.api.health import router as health_router
from app.modules.auth.router import router as auth_router
from app.modules.baseline.router import router as baseline_router
from app.modules.parsing.router import router as parsing_router
from app.modules.reporting.router import router as reporting_router
from app.modules.scoring.router import router as scoring_router
from app.modules.snapshots.router import router as snapshots_router

api_router = APIRouter()
api_router.include_router(health_router)
api_router.include_router(auth_router)
api_router.include_router(snapshots_router)
api_router.include_router(parsing_router)
api_router.include_router(baseline_router)
api_router.include_router(scoring_router)
api_router.include_router(reporting_router)
