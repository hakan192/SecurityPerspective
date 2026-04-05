from fastapi import FastAPI

from app.api import api_router
from app.core_config import settings

app = FastAPI(title="FortiWeb Assessment Platform")
app.include_router(api_router)


@app.get("/")
def root():
    return {
        "name": settings.app_name,
        "status": "running",
        "docs": "/docs",
        "health": "/health",
        "ready": "/health/ready",
    }
