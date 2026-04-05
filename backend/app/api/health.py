from fastapi import APIRouter
from redis import Redis
from sqlalchemy import text

from app.core_config import settings
from app.core_db import SessionLocal

router = APIRouter(tags=["health"])


@router.get("/health")
def health():
    return {"status": "ok", "service": settings.app_name}


@router.get("/health/ready")
def ready():
    db = SessionLocal()
    redis = Redis.from_url(settings.redis_url)
    try:
        db.execute(text("SELECT 1"))
        redis.ping()
        return {"status": "ready"}
    finally:
        db.close()
