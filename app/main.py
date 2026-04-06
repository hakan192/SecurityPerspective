from io import BytesIO
import logging
import time
from typing import Annotated

import redis
from apscheduler.schedulers.background import BackgroundScheduler
from fastapi import Depends, FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse
from sqlalchemy import text
from sqlalchemy.orm import Session

from app.celery_app import celery_app
from app.config import settings
from app.database import Base, SessionLocal, engine, get_db
from app.models import ExchangeRateSnapshot, FortiWebSnapshot, MaturityAssessment, ParsedConfig, ServerPolicy
from app.schemas import (
    AssessmentOut,
    ExchangeRateOut,
    ExchangeRateSnapshotOut,
    LoginRequest,
    LoginResponse,
    ParsedConfigOut,
    ServerPolicyOut,
    SnapshotOut,
)
from app.security import require_analyst_or_admin, require_role, verify_local_admin
from app.services import (
    assess_snapshot,
    create_snapshot,
    fetch_fortiweb_config,
    parse_snapshot,
    collect_exchange_rates,
    fetch_fortiweb_server_policy,
    seed_baseline_controls,
    seed_server_policy_samples,
    latest_exchange_rates,
)

app = FastAPI(title=settings.app_name)
scheduler = BackgroundScheduler()
redis_client = redis.from_url(settings.redis_url)
logger = logging.getLogger(__name__)
cors_origins = [origin.strip() for origin in settings.cors_allow_origins.split(",") if origin.strip()]

app.add_middleware(
    CORSMiddleware,
    allow_origins=cors_origins,
    allow_origin_regex=settings.cors_allow_origin_regex,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


def run_collection_job():
    db = SessionLocal()
    try:
        payload = fetch_fortiweb_config()
        snapshot = create_snapshot(db, settings.fortiweb_config_endpoint, payload)
        parse_snapshot(db, snapshot)
        assess_snapshot(db, snapshot.id)
    finally:
        db.close()


@app.on_event("startup")
def startup_event():
    for attempt in range(1, 16):
        try:
            with engine.connect() as connection:
                connection.execute(text("SELECT 1"))
            redis_client.ping()
            break
        except Exception as exc:
            logger.warning("Startup dependency check failed (attempt %s/15): %s", attempt, exc)
            if attempt == 15:
                raise
            time.sleep(2)

    Base.metadata.create_all(bind=engine)
    db = SessionLocal()
    try:
        seed_baseline_controls(db)
        seed_server_policy_samples(db)
    finally:
        db.close()

    if settings.scheduler_enabled:
        scheduler.add_job(run_collection_job, "interval", minutes=settings.scheduler_minutes)
        scheduler.start()


@app.on_event("shutdown")
def shutdown_event():
    if scheduler.running:
        scheduler.shutdown(wait=False)


@app.get("/health/live")
def health_live():
    return {"status": "ok", "service": settings.app_name}


@app.get("/health/ready")
def health_ready():
    checks = {"database": False, "redis": False}

    try:
        with engine.connect() as connection:
            connection.execute(text("SELECT 1"))
        checks["database"] = True
    except Exception:
        checks["database"] = False

    try:
        checks["redis"] = bool(redis_client.ping())
    except Exception:
        checks["redis"] = False

    status = "ready" if all(checks.values()) else "degraded"
    return {"status": status, "checks": checks}


@app.post("/auth/login", response_model=LoginResponse)
def login(payload: LoginRequest):
    if not verify_local_admin(payload.username, payload.password):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    # Phase-1 local token placeholder (replace with JWT in next phase)
    return LoginResponse(access_token="local-admin-token")


@app.post("/collect", response_model=SnapshotOut)
def collect_on_demand(
    db: Session = Depends(get_db),
    _: Annotated[str, Depends(require_analyst_or_admin)] = "analyst",
):
    payload = fetch_fortiweb_config()
    snapshot = create_snapshot(db, settings.fortiweb_config_endpoint, payload)
    parse_snapshot(db, snapshot)
    assess_snapshot(db, snapshot.id)
    return snapshot


@app.post("/fortiweb/server-policy/collect", response_model=SnapshotOut)
def collect_fortiweb_server_policy(
    db: Session = Depends(get_db),
    _: Annotated[str, Depends(require_analyst_or_admin)] = "analyst",
):
    payload = fetch_fortiweb_server_policy()
    return create_snapshot(db, settings.fortiweb_server_policy_endpoint, payload)


@app.get("/fortiweb/server-policy/latest", response_model=SnapshotOut)
def latest_fortiweb_server_policy(
    db: Session = Depends(get_db),
    _: Annotated[str, Depends(require_role)] = "viewer",
):
    snapshot = (
        db.query(FortiWebSnapshot)
        .filter(FortiWebSnapshot.endpoint == settings.fortiweb_server_policy_endpoint)
        .order_by(FortiWebSnapshot.collected_at.desc())
        .first()
    )
    if not snapshot:
        raise HTTPException(status_code=404, detail="Server policy snapshot not found")
    return snapshot


@app.get("/server-policies", response_model=list[ServerPolicyOut])
def list_server_policies(
    db: Session = Depends(get_db),
    _: Annotated[str, Depends(require_role)] = "viewer",
):
    return db.query(ServerPolicy).order_by(ServerPolicy.id.asc()).all()


@app.post("/exchange-rates/collect", response_model=ExchangeRateSnapshotOut)
def collect_exchange_rates_snapshot(
    db: Session = Depends(get_db),
    _: Annotated[str, Depends(require_analyst_or_admin)] = "analyst",
):
    return collect_exchange_rates(db)


@app.get("/exchange-rates/snapshots", response_model=list[ExchangeRateSnapshotOut])
def list_exchange_rate_snapshots(
    db: Session = Depends(get_db),
    _: Annotated[str, Depends(require_role)] = "viewer",
):
    return db.query(ExchangeRateSnapshot).order_by(ExchangeRateSnapshot.fetched_at.desc()).limit(20).all()


@app.get("/exchange-rates/latest", response_model=list[ExchangeRateOut])
def list_latest_exchange_rates(
    db: Session = Depends(get_db),
    _: Annotated[str, Depends(require_role)] = "viewer",
):
    return latest_exchange_rates(db)


@app.post("/collect/async")
def collect_on_demand_async(_: Annotated[str, Depends(require_analyst_or_admin)] = "analyst"):
    task = celery_app.send_task("fortiweb.collect_snapshot")
    return {"task_id": task.id, "status": "queued"}


@app.get("/snapshots", response_model=list[SnapshotOut])
def list_snapshots(
    db: Session = Depends(get_db),
    _: Annotated[str, Depends(require_role)] = "viewer",
):
    return db.query(FortiWebSnapshot).order_by(FortiWebSnapshot.collected_at.desc()).all()


@app.get("/snapshots/{snapshot_id}/raw", response_model=SnapshotOut)
def get_raw_snapshot(
    snapshot_id: int,
    db: Session = Depends(get_db),
    _: Annotated[str, Depends(require_role)] = "viewer",
):
    snapshot = db.query(FortiWebSnapshot).filter(FortiWebSnapshot.id == snapshot_id).first()
    if not snapshot:
        raise HTTPException(status_code=404, detail="Snapshot not found")
    return snapshot


@app.get("/snapshots/{snapshot_id}/parsed", response_model=list[ParsedConfigOut])
def get_parsed_snapshot(
    snapshot_id: int,
    db: Session = Depends(get_db),
    _: Annotated[str, Depends(require_role)] = "viewer",
):
    return db.query(ParsedConfig).filter(ParsedConfig.snapshot_id == snapshot_id).all()


@app.get("/snapshots/{snapshot_id}/assessment", response_model=AssessmentOut)
def get_assessment(
    snapshot_id: int,
    db: Session = Depends(get_db),
    _: Annotated[str, Depends(require_role)] = "viewer",
):
    assessment = (
        db.query(MaturityAssessment)
        .filter(MaturityAssessment.snapshot_id == snapshot_id)
        .order_by(MaturityAssessment.generated_at.desc())
        .first()
    )
    if not assessment:
        raise HTTPException(status_code=404, detail="Assessment not found")
    return assessment


@app.get("/snapshots/{snapshot_id}/assessment/report")
def download_assessment_report(
    snapshot_id: int,
    db: Session = Depends(get_db),
    _: Annotated[str, Depends(require_role)] = "viewer",
):
    assessment = (
        db.query(MaturityAssessment)
        .filter(MaturityAssessment.snapshot_id == snapshot_id)
        .order_by(MaturityAssessment.generated_at.desc())
        .first()
    )
    if not assessment:
        raise HTTPException(status_code=404, detail="Assessment not found")

    report_bytes = BytesIO(str(assessment.details).encode("utf-8"))
    return StreamingResponse(
        report_bytes,
        media_type="application/json",
        headers={"Content-Disposition": f"attachment; filename=assessment-{snapshot_id}.json"},
    )
