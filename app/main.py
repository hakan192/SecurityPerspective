import logging
import time
from typing import Annotated

import redis
from apscheduler.schedulers.background import BackgroundScheduler
from fastapi import Depends, FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy import text
from sqlalchemy.orm import Session

from app.config import settings
from app.database import Base, SessionLocal, engine, get_db
from app.models import ManagedDevice
from app.schemas import LoginRequest, LoginResponse, ManagedDeviceCreate, ManagedDeviceOut
from app.security import require_analyst_or_admin, require_role, verify_local_admin
from app.services import fetch_and_store_server_policies_by_device, load_server_policies_from_db

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
        devices = db.query(ManagedDevice).order_by(ManagedDevice.id.desc()).all()
        fetch_and_store_server_policies_by_device(db, devices)
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
    with engine.begin() as connection:
        connection.execute(text("ALTER TABLE managed_devices ADD COLUMN IF NOT EXISTS apikey VARCHAR(255)"))
        connection.execute(text("UPDATE managed_devices SET apikey = '' WHERE apikey IS NULL"))
        connection.execute(text("DROP TABLE IF EXISTS baseline_controls CASCADE"))
        connection.execute(text("DROP TABLE IF EXISTS exchange_rate_snapshots CASCADE"))
        connection.execute(text("DROP TABLE IF EXISTS fortiweb_snapshots CASCADE"))
        connection.execute(text("DROP TABLE IF EXISTS maturity_assessments CASCADE"))
        connection.execute(text("DROP TABLE IF EXISTS parsed_configs CASCADE"))
        connection.execute(text('DROP TABLE IF EXISTS "Server_Policy" CASCADE'))
        connection.execute(text("DROP TABLE IF EXISTS server_policy CASCADE"))
        connection.execute(text("DROP TABLE IF EXISTS server_pool CASCADE"))
        connection.execute(text("DROP SEQUENCE IF EXISTS baseline_controls_id_seq CASCADE"))
        connection.execute(text("DROP SEQUENCE IF EXISTS exchange_rate_snapshots_id_seq CASCADE"))
        connection.execute(text("DROP SEQUENCE IF EXISTS fortiweb_snapshots_id_seq CASCADE"))
        connection.execute(text("DROP SEQUENCE IF EXISTS maturity_assessments_id_seq CASCADE"))
        connection.execute(text("DROP SEQUENCE IF EXISTS parsed_configs_id_seq CASCADE"))
        connection.execute(text('DROP SEQUENCE IF EXISTS "Server_Policy_id_seq" CASCADE'))
        connection.execute(
            text(
                """
                CREATE TABLE IF NOT EXISTS web_protection_profiles (
                    device_id bigint NOT NULL REFERENCES managed_devices(id) ON DELETE CASCADE,
                    web_protection_profile_name text NOT NULL,
                    created_at timestamptz NOT NULL DEFAULT now(),
                    updated_at timestamptz NOT NULL DEFAULT now(),
                    PRIMARY KEY (device_id, web_protection_profile_name)
                )
                """
            )
        )
        connection.execute(
            text(
                """
                CREATE TABLE IF NOT EXISTS certificate_local (
                    device_id bigint NOT NULL REFERENCES managed_devices(id) ON DELETE CASCADE,
                    certificate_name text NOT NULL,
                    PRIMARY KEY (device_id, certificate_name)
                )
                """
            )
        )
        connection.execute(
            text(
                """
                CREATE TABLE IF NOT EXISTS certificate_sni (
                    device_id bigint NOT NULL REFERENCES managed_devices(id) ON DELETE CASCADE,
                    sni_name text NOT NULL,
                    PRIMARY KEY (device_id, sni_name)
                )
                """
            )
        )
        connection.execute(
            text(
                """
                CREATE TABLE IF NOT EXISTS intermediate_certificate_groups (
                    device_id bigint NOT NULL REFERENCES managed_devices(id) ON DELETE CASCADE,
                    intermediate_certificate_group_name text NOT NULL,
                    PRIMARY KEY (device_id, intermediate_certificate_group_name)
                )
                """
            )
        )
        connection.execute(
            text(
                """
                CREATE TABLE IF NOT EXISTS server_pool (
                    id bigserial PRIMARY KEY,
                    device_id bigint NOT NULL,
                    server_pool_name text NOT NULL,
                    ip inet,
                    certificate_name text,
                    sni_certificate_name text,
                    intermediate_certificate_group_name text,
                    ssl_custom_cipher text,
                    tls13_custom_cipher text,
                    tls_v10 boolean,
                    tls_v11 boolean,
                    tls_v12 boolean,
                    tls_v13 boolean,
                    http2 boolean,
                    raw_json jsonb NOT NULL,
                    created_at timestamptz NOT NULL DEFAULT now(),
                    updated_at timestamptz NOT NULL DEFAULT now(),

                    CONSTRAINT fk_server_pool_device
                        FOREIGN KEY (device_id)
                        REFERENCES managed_devices(id)
                        ON DELETE CASCADE,

                    CONSTRAINT uq_server_pool_device_name
                        UNIQUE (device_id, server_pool_name),

                    CONSTRAINT fk_server_pool_certificate
                        FOREIGN KEY (device_id, certificate_name)
                        REFERENCES certificate_local(device_id, certificate_name)
                        ON DELETE SET NULL,

                    CONSTRAINT fk_server_pool_sni_certificate
                        FOREIGN KEY (device_id, sni_certificate_name)
                        REFERENCES certificate_sni(device_id, sni_name)
                        ON DELETE SET NULL,

                    CONSTRAINT fk_server_pool_intermediate_group
                        FOREIGN KEY (device_id, intermediate_certificate_group_name)
                        REFERENCES intermediate_certificate_groups(device_id, intermediate_certificate_group_name)
                        ON DELETE SET NULL
                )
                """
            )
        )
        connection.execute(
            text(
                """
                CREATE TABLE IF NOT EXISTS server_policy (
                    id bigserial PRIMARY KEY,
                    device_id bigint NOT NULL,
                    server_policy_name text NOT NULL,
                    web_protection_profile_name text,
                    server_pool_name text,
                    allow_hosts text,
                    traffic_mirror boolean,
                    raw_json jsonb NOT NULL,
                    created_at timestamptz NOT NULL DEFAULT now(),
                    updated_at timestamptz NOT NULL DEFAULT now(),

                    CONSTRAINT fk_server_policy_device
                        FOREIGN KEY (device_id)
                        REFERENCES managed_devices(id)
                        ON DELETE CASCADE,

                    CONSTRAINT uq_server_policy_device_name
                        UNIQUE (device_id, server_policy_name),

                    CONSTRAINT fk_server_policy_web_protection_profile
                        FOREIGN KEY (device_id, web_protection_profile_name)
                        REFERENCES web_protection_profiles(device_id, web_protection_profile_name)
                        ON DELETE SET NULL,

                    CONSTRAINT fk_server_policy_server_pool
                        FOREIGN KEY (device_id, server_pool_name)
                        REFERENCES server_pool(device_id, server_pool_name)
                        ON DELETE SET NULL
                )
                """
            )
        )
        connection.execute(text("ALTER TABLE server_policy ADD COLUMN IF NOT EXISTS allow_hosts text"))
        connection.execute(
            text(
                """
                CREATE TABLE IF NOT EXISTS allow_hosts (
                    id bigserial PRIMARY KEY,
                    device_id bigint NOT NULL,
                    allow_hosts text NOT NULL,
                    host text,
                    raw_json jsonb NOT NULL,
                    created_at timestamptz NOT NULL DEFAULT now(),
                    updated_at timestamptz NOT NULL DEFAULT now(),

                    CONSTRAINT fk_allow_hosts_device
                        FOREIGN KEY (device_id)
                        REFERENCES managed_devices(id)
                        ON DELETE CASCADE,

                    CONSTRAINT uq_allow_hosts_row
                        UNIQUE (device_id, allow_hosts, host)
                )
                """
            )
        )

    db = SessionLocal()
    try:
        if db.query(ManagedDevice).count() == 0:
            db.add_all(
                [
                    ManagedDevice(name="FortiWeb-Prod-TR-01", ip="10.10.1.15", model="FortiWeb VM", environment="Production", region="Istanbul", firmware="7.4.2", apikey="prod-tr-apikey", status="Online", last_sync="5 min ago"),
                    ManagedDevice(name="FortiWeb-DR-01", ip="10.20.1.22", model="FortiWeb 4000E", environment="Disaster Recovery", region="Ankara", firmware="7.2.6", apikey="dr-apikey", status="Warning", last_sync="42 min ago"),
                    ManagedDevice(name="FortiWeb-Test-01", ip="10.30.8.9", model="FortiWeb VM", environment="Test", region="Izmir", firmware="7.4.1", apikey="test-apikey", status="Offline", last_sync="3 hours ago"),
                ]
            )
            db.commit()
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
    return LoginResponse(access_token="local-admin-token", username=payload.username)


@app.post("/fortiweb/server-policy/collect")
def collect_fortiweb_server_policy(
    db: Session = Depends(get_db),
    _: Annotated[str, Depends(require_analyst_or_admin)] = "analyst",
):
    devices = db.query(ManagedDevice).order_by(ManagedDevice.id.desc()).all()
    fetch_and_store_server_policies_by_device(db, devices)
    return {"payload": load_server_policies_from_db(db)}


@app.get("/fortiweb/server-policy/latest")
def latest_fortiweb_server_policy(
    db: Session = Depends(get_db),
    _: Annotated[str, Depends(require_role)] = "viewer",
):
    return {"payload": load_server_policies_from_db(db)}


@app.get("/devices", response_model=list[ManagedDeviceOut])
def list_devices(
    db: Session = Depends(get_db),
    _: Annotated[str, Depends(require_role)] = "viewer",
):
    return db.query(ManagedDevice).order_by(ManagedDevice.id.desc()).all()


@app.get("/devices/{device_id}", response_model=ManagedDeviceOut)
def get_device(
    device_id: int,
    db: Session = Depends(get_db),
    _: Annotated[str, Depends(require_role)] = "viewer",
):
    device = db.query(ManagedDevice).filter(ManagedDevice.id == device_id).first()
    if not device:
        raise HTTPException(status_code=404, detail="Device not found")
    return device


@app.post("/devices", response_model=ManagedDeviceOut)
def create_device(
    payload: ManagedDeviceCreate,
    db: Session = Depends(get_db),
    _: Annotated[str, Depends(require_analyst_or_admin)] = "analyst",
):
    device = ManagedDevice(**payload.model_dump())
    db.add(device)
    db.commit()
    db.refresh(device)
    return device


@app.delete("/devices/{device_id}")
def delete_device(
    device_id: int,
    db: Session = Depends(get_db),
    _: Annotated[str, Depends(require_analyst_or_admin)] = "analyst",
):
    device = db.query(ManagedDevice).filter(ManagedDevice.id == device_id).first()
    if not device:
        raise HTTPException(status_code=404, detail="Device not found")
    db.delete(device)
    db.commit()
    return {"status": "deleted", "id": device_id}
