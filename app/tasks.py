from app.celery_app import celery_app
from app.database import SessionLocal
from app.models import ManagedDevice
from app.services import fetch_and_store_server_policies_by_device


@celery_app.task(name="fortiweb.collect_snapshot")
def collect_snapshot_task() -> int:
    db = SessionLocal()
    try:
        devices = db.query(ManagedDevice).order_by(ManagedDevice.id.desc()).all()
        payload = fetch_and_store_server_policies_by_device(db, devices)
        return len(payload.get("devices", []))
    finally:
        db.close()
