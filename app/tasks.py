from app.celery_app import celery_app
from app.config import settings
from app.database import SessionLocal
from app.services import assess_snapshot, create_snapshot, fetch_fortiweb_config, parse_snapshot


@celery_app.task(name="fortiweb.collect_snapshot")
def collect_snapshot_task() -> int:
    db = SessionLocal()
    try:
        payload = fetch_fortiweb_config()
        snapshot = create_snapshot(db, settings.fortiweb_config_endpoint, payload)
        parse_snapshot(db, snapshot)
        assess_snapshot(db, snapshot.id)
        return snapshot.id
    finally:
        db.close()
