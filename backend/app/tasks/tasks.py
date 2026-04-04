from app.db.session import SessionLocal
from app.models.entities import FortiWebSnapshot
from app.services.fortiweb import fetch_fortiweb_configuration
from app.services.parser import extract_critical_configurations
from app.tasks.celery_app import celery_app


@celery_app.task(name='app.tasks.tasks.collect_and_parse_snapshot')
def collect_and_parse_snapshot():
    db = SessionLocal()
    try:
        payload = fetch_fortiweb_configuration('/cmdb')
        snapshot = FortiWebSnapshot(source_endpoint='/cmdb', raw_payload=payload)
        db.add(snapshot)
        db.commit()
        db.refresh(snapshot)

        parsed_items = extract_critical_configurations(snapshot.id, payload)
        db.add_all(parsed_items)
        db.commit()
        return {'snapshot_id': snapshot.id, 'parsed_count': len(parsed_items)}
    finally:
        db.close()
