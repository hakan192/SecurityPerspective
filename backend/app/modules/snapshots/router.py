from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.core_db import get_db
from app.core_deps import current_user, require_roles
from app.models import Connector, RawArtifact, Role, Snapshot, User
from app.modules.audit.service import record_audit
from app.tasks import ingest_connector

router = APIRouter(prefix="/api/v1/snapshots", tags=["snapshots"])


@router.post("/connectors")
def create_connector(payload: dict, db: Session = Depends(get_db), user: User = Depends(require_roles(Role.admin, Role.security_analyst))):
    connector = Connector(**payload)
    db.add(connector)
    db.commit()
    db.refresh(connector)
    record_audit(db, user.username, "create", "connector", {"connector_id": connector.id})
    return connector


@router.get("/connectors")
def list_connectors(db: Session = Depends(get_db), _: User = Depends(current_user)):
    return db.query(Connector).order_by(Connector.id.desc()).all()


@router.post("/ingest/{connector_id}")
def ingest(connector_id: int, db: Session = Depends(get_db), user: User = Depends(require_roles(Role.admin, Role.security_analyst))):
    connector = db.query(Connector).filter(Connector.id == connector_id).first()
    if not connector:
        raise HTTPException(status_code=404, detail="Connector not found")
    task = ingest_connector.delay(connector_id)
    record_audit(db, user.username, "enqueue", "ingestion", {"connector_id": connector_id, "task_id": task.id})
    return {"status": "queued", "task_id": task.id}


@router.get("")
def list_snapshots(db: Session = Depends(get_db), _: User = Depends(current_user)):
    return db.query(Snapshot).order_by(Snapshot.id.desc()).all()


@router.get("/{snapshot_id}/raw")
def raw(snapshot_id: int, db: Session = Depends(get_db), _: User = Depends(require_roles(Role.admin, Role.security_analyst))):
    return db.query(RawArtifact).filter(RawArtifact.snapshot_id == snapshot_id).all()
