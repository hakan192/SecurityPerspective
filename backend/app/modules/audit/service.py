from sqlalchemy.orm import Session

from app.models import AuditEvent


def record_audit(db: Session, actor: str, action: str, resource: str, details: dict):
    db.add(AuditEvent(actor=actor, action=action, resource=resource, details=details))
    db.commit()
