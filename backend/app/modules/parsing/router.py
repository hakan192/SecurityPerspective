from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from app.core_db import get_db
from app.core_deps import require_roles
from app.models import ParsedRecord, Role, User

router = APIRouter(prefix="/api/v1/parsing", tags=["parsing"])


@router.get("/records")
def parsed_records(db: Session = Depends(get_db), _: User = Depends(require_roles(Role.admin, Role.security_analyst, Role.reviewer))):
    return db.query(ParsedRecord).order_by(ParsedRecord.id.desc()).all()
