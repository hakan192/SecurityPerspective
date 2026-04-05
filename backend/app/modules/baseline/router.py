from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from app.core_config import settings
from app.core_db import get_db
from app.core_deps import current_user
from app.models import BaselineControl, User

router = APIRouter(prefix="/api/v1/baseline", tags=["baseline"])


@router.get("/controls")
def controls(db: Session = Depends(get_db), _: User = Depends(current_user)):
    return db.query(BaselineControl).filter(BaselineControl.baseline_version == settings.baseline_version).all()
