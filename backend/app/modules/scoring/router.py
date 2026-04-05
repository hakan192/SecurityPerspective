from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.core_db import get_db
from app.core_deps import current_user
from app.models import Assessment, AssessmentControl, Role, Snapshot, User

router = APIRouter(prefix="/api/v1/scoring", tags=["scoring"])


@router.get("/latest/{connector_id}")
def latest(connector_id: int, db: Session = Depends(get_db), user: User = Depends(current_user)):
    snap = db.query(Snapshot).filter(Snapshot.connector_id == connector_id, Snapshot.status == "completed").order_by(Snapshot.id.desc()).first()
    if not snap:
        raise HTTPException(status_code=404, detail="No completed snapshot")
    assessment = db.query(Assessment).filter(Assessment.snapshot_id == snap.id).order_by(Assessment.id.desc()).first()
    if not assessment:
        raise HTTPException(status_code=404, detail="No assessment")
    if user.role == Role.stakeholder:
        return {"overall_score": assessment.overall_score, "maturity_level": assessment.maturity_level, "summary": assessment.summary}
    controls = db.query(AssessmentControl).filter(AssessmentControl.assessment_id == assessment.id).all()
    return {
        "overall_score": assessment.overall_score,
        "maturity_level": assessment.maturity_level,
        "summary": assessment.summary,
        "controls": controls,
    }
