from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.db.session import get_db
from app.models.entities import BaselineControl, FortiWebSnapshot, MaturityAssessment, ParsedConfigItem, User, UserRole
from app.schemas.dto import AssessmentResponse, LoginRequest, ParsedConfigResponse, SnapshotResponse
from app.services.fortiweb import fetch_fortiweb_configuration
from app.services.ldap_auth import authenticate_ldap
from app.services.parser import extract_critical_configurations
from app.services.scoring import evaluate_maturity

router = APIRouter()


@router.post('/auth/login')
def login(payload: LoginRequest, db: Session = Depends(get_db)):
    if not authenticate_ldap(payload.username, payload.password):
        raise HTTPException(status_code=401, detail='Invalid LDAP credentials')

    user = db.query(User).filter(User.username == payload.username).first()
    if not user:
        user = User(username=payload.username, role=UserRole.STAKEHOLDER)
        db.add(user)
        db.commit()
        db.refresh(user)

    return {'username': user.username, 'role': user.role}


@router.post('/fortiweb/snapshots', response_model=SnapshotResponse)
def collect_snapshot(db: Session = Depends(get_db)):
    payload = fetch_fortiweb_configuration('/cmdb')
    snapshot = FortiWebSnapshot(source_endpoint='/cmdb', raw_payload=payload)
    db.add(snapshot)
    db.commit()
    db.refresh(snapshot)

    parsed_items = extract_critical_configurations(snapshot.id, payload)
    db.add_all(parsed_items)
    db.commit()
    return snapshot


@router.get('/fortiweb/snapshots', response_model=list[SnapshotResponse])
def list_snapshots(db: Session = Depends(get_db)):
    return db.query(FortiWebSnapshot).order_by(FortiWebSnapshot.collected_at.desc()).all()


@router.get('/fortiweb/parsed/{snapshot_id}', response_model=list[ParsedConfigResponse])
def get_parsed(snapshot_id: int, db: Session = Depends(get_db)):
    return db.query(ParsedConfigItem).filter(ParsedConfigItem.snapshot_id == snapshot_id).all()


@router.post('/analysis/assess/{snapshot_id}', response_model=AssessmentResponse)
def assess_snapshot(snapshot_id: int, db: Session = Depends(get_db)):
    parsed_items = db.query(ParsedConfigItem).filter(ParsedConfigItem.snapshot_id == snapshot_id).all()
    controls = db.query(BaselineControl).all()

    if not controls:
        raise HTTPException(status_code=400, detail='No baseline controls configured')

    result = evaluate_maturity(controls, parsed_items)
    assessment = MaturityAssessment(snapshot_id=snapshot_id, **result)
    db.add(assessment)
    db.commit()
    db.refresh(assessment)
    return assessment


@router.get('/analysis/assess/{snapshot_id}', response_model=list[AssessmentResponse])
def get_assessments(snapshot_id: int, db: Session = Depends(get_db)):
    return db.query(MaturityAssessment).filter(MaturityAssessment.snapshot_id == snapshot_id).all()
