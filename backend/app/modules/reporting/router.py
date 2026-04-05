from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import Response
from sqlalchemy.orm import Session

from app.core_db import get_db
from app.core_deps import current_user, require_roles
from app.models import ReportJob, Role, User
from app.modules.audit.service import record_audit
from app.tasks import generate_report

router = APIRouter(prefix="/api/v1/reporting", tags=["reporting"])


@router.post("/jobs/{connector_id}/{fmt}")
def request_report(
    connector_id: int,
    fmt: str,
    db: Session = Depends(get_db),
    user: User = Depends(require_roles(Role.admin, Role.security_analyst, Role.reviewer)),
):
    if fmt not in {"csv", "pdf"}:
        raise HTTPException(status_code=400, detail="Unsupported format")
    job = ReportJob(connector_id=connector_id, requested_by=user.username, format=fmt, status="queued")
    db.add(job)
    db.commit()
    db.refresh(job)
    generate_report.delay(job.id)
    record_audit(db, user.username, "enqueue", "report_job", {"report_job_id": job.id, "format": fmt})
    return {"report_job_id": job.id, "status": job.status}


@router.get("/jobs/{job_id}")
def report_job_status(job_id: int, db: Session = Depends(get_db), user: User = Depends(current_user)):
    job = db.query(ReportJob).filter(ReportJob.id == job_id).first()
    if not job:
        raise HTTPException(status_code=404, detail="Report job not found")
    if user.role != Role.admin and job.requested_by != user.username:
        raise HTTPException(status_code=403, detail="Forbidden")
    return {"report_job_id": job.id, "status": job.status, "format": job.format, "error_message": job.error_message}


@router.get("/jobs/{job_id}/download")
def download_report(job_id: int, db: Session = Depends(get_db), user: User = Depends(current_user)):
    job = db.query(ReportJob).filter(ReportJob.id == job_id).first()
    if not job:
        raise HTTPException(status_code=404, detail="Report job not found")
    if user.role != Role.admin and job.requested_by != user.username:
        raise HTTPException(status_code=403, detail="Forbidden")
    if job.status != "completed" or not job.artifact:
        raise HTTPException(status_code=409, detail="Report not ready")

    media = "text/csv" if job.format == "csv" else "application/pdf"
    return Response(job.artifact, media_type=media, headers={"Content-Disposition": f"attachment; filename=report-{job.connector_id}.{job.format}"})
