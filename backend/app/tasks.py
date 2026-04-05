import asyncio
from datetime import datetime, timezone

from celery import Celery

from app.core_config import settings
from app.core_db import SessionLocal
from app.models import (
    Assessment,
    AssessmentControl,
    BaselineControl,
    Connector,
    MaturityThreshold,
    RawArtifact,
    ReportJob,
    Snapshot,
)
from app.modules.fortiweb_integration.service import FortiWebClient
from app.modules.parsing.service import parse_raw_artifact
from app.modules.reporting.service import build_csv_bytes, build_pdf_bytes
from app.modules.scoring.service import score

celery_app = Celery("fortiweb", broker=settings.redis_url, backend=settings.redis_url)


def _report_data(connector_id: int, db):
    snap = db.query(Snapshot).filter(Snapshot.connector_id == connector_id, Snapshot.status == "completed").order_by(Snapshot.id.desc()).first()
    if not snap:
        raise RuntimeError("No completed snapshot")
    assessment = db.query(Assessment).filter(Assessment.snapshot_id == snap.id).order_by(Assessment.id.desc()).first()
    controls = db.query(AssessmentControl).filter(AssessmentControl.assessment_id == assessment.id).all()
    return {
        "snapshot": {"id": snap.id, "connector_id": snap.connector_id, "status": snap.status},
        "assessment": {"overall_score": assessment.overall_score, "maturity_level": assessment.maturity_level},
        "controls": [
            {"control_code": c.control_code, "category": c.category, "score": c.score, "max_score": c.max_score, "maturity_level": c.maturity_level, "recommendation": c.recommendation}
            for c in controls
        ],
    }


@celery_app.task(name="app.tasks.ingest_connector")
def ingest_connector(connector_id: int):
    db = SessionLocal()
    dedupe = datetime.now(timezone.utc).strftime("%Y%m%d%H")
    try:
        connector = db.query(Connector).filter(Connector.id == connector_id, Connector.is_active.is_(True)).first()
        if not connector:
            return {"status": "missing_connector"}

        existing = db.query(Snapshot).filter(Snapshot.connector_id == connector_id, Snapshot.dedupe_key == dedupe).first()
        if existing:
            return {"status": "skipped_duplicate", "snapshot_id": existing.id}

        snapshot = Snapshot(connector_id=connector_id, dedupe_key=dedupe, status="running", collector_version=settings.collector_version)
        db.add(snapshot)
        db.commit()
        db.refresh(snapshot)

        payloads = asyncio.run(FortiWebClient(connector.base_url, connector.api_token, connector.verify_tls).collect())

        artifacts = []
        for endpoint, payload in payloads.items():
            artifact = RawArtifact(snapshot_id=snapshot.id, endpoint=endpoint, payload=payload, payload_meta={"collector_version": settings.collector_version})
            db.add(artifact)
            artifacts.append(artifact)
        db.commit()
        for a in artifacts:
            db.refresh(a)

        parsed = []
        for artifact in artifacts:
            parsed.extend(parse_raw_artifact(artifact))
        db.add_all(parsed)
        db.commit()
        for p in parsed:
            db.refresh(p)

        baseline = db.query(BaselineControl).filter(BaselineControl.baseline_version == settings.baseline_version).all()
        thresholds = db.query(MaturityThreshold).filter(MaturityThreshold.baseline_version == settings.baseline_version).all()
        assessment, controls = score(snapshot.id, baseline, parsed, thresholds, settings.baseline_version, settings.scoring_version)
        db.add(assessment)
        db.commit()
        db.refresh(assessment)

        linked = [
            AssessmentControl(
                assessment_id=assessment.id,
                parsed_record_id=c.parsed_record_id,
                control_code=c.control_code,
                category=c.category,
                score=c.score,
                max_score=c.max_score,
                maturity_level=c.maturity_level,
                recommendation=c.recommendation,
                evidence=c.evidence,
            )
            for c in controls
        ]
        db.add_all(linked)
        snapshot.status = "completed"
        db.commit()
        return {"status": "completed", "snapshot_id": snapshot.id, "assessment_id": assessment.id}
    except Exception as exc:
        db.rollback()
        snap = db.query(Snapshot).filter(Snapshot.connector_id == connector_id).order_by(Snapshot.id.desc()).first()
        if snap and snap.status == "running":
            snap.status = "failed"
            snap.error_message = str(exc)
            db.commit()
        return {"status": "failed", "error": str(exc)}
    finally:
        db.close()


@celery_app.task(name="app.tasks.generate_report")
def generate_report(report_job_id: int):
    db = SessionLocal()
    try:
        job = db.query(ReportJob).filter(ReportJob.id == report_job_id).first()
        if not job:
            return {"status": "missing_job"}
        job.status = "running"
        db.commit()

        data = _report_data(job.connector_id, db)
        artifact = build_csv_bytes(data) if job.format == "csv" else build_pdf_bytes(data)
        job.artifact = artifact
        job.status = "completed"
        db.commit()
        return {"status": "completed", "report_job_id": job.id}
    except Exception as exc:
        db.rollback()
        job = db.query(ReportJob).filter(ReportJob.id == report_job_id).first()
        if job:
            job.status = "failed"
            job.error_message = str(exc)
            db.commit()
        return {"status": "failed", "error": str(exc)}
    finally:
        db.close()


@celery_app.on_after_configure.connect
def setup_periodic_tasks(sender, **kwargs):
    sender.add_periodic_task(300.0, schedule_active_connectors.s(), name="enqueue_active_connectors")


@celery_app.task(name="app.tasks.schedule_active_connectors")
def schedule_active_connectors():
    db = SessionLocal()
    try:
        connectors = db.query(Connector).filter(Connector.is_active.is_(True)).all()
        for c in connectors:
            ingest_connector.delay(c.id)
    finally:
        db.close()
