from collections import defaultdict
from datetime import datetime

import requests
from sqlalchemy.orm import Session

from app.config import settings
from app.models import BaselineControl, FortiWebSnapshot, MaturityAssessment, ParsedConfig


def fetch_fortiweb_config() -> dict:
    url = f"{settings.fortiweb_base_url.rstrip('/')}{settings.fortiweb_config_endpoint}"
    response = requests.get(
        url,
        headers={"Authorization": f"Bearer {settings.fortiweb_token}"},
        timeout=30,
        verify=settings.fortiweb_verify_ssl,
    )
    response.raise_for_status()
    return response.json()


def create_snapshot(db: Session, endpoint: str, payload: dict) -> FortiWebSnapshot:
    snapshot = FortiWebSnapshot(endpoint=endpoint, payload=payload, collected_at=datetime.utcnow())
    db.add(snapshot)
    db.commit()
    db.refresh(snapshot)
    return snapshot


def _iter_relevant_objects(payload: dict):
    if isinstance(payload, dict):
        if "results" in payload and isinstance(payload["results"], list):
            for item in payload["results"]:
                if isinstance(item, dict):
                    yield item
        else:
            yield payload


def parse_snapshot(db: Session, snapshot: FortiWebSnapshot) -> list[ParsedConfig]:
    controls = db.query(BaselineControl).all()
    entries = []
    for obj in _iter_relevant_objects(snapshot.payload):
        obj_type = obj.get("type", "unknown")
        obj_name = obj.get("name", obj.get("id", "unnamed"))
        for control in controls:
            value = str(obj.get(control.expected_field, ""))
            compliant = value.lower() == str(control.expected_value).lower()
            entry = ParsedConfig(
                snapshot_id=snapshot.id,
                object_type=obj_type,
                object_name=str(obj_name),
                control_id=control.control_id,
                category=control.category,
                field_name=control.expected_field,
                field_value=value,
                is_compliant=compliant,
            )
            entries.append(entry)
            db.add(entry)

    db.commit()
    for entry in entries:
        db.refresh(entry)
    return entries


def maturity_level_from_score(score: float) -> str:
    if score >= 90:
        return "Optimized"
    if score >= 75:
        return "Managed"
    if score >= 50:
        return "Defined"
    if score >= 25:
        return "Initial"
    return "Ad Hoc"


def assess_snapshot(db: Session, snapshot_id: int) -> MaturityAssessment:
    controls = {c.control_id: c for c in db.query(BaselineControl).all()}
    parsed = db.query(ParsedConfig).filter(ParsedConfig.snapshot_id == snapshot_id).all()

    if not parsed or not controls:
        details = {"per_control": {}, "per_category": {}, "recommendations": ["No data or baseline controls available"]}
        assessment = MaturityAssessment(
            snapshot_id=snapshot_id,
            overall_score=0,
            maturity_level="Ad Hoc",
            details=details,
        )
        db.add(assessment)
        db.commit()
        db.refresh(assessment)
        return assessment

    per_control = {}
    category_scores = defaultdict(lambda: {"weighted": 0.0, "total": 0.0})

    latest_by_control = {}
    for row in parsed:
        latest_by_control[row.control_id] = row

    for control_id, control in controls.items():
        parsed_value = latest_by_control.get(control_id)
        score = 100.0 if parsed_value and parsed_value.is_compliant else 0.0
        weighted = score * control.weight
        per_control[control_id] = {
            "category": control.category,
            "score": score,
            "weight": control.weight,
            "description": control.description,
            "compliant": bool(parsed_value and parsed_value.is_compliant),
        }
        category_scores[control.category]["weighted"] += weighted
        category_scores[control.category]["total"] += 100.0 * control.weight

    per_category = {}
    total_weighted = 0.0
    total_possible = 0.0
    recommendations = []
    for category, values in category_scores.items():
        cat_score = (values["weighted"] / values["total"] * 100.0) if values["total"] else 0.0
        per_category[category] = round(cat_score, 2)
        total_weighted += values["weighted"]
        total_possible += values["total"]

    for cid, detail in per_control.items():
        if not detail["compliant"]:
            recommendations.append(f"Improve control {cid}: {detail['description']}")

    overall_score = (total_weighted / total_possible * 100.0) if total_possible else 0.0
    details = {
        "per_control": per_control,
        "per_category": per_category,
        "recommendations": recommendations,
    }

    assessment = MaturityAssessment(
        snapshot_id=snapshot_id,
        overall_score=round(overall_score, 2),
        maturity_level=maturity_level_from_score(overall_score),
        details=details,
    )
    db.add(assessment)
    db.commit()
    db.refresh(assessment)
    return assessment


def seed_baseline_controls(db: Session):
    existing = db.query(BaselineControl).count()
    if existing:
        return

    defaults = [
        BaselineControl(
            control_id="AUTH-001",
            category="Authentication",
            description="Administrative interfaces should enforce strong authentication",
            expected_field="auth_mode",
            expected_value="2fa",
            weight=1.5,
        ),
        BaselineControl(
            control_id="TLS-001",
            category="Transport Security",
            description="TLS should be enabled for protected virtual servers",
            expected_field="tls_enabled",
            expected_value="true",
            weight=1.0,
        ),
        BaselineControl(
            control_id="LOG-001",
            category="Monitoring",
            description="Security logging must be enabled",
            expected_field="logging",
            expected_value="enabled",
            weight=1.0,
        ),
    ]
    db.add_all(defaults)
    db.commit()
