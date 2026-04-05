from app.core_config import settings
from app.core_db import SessionLocal
from app.core_security import hash_password
from app.models import BaselineControl, MaturityThreshold, Role, User


def seed():
    db = SessionLocal()
    try:
        users = [
            ("admin", "admin123", Role.admin),
            ("analyst", "analyst123", Role.security_analyst),
            ("reviewer", "reviewer123", Role.reviewer),
            ("stakeholder", "stakeholder123", Role.stakeholder),
        ]
        for u, p, r in users:
            if not db.query(User).filter(User.username == u).first():
                db.add(User(username=u, password_hash=hash_password(p), role=r))

        controls = [
            {"control_code": "FW-POL-001", "category": "policy_hardening", "title": "HTTPS enforcement", "recommendation": "Enable HTTPS service", "weight": 1.0, "max_score": 5.0, "expected": {"checks": [{"key": "https_enforced", "op": "eq", "value": True}, {"key": "policy_count", "op": "gte", "value": 1}]}} ,
            {"control_code": "FW-PROF-001", "category": "threat_protection", "title": "Signatures", "recommendation": "Enable signature-detection", "weight": 1.0, "max_score": 5.0, "expected": {"checks": [{"key": "signatures_enabled", "op": "eq", "value": True}]}} ,
            {"control_code": "FW-SYS-001", "category": "platform_security", "title": "Admin HTTPS", "recommendation": "Enable admin HTTPS", "weight": 1.0, "max_score": 5.0, "expected": {"checks": [{"key": "admin_https", "op": "eq", "value": True}]}} ,
        ]
        for c in controls:
            if not db.query(BaselineControl).filter(BaselineControl.control_code == c["control_code"], BaselineControl.baseline_version == settings.baseline_version).first():
                db.add(BaselineControl(**c, baseline_version=settings.baseline_version))

        thresholds = [
            ("optimized", 0.90, 5),
            ("managed", 0.75, 4),
            ("defined", 0.50, 3),
            ("initial", 0.01, 2),
            ("ad-hoc", 0.0, 1),
        ]
        for level, min_ratio, order in thresholds:
            if not db.query(MaturityThreshold).filter(MaturityThreshold.baseline_version == settings.baseline_version, MaturityThreshold.level == level).first():
                db.add(MaturityThreshold(baseline_version=settings.baseline_version, level=level, min_ratio=min_ratio, order_index=order))

        db.commit()
    finally:
        db.close()


if __name__ == "__main__":
    seed()
