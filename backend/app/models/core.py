import enum
from sqlalchemy import Boolean, DateTime, Enum, Float, ForeignKey, Integer, String, Text, UniqueConstraint, func
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from app.core_db import Base


class Role(str, enum.Enum):
    admin = "admin"
    security_analyst = "security_analyst"
    reviewer = "reviewer"
    stakeholder = "stakeholder"


class User(Base):
    __tablename__ = "users"
    id: Mapped[int] = mapped_column(primary_key=True)
    username: Mapped[str] = mapped_column(String(120), unique=True, nullable=False)
    password_hash: Mapped[str] = mapped_column(String(255), nullable=False)
    role: Mapped[Role] = mapped_column(Enum(Role), nullable=False)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    created_at: Mapped[DateTime] = mapped_column(DateTime(timezone=True), server_default=func.now())


class Connector(Base):
    __tablename__ = "fortiweb_connectors"
    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(150), unique=True, nullable=False)
    base_url: Mapped[str] = mapped_column(String(255), nullable=False)
    api_token: Mapped[str] = mapped_column(String(255), nullable=False)
    verify_tls: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    schedule_cron: Mapped[str | None] = mapped_column(String(80), nullable=True)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)


class Snapshot(Base):
    __tablename__ = "snapshots"
    __table_args__ = (UniqueConstraint("connector_id", "dedupe_key", name="uq_snapshot_dedupe"),)
    id: Mapped[int] = mapped_column(primary_key=True)
    connector_id: Mapped[int] = mapped_column(ForeignKey("fortiweb_connectors.id"), nullable=False)
    dedupe_key: Mapped[str] = mapped_column(String(120), nullable=False)
    collected_at: Mapped[DateTime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    status: Mapped[str] = mapped_column(String(30), nullable=False)
    collector_version: Mapped[str] = mapped_column(String(30), nullable=False)
    error_message: Mapped[str | None] = mapped_column(Text, nullable=True)


class RawArtifact(Base):
    __tablename__ = "raw_artifacts"
    id: Mapped[int] = mapped_column(primary_key=True)
    snapshot_id: Mapped[int] = mapped_column(ForeignKey("snapshots.id"), nullable=False)
    endpoint: Mapped[str] = mapped_column(String(255), nullable=False)
    payload: Mapped[dict] = mapped_column(JSONB, nullable=False)
    payload_meta: Mapped[dict] = mapped_column(JSONB, nullable=False, default=dict)
    collected_at: Mapped[DateTime] = mapped_column(DateTime(timezone=True), server_default=func.now())


class ParsedRecord(Base):
    __tablename__ = "parsed_records"
    id: Mapped[int] = mapped_column(primary_key=True)
    snapshot_id: Mapped[int] = mapped_column(ForeignKey("snapshots.id"), nullable=False)
    raw_artifact_id: Mapped[int] = mapped_column(ForeignKey("raw_artifacts.id"), nullable=False)
    control_code: Mapped[str] = mapped_column(String(50), nullable=False)
    normalized_data: Mapped[dict] = mapped_column(JSONB, nullable=False)
    parser_version: Mapped[str] = mapped_column(String(30), nullable=False)


class BaselineControl(Base):
    __tablename__ = "baseline_controls"
    __table_args__ = (UniqueConstraint("control_code", "baseline_version", name="uq_control_baseline"),)
    id: Mapped[int] = mapped_column(primary_key=True)
    control_code: Mapped[str] = mapped_column(String(50), nullable=False)
    category: Mapped[str] = mapped_column(String(120), nullable=False)
    title: Mapped[str] = mapped_column(String(255), nullable=False)
    recommendation: Mapped[str] = mapped_column(Text, nullable=False)
    weight: Mapped[float] = mapped_column(Float, nullable=False)
    max_score: Mapped[float] = mapped_column(Float, nullable=False)
    expected: Mapped[dict] = mapped_column(JSONB, nullable=False)
    baseline_version: Mapped[str] = mapped_column(String(30), nullable=False)


class MaturityThreshold(Base):
    __tablename__ = "maturity_thresholds"
    __table_args__ = (UniqueConstraint("baseline_version", "level", name="uq_threshold_level"),)
    id: Mapped[int] = mapped_column(primary_key=True)
    baseline_version: Mapped[str] = mapped_column(String(30), nullable=False)
    level: Mapped[str] = mapped_column(String(50), nullable=False)
    min_ratio: Mapped[float] = mapped_column(Float, nullable=False)
    order_index: Mapped[int] = mapped_column(Integer, nullable=False)


class Assessment(Base):
    __tablename__ = "assessments"
    id: Mapped[int] = mapped_column(primary_key=True)
    snapshot_id: Mapped[int] = mapped_column(ForeignKey("snapshots.id"), nullable=False)
    overall_score: Mapped[float] = mapped_column(Float, nullable=False)
    maturity_level: Mapped[str] = mapped_column(String(50), nullable=False)
    baseline_version: Mapped[str] = mapped_column(String(30), nullable=False)
    scoring_version: Mapped[str] = mapped_column(String(30), nullable=False)
    summary: Mapped[dict] = mapped_column(JSONB, nullable=False)


class AssessmentControl(Base):
    __tablename__ = "assessment_controls"
    id: Mapped[int] = mapped_column(primary_key=True)
    assessment_id: Mapped[int] = mapped_column(ForeignKey("assessments.id"), nullable=False)
    parsed_record_id: Mapped[int] = mapped_column(ForeignKey("parsed_records.id"), nullable=False)
    control_code: Mapped[str] = mapped_column(String(50), nullable=False)
    category: Mapped[str] = mapped_column(String(120), nullable=False)
    score: Mapped[float] = mapped_column(Float, nullable=False)
    max_score: Mapped[float] = mapped_column(Float, nullable=False)
    maturity_level: Mapped[str] = mapped_column(String(50), nullable=False)
    recommendation: Mapped[str] = mapped_column(Text, nullable=False)
    evidence: Mapped[dict] = mapped_column(JSONB, nullable=False)


class ReportJob(Base):
    __tablename__ = "report_jobs"
    id: Mapped[int] = mapped_column(primary_key=True)
    connector_id: Mapped[int] = mapped_column(ForeignKey("fortiweb_connectors.id"), nullable=False)
    requested_by: Mapped[str] = mapped_column(String(120), nullable=False)
    format: Mapped[str] = mapped_column(String(20), nullable=False)
    status: Mapped[str] = mapped_column(String(20), nullable=False)
    artifact: Mapped[bytes | None] = mapped_column(nullable=True)
    error_message: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[DateTime] = mapped_column(DateTime(timezone=True), server_default=func.now())


class AuditEvent(Base):
    __tablename__ = "audit_events"
    id: Mapped[int] = mapped_column(primary_key=True)
    actor: Mapped[str] = mapped_column(String(120), nullable=False)
    action: Mapped[str] = mapped_column(String(120), nullable=False)
    resource: Mapped[str] = mapped_column(String(120), nullable=False)
    details: Mapped[dict] = mapped_column(JSONB, nullable=False)
    created_at: Mapped[DateTime] = mapped_column(DateTime(timezone=True), server_default=func.now())
