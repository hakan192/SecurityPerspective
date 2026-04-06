from datetime import datetime

from sqlalchemy import JSON, Boolean, DateTime, Float, ForeignKey, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database import Base


class FortiWebSnapshot(Base):
    __tablename__ = "fortiweb_snapshots"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    endpoint: Mapped[str] = mapped_column(String(255), nullable=False)
    collected_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, nullable=False, index=True)
    payload: Mapped[dict] = mapped_column(JSON, nullable=False)

    parsed_entries = relationship("ParsedConfig", back_populates="snapshot", cascade="all, delete-orphan")


class ParsedConfig(Base):
    __tablename__ = "parsed_configs"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    snapshot_id: Mapped[int] = mapped_column(ForeignKey("fortiweb_snapshots.id"), index=True)
    object_type: Mapped[str] = mapped_column(String(120), index=True)
    object_name: Mapped[str] = mapped_column(String(255))
    control_id: Mapped[str] = mapped_column(String(120), index=True)
    category: Mapped[str] = mapped_column(String(120), index=True)
    field_name: Mapped[str] = mapped_column(String(255))
    field_value: Mapped[str] = mapped_column(Text)
    is_compliant: Mapped[bool] = mapped_column(Boolean, default=False)

    snapshot = relationship("FortiWebSnapshot", back_populates="parsed_entries")


class BaselineControl(Base):
    __tablename__ = "baseline_controls"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    control_id: Mapped[str] = mapped_column(String(120), unique=True, index=True)
    category: Mapped[str] = mapped_column(String(120), index=True)
    description: Mapped[str] = mapped_column(Text)
    expected_field: Mapped[str] = mapped_column(String(255))
    expected_value: Mapped[str] = mapped_column(String(255))
    weight: Mapped[float] = mapped_column(Float, default=1.0)


class MaturityAssessment(Base):
    __tablename__ = "maturity_assessments"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    snapshot_id: Mapped[int] = mapped_column(ForeignKey("fortiweb_snapshots.id"), index=True)
    generated_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, nullable=False)
    overall_score: Mapped[float] = mapped_column(Float, default=0.0)
    maturity_level: Mapped[str] = mapped_column(String(120))
    details: Mapped[dict] = mapped_column(JSON, nullable=False)


class ServerPolicy(Base):
    __tablename__ = "Server_Policy"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    ip: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    hostnames: Mapped[str] = mapped_column(String(255), nullable=False)
