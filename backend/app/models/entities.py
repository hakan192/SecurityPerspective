from datetime import datetime

from sqlalchemy import JSON, Boolean, DateTime, Float, ForeignKey, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.session import Base


class FortiWebSnapshot(Base):
    __tablename__ = 'fortiweb_snapshots'

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    collected_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, index=True)
    source_endpoint: Mapped[str] = mapped_column(String(255))
    raw_payload: Mapped[dict] = mapped_column(JSON)

    parsed_items = relationship('ParsedConfigItem', back_populates='snapshot', cascade='all, delete-orphan')


class ParsedConfigItem(Base):
    __tablename__ = 'parsed_config_items'

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    snapshot_id: Mapped[int] = mapped_column(ForeignKey('fortiweb_snapshots.id'), index=True)
    object_type: Mapped[str] = mapped_column(String(120), index=True)
    object_name: Mapped[str] = mapped_column(String(255), index=True)
    attributes: Mapped[dict] = mapped_column(JSON)

    snapshot = relationship('FortiWebSnapshot', back_populates='parsed_items')


class BaselineControl(Base):
    __tablename__ = 'baseline_controls'

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    control_key: Mapped[str] = mapped_column(String(120), unique=True, index=True)
    category: Mapped[str] = mapped_column(String(120), index=True)
    description: Mapped[str] = mapped_column(Text)
    required: Mapped[bool] = mapped_column(Boolean, default=True)
    weight: Mapped[float] = mapped_column(Float, default=1.0)


class MaturityAssessment(Base):
    __tablename__ = 'maturity_assessments'

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    snapshot_id: Mapped[int] = mapped_column(ForeignKey('fortiweb_snapshots.id'), index=True)
    calculated_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, index=True)
    overall_score: Mapped[float] = mapped_column(Float)
    maturity_level: Mapped[str] = mapped_column(String(64))
    per_control_scores: Mapped[dict] = mapped_column(JSON)
    category_scores: Mapped[dict] = mapped_column(JSON)


class UserRole:
    ADMIN = 'admin'
    ANALYST = 'analyst'
    STAKEHOLDER = 'stakeholder'


class User(Base):
    __tablename__ = 'users'

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    username: Mapped[str] = mapped_column(String(120), unique=True, index=True)
    role: Mapped[str] = mapped_column(String(32), default=UserRole.STAKEHOLDER)
