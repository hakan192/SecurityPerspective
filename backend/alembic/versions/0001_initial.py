"""initial

Revision ID: 0001
Revises:
Create Date: 2026-04-05
"""

import sqlalchemy as sa
from alembic import op

revision = "0001"
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    role_enum = sa.Enum("admin", "security_analyst", "reviewer", "stakeholder", name="role_enum")
    role_enum.create(op.get_bind(), checkfirst=True)

    op.create_table("users", sa.Column("id", sa.Integer, primary_key=True), sa.Column("username", sa.String(120), nullable=False, unique=True), sa.Column("password_hash", sa.String(255), nullable=False), sa.Column("role", role_enum, nullable=False), sa.Column("is_active", sa.Boolean, nullable=False, server_default=sa.true()), sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()))
    op.create_table("fortiweb_connectors", sa.Column("id", sa.Integer, primary_key=True), sa.Column("name", sa.String(150), nullable=False, unique=True), sa.Column("base_url", sa.String(255), nullable=False), sa.Column("api_token", sa.String(255), nullable=False), sa.Column("verify_tls", sa.Boolean, nullable=False, server_default=sa.true()), sa.Column("schedule_cron", sa.String(80), nullable=True), sa.Column("is_active", sa.Boolean, nullable=False, server_default=sa.true()))
    op.create_table("snapshots", sa.Column("id", sa.Integer, primary_key=True), sa.Column("connector_id", sa.Integer, sa.ForeignKey("fortiweb_connectors.id"), nullable=False), sa.Column("dedupe_key", sa.String(120), nullable=False), sa.Column("collected_at", sa.DateTime(timezone=True), server_default=sa.func.now()), sa.Column("status", sa.String(30), nullable=False), sa.Column("collector_version", sa.String(30), nullable=False), sa.Column("error_message", sa.Text, nullable=True), sa.UniqueConstraint("connector_id", "dedupe_key", name="uq_snapshot_dedupe"))
    op.create_table("raw_artifacts", sa.Column("id", sa.Integer, primary_key=True), sa.Column("snapshot_id", sa.Integer, sa.ForeignKey("snapshots.id"), nullable=False), sa.Column("endpoint", sa.String(255), nullable=False), sa.Column("payload", sa.JSON, nullable=False), sa.Column("collected_at", sa.DateTime(timezone=True), server_default=sa.func.now()))
    op.create_table("parsed_records", sa.Column("id", sa.Integer, primary_key=True), sa.Column("snapshot_id", sa.Integer, sa.ForeignKey("snapshots.id"), nullable=False), sa.Column("raw_artifact_id", sa.Integer, sa.ForeignKey("raw_artifacts.id"), nullable=False), sa.Column("control_code", sa.String(50), nullable=False), sa.Column("normalized_data", sa.JSON, nullable=False), sa.Column("parser_version", sa.String(30), nullable=False))
    op.create_table("baseline_controls", sa.Column("id", sa.Integer, primary_key=True), sa.Column("control_code", sa.String(50), nullable=False), sa.Column("category", sa.String(120), nullable=False), sa.Column("title", sa.String(255), nullable=False), sa.Column("recommendation", sa.Text, nullable=False), sa.Column("weight", sa.Float, nullable=False), sa.Column("max_score", sa.Float, nullable=False), sa.Column("expected", sa.JSON, nullable=False), sa.Column("baseline_version", sa.String(30), nullable=False), sa.UniqueConstraint("control_code", "baseline_version", name="uq_control_baseline"))
    op.create_table("assessments", sa.Column("id", sa.Integer, primary_key=True), sa.Column("snapshot_id", sa.Integer, sa.ForeignKey("snapshots.id"), nullable=False), sa.Column("overall_score", sa.Float, nullable=False), sa.Column("maturity_level", sa.String(50), nullable=False), sa.Column("baseline_version", sa.String(30), nullable=False), sa.Column("scoring_version", sa.String(30), nullable=False), sa.Column("summary", sa.JSON, nullable=False))
    op.create_table("assessment_controls", sa.Column("id", sa.Integer, primary_key=True), sa.Column("assessment_id", sa.Integer, sa.ForeignKey("assessments.id"), nullable=False), sa.Column("parsed_record_id", sa.Integer, sa.ForeignKey("parsed_records.id"), nullable=False), sa.Column("control_code", sa.String(50), nullable=False), sa.Column("category", sa.String(120), nullable=False), sa.Column("score", sa.Float, nullable=False), sa.Column("max_score", sa.Float, nullable=False), sa.Column("maturity_level", sa.String(50), nullable=False), sa.Column("recommendation", sa.Text, nullable=False), sa.Column("evidence", sa.JSON, nullable=False))
    op.create_table("audit_events", sa.Column("id", sa.Integer, primary_key=True), sa.Column("actor", sa.String(120), nullable=False), sa.Column("action", sa.String(120), nullable=False), sa.Column("resource", sa.String(120), nullable=False), sa.Column("details", sa.JSON, nullable=False), sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()))


def downgrade() -> None:
    op.drop_table("audit_events")
    op.drop_table("assessment_controls")
    op.drop_table("assessments")
    op.drop_table("baseline_controls")
    op.drop_table("parsed_records")
    op.drop_table("raw_artifacts")
    op.drop_table("snapshots")
    op.drop_table("fortiweb_connectors")
    op.drop_table("users")
