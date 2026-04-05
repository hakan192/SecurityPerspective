"""guardrail updates

Revision ID: 0002
Revises: 0001
Create Date: 2026-04-05
"""

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "0002"
down_revision = "0001"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("raw_artifacts", sa.Column("payload_meta", postgresql.JSONB(astext_type=sa.Text()), nullable=False, server_default=sa.text("'{}'::jsonb")))
    op.alter_column("raw_artifacts", "payload", type_=postgresql.JSONB(astext_type=sa.Text()), postgresql_using="payload::jsonb")
    op.alter_column("parsed_records", "normalized_data", type_=postgresql.JSONB(astext_type=sa.Text()), postgresql_using="normalized_data::jsonb")
    op.alter_column("baseline_controls", "expected", type_=postgresql.JSONB(astext_type=sa.Text()), postgresql_using="expected::jsonb")
    op.alter_column("assessments", "summary", type_=postgresql.JSONB(astext_type=sa.Text()), postgresql_using="summary::jsonb")
    op.alter_column("assessment_controls", "evidence", type_=postgresql.JSONB(astext_type=sa.Text()), postgresql_using="evidence::jsonb")
    op.alter_column("audit_events", "details", type_=postgresql.JSONB(astext_type=sa.Text()), postgresql_using="details::jsonb")

    op.create_table(
        "maturity_thresholds",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("baseline_version", sa.String(30), nullable=False),
        sa.Column("level", sa.String(50), nullable=False),
        sa.Column("min_ratio", sa.Float(), nullable=False),
        sa.Column("order_index", sa.Integer(), nullable=False),
        sa.UniqueConstraint("baseline_version", "level", name="uq_threshold_level"),
    )

    op.create_table(
        "report_jobs",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("connector_id", sa.Integer(), sa.ForeignKey("fortiweb_connectors.id"), nullable=False),
        sa.Column("requested_by", sa.String(120), nullable=False),
        sa.Column("format", sa.String(20), nullable=False),
        sa.Column("status", sa.String(20), nullable=False),
        sa.Column("artifact", sa.LargeBinary(), nullable=True),
        sa.Column("error_message", sa.Text(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
    )


def downgrade() -> None:
    op.drop_table("report_jobs")
    op.drop_table("maturity_thresholds")
    op.drop_column("raw_artifacts", "payload_meta")
