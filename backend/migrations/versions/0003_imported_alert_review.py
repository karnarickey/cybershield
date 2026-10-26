"""Add a separate imported alert review queue.

Revision ID: 0003_imported_alerts
Revises: 0002_incident_details
"""
from alembic import op
import sqlalchemy as sa


revision = "0003_imported_alerts"
down_revision = "0002_incident_details"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "imported_alerts",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("dedupe_key", sa.String(length=64), nullable=False),
        sa.Column("source_system", sa.String(length=120), nullable=True),
        sa.Column("source_id", sa.String(length=255), nullable=True),
        sa.Column("source_timestamp", sa.DateTime(timezone=True), nullable=True),
        sa.Column("title", sa.String(length=200), nullable=False),
        sa.Column("severity", sa.String(length=20), nullable=False),
        sa.Column("payload_json", sa.Text(), nullable=False),
        sa.Column("review_status", sa.String(length=20), nullable=False, server_default="pending"),
        sa.Column("imported_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("imported_by_id", sa.Integer(), sa.ForeignKey("users.id", ondelete="SET NULL"), nullable=True),
        sa.Column("promoted_incident_id", sa.Integer(), sa.ForeignKey("incidents.id", ondelete="SET NULL"), nullable=True),
        sa.Column("promoted_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("promoted_by_id", sa.Integer(), sa.ForeignKey("users.id", ondelete="SET NULL"), nullable=True),
        sa.UniqueConstraint("promoted_incident_id", name="uq_imported_alert_promoted_incident_id"),
    )
    op.create_index("ix_imported_alerts_dedupe_key", "imported_alerts", ["dedupe_key"], unique=True)
    op.create_index("ix_imported_alerts_source_system", "imported_alerts", ["source_system"])
    op.create_index("ix_imported_alerts_source_timestamp", "imported_alerts", ["source_timestamp"])
    op.create_index("ix_imported_alerts_title", "imported_alerts", ["title"])
    op.create_index("ix_imported_alerts_review_status", "imported_alerts", ["review_status"])
    op.create_index("ix_imported_alerts_imported_at", "imported_alerts", ["imported_at"])


def downgrade() -> None:
    op.drop_index("ix_imported_alerts_imported_at", table_name="imported_alerts")
    op.drop_index("ix_imported_alerts_review_status", table_name="imported_alerts")
    op.drop_index("ix_imported_alerts_title", table_name="imported_alerts")
    op.drop_index("ix_imported_alerts_source_timestamp", table_name="imported_alerts")
    op.drop_index("ix_imported_alerts_source_system", table_name="imported_alerts")
    op.drop_index("ix_imported_alerts_dedupe_key", table_name="imported_alerts")
    op.drop_table("imported_alerts")
