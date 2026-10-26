"""Expand incident workflow and incident detail fields.

Revision ID: 0002_incident_details
Revises: 0001_initial
"""
from alembic import op
import sqlalchemy as sa


revision = "0002_incident_details"
down_revision = "0001_initial"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("incidents", sa.Column("priority", sa.String(length=20), server_default="medium", nullable=False))
    op.add_column("incidents", sa.Column("reporter", sa.String(length=120), nullable=True))
    op.add_column("incidents", sa.Column("affected_asset", sa.String(length=200), nullable=True))
    op.add_column("incidents", sa.Column("source_ip", sa.String(length=45), nullable=True))
    op.add_column("incidents", sa.Column("destination_ip", sa.String(length=45), nullable=True))
    op.add_column("incidents", sa.Column("detection_source", sa.String(length=200), nullable=True))
    op.add_column("incidents", sa.Column("tags", sa.Text(), server_default="[]", nullable=False))
    op.add_column("incidents", sa.Column("root_cause", sa.Text(), server_default="", nullable=False))
    op.add_column("incidents", sa.Column("business_impact", sa.Text(), server_default="", nullable=False))
    op.add_column("incidents", sa.Column("containment_notes", sa.Text(), server_default="", nullable=False))
    op.add_column("incidents", sa.Column("remediation_notes", sa.Text(), server_default="", nullable=False))
    op.add_column("incidents", sa.Column("resolution_notes", sa.Text(), server_default="", nullable=False))
    op.add_column("incidents", sa.Column("simulated", sa.Boolean(), server_default=sa.text("0"), nullable=False))
    op.create_index("ix_incidents_simulated", "incidents", ["simulated"])
    op.execute("UPDATE incidents SET status = 'new' WHERE status = 'open'")
    op.execute("UPDATE incidents SET status = 'containment' WHERE status = 'contained'")


def downgrade() -> None:
    op.execute("UPDATE incidents SET status = 'open' WHERE status IN ('new', 'triaged', 'eradication', 'recovery')")
    op.execute("UPDATE incidents SET status = 'contained' WHERE status = 'containment'")
    op.drop_index("ix_incidents_simulated", table_name="incidents")
    for column in (
        "simulated",
        "resolution_notes",
        "remediation_notes",
        "containment_notes",
        "business_impact",
        "root_cause",
        "tags",
        "detection_source",
        "destination_ip",
        "source_ip",
        "affected_asset",
        "reporter",
        "priority",
    ):
        op.drop_column("incidents", column)
