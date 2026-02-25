"""Add correlation layer and fix FindingDB

Revision ID: 0002
Revises: 0001
Create Date: 2024-01-16

This migration:
- Adds ownership fields to risk_findings (tenant_id, owner_id)
- Adds correlation fields (fingerprint, correlation_id)
- Adds SLA tracking (sla_due_at, sla_breached)
- Adds evidence_refs and recommended_actions
- Creates event_correlations table for correlation layer
- Updates processed_events with fingerprint support
"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision: str = "0002"
down_revision: Union[str, None] = "0001"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # ==========================================================================
    # Update risk_findings table
    # ==========================================================================

    # Add new columns
    op.add_column(
        "risk_findings",
        sa.Column("tenant_id", sa.String(64), nullable=False, server_default="default"),
    )
    op.add_column(
        "risk_findings",
        sa.Column("owner_id", sa.String(255), nullable=True),
    )
    op.add_column(
        "risk_findings",
        sa.Column("fingerprint", sa.String(64), nullable=False, server_default=""),
    )
    op.add_column(
        "risk_findings",
        sa.Column("correlation_id", sa.String(36), nullable=True),
    )
    op.add_column(
        "risk_findings",
        sa.Column("primary_entity_id", sa.String(255), nullable=False, server_default="unknown"),
    )
    op.add_column(
        "risk_findings",
        sa.Column("primary_entity_type", sa.String(50), nullable=False, server_default="unknown"),
    )
    op.add_column(
        "risk_findings",
        sa.Column("evidence_refs", postgresql.JSONB(), nullable=False, server_default="[]"),
    )
    op.add_column(
        "risk_findings",
        sa.Column("evidence_count", sa.Integer(), nullable=False, server_default="0"),
    )
    op.add_column(
        "risk_findings",
        sa.Column("recommended_actions", postgresql.JSONB(), nullable=False, server_default="[]"),
    )
    op.add_column(
        "risk_findings",
        sa.Column("status_reason", sa.Text(), nullable=True),
    )
    op.add_column(
        "risk_findings",
        sa.Column("sla_due_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.add_column(
        "risk_findings",
        sa.Column("sla_breached", sa.Boolean(), nullable=False, server_default="false"),
    )
    op.add_column(
        "risk_findings",
        sa.Column("first_seen_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
    )
    op.add_column(
        "risk_findings",
        sa.Column("last_seen_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
    )
    op.add_column(
        "risk_findings",
        sa.Column("occurrence_count", sa.Integer(), nullable=False, server_default="1"),
    )

    # Drop old indexes
    op.drop_index("ix_findings_status", table_name="risk_findings")

    # Create new indexes
    op.create_index("ix_findings_tenant_status", "risk_findings", ["tenant_id", "status"])
    op.create_index("ix_findings_fingerprint", "risk_findings", ["fingerprint"])
    op.create_index("ix_findings_sla_due", "risk_findings", ["sla_due_at"])
    op.create_index("ix_findings_primary_entity", "risk_findings", ["primary_entity_id"])
    op.create_index("ix_findings_owner", "risk_findings", ["owner_id"])
    op.create_index("ix_findings_correlation", "risk_findings", ["correlation_id"])

    # ==========================================================================
    # Update processed_events table
    # ==========================================================================

    op.add_column(
        "processed_events",
        sa.Column("fingerprint", sa.String(64), nullable=False, server_default=""),
    )
    op.add_column(
        "processed_events",
        sa.Column("correlation_id", sa.String(36), nullable=True),
    )

    op.create_index(
        "ix_processed_events_fingerprint_time",
        "processed_events",
        ["fingerprint", "processed_at"],
    )
    op.create_index(
        "ix_processed_events_correlation",
        "processed_events",
        ["correlation_id"],
    )

    # ==========================================================================
    # Create event_correlations table
    # ==========================================================================

    op.create_table(
        "event_correlations",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("correlation_id", sa.String(36), nullable=False),
        sa.Column("fingerprint", sa.String(64), nullable=False),
        sa.Column("correlation_type", sa.String(50), nullable=False),
        sa.Column("window_start", sa.DateTime(timezone=True), nullable=False),
        sa.Column("window_end", sa.DateTime(timezone=True), nullable=False),
        sa.Column("window_duration_minutes", sa.Integer(), nullable=False, server_default="15"),
        sa.Column("event_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("event_ids", postgresql.ARRAY(sa.String()), nullable=False, server_default="{}"),
        sa.Column("event_types", postgresql.ARRAY(sa.String()), nullable=False, server_default="{}"),
        sa.Column("primary_entity_id", sa.String(255), nullable=False),
        sa.Column("primary_entity_type", sa.String(50), nullable=False),
        sa.Column("related_entity_ids", postgresql.ARRAY(sa.String()), nullable=False, server_default="{}"),
        sa.Column("max_severity", sa.String(20), nullable=False, server_default="low"),
        sa.Column("sensitivity_tags", postgresql.ARRAY(sa.String()), nullable=False, server_default="{}"),
        sa.Column("total_data_volume", sa.Integer(), nullable=True),
        sa.Column("finding_id", sa.String(32), nullable=True),
        sa.Column("finding_generated_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("status", sa.String(20), nullable=False, server_default="open"),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("correlation_id"),
    )

    op.create_index(
        "ix_correlation_fingerprint_window",
        "event_correlations",
        ["fingerprint", "window_start"],
    )
    op.create_index("ix_correlation_status", "event_correlations", ["status"])
    op.create_index("ix_correlation_primary_entity", "event_correlations", ["primary_entity_id"])
    op.create_index("ix_correlation_finding", "event_correlations", ["finding_id"])


def downgrade() -> None:
    # Drop event_correlations
    op.drop_table("event_correlations")

    # Remove columns from processed_events
    op.drop_index("ix_processed_events_correlation", table_name="processed_events")
    op.drop_index("ix_processed_events_fingerprint_time", table_name="processed_events")
    op.drop_column("processed_events", "correlation_id")
    op.drop_column("processed_events", "fingerprint")

    # Remove columns from risk_findings
    op.drop_index("ix_findings_correlation", table_name="risk_findings")
    op.drop_index("ix_findings_owner", table_name="risk_findings")
    op.drop_index("ix_findings_primary_entity", table_name="risk_findings")
    op.drop_index("ix_findings_sla_due", table_name="risk_findings")
    op.drop_index("ix_findings_fingerprint", table_name="risk_findings")
    op.drop_index("ix_findings_tenant_status", table_name="risk_findings")

    op.create_index("ix_findings_status", "risk_findings", ["status"])

    op.drop_column("risk_findings", "occurrence_count")
    op.drop_column("risk_findings", "last_seen_at")
    op.drop_column("risk_findings", "first_seen_at")
    op.drop_column("risk_findings", "sla_breached")
    op.drop_column("risk_findings", "sla_due_at")
    op.drop_column("risk_findings", "status_reason")
    op.drop_column("risk_findings", "recommended_actions")
    op.drop_column("risk_findings", "evidence_count")
    op.drop_column("risk_findings", "evidence_refs")
    op.drop_column("risk_findings", "primary_entity_type")
    op.drop_column("risk_findings", "primary_entity_id")
    op.drop_column("risk_findings", "correlation_id")
    op.drop_column("risk_findings", "fingerprint")
    op.drop_column("risk_findings", "owner_id")
    op.drop_column("risk_findings", "tenant_id")
