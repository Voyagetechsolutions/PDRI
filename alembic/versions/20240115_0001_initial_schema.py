"""Initial PDRI schema

Revision ID: 0001
Revises:
Create Date: 2024-01-15

Creates core tables for PDRI persistence:
- risk_findings: Generated risk findings
- score_history: Historical scores for trend analysis
- audit_logs: Compliance audit trail
- compliance_assessments: Stored assessment results
- processed_events: Event idempotency tracking
"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision: str = "0001"
down_revision: Union[str, None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # ==========================================================================
    # risk_findings table
    # ==========================================================================
    op.create_table(
        "risk_findings",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("finding_id", sa.String(32), nullable=False),
        sa.Column("title", sa.String(255), nullable=False),
        sa.Column("description", sa.Text(), nullable=False),
        sa.Column("finding_type", sa.String(50), nullable=False, server_default="risk_detected"),
        sa.Column("severity", sa.String(20), nullable=False, server_default="medium"),
        sa.Column("risk_score", sa.Float(), nullable=False),
        sa.Column("exposure_score", sa.Float(), nullable=True),
        sa.Column("volatility_score", sa.Float(), nullable=True),
        sa.Column("sensitivity_score", sa.Float(), nullable=True),
        sa.Column("entities_involved", postgresql.JSONB(), nullable=False, server_default="[]"),
        sa.Column("exposure_path", postgresql.ARRAY(sa.String()), nullable=False, server_default="{}"),
        sa.Column("evidence", postgresql.JSONB(), nullable=False, server_default="[]"),
        sa.Column("recommendations", postgresql.JSONB(), nullable=False, server_default="[]"),
        sa.Column("status", sa.String(20), nullable=False, server_default="open"),
        sa.Column("assigned_to", sa.String(255), nullable=True),
        sa.Column("resolved_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("tags", postgresql.ARRAY(sa.String()), nullable=False, server_default="{}"),
        sa.Column("metadata", postgresql.JSONB(), nullable=False, server_default="{}"),
        sa.Column("schema_version", sa.String(20), nullable=False, server_default="1.0.0"),
        sa.Column("producer_version", sa.String(20), nullable=False, server_default="1.0.0"),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("finding_id"),
    )

    # Indexes for risk_findings
    op.create_index("ix_findings_status", "risk_findings", ["status"])
    op.create_index("ix_findings_severity", "risk_findings", ["severity"])
    op.create_index("ix_findings_risk_score", "risk_findings", ["risk_score"])
    op.create_index("ix_findings_created_at", "risk_findings", ["created_at"])
    op.create_index("ix_findings_finding_type", "risk_findings", ["finding_type"])

    # ==========================================================================
    # score_history table
    # ==========================================================================
    op.create_table(
        "score_history",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("entity_id", sa.String(255), nullable=False),
        sa.Column("entity_type", sa.String(50), nullable=False),
        sa.Column("composite_score", sa.Float(), nullable=False),
        sa.Column("exposure_score", sa.Float(), nullable=False),
        sa.Column("volatility_score", sa.Float(), nullable=False),
        sa.Column("sensitivity_score", sa.Float(), nullable=False),
        sa.Column("factors", postgresql.JSONB(), nullable=False, server_default="{}"),
        sa.Column("scoring_version", sa.String(20), nullable=False, server_default="1.0.0"),
        sa.Column("calculated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.PrimaryKeyConstraint("id"),
    )

    # Indexes for score_history
    op.create_index("ix_score_history_entity_id", "score_history", ["entity_id"])
    op.create_index("ix_score_history_entity_time", "score_history", ["entity_id", "calculated_at"])
    op.create_index("ix_score_history_composite", "score_history", ["composite_score"])

    # ==========================================================================
    # audit_logs table
    # ==========================================================================
    op.create_table(
        "audit_logs",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("log_id", sa.String(36), nullable=False),
        sa.Column("action", sa.String(100), nullable=False),
        sa.Column("resource_type", sa.String(50), nullable=False),
        sa.Column("resource_id", sa.String(255), nullable=True),
        sa.Column("actor_id", sa.String(255), nullable=True),
        sa.Column("actor_type", sa.String(20), nullable=False, server_default="system"),
        sa.Column("outcome", sa.String(20), nullable=False, server_default="success"),
        sa.Column("error_message", sa.Text(), nullable=True),
        sa.Column("request_id", sa.String(36), nullable=True),
        sa.Column("ip_address", sa.String(45), nullable=True),
        sa.Column("user_agent", sa.String(500), nullable=True),
        sa.Column("payload", postgresql.JSONB(), nullable=False, server_default="{}"),
        sa.Column("timestamp", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("log_id"),
    )

    # Indexes for audit_logs
    op.create_index("ix_audit_timestamp", "audit_logs", ["timestamp"])
    op.create_index("ix_audit_action", "audit_logs", ["action"])
    op.create_index("ix_audit_resource", "audit_logs", ["resource_type", "resource_id"])
    op.create_index("ix_audit_actor", "audit_logs", ["actor_id"])

    # ==========================================================================
    # compliance_assessments table
    # ==========================================================================
    op.create_table(
        "compliance_assessments",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("assessment_id", sa.String(36), nullable=False),
        sa.Column("framework", sa.String(50), nullable=False),
        sa.Column("framework_version", sa.String(20), nullable=False),
        sa.Column("scope_entity_ids", postgresql.ARRAY(sa.String()), nullable=False, server_default="{}"),
        sa.Column("scope_type", sa.String(20), nullable=False, server_default="full"),
        sa.Column("overall_score", sa.Float(), nullable=False),
        sa.Column("compliance_status", sa.String(20), nullable=False),
        sa.Column("controls_passed", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("controls_failed", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("controls_not_applicable", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("control_results", postgresql.JSONB(), nullable=False, server_default="{}"),
        sa.Column("findings", postgresql.JSONB(), nullable=False, server_default="[]"),
        sa.Column("recommendations", postgresql.JSONB(), nullable=False, server_default="[]"),
        sa.Column("assessed_by", sa.String(255), nullable=True),
        sa.Column("notes", sa.Text(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("assessment_id"),
    )

    # Indexes for compliance_assessments
    op.create_index("ix_assessment_framework", "compliance_assessments", ["framework"])
    op.create_index("ix_assessment_status", "compliance_assessments", ["compliance_status"])

    # ==========================================================================
    # processed_events table (for idempotency)
    # ==========================================================================
    op.create_table(
        "processed_events",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("event_id", sa.String(255), nullable=False),
        sa.Column("event_type", sa.String(50), nullable=False),
        sa.Column("source_system", sa.String(255), nullable=False),
        sa.Column("processed_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("processing_result", sa.String(20), nullable=False, server_default="success"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("event_id"),
    )

    # Indexes for processed_events
    op.create_index("ix_processed_events_time", "processed_events", ["processed_at"])


def downgrade() -> None:
    # Drop all tables in reverse order
    op.drop_table("processed_events")
    op.drop_table("compliance_assessments")
    op.drop_table("audit_logs")
    op.drop_table("score_history")
    op.drop_table("risk_findings")
