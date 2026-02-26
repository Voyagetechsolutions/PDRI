"""Add graph-lite tables for PDRI MVP

Revision ID: 0003
Revises: 0002
Create Date: 2026-02-25

This migration creates the graph-lite Postgres tables:
- entities: Entity inventory (AI tools, identities, datastores, SaaS apps)
- edges: Relationships between entities
- events: Raw + normalized security events
- risk_scores: Per-entity risk scores with explainable breakdown
- findings: Risk findings (replaces risk_findings for MVP)
- findings_evidence: Evidence trail linking findings to events
"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision: str = "0003"
down_revision: Union[str, None] = "0002"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # ==========================================================================
    # entities table
    # ==========================================================================
    op.create_table(
        "entities",
        sa.Column("id", postgresql.UUID(as_uuid=True), server_default=sa.text("gen_random_uuid()"), nullable=False),
        sa.Column("tenant_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("external_id", sa.String(255), nullable=False),
        sa.Column("entity_type", sa.String(50), nullable=False),
        sa.Column("name", sa.String(500), nullable=False),
        sa.Column("attributes", postgresql.JSONB(), nullable=False, server_default="{}"),
        sa.Column("confidence", sa.Numeric(3, 2), nullable=False, server_default="1.0"),
        sa.Column("first_seen", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("last_seen", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("tenant_id", "external_id", name="uq_entities_tenant_external"),
    )
    op.create_index("ix_entities_tenant", "entities", ["tenant_id"])
    op.create_index("ix_entities_type", "entities", ["tenant_id", "entity_type"])
    op.create_index("ix_entities_name", "entities", ["tenant_id", "name"])
    op.create_index("ix_entities_last_seen", "entities", ["tenant_id", sa.text("last_seen DESC")])

    # ==========================================================================
    # edges table
    # ==========================================================================
    op.create_table(
        "edges",
        sa.Column("id", postgresql.UUID(as_uuid=True), server_default=sa.text("gen_random_uuid()"), nullable=False),
        sa.Column("tenant_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("src_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("dst_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("relation_type", sa.String(50), nullable=False),
        sa.Column("weight", sa.Numeric(3, 2), nullable=False, server_default="1.0"),
        sa.Column("attributes", postgresql.JSONB(), nullable=False, server_default="{}"),
        sa.Column("first_seen", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("last_seen", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.PrimaryKeyConstraint("id"),
        sa.ForeignKeyConstraint(["src_id"], ["entities.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["dst_id"], ["entities.id"], ondelete="CASCADE"),
        sa.UniqueConstraint("tenant_id", "src_id", "dst_id", "relation_type", name="uq_edges_tenant_src_dst_rel"),
    )
    op.create_index("ix_edges_tenant", "edges", ["tenant_id"])
    op.create_index("ix_edges_src", "edges", ["tenant_id", "src_id"])
    op.create_index("ix_edges_dst", "edges", ["tenant_id", "dst_id"])
    op.create_index("ix_edges_relation", "edges", ["tenant_id", "relation_type"])

    # ==========================================================================
    # events table (security events - raw + normalized)
    # ==========================================================================
    op.create_table(
        "security_events",
        sa.Column("id", postgresql.UUID(as_uuid=True), server_default=sa.text("gen_random_uuid()"), nullable=False),
        sa.Column("tenant_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("event_id", sa.String(255), nullable=False),
        sa.Column("event_type", sa.String(50), nullable=False),
        sa.Column("source_system_id", sa.String(255), nullable=False),
        sa.Column("timestamp", sa.DateTime(timezone=True), nullable=False),
        sa.Column("entity_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("identity_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("severity", sa.String(20), nullable=False, server_default="medium"),
        sa.Column("exposure_direction", sa.String(50), nullable=True),
        sa.Column("sensitivity_tags", postgresql.ARRAY(sa.Text()), nullable=False, server_default="{}"),
        sa.Column("raw_event", postgresql.JSONB(), nullable=False),
        sa.Column("normalized", postgresql.JSONB(), nullable=False, server_default="{}"),
        sa.Column("processed_at", sa.DateTime(timezone=True), nullable=True, server_default=sa.func.now()),
        sa.Column("fingerprint", sa.String(64), nullable=True),
        sa.PrimaryKeyConstraint("id"),
        sa.ForeignKeyConstraint(["entity_id"], ["entities.id"], ondelete="SET NULL"),
        sa.ForeignKeyConstraint(["identity_id"], ["entities.id"], ondelete="SET NULL"),
        sa.UniqueConstraint("tenant_id", "event_id", name="uq_events_tenant_event_id"),
    )
    op.create_index("ix_sevents_tenant_time", "security_events", ["tenant_id", sa.text("timestamp DESC")])
    op.create_index("ix_sevents_entity", "security_events", ["tenant_id", "entity_id"])
    op.create_index("ix_sevents_type", "security_events", ["tenant_id", "event_type"])
    op.create_index("ix_sevents_fingerprint", "security_events", ["tenant_id", "fingerprint"])

    # ==========================================================================
    # risk_scores table
    # ==========================================================================
    op.create_table(
        "risk_scores",
        sa.Column("id", postgresql.UUID(as_uuid=True), server_default=sa.text("gen_random_uuid()"), nullable=False),
        sa.Column("tenant_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("entity_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("composite_score", sa.Numeric(5, 4), nullable=False),
        sa.Column("exposure_score", sa.Numeric(5, 4), nullable=False),
        sa.Column("sensitivity_score", sa.Numeric(5, 4), nullable=False),
        sa.Column("volatility_score", sa.Numeric(5, 4), nullable=False),
        sa.Column("confidence", sa.Numeric(3, 2), nullable=False, server_default="1.0"),
        sa.Column("risk_level", sa.String(20), nullable=False),
        sa.Column("explain", postgresql.JSONB(), nullable=False),
        sa.Column("scoring_version", sa.String(20), nullable=False, server_default="1.0.0"),
        sa.Column("calculated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.PrimaryKeyConstraint("id"),
        sa.ForeignKeyConstraint(["entity_id"], ["entities.id"], ondelete="CASCADE"),
        sa.UniqueConstraint("tenant_id", "entity_id", name="uq_risk_scores_tenant_entity"),
    )
    op.create_index("ix_rscores_tenant", "risk_scores", ["tenant_id"])
    op.create_index("ix_rscores_level", "risk_scores", ["tenant_id", "risk_level"])
    op.create_index("ix_rscores_composite", "risk_scores", ["tenant_id", sa.text("composite_score DESC")])

    # ==========================================================================
    # mvp_findings table (separate from legacy risk_findings)
    # ==========================================================================
    op.create_table(
        "mvp_findings",
        sa.Column("id", postgresql.UUID(as_uuid=True), server_default=sa.text("gen_random_uuid()"), nullable=False),
        sa.Column("tenant_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("title", sa.String(500), nullable=False),
        sa.Column("description", sa.Text(), nullable=False),
        sa.Column("finding_type", sa.String(100), nullable=False),
        sa.Column("severity", sa.String(20), nullable=False),
        sa.Column("risk_score", sa.Numeric(5, 4), nullable=False),
        sa.Column("status", sa.String(30), nullable=False, server_default="open"),
        sa.Column("primary_entity_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("affected_entities", postgresql.JSONB(), nullable=False, server_default="[]"),
        sa.Column("recommendations", postgresql.JSONB(), nullable=False, server_default="[]"),
        sa.Column("tags", postgresql.ARRAY(sa.Text()), nullable=False, server_default="{}"),
        sa.Column("sla_due_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("acknowledged_by", sa.String(255), nullable=True),
        sa.Column("resolved_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.PrimaryKeyConstraint("id"),
        sa.ForeignKeyConstraint(["primary_entity_id"], ["entities.id"], ondelete="SET NULL"),
    )
    op.create_index("ix_mvpfindings_tenant", "mvp_findings", ["tenant_id"])
    op.create_index("ix_mvpfindings_status", "mvp_findings", ["tenant_id", "status"])
    op.create_index("ix_mvpfindings_severity", "mvp_findings", ["tenant_id", "severity"])
    op.create_index("ix_mvpfindings_type", "mvp_findings", ["tenant_id", "finding_type"])
    op.create_index("ix_mvpfindings_entity", "mvp_findings", ["tenant_id", "primary_entity_id"])
    op.create_index("ix_mvpfindings_created", "mvp_findings", ["tenant_id", sa.text("created_at DESC")])

    # ==========================================================================
    # findings_evidence table
    # ==========================================================================
    op.create_table(
        "findings_evidence",
        sa.Column("id", postgresql.UUID(as_uuid=True), server_default=sa.text("gen_random_uuid()"), nullable=False),
        sa.Column("tenant_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("finding_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("event_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("evidence_type", sa.String(50), nullable=False),
        sa.Column("summary", sa.Text(), nullable=False),
        sa.Column("data", postgresql.JSONB(), nullable=False, server_default="{}"),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.PrimaryKeyConstraint("id"),
        sa.ForeignKeyConstraint(["finding_id"], ["mvp_findings.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["event_id"], ["security_events.id"], ondelete="SET NULL"),
    )
    op.create_index("ix_evidence_finding", "findings_evidence", ["tenant_id", "finding_id"])

    # ==========================================================================
    # Row-Level Security (defense in depth)
    # ==========================================================================
    for table in ["entities", "edges", "security_events", "risk_scores", "mvp_findings", "findings_evidence"]:
        op.execute(f"ALTER TABLE {table} ENABLE ROW LEVEL SECURITY")
        op.execute(
            f"CREATE POLICY tenant_isolation_{table} ON {table} "
            f"USING (tenant_id = current_setting('app.current_tenant', true)::UUID)"
        )


def downgrade() -> None:
    for table in ["findings_evidence", "mvp_findings", "risk_scores", "security_events", "edges", "entities"]:
        op.execute(f"DROP POLICY IF EXISTS tenant_isolation_{table} ON {table}")
        op.drop_table(table)
