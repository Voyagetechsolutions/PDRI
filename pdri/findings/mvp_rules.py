"""
MVP Finding Rules Engine
=========================

Implements 3 finding rules for the PDRI MVP:
    1. Shadow AI Accessing Sensitive Assets
    2. Privileged Identity Linked to AI Integration
    3. Excessive Data Export to External AI/SaaS

Author: PDRI Team
Version: 1.0.0
"""

import logging
from datetime import datetime, timedelta, timezone
from typing import Optional
from uuid import uuid4

from sqlalchemy import select, func
from sqlalchemy.ext.asyncio import AsyncSession

from pdri.db.models import (
    EntityDB,
    EdgeDB,
    SecurityEventDB,
    RiskScoreDB,
    MVPFindingDB,
    FindingsEvidenceDB,
)
from pdri.scoring.pg_engine import classify_risk_level, SLA_HOURS

logger = logging.getLogger(__name__)


# =============================================================================
# Finding Rule Base
# =============================================================================


class MVPFindingRules:
    """
    Evaluates all 3 finding rules against a set of entities.
    """

    def __init__(self, db: AsyncSession):
        self.db = db

    async def evaluate_all(self, entity_ids: list[str], tenant_id: str) -> list[dict]:
        """Run all finding rules for the given entities. Returns created findings."""
        findings = []

        for entity_id in entity_ids:
            # Rule 1: Shadow AI
            f1 = await self.check_shadow_ai(entity_id, tenant_id)
            if f1:
                findings.append(f1)

            # Rule 2: Privileged Identity
            f2 = await self.check_privileged_identity(entity_id, tenant_id)
            if f2:
                findings.append(f2)

            # Rule 3: Excessive Export
            f3 = await self.check_excessive_export(entity_id, tenant_id)
            if f3:
                findings.append(f3)

        return findings

    # ── Rule 1: Shadow AI ───────────────────────────────────────────────

    async def check_shadow_ai(self, entity_id: str, tenant_id: str) -> Optional[dict]:
        """
        Trigger: An unsanctioned AI tool has an edge to an entity
        whose sensitivity_score >= 0.6.
        """
        entity = await self._get_entity(entity_id, tenant_id)
        if not entity:
            return None

        # Find AI tools connected to this entity
        edges_result = await self.db.execute(
            select(EdgeDB)
            .where(EdgeDB.tenant_id == tenant_id)
            .where(EdgeDB.dst_id == entity.id)
            .where(EdgeDB.relation_type.in_(["ACCESSES", "INTEGRATES_WITH", "MOVES_DATA_TO"]))
        )
        edges = edges_result.scalars().all()

        for edge in edges:
            ai_tool = await self._get_entity_by_id(edge.src_id, tenant_id)
            if not ai_tool or ai_tool.entity_type != "ai_tool":
                continue
            if ai_tool.attributes.get("is_sanctioned", True):
                continue

            # Check sensitivity of target entity
            score = await self._get_score(entity.id, tenant_id)
            sensitivity = score.sensitivity_score if score else 0.0
            if sensitivity < 0.6:
                continue

            # Check for existing open finding
            if await self._finding_exists("shadow_ai", entity.id, ai_tool.id, tenant_id):
                continue

            composite = score.composite_score if score else sensitivity
            severity = classify_risk_level(composite)

            # Create finding
            finding = await self._create_finding(
                tenant_id=tenant_id,
                title=f"Shadow AI Tool Accessing {entity.name}",
                description=(
                    f"Unsanctioned AI tool '{ai_tool.name}' is accessing "
                    f"'{entity.name}' (sensitivity: {sensitivity:.2f}). "
                    f"This poses a data exfiltration risk."
                ),
                finding_type="shadow_ai",
                severity=severity,
                risk_score=composite,
                primary_entity_id=entity.id,
                affected_entities=[
                    {"entity_id": entity.id, "role": "target", "name": entity.name},
                    {"entity_id": ai_tool.id, "role": "accessor", "name": ai_tool.name},
                ],
                recommendations=[
                    {
                        "action": "block_access",
                        "description": f"Block {ai_tool.name} access to {entity.name}",
                        "priority": "immediate",
                    },
                    {
                        "action": "review_data",
                        "description": f"Audit data exported to {ai_tool.name}",
                        "priority": "high",
                    },
                    {
                        "action": "sanctioning",
                        "description": f"Evaluate {ai_tool.name} for sanctioning or removal",
                        "priority": "medium",
                    },
                ],
                tags=["shadow_ai", "unsanctioned", "data_risk"],
            )

            # Add evidence
            events = await self._get_events_between(entity.id, ai_tool.id, tenant_id)
            for evt in events[:10]:
                await self._add_evidence(
                    tenant_id=tenant_id,
                    finding_id=finding["id"],
                    event_id=evt.id,
                    evidence_type="event",
                    summary=f"{evt.event_type}: {ai_tool.name} → {entity.name}",
                )

            if score:
                await self._add_evidence(
                    tenant_id=tenant_id,
                    finding_id=finding["id"],
                    evidence_type="score_snapshot",
                    summary=f"Entity risk score: {composite:.2f} ({severity})",
                    data={"composite_score": composite, "sensitivity_score": sensitivity},
                )

            return finding

        return None

    # ── Rule 2: Privileged Identity ─────────────────────────────────────

    async def check_privileged_identity(self, entity_id: str, tenant_id: str) -> Optional[dict]:
        """
        Trigger: An identity with admin/super_admin privilege has a path
        (depth <= 2) to an AI tool entity.
        """
        entity = await self._get_entity(entity_id, tenant_id)
        if not entity or entity.entity_type != "identity":
            return None

        privilege = entity.attributes.get("privilege_level", "unknown")
        if privilege not in ("admin", "super_admin"):
            return None

        # Find AI tools within 2 hops
        ai_tools = await self._find_ai_tools_within_depth(entity.id, tenant_id, max_depth=2)
        if not ai_tools:
            return None

        # Check for existing open finding
        if await self._finding_exists("privileged_identity", entity.id, None, tenant_id):
            return None

        ai_tool_names = [t.name for t in ai_tools[:5]]
        score = await self._get_score(entity.id, tenant_id)
        composite = score.composite_score if score else 0.7

        finding = await self._create_finding(
            tenant_id=tenant_id,
            title=f"Privileged Identity '{entity.name}' Linked to AI Tools",
            description=(
                f"Identity '{entity.name}' with {privilege} privileges "
                f"has paths to {len(ai_tools)} AI tool(s): {', '.join(ai_tool_names)}. "
                f"This creates a high-value target for credential compromise."
            ),
            finding_type="privileged_identity",
            severity="high",
            risk_score=composite,
            primary_entity_id=entity.id,
            affected_entities=[
                {"entity_id": entity.id, "role": "identity", "name": entity.name},
                *[{"entity_id": t.id, "role": "ai_tool", "name": t.name} for t in ai_tools[:5]],
            ],
            recommendations=[
                {
                    "action": "review_access",
                    "description": f"Review if {privilege} access to AI tools is justified",
                    "priority": "high",
                },
                {
                    "action": "least_privilege",
                    "description": "Apply least-privilege principle to this identity",
                    "priority": "high",
                },
                {
                    "action": "enable_mfa",
                    "description": "Enable MFA on this identity if not already enabled",
                    "priority": "medium",
                },
            ],
            tags=["privileged_identity", "ai_access", privilege],
        )

        return finding

    # ── Rule 3: Excessive Data Export ───────────────────────────────────

    async def check_excessive_export(self, entity_id: str, tenant_id: str) -> Optional[dict]:
        """
        Trigger: > 100MB data exported to external/AI in 7 days for one entity.
        """
        entity = await self._get_entity(entity_id, tenant_id)
        if not entity:
            return None

        seven_days_ago = datetime.now(timezone.utc) - timedelta(days=7)

        result = await self.db.execute(
            select(SecurityEventDB)
            .where(SecurityEventDB.tenant_id == tenant_id)
            .where(SecurityEventDB.entity_id == entity.id)
            .where(SecurityEventDB.event_type.in_(["DATA_EXPORT", "DATA_MOVEMENT"]))
            .where(SecurityEventDB.exposure_direction.in_([
                "internal_to_external", "internal_to_ai",
                "INTERNAL_TO_EXTERNAL", "INTERNAL_TO_AI",
            ]))
            .where(SecurityEventDB.timestamp >= seven_days_ago)
        )
        events = result.scalars().all()

        total_volume = 0
        for evt in events:
            raw = evt.raw_event if isinstance(evt.raw_event, dict) else {}
            ai_ctx = raw.get("ai_context", {})
            total_volume += ai_ctx.get("data_volume_bytes", 0)

        threshold = 100_000_000  # 100MB
        if total_volume < threshold:
            return None

        if await self._finding_exists("excessive_export", entity.id, None, tenant_id):
            return None

        # Severity scales with volume
        if total_volume > 500_000_000:
            severity = "critical"
        elif total_volume > 250_000_000:
            severity = "high"
        else:
            severity = "medium"

        mb = total_volume // 1_000_000

        finding = await self._create_finding(
            tenant_id=tenant_id,
            title=f"Excessive Data Export from {entity.name} ({mb}MB in 7d)",
            description=(
                f"Entity '{entity.name}' has exported {mb}MB of data "
                f"to external/AI destinations in the last 7 days, "
                f"exceeding the {threshold // 1_000_000}MB threshold."
            ),
            finding_type="excessive_export",
            severity=severity,
            risk_score=min(1.0, total_volume / 500_000_000),
            primary_entity_id=entity.id,
            affected_entities=[
                {"entity_id": entity.id, "role": "source", "name": entity.name},
            ],
            recommendations=[
                {
                    "action": "review_exports",
                    "description": f"Review and justify {mb}MB data export volume",
                    "priority": "high",
                },
                {
                    "action": "dlp_controls",
                    "description": "Implement DLP controls on export paths",
                    "priority": "high",
                },
                {
                    "action": "alert_setup",
                    "description": "Set up alerts for future volume spikes",
                    "priority": "medium",
                },
            ],
            tags=["excessive_export", "data_loss", f"{mb}mb"],
        )

        # Link events as evidence
        for evt in events[:10]:
            await self._add_evidence(
                tenant_id=tenant_id,
                finding_id=finding["id"],
                event_id=evt.id,
                evidence_type="event",
                summary=f"{evt.event_type}: {evt.exposure_direction}",
            )

        return finding

    # ── Helpers ──────────────────────────────────────────────────────────

    async def _get_entity(self, eid: str, tid: str) -> Optional[EntityDB]:
        result = await self.db.execute(
            select(EntityDB).where(EntityDB.tenant_id == tid)
            .where((EntityDB.id == eid) | (EntityDB.external_id == eid))
        )
        return result.scalar_one_or_none()

    async def _get_entity_by_id(self, eid: str, tid: str) -> Optional[EntityDB]:
        result = await self.db.execute(
            select(EntityDB).where(EntityDB.id == eid).where(EntityDB.tenant_id == tid)
        )
        return result.scalar_one_or_none()

    async def _get_score(self, entity_id: str, tid: str) -> Optional[RiskScoreDB]:
        result = await self.db.execute(
            select(RiskScoreDB).where(RiskScoreDB.entity_id == entity_id).where(RiskScoreDB.tenant_id == tid)
        )
        return result.scalar_one_or_none()

    async def _finding_exists(self, finding_type: str, primary_id: str, secondary_id: Optional[str], tid: str) -> bool:
        q = select(MVPFindingDB.id).where(
            MVPFindingDB.tenant_id == tid,
            MVPFindingDB.finding_type == finding_type,
            MVPFindingDB.primary_entity_id == primary_id,
            MVPFindingDB.status.in_(["open", "acknowledged", "in_progress"]),
        )
        result = await self.db.execute(q)
        return result.scalar_one_or_none() is not None

    async def _find_ai_tools_within_depth(self, src_id: str, tid: str, max_depth: int = 2) -> list[EntityDB]:
        """BFS to find AI tools within max_depth hops."""
        visited = {src_id}
        frontier = [src_id]
        ai_tools = []

        for _ in range(max_depth):
            if not frontier:
                break
            next_frontier = []
            for node_id in frontier:
                edges_result = await self.db.execute(
                    select(EdgeDB).where(EdgeDB.tenant_id == tid)
                    .where((EdgeDB.src_id == node_id) | (EdgeDB.dst_id == node_id))
                )
                for edge in edges_result.scalars().all():
                    other = edge.dst_id if edge.src_id == node_id else edge.src_id
                    if other not in visited:
                        visited.add(other)
                        next_frontier.append(other)
                        ent = await self._get_entity_by_id(other, tid)
                        if ent and ent.entity_type == "ai_tool":
                            ai_tools.append(ent)
            frontier = next_frontier

        return ai_tools

    async def _get_events_between(self, entity_id: str, identity_id: str, tid: str) -> list[SecurityEventDB]:
        result = await self.db.execute(
            select(SecurityEventDB).where(
                SecurityEventDB.tenant_id == tid,
                SecurityEventDB.entity_id == entity_id,
                SecurityEventDB.identity_id == identity_id,
            ).order_by(SecurityEventDB.timestamp.desc()).limit(10)
        )
        return list(result.scalars().all())

    async def _create_finding(self, **kwargs) -> dict:
        """Create and persist a finding. Returns dict."""
        finding_id = str(uuid4())
        severity = kwargs.get("severity", "medium")
        sla_hours = SLA_HOURS.get(severity)
        sla_due = datetime.now(timezone.utc) + timedelta(hours=sla_hours) if sla_hours else None

        finding = MVPFindingDB(
            id=finding_id,
            tenant_id=kwargs["tenant_id"],
            title=kwargs["title"],
            description=kwargs["description"],
            finding_type=kwargs["finding_type"],
            severity=severity,
            risk_score=kwargs.get("risk_score", 0.5),
            primary_entity_id=kwargs.get("primary_entity_id"),
            affected_entities=kwargs.get("affected_entities", []),
            recommendations=kwargs.get("recommendations", []),
            tags=kwargs.get("tags", []),
            sla_due_at=sla_due,
        )
        self.db.add(finding)
        await self.db.flush()

        return {
            "id": finding_id,
            "title": kwargs["title"],
            "finding_type": kwargs["finding_type"],
            "severity": severity,
            "risk_score": kwargs.get("risk_score"),
            "status": "open",
        }

    async def _add_evidence(self, **kwargs) -> None:
        evidence = FindingsEvidenceDB(
            id=str(uuid4()),
            tenant_id=kwargs["tenant_id"],
            finding_id=kwargs["finding_id"],
            event_id=kwargs.get("event_id"),
            evidence_type=kwargs["evidence_type"],
            summary=kwargs["summary"],
            data=kwargs.get("data", {}),
        )
        self.db.add(evidence)
        await self.db.flush()
