"""
Postgres-Based Scoring Engine (MVP)
====================================

Computes risk scores from the graph-lite Postgres tables
instead of Neo4j. Implements the v1 scoring formula:

    composite = (exposure × 0.45) + (sensitivity × 0.30)
              + (volatility × 0.15) + (confidence_penalty × 0.10)

Author: PDRI Team
Version: 1.0.0
"""

import logging
import re
from datetime import datetime, timedelta, timezone
from typing import Optional
from uuid import uuid4

from sqlalchemy import select, func, and_
from sqlalchemy.ext.asyncio import AsyncSession

from pdri.db.models import EntityDB, EdgeDB, SecurityEventDB, RiskScoreDB

logger = logging.getLogger(__name__)


# =============================================================================
# Constants
# =============================================================================

SCORING_VERSION = "1.0.0"

# Composite weights (sum = 1.0)
W_EXPOSURE = 0.45
W_SENSITIVITY = 0.30
W_VOLATILITY = 0.15
W_CONFIDENCE = 0.10

# Exposure factor weights
EF_EXTERNAL_CONN = 0.25
EF_AI_INTEGRATION = 0.30
EF_DATA_VOLUME = 0.20
EF_PRIVILEGE = 0.15
EF_PUBLIC = 0.10

# Sensitivity factor weights
SF_NAME_HEURISTIC = 0.30
SF_DATA_CLASSIFICATION = 0.40
SF_SENSITIVITY_TAGS = 0.30

# Volatility factor weights
VF_HISTORICAL_VAR = 0.50
VF_CONN_CHANGE_RATE = 0.30
VF_RECENT_AI = 0.20

# Severity thresholds
THRESHOLDS = {
    "critical": 0.80,
    "high": 0.60,
    "medium": 0.40,
    "low": 0.20,
}

# SLA hours per severity
SLA_HOURS = {
    "critical": 4,
    "high": 24,
    "medium": 72,
    "low": 168,
    "minimal": None,
}

# Sensitive name patterns
SENSITIVE_PATTERNS = [
    r"customer", r"user", r"patient", r"employee",
    r"credential", r"password", r"secret", r"token",
    r"pii", r"phi", r"ssn", r"credit.?card",
    r"financial", r"bank", r"payment", r"salary",
    r"medical", r"health", r"diagnosis",
]
_SENSITIVE_RE = re.compile("|".join(SENSITIVE_PATTERNS), re.IGNORECASE)

# Data classification levels
CLASSIFICATION_SCORES = {
    "public": 0.0,
    "internal": 0.3,
    "confidential": 0.7,
    "restricted": 1.0,
    "secret": 1.0,
    "top_secret": 1.0,
}

# Privilege weights
PRIVILEGE_WEIGHTS = {
    "read": 0.2,
    "write": 0.4,
    "execute": 0.5,
    "admin": 0.7,
    "super_admin": 1.0,
    "unknown": 0.3,
}


# =============================================================================
# Scoring Engine
# =============================================================================


def classify_risk_level(score: float) -> str:
    """Map composite score to risk level string."""
    if score >= THRESHOLDS["critical"]:
        return "critical"
    if score >= THRESHOLDS["high"]:
        return "high"
    if score >= THRESHOLDS["medium"]:
        return "medium"
    if score >= THRESHOLDS["low"]:
        return "low"
    return "minimal"


class PostgresScoringEngine:
    """
    Computes risk scores for entities using Postgres graph-lite tables.

    Usage:
        engine = PostgresScoringEngine(db)
        score = await engine.score_entity(entity_id, tenant_id)
    """

    def __init__(self, db: AsyncSession):
        self.db = db

    async def score_entity(self, entity_id: str, tenant_id: str) -> dict:
        """
        Compute and persist the risk score for an entity.

        Returns the full score dict including explain breakdown.
        """
        # Fetch entity
        entity = await self._get_entity(entity_id, tenant_id)
        if not entity:
            raise ValueError(f"Entity not found: {entity_id}")

        # Compute dimensions
        exposure, exposure_explain = await self._compute_exposure(entity, tenant_id)
        sensitivity, sensitivity_explain = self._compute_sensitivity(entity, tenant_id)
        volatility, volatility_explain = await self._compute_volatility(entity, tenant_id)
        confidence = entity.confidence or 1.0
        confidence_penalty = 1.0 - confidence

        # Composite
        composite = (
            exposure * W_EXPOSURE
            + sensitivity * W_SENSITIVITY
            + volatility * W_VOLATILITY
            + confidence_penalty * W_CONFIDENCE
        )
        composite = min(1.0, max(0.0, composite))
        risk_level = classify_risk_level(composite)

        # Build explain JSONB
        explain = {
            "composite_score": round(composite, 4),
            "risk_level": risk_level,
            "dimensions": {
                "exposure": {
                    "score": round(exposure, 4),
                    "weight": W_EXPOSURE,
                    "factors": exposure_explain,
                },
                "sensitivity": {
                    "score": round(sensitivity, 4),
                    "weight": W_SENSITIVITY,
                    "factors": sensitivity_explain,
                },
                "volatility": {
                    "score": round(volatility, 4),
                    "weight": W_VOLATILITY,
                    "factors": volatility_explain,
                },
                "confidence": {
                    "score": round(confidence, 4),
                    "penalty": round(confidence_penalty, 4),
                    "weight": W_CONFIDENCE,
                },
            },
            "scoring_version": SCORING_VERSION,
            "calculated_at": datetime.now(timezone.utc).isoformat(),
        }

        # Upsert risk_scores row
        await self._upsert_score(
            entity_id=entity.id,
            tenant_id=tenant_id,
            composite=composite,
            exposure=exposure,
            sensitivity=sensitivity,
            volatility=volatility,
            confidence=confidence,
            risk_level=risk_level,
            explain=explain,
        )

        return {
            "entity_id": entity.id,
            "external_id": entity.external_id,
            "entity_name": entity.name,
            "composite_score": round(composite, 4),
            "exposure_score": round(exposure, 4),
            "sensitivity_score": round(sensitivity, 4),
            "volatility_score": round(volatility, 4),
            "confidence": round(confidence, 4),
            "risk_level": risk_level,
            "explain": explain,
        }

    # ── Exposure ────────────────────────────────────────────────────────

    async def _compute_exposure(self, entity: EntityDB, tenant_id: str) -> tuple[float, dict]:
        """Compute exposure score based on connections and attributes."""

        # Count external/AI edges
        edges_result = await self.db.execute(
            select(EdgeDB)
            .where(EdgeDB.tenant_id == tenant_id)
            .where((EdgeDB.src_id == entity.id) | (EdgeDB.dst_id == entity.id))
        )
        edges = edges_result.scalars().all()

        # Classify edges
        ai_tool_edges = 0
        external_edges = 0
        for edge in edges:
            other_id = edge.dst_id if edge.src_id == entity.id else edge.src_id
            other = await self._get_entity_by_internal_id(other_id, tenant_id)
            if other:
                if other.entity_type == "ai_tool":
                    ai_tool_edges += 1
                if other.entity_type in ("external", "ai_tool", "saas_app"):
                    external_edges += 1

        # Factor: external connections (0–1, capped at 10)
        ext_conn_val = min(1.0, external_edges / 10.0)
        # Factor: AI integrations (0–1, capped at 5)
        ai_int_val = min(1.0, ai_tool_edges / 5.0)

        # Factor: data volume (from recent events)
        volume_bytes = await self._get_recent_data_volume(entity.id, tenant_id)
        data_vol_val = min(1.0, volume_bytes / 100_000_000)  # 100MB = 1.0

        # Factor: privilege level
        max_privilege = await self._get_max_privilege(entity.id, tenant_id)
        priv_val = PRIVILEGE_WEIGHTS.get(max_privilege, 0.3)

        # Factor: public exposure
        is_public = entity.attributes.get("is_public", False)
        pub_val = 1.0 if is_public else 0.0

        # Weighted exposure
        exposure = (
            ext_conn_val * EF_EXTERNAL_CONN
            + ai_int_val * EF_AI_INTEGRATION
            + data_vol_val * EF_DATA_VOLUME
            + priv_val * EF_PRIVILEGE
            + pub_val * EF_PUBLIC
        )
        exposure = min(1.0, exposure * 1.2)  # Apply amplification factor

        explain = {
            "external_connections": {
                "value": round(ext_conn_val, 4),
                "weight": EF_EXTERNAL_CONN,
                "detail": f"{external_edges} external connections",
            },
            "ai_integrations": {
                "value": round(ai_int_val, 4),
                "weight": EF_AI_INTEGRATION,
                "detail": f"{ai_tool_edges} AI tools connected",
            },
            "data_volume": {
                "value": round(data_vol_val, 4),
                "weight": EF_DATA_VOLUME,
                "detail": f"{volume_bytes // 1_000_000}MB in 7d",
            },
            "privilege_level": {
                "value": round(priv_val, 4),
                "weight": EF_PRIVILEGE,
                "detail": f"{max_privilege} access detected",
            },
            "public_exposure": {
                "value": round(pub_val, 4),
                "weight": EF_PUBLIC,
                "detail": "public" if is_public else "not public",
            },
        }

        return exposure, explain

    # ── Sensitivity ─────────────────────────────────────────────────────

    def _compute_sensitivity(self, entity: EntityDB, tenant_id: str) -> tuple[float, dict]:
        """Compute sensitivity based on name, classification, and tags."""

        # Name heuristic
        name_match = bool(_SENSITIVE_RE.search(entity.name))
        name_val = 0.8 if name_match else 0.0

        # Data classification
        classification = entity.attributes.get("data_classification", "internal")
        class_val = CLASSIFICATION_SCORES.get(classification, 0.3)

        # Sensitivity tags (from attributes or aggregated)
        tags = entity.attributes.get("sensitivity_tags", [])
        tag_val = min(1.0, len(tags) * 0.3) if tags else 0.0

        # Weighted sensitivity
        sensitivity = (
            name_val * SF_NAME_HEURISTIC
            + class_val * SF_DATA_CLASSIFICATION
            + tag_val * SF_SENSITIVITY_TAGS
        )
        sensitivity = min(1.0, sensitivity)

        explain = {
            "name_heuristic": {
                "value": round(name_val, 4),
                "weight": SF_NAME_HEURISTIC,
                "detail": f"matches: {_SENSITIVE_RE.search(entity.name).group()}" if name_match else "no match",
            },
            "data_classification": {
                "value": round(class_val, 4),
                "weight": SF_DATA_CLASSIFICATION,
                "detail": classification,
            },
            "sensitivity_tags": {
                "value": round(tag_val, 4),
                "weight": SF_SENSITIVITY_TAGS,
                "detail": ", ".join(tags) if tags else "none",
            },
        }

        return sensitivity, explain

    # ── Volatility ──────────────────────────────────────────────────────

    async def _compute_volatility(self, entity: EntityDB, tenant_id: str) -> tuple[float, dict]:
        """Compute volatility from connection changes and score history."""

        now = datetime.now(timezone.utc)
        seven_days_ago = now - timedelta(days=7)

        # Connection change rate: edges created/updated in last 7 days vs total
        total_edges_result = await self.db.execute(
            select(func.count(EdgeDB.id))
            .where(EdgeDB.tenant_id == tenant_id)
            .where((EdgeDB.src_id == entity.id) | (EdgeDB.dst_id == entity.id))
        )
        total_edges = total_edges_result.scalar() or 0

        recent_edges_result = await self.db.execute(
            select(func.count(EdgeDB.id))
            .where(EdgeDB.tenant_id == tenant_id)
            .where((EdgeDB.src_id == entity.id) | (EdgeDB.dst_id == entity.id))
            .where(EdgeDB.first_seen >= seven_days_ago)
        )
        recent_edges = recent_edges_result.scalar() or 0

        conn_change = (recent_edges / max(total_edges, 1))

        # Recent AI integrations
        recent_ai_result = await self.db.execute(
            select(func.count(EdgeDB.id))
            .where(EdgeDB.tenant_id == tenant_id)
            .where((EdgeDB.src_id == entity.id) | (EdgeDB.dst_id == entity.id))
            .where(EdgeDB.relation_type.in_(["INTEGRATES_WITH", "ACCESSES"]))
            .where(EdgeDB.first_seen >= seven_days_ago)
        )
        recent_ai = recent_ai_result.scalar() or 0
        recent_ai_val = min(1.0, recent_ai / 3.0)

        # Historical variance (placeholder — no history yet in MVP)
        hist_var_val = 0.0

        # Weighted volatility
        volatility = (
            hist_var_val * VF_HISTORICAL_VAR
            + conn_change * VF_CONN_CHANGE_RATE
            + recent_ai_val * VF_RECENT_AI
        )
        volatility = min(1.0, volatility)

        explain = {
            "historical_variance": {
                "value": round(hist_var_val, 4),
                "weight": VF_HISTORICAL_VAR,
                "detail": "no history yet",
            },
            "connection_change_rate": {
                "value": round(conn_change, 4),
                "weight": VF_CONN_CHANGE_RATE,
                "detail": f"{recent_edges} new of {total_edges} total in 7d",
            },
            "recent_ai_integrations": {
                "value": round(recent_ai_val, 4),
                "weight": VF_RECENT_AI,
                "detail": f"{recent_ai} new AI edges in 7d",
            },
        }

        return volatility, explain

    # ── Helpers ──────────────────────────────────────────────────────────

    async def _get_entity(self, entity_id: str, tenant_id: str) -> Optional[EntityDB]:
        result = await self.db.execute(
            select(EntityDB)
            .where(EntityDB.tenant_id == tenant_id)
            .where((EntityDB.id == entity_id) | (EntityDB.external_id == entity_id))
        )
        return result.scalar_one_or_none()

    async def _get_entity_by_internal_id(self, internal_id: str, tenant_id: str) -> Optional[EntityDB]:
        result = await self.db.execute(
            select(EntityDB)
            .where(EntityDB.id == internal_id)
            .where(EntityDB.tenant_id == tenant_id)
        )
        return result.scalar_one_or_none()

    async def _get_recent_data_volume(self, entity_id: str, tenant_id: str) -> int:
        """Sum data_volume_bytes from events in the last 7 days."""
        seven_days_ago = datetime.now(timezone.utc) - timedelta(days=7)
        result = await self.db.execute(
            select(SecurityEventDB.raw_event)
            .where(SecurityEventDB.tenant_id == tenant_id)
            .where(SecurityEventDB.entity_id == entity_id)
            .where(SecurityEventDB.timestamp >= seven_days_ago)
        )
        rows = result.scalars().all()
        total = 0
        for raw in rows:
            ai_ctx = raw.get("ai_context", {}) if isinstance(raw, dict) else {}
            total += ai_ctx.get("data_volume_bytes", 0)
        return total

    async def _get_max_privilege(self, entity_id: str, tenant_id: str) -> str:
        """Get max privilege level from identities connected to this entity."""
        result = await self.db.execute(
            select(EdgeDB)
            .where(EdgeDB.tenant_id == tenant_id)
            .where(EdgeDB.dst_id == entity_id)
        )
        edges = result.scalars().all()

        max_weight = 0.0
        max_priv = "unknown"
        for edge in edges:
            access_type = edge.attributes.get("access_type", "read")
            weight = PRIVILEGE_WEIGHTS.get(access_type, 0.3)
            if weight > max_weight:
                max_weight = weight
                max_priv = access_type

        return max_priv

    async def _upsert_score(
        self,
        entity_id: str,
        tenant_id: str,
        composite: float,
        exposure: float,
        sensitivity: float,
        volatility: float,
        confidence: float,
        risk_level: str,
        explain: dict,
    ) -> None:
        """Insert or update the risk score for an entity."""
        result = await self.db.execute(
            select(RiskScoreDB)
            .where(RiskScoreDB.tenant_id == tenant_id)
            .where(RiskScoreDB.entity_id == entity_id)
        )
        existing = result.scalar_one_or_none()

        now = datetime.now(timezone.utc)

        if existing:
            existing.composite_score = composite
            existing.exposure_score = exposure
            existing.sensitivity_score = sensitivity
            existing.volatility_score = volatility
            existing.confidence = confidence
            existing.risk_level = risk_level
            existing.explain = explain
            existing.scoring_version = SCORING_VERSION
            existing.calculated_at = now
        else:
            score = RiskScoreDB(
                id=str(uuid4()),
                tenant_id=tenant_id,
                entity_id=entity_id,
                composite_score=composite,
                exposure_score=exposure,
                sensitivity_score=sensitivity,
                volatility_score=volatility,
                confidence=confidence,
                risk_level=risk_level,
                explain=explain,
                scoring_version=SCORING_VERSION,
                calculated_at=now,
            )
            self.db.add(score)

        await self.db.flush()

    async def score_affected_entities(self, entity_ids: list[str], tenant_id: str) -> list[dict]:
        """Score all given entities. Used after ingestion to update affected entities."""
        results = []
        for eid in entity_ids:
            try:
                result = await self.score_entity(eid, tenant_id)
                results.append(result)
            except Exception as e:
                logger.error("Failed to score entity %s: %s", eid, e)
                results.append({"entity_id": eid, "error": str(e)})
        return results
