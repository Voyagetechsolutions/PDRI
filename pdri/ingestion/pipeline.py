"""
Ingestion Pipeline
==================

Synchronous pipeline for processing SecurityEvents:
    Validate → Dedupe → Upsert Entities → Upsert Edges → Trigger Scoring

Author: PDRI Team
Version: 1.0.0
"""

import hashlib
import logging
from datetime import datetime, timezone
from typing import Optional
from uuid import uuid4

from sqlalchemy import select, update
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.ext.asyncio import AsyncSession

from pdri.db.models import (
    EntityDB,
    EdgeDB,
    SecurityEventDB,
    RiskScoreDB,
    MVPFindingDB,
    FindingsEvidenceDB,
)

logger = logging.getLogger(__name__)


# =============================================================================
# Helpers
# =============================================================================


def _fingerprint(event_id: str, source_system_id: str) -> str:
    """SHA256 fingerprint for event deduplication."""
    raw = f"{source_system_id}:{event_id}"
    return hashlib.sha256(raw.encode()).hexdigest()


def _now() -> datetime:
    return datetime.now(timezone.utc)


# =============================================================================
# Entity/Edge Extraction from Event
# =============================================================================

# Mapping of event_type → relation_type for edge creation
EVENT_TO_RELATION = {
    "AI_DATA_ACCESS": "ACCESSES",
    "AI_TOOL_DISCOVERY": "INTEGRATES_WITH",
    "DATA_MOVEMENT": "MOVES_DATA_TO",
    "DATA_EXPORT": "EXPORTS_TO",
    "SYSTEM_ACCESS": "ACCESSES",
    "PRIVILEGE_ESCALATION": "HAS_PERMISSION",
    "IDENTITY_RISK": "AUTHENTICATES_VIA",
    "POLICY_VIOLATION": "ACCESSES",
    "ANOMALY_DETECTED": "ACCESSES",
    "INTEGRATION_CHANGE": "INTEGRATES_WITH",
}


def _extract_entities(event: dict, tenant_id: str) -> list[dict]:
    """Extract entity upsert payloads from a security event."""
    entities = []

    # Primary entity (target)
    entity_id = event.get("entity_id") or event.get("target_entity_id")
    entity_type = event.get("entity_type", "data_store")
    if entity_id:
        attrs = {}
        if event.get("ai_context", {}).get("data_volume_bytes"):
            attrs["data_volume_bytes"] = event["ai_context"]["data_volume_bytes"]
        entities.append({
            "tenant_id": tenant_id,
            "external_id": entity_id,
            "entity_type": entity_type,
            "name": event.get("entity_name", entity_id),
            "attributes": attrs,
        })

    # Identity / AI tool entity (source)
    identity_id = event.get("identity_id")
    ai_context = event.get("ai_context", {})
    if identity_id:
        ai_tool_id = ai_context.get("ai_tool_id")
        if ai_tool_id and ai_tool_id == identity_id:
            # This identity IS the AI tool
            entities.append({
                "tenant_id": tenant_id,
                "external_id": identity_id,
                "entity_type": "ai_tool",
                "name": ai_context.get("model_name", identity_id),
                "attributes": {
                    "vendor": ai_context.get("vendor", "unknown"),
                    "model_name": ai_context.get("model_name"),
                    "is_sanctioned": ai_context.get("is_sanctioned", True),
                    "sends_data_external": ai_context.get("sends_data_external", False),
                },
            })
        else:
            entities.append({
                "tenant_id": tenant_id,
                "external_id": identity_id,
                "entity_type": "identity",
                "name": event.get("identity_name", identity_id),
                "attributes": {
                    "privilege_level": event.get("privilege_level", "unknown"),
                },
            })

    return entities


def _extract_edge(event: dict, tenant_id: str) -> Optional[dict]:
    """Extract a single edge from the event (source → target)."""
    entity_id = event.get("entity_id") or event.get("target_entity_id")
    identity_id = event.get("identity_id")

    if not entity_id or not identity_id:
        return None

    event_type = event.get("event_type", "SYSTEM_ACCESS")
    if isinstance(event_type, str):
        rel_type = EVENT_TO_RELATION.get(event_type, "ACCESSES")
    else:
        rel_type = EVENT_TO_RELATION.get(event_type.value, "ACCESSES")

    attrs = {}
    ai_ctx = event.get("ai_context", {})
    if ai_ctx.get("data_volume_bytes"):
        attrs["data_volume_bytes"] = ai_ctx["data_volume_bytes"]
    attrs["access_type"] = event.get("privilege_level", "read")
    if event.get("exposure_direction"):
        exp_dir = event["exposure_direction"]
        attrs["exposure_direction"] = exp_dir if isinstance(exp_dir, str) else exp_dir.value

    return {
        "tenant_id": tenant_id,
        "src_external_id": identity_id,
        "dst_external_id": entity_id,
        "relation_type": rel_type,
        "weight": 0.9 if rel_type in ("ACCESSES", "EXPORTS_TO") else 0.7,
        "attributes": attrs,
    }


# =============================================================================
# Core Pipeline
# =============================================================================


class IngestionPipeline:
    """
    Process a SecurityEvent through the full pipeline:
        validate → dedupe → upsert entities → upsert edges → store event
    """

    def __init__(self, db: AsyncSession):
        self.db = db

    async def process_event(self, event_data: dict, tenant_id: str) -> dict:
        """
        Process a single SecurityEvent.

        Returns:
            dict with status, entity_ids created/updated, and event record id
        """
        # 1. Compute fingerprint
        event_id = event_data.get("event_id", str(uuid4()))
        source = event_data.get("source_system_id", "unknown")
        fp = _fingerprint(event_id, source)

        # 2. Dedupe check
        existing = await self.db.execute(
            select(SecurityEventDB.id)
            .where(SecurityEventDB.tenant_id == tenant_id)
            .where(SecurityEventDB.fingerprint == fp)
        )
        if existing.scalar_one_or_none():
            logger.info("Duplicate event %s (fingerprint=%s), skipping", event_id, fp[:12])
            return {"status": "duplicate", "event_id": event_id}

        # 3. Upsert entities
        entity_payloads = _extract_entities(event_data, tenant_id)
        entity_id_map = {}  # external_id → internal UUID
        for ent in entity_payloads:
            db_id = await self._upsert_entity(ent)
            entity_id_map[ent["external_id"]] = db_id

        # 4. Upsert edge
        edge_payload = _extract_edge(event_data, tenant_id)
        if edge_payload:
            src_db_id = entity_id_map.get(edge_payload["src_external_id"])
            dst_db_id = entity_id_map.get(edge_payload["dst_external_id"])
            if src_db_id and dst_db_id:
                await self._upsert_edge(edge_payload, src_db_id, dst_db_id)

        # 5. Store event
        primary_entity_id = event_data.get("entity_id") or event_data.get("target_entity_id")
        identity_entity_id = event_data.get("identity_id")
        event_type = event_data.get("event_type", "SYSTEM_ACCESS")
        if not isinstance(event_type, str):
            event_type = event_type.value
        exposure_dir = event_data.get("exposure_direction")
        if exposure_dir and not isinstance(exposure_dir, str):
            exposure_dir = exposure_dir.value

        tags = event_data.get("sensitivity_tags", [])
        if tags and not isinstance(tags[0], str):
            tags = [t.value for t in tags]

        event_record = SecurityEventDB(
            id=str(uuid4()),
            tenant_id=tenant_id,
            event_id=event_id,
            event_type=event_type,
            source_system_id=source,
            timestamp=event_data.get("timestamp", _now()),
            entity_id=entity_id_map.get(primary_entity_id),
            identity_id=entity_id_map.get(identity_entity_id),
            severity=event_data.get("severity", "medium"),
            exposure_direction=exposure_dir,
            sensitivity_tags=tags,
            raw_event=event_data,
            normalized={
                "entity_ids": list(entity_id_map.values()),
                "relation_type": edge_payload.get("relation_type") if edge_payload else None,
            },
            fingerprint=fp,
        )
        self.db.add(event_record)
        await self.db.flush()

        logger.info(
            "Processed event %s: %d entities, edge=%s",
            event_id,
            len(entity_id_map),
            bool(edge_payload),
        )

        return {
            "status": "processed",
            "event_id": event_id,
            "event_db_id": event_record.id,
            "entity_ids": list(entity_id_map.values()),
            "entities_upserted": len(entity_id_map),
        }

    async def _upsert_entity(self, payload: dict) -> str:
        """Insert entity or update last_seen + merge attributes. Returns entity id."""
        result = await self.db.execute(
            select(EntityDB)
            .where(EntityDB.tenant_id == payload["tenant_id"])
            .where(EntityDB.external_id == payload["external_id"])
        )
        existing = result.scalar_one_or_none()

        if existing:
            # Merge attributes
            merged = {**existing.attributes, **payload.get("attributes", {})}
            existing.attributes = merged
            existing.last_seen = _now()
            existing.updated_at = _now()
            # Update name if entity had a placeholder
            if existing.name == existing.external_id and payload["name"] != payload["external_id"]:
                existing.name = payload["name"]
            await self.db.flush()
            return existing.id
        else:
            entity = EntityDB(
                id=str(uuid4()),
                tenant_id=payload["tenant_id"],
                external_id=payload["external_id"],
                entity_type=payload["entity_type"],
                name=payload["name"],
                attributes=payload.get("attributes", {}),
            )
            self.db.add(entity)
            await self.db.flush()
            return entity.id

    async def _upsert_edge(self, payload: dict, src_db_id: str, dst_db_id: str) -> str:
        """Insert edge or update last_seen + merge attributes. Returns edge id."""
        result = await self.db.execute(
            select(EdgeDB)
            .where(EdgeDB.tenant_id == payload["tenant_id"])
            .where(EdgeDB.src_id == src_db_id)
            .where(EdgeDB.dst_id == dst_db_id)
            .where(EdgeDB.relation_type == payload["relation_type"])
        )
        existing = result.scalar_one_or_none()

        if existing:
            merged = {**existing.attributes, **payload.get("attributes", {})}
            existing.attributes = merged
            existing.last_seen = _now()
            existing.weight = max(existing.weight, payload.get("weight", 0.7))
            await self.db.flush()
            return existing.id
        else:
            edge = EdgeDB(
                id=str(uuid4()),
                tenant_id=payload["tenant_id"],
                src_id=src_db_id,
                dst_id=dst_db_id,
                relation_type=payload["relation_type"],
                weight=payload.get("weight", 1.0),
                attributes=payload.get("attributes", {}),
            )
            self.db.add(edge)
            await self.db.flush()
            return edge.id

    async def process_batch(self, events: list[dict], tenant_id: str) -> dict:
        """Process a batch of events. Returns summary."""
        results = {"processed": 0, "duplicates": 0, "errors": 0, "details": []}

        for event_data in events:
            try:
                result = await self.process_event(event_data, tenant_id)
                if result["status"] == "duplicate":
                    results["duplicates"] += 1
                else:
                    results["processed"] += 1
                results["details"].append(result)
            except Exception as e:
                logger.error("Failed to process event: %s", e, exc_info=True)
                results["errors"] += 1
                results["details"].append({
                    "status": "error",
                    "event_id": event_data.get("event_id", "unknown"),
                    "error": str(e),
                })

        return results
