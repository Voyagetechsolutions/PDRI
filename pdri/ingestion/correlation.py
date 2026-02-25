"""
Event Correlation Service
=========================

Correlates related events into single findings.

The correlation layer sits between raw event ingestion and finding generation:

    SecurityEvent → Deduplication → Correlation → Finding

This prevents:
    - Duplicate findings from the same event
    - Finding spam from related events in a time window
    - Loss of context by aggregating related signals

Architecture:
    - Neo4j: Owns risk computation and entity relationships
    - Postgres: Owns event tracking, correlations, and finding lifecycle

Author: PDRI Team
Version: 1.0.0
"""

import hashlib
import logging
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional, Tuple
from uuid import uuid4

from sqlalchemy import select, update, and_
from sqlalchemy.ext.asyncio import AsyncSession

from shared.schemas.events import SecurityEvent, SecurityEventType
from pdri.db.models import ProcessedEventDB, EventCorrelationDB, FindingDB
from pdri.config import settings


logger = logging.getLogger(__name__)


# Correlation time window (minutes)
DEFAULT_CORRELATION_WINDOW = 15

# Severity ranking for max calculation
SEVERITY_RANK = {
    "low": 1,
    "medium": 2,
    "high": 3,
    "critical": 4,
}


def compute_event_fingerprint(event: SecurityEvent) -> str:
    """
    Compute a fingerprint for semantic deduplication.

    Events with the same fingerprint within a time window are considered
    duplicates or related events that should be correlated.

    Fingerprint components:
        - source_system_id
        - target_entity_id (if present)
        - event_type
        - time_bucket (15-minute window)

    Returns:
        SHA256 hex digest (64 chars)
    """
    # Time bucket: round down to 15-minute window
    bucket = event.timestamp.replace(
        minute=(event.timestamp.minute // 15) * 15,
        second=0,
        microsecond=0,
    )

    components = [
        event.source_system_id,
        event.target_entity_id or "no_target",
        event.event_type.value,
        bucket.isoformat(),
    ]

    fingerprint_input = "|".join(components)
    return hashlib.sha256(fingerprint_input.encode()).hexdigest()


def compute_correlation_fingerprint(
    entity_id: str,
    entity_type: str,
    correlation_type: str,
    time_bucket: datetime,
) -> str:
    """
    Compute a fingerprint for correlation grouping.

    Findings with the same correlation fingerprint are merged.
    """
    components = [
        entity_id,
        entity_type,
        correlation_type,
        time_bucket.isoformat(),
    ]

    fingerprint_input = "|".join(components)
    return hashlib.sha256(fingerprint_input.encode()).hexdigest()


def determine_correlation_type(event_type: SecurityEventType) -> str:
    """Map event type to correlation type."""
    mapping = {
        SecurityEventType.AI_DATA_ACCESS: "ai_exposure",
        SecurityEventType.AI_PROMPT_SENSITIVE: "ai_exposure",
        SecurityEventType.AI_API_INTEGRATION: "ai_integration",
        SecurityEventType.AI_AGENT_PRIV_ACCESS: "privilege_escalation",
        SecurityEventType.UNSANCTIONED_AI_TOOL: "shadow_ai",
        SecurityEventType.SYSTEM_ACCESS: "access_pattern",
        SecurityEventType.SYSTEM_AUTH_FAILURE: "auth_failure",
        SecurityEventType.PRIVILEGE_ESCALATION: "privilege_escalation",
        SecurityEventType.DATA_MOVEMENT: "data_movement",
        SecurityEventType.DATA_EXPORT: "data_exfiltration",
        SecurityEventType.DATA_AGGREGATION: "data_aggregation",
    }
    return mapping.get(event_type, "unknown")


def severity_from_event(event: SecurityEvent) -> str:
    """Determine severity based on event properties."""
    # Critical: privileged access + sensitive data + external exposure
    if (
        event.privilege_level in ("admin", "super_admin")
        and event.sensitivity_tags
        and event.exposure_direction.value.startswith("internal_to_")
    ):
        return "critical"

    # High: sensitive data going external or to AI
    if event.exposure_direction.value in ("internal_to_external", "internal_to_ai"):
        if event.sensitivity_tags:
            return "high"
        return "medium"

    # Medium: privileged access
    if event.privilege_level in ("admin", "super_admin"):
        return "medium"

    return "low"


class CorrelationService:
    """
    Service for event correlation and deduplication.

    Handles the event → correlation → finding pipeline.
    """

    def __init__(
        self,
        db: AsyncSession,
        correlation_window_minutes: int = DEFAULT_CORRELATION_WINDOW,
    ):
        self.db = db
        self.window_minutes = correlation_window_minutes

    async def process_event(
        self,
        event: SecurityEvent,
    ) -> Tuple[bool, Optional[str], Optional[str]]:
        """
        Process an incoming event through deduplication and correlation.

        Returns:
            Tuple of:
                - is_new: True if this is a new event (not duplicate)
                - correlation_id: ID of the correlation this event belongs to
                - finding_id: ID of finding if one was generated/updated

        Flow:
            1. Check if event_id already processed → skip if duplicate
            2. Compute fingerprint for semantic deduplication
            3. Find or create correlation group
            4. Add event to correlation
            5. Check if finding should be generated/updated
        """
        # Step 1: Exact duplicate check
        if await self._is_duplicate_event_id(event.event_id):
            logger.debug(f"Skipping duplicate event_id: {event.event_id}")
            return False, None, None

        # Step 2: Compute fingerprint
        fingerprint = compute_event_fingerprint(event)

        # Step 3: Find or create correlation
        correlation = await self._get_or_create_correlation(event, fingerprint)

        # Step 4: Record processed event
        await self._record_processed_event(event, fingerprint, correlation.correlation_id)

        # Step 5: Add event to correlation
        correlation = await self._add_event_to_correlation(correlation, event)

        # Step 6: Check if we should generate/update finding
        finding_id = await self._maybe_generate_finding(correlation)

        logger.info(
            f"Processed event {event.event_id}: "
            f"correlation={correlation.correlation_id}, finding={finding_id}"
        )

        return True, correlation.correlation_id, finding_id

    async def _is_duplicate_event_id(self, event_id: str) -> bool:
        """Check if event_id has already been processed."""
        stmt = select(ProcessedEventDB.id).where(
            ProcessedEventDB.event_id == event_id
        )
        result = await self.db.execute(stmt)
        return result.scalar_one_or_none() is not None

    async def _get_or_create_correlation(
        self,
        event: SecurityEvent,
        fingerprint: str,
    ) -> EventCorrelationDB:
        """Find existing open correlation or create new one."""
        # Calculate time window
        window_start = event.timestamp - timedelta(minutes=self.window_minutes)
        window_end = event.timestamp + timedelta(minutes=self.window_minutes)

        # Look for existing open correlation with same fingerprint
        stmt = select(EventCorrelationDB).where(
            and_(
                EventCorrelationDB.fingerprint == fingerprint,
                EventCorrelationDB.status == "open",
                EventCorrelationDB.window_end >= event.timestamp,
            )
        )
        result = await self.db.execute(stmt)
        existing = result.scalar_one_or_none()

        if existing:
            logger.debug(f"Found existing correlation: {existing.correlation_id}")
            return existing

        # Create new correlation
        correlation_type = determine_correlation_type(event.event_type)
        primary_entity = event.target_entity_id or event.source_system_id

        # Determine entity type from ID pattern or default
        entity_type = "unknown"
        if primary_entity.startswith("datastore:"):
            entity_type = "data_store"
        elif primary_entity.startswith("service:"):
            entity_type = "service"
        elif primary_entity.startswith("ai:") or "chatgpt" in primary_entity.lower():
            entity_type = "ai_tool"

        time_bucket = event.timestamp.replace(
            minute=(event.timestamp.minute // 15) * 15,
            second=0,
            microsecond=0,
        )

        correlation = EventCorrelationDB(
            correlation_id=str(uuid4()),
            fingerprint=fingerprint,
            correlation_type=correlation_type,
            window_start=window_start,
            window_end=window_end,
            window_duration_minutes=self.window_minutes,
            event_count=0,  # Will be incremented in _add_event
            event_ids=[],
            event_types=[],
            primary_entity_id=primary_entity,
            primary_entity_type=entity_type,
            related_entity_ids=[],
            max_severity="low",
            sensitivity_tags=[],
            total_data_volume=0,
            status="open",
        )

        self.db.add(correlation)
        await self.db.flush()

        logger.info(f"Created new correlation: {correlation.correlation_id}")
        return correlation

    async def _record_processed_event(
        self,
        event: SecurityEvent,
        fingerprint: str,
        correlation_id: str,
    ) -> None:
        """Record event as processed for idempotency."""
        processed = ProcessedEventDB(
            event_id=event.event_id,
            event_type=event.event_type.value,
            source_system=event.source_system_id,
            fingerprint=fingerprint,
            correlation_id=correlation_id,
            processing_result="success",
        )

        self.db.add(processed)
        await self.db.flush()

    async def _add_event_to_correlation(
        self,
        correlation: EventCorrelationDB,
        event: SecurityEvent,
    ) -> EventCorrelationDB:
        """Add event to correlation and update aggregates."""
        # Update event list
        event_ids = list(correlation.event_ids or [])
        event_ids.append(event.event_id)

        # Update event types
        event_types = list(correlation.event_types or [])
        if event.event_type.value not in event_types:
            event_types.append(event.event_type.value)

        # Update related entities
        related = list(correlation.related_entity_ids or [])
        if event.identity_id and event.identity_id not in related:
            related.append(event.identity_id)
        if event.source_system_id not in related:
            related.append(event.source_system_id)

        # Update sensitivity tags
        tags = list(correlation.sensitivity_tags or [])
        for tag in event.sensitivity_tags:
            if tag.value not in tags:
                tags.append(tag.value)

        # Update max severity
        event_severity = severity_from_event(event)
        current_rank = SEVERITY_RANK.get(correlation.max_severity, 0)
        new_rank = SEVERITY_RANK.get(event_severity, 0)
        max_severity = event_severity if new_rank > current_rank else correlation.max_severity

        # Update data volume
        total_volume = (correlation.total_data_volume or 0) + (event.data_volume_estimate or 0)

        # Extend window if needed
        window_end = max(correlation.window_end, event.timestamp + timedelta(minutes=5))

        # Update correlation
        stmt = (
            update(EventCorrelationDB)
            .where(EventCorrelationDB.id == correlation.id)
            .values(
                event_count=correlation.event_count + 1,
                event_ids=event_ids,
                event_types=event_types,
                related_entity_ids=related,
                sensitivity_tags=tags,
                max_severity=max_severity,
                total_data_volume=total_volume,
                window_end=window_end,
                updated_at=datetime.now(timezone.utc),
            )
        )
        await self.db.execute(stmt)
        await self.db.flush()

        # Refresh and return
        await self.db.refresh(correlation)
        return correlation

    async def _maybe_generate_finding(
        self,
        correlation: EventCorrelationDB,
    ) -> Optional[str]:
        """
        Generate or update finding from correlation.

        Findings are generated when:
            - Severity is high or critical
            - Event count reaches threshold
            - Correlation window is closing

        Existing findings are updated (not duplicated) using fingerprint.
        """
        # Check if we should generate a finding
        should_generate = (
            correlation.max_severity in ("high", "critical")
            or correlation.event_count >= 3
        )

        if not should_generate:
            return None

        # Check if finding already exists for this correlation fingerprint
        finding_fingerprint = compute_correlation_fingerprint(
            entity_id=correlation.primary_entity_id,
            entity_type=correlation.primary_entity_type,
            correlation_type=correlation.correlation_type,
            time_bucket=correlation.window_start,
        )

        stmt = select(FindingDB).where(FindingDB.fingerprint == finding_fingerprint)
        result = await self.db.execute(stmt)
        existing_finding = result.scalar_one_or_none()

        if existing_finding:
            # Update existing finding
            return await self._update_finding_from_correlation(
                existing_finding, correlation
            )
        else:
            # Create new finding
            return await self._create_finding_from_correlation(
                correlation, finding_fingerprint
            )

    async def _create_finding_from_correlation(
        self,
        correlation: EventCorrelationDB,
        fingerprint: str,
    ) -> str:
        """Create a new finding from correlation data."""
        finding_id = f"f-{uuid4().hex[:8]}"

        # Build evidence refs
        evidence_refs = [
            {"event_id": eid, "event_type": etype}
            for eid, etype in zip(
                correlation.event_ids[:10],  # Limit to 10
                correlation.event_types[:10] if correlation.event_types else ["unknown"] * 10,
            )
        ]

        # Build recommended actions based on correlation type
        recommended_actions = self._generate_recommended_actions(correlation)

        # Calculate risk score (simplified - should use scoring engine)
        risk_score = SEVERITY_RANK.get(correlation.max_severity, 1) / 4.0

        # Calculate SLA based on severity
        sla_hours = {"critical": 4, "high": 24, "medium": 72, "low": 168}
        sla_due = datetime.now(timezone.utc) + timedelta(
            hours=sla_hours.get(correlation.max_severity, 168)
        )

        finding = FindingDB(
            finding_id=finding_id,
            tenant_id="default",
            fingerprint=fingerprint,
            correlation_id=correlation.correlation_id,
            title=self._generate_finding_title(correlation),
            description=self._generate_finding_description(correlation),
            finding_type=correlation.correlation_type,
            severity=correlation.max_severity,
            risk_score=risk_score,
            primary_entity_id=correlation.primary_entity_id,
            primary_entity_type=correlation.primary_entity_type,
            entities_involved=[
                {"entity_id": eid, "entity_type": "unknown", "role": "related"}
                for eid in (correlation.related_entity_ids or [])[:5]
            ],
            evidence_refs=evidence_refs,
            evidence_count=correlation.event_count,
            recommended_actions=recommended_actions,
            status="open",
            sla_due_at=sla_due,
            first_seen_at=correlation.window_start,
            last_seen_at=datetime.now(timezone.utc),
            occurrence_count=1,
            tags=list(correlation.sensitivity_tags or []) + [correlation.correlation_type],
        )

        self.db.add(finding)

        # Update correlation with finding reference
        stmt = (
            update(EventCorrelationDB)
            .where(EventCorrelationDB.id == correlation.id)
            .values(
                finding_id=finding_id,
                finding_generated_at=datetime.now(timezone.utc),
                status="closed",
            )
        )
        await self.db.execute(stmt)
        await self.db.flush()

        logger.info(f"Created finding {finding_id} from correlation {correlation.correlation_id}")
        return finding_id

    async def _update_finding_from_correlation(
        self,
        finding: FindingDB,
        correlation: EventCorrelationDB,
    ) -> str:
        """Update existing finding with new correlation data."""
        # Merge evidence
        existing_evidence = finding.evidence_refs or []
        new_evidence = [
            {"event_id": eid, "event_type": etype}
            for eid, etype in zip(
                correlation.event_ids[:5],
                correlation.event_types[:5] if correlation.event_types else ["unknown"] * 5,
            )
        ]
        # Keep unique by event_id
        seen_ids = {e.get("event_id") for e in existing_evidence}
        for ev in new_evidence:
            if ev.get("event_id") not in seen_ids:
                existing_evidence.append(ev)
                seen_ids.add(ev.get("event_id"))

        # Update severity if higher
        current_rank = SEVERITY_RANK.get(finding.severity, 0)
        new_rank = SEVERITY_RANK.get(correlation.max_severity, 0)
        new_severity = correlation.max_severity if new_rank > current_rank else finding.severity

        # Update finding
        stmt = (
            update(FindingDB)
            .where(FindingDB.id == finding.id)
            .values(
                evidence_refs=existing_evidence[:20],  # Cap at 20
                evidence_count=finding.evidence_count + correlation.event_count,
                severity=new_severity,
                risk_score=max(finding.risk_score, SEVERITY_RANK.get(new_severity, 1) / 4.0),
                last_seen_at=datetime.now(timezone.utc),
                occurrence_count=finding.occurrence_count + 1,
                updated_at=datetime.now(timezone.utc),
            )
        )
        await self.db.execute(stmt)

        # Update correlation with finding reference
        stmt = (
            update(EventCorrelationDB)
            .where(EventCorrelationDB.id == correlation.id)
            .values(
                finding_id=finding.finding_id,
                finding_generated_at=datetime.now(timezone.utc),
                status="closed",
            )
        )
        await self.db.execute(stmt)
        await self.db.flush()

        logger.info(
            f"Updated finding {finding.finding_id} with correlation {correlation.correlation_id}"
        )
        return finding.finding_id

    def _generate_finding_title(self, correlation: EventCorrelationDB) -> str:
        """Generate a concise finding title."""
        type_titles = {
            "ai_exposure": "AI Tool Data Exposure",
            "ai_integration": "AI Integration Risk",
            "shadow_ai": "Unsanctioned AI Tool Detected",
            "privilege_escalation": "Privilege Escalation",
            "data_movement": "Sensitive Data Movement",
            "data_exfiltration": "Data Export to External",
            "auth_failure": "Authentication Anomaly",
            "access_pattern": "Unusual Access Pattern",
        }
        base_title = type_titles.get(correlation.correlation_type, "Security Finding")
        return f"{base_title}: {correlation.primary_entity_id}"

    def _generate_finding_description(self, correlation: EventCorrelationDB) -> str:
        """Generate finding description from correlation."""
        parts = [
            f"Detected {correlation.event_count} related security events "
            f"affecting '{correlation.primary_entity_id}' "
            f"over {correlation.window_duration_minutes} minutes.",
        ]

        if correlation.sensitivity_tags:
            tags = ", ".join(correlation.sensitivity_tags[:3])
            parts.append(f"Sensitivity indicators: {tags}.")

        if correlation.total_data_volume and correlation.total_data_volume > 0:
            volume_mb = correlation.total_data_volume / (1024 * 1024)
            parts.append(f"Estimated data volume: {volume_mb:.2f} MB.")

        return " ".join(parts)

    def _generate_recommended_actions(
        self,
        correlation: EventCorrelationDB,
    ) -> List[Dict[str, Any]]:
        """Generate recommended actions based on correlation type."""
        actions = []

        if correlation.correlation_type in ("ai_exposure", "shadow_ai"):
            actions.append({
                "action": "review_ai_access",
                "target": correlation.primary_entity_id,
                "priority": "high",
                "description": "Review and restrict AI tool access to this data source",
            })

        if correlation.correlation_type == "data_exfiltration":
            actions.append({
                "action": "block_export",
                "target": correlation.primary_entity_id,
                "priority": "critical",
                "description": "Consider blocking data export pending review",
            })

        if correlation.correlation_type == "privilege_escalation":
            actions.append({
                "action": "audit_privileges",
                "target": correlation.primary_entity_id,
                "priority": "high",
                "description": "Audit privilege assignments and access logs",
            })

        # Default action
        if not actions:
            actions.append({
                "action": "investigate",
                "target": correlation.primary_entity_id,
                "priority": "medium",
                "description": "Investigate the related security events",
            })

        return actions
