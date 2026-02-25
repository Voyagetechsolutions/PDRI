"""
Findings Service
================

Service layer for risk findings CRUD and lifecycle management.

This service handles:
    - Persisting findings to PostgreSQL
    - Finding queries with filtering and pagination
    - Status transitions (acknowledge, resolve, etc.)
    - Finding generation triggers

Author: PDRI Team
Version: 1.0.0
"""

import logging
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple
from uuid import uuid4

from sqlalchemy import select, update, delete, func, and_, or_
from sqlalchemy.ext.asyncio import AsyncSession

from shared.schemas.findings import (
    FindingSeverity,
    FindingStatus,
    RiskFinding,
    RiskFindingSummary,
    RiskFindingsResponse,
)
from pdri.db.models import FindingDB, ScoreHistoryDB
from pdri.findings.generator import FindingGenerator
from pdri.scoring.engine import ScoringResult
from pdri.config import settings


logger = logging.getLogger(__name__)


class FindingsService:
    """
    Service for managing risk findings.

    Provides CRUD operations and lifecycle management for findings.
    Integrates with the scoring engine to generate findings
    when risk thresholds are exceeded.

    Example:
        service = FindingsService(db_session)

        # Create finding from scoring result
        finding = await service.create_from_scoring(scoring_result)

        # Query findings
        findings = await service.list_findings(
            status="open",
            severity="high",
            page=1,
            page_size=20
        )

        # Update status
        await service.acknowledge(finding_id, user_id="analyst-1")
    """

    def __init__(self, db: AsyncSession):
        """
        Initialize the findings service.

        Args:
            db: Async database session
        """
        self.db = db
        self.generator = FindingGenerator()

    # =========================================================================
    # Create Operations
    # =========================================================================

    async def create(self, finding: RiskFinding) -> FindingDB:
        """
        Create a new finding in the database.

        Args:
            finding: RiskFinding Pydantic model

        Returns:
            Created FindingDB record
        """
        db_finding = FindingDB(
            finding_id=finding.finding_id,
            title=finding.title,
            description=finding.description,
            finding_type=finding.finding_type,
            severity=finding.severity.value,
            risk_score=finding.risk_score,
            exposure_score=finding.exposure_score,
            volatility_score=finding.volatility_score,
            sensitivity_score=finding.sensitivity_score,
            entities_involved=[e.model_dump() for e in finding.entities_involved],
            exposure_path=finding.exposure_path,
            evidence=[e.model_dump(mode="json") for e in finding.evidence],
            recommendations=[r.model_dump() for r in finding.recommendations],
            status=finding.status.value,
            assigned_to=finding.assigned_to,
            tags=finding.tags,
            metadata=finding.metadata,
            schema_version=finding.metadata.get("schema_version", "1.0.0"),
            producer_version=finding.metadata.get("producer_version", settings.app_version),
        )

        self.db.add(db_finding)
        await self.db.flush()
        await self.db.refresh(db_finding)

        logger.info(f"Created finding: {finding.finding_id}")
        return db_finding

    async def create_from_scoring(
        self,
        result: ScoringResult,
        entity_type: str = "unknown",
        entity_name: Optional[str] = None,
        exposure_path: Optional[List[str]] = None,
        related_events: Optional[List[Dict[str, Any]]] = None,
    ) -> Optional[FindingDB]:
        """
        Create a finding from a scoring result if thresholds are met.

        Gets previous score from history to detect significant changes.

        Args:
            result: ScoringResult from scoring engine
            entity_type: Type of entity
            entity_name: Human-readable name
            exposure_path: Exposure path for the entity
            related_events: Events that contributed to the score

        Returns:
            Created FindingDB if thresholds met, None otherwise
        """
        # Get previous score from history
        previous_score = await self._get_previous_score(result.entity_id)

        # Generate finding (may return None if below thresholds)
        finding = self.generator.from_scoring_result(
            result=result,
            previous_score=previous_score,
            entity_type=entity_type,
            entity_name=entity_name,
            exposure_path=exposure_path,
            related_events=related_events,
        )

        if finding is None:
            return None

        # Persist the finding
        db_finding = await self.create(finding)

        # Record score in history
        await self._record_score_history(result, entity_type)

        return db_finding

    # =========================================================================
    # Read Operations
    # =========================================================================

    async def get(self, finding_id: str) -> Optional[RiskFinding]:
        """
        Get a finding by ID.

        Args:
            finding_id: Finding identifier (e.g., "f-abc12345")

        Returns:
            RiskFinding if found, None otherwise
        """
        stmt = select(FindingDB).where(FindingDB.finding_id == finding_id)
        result = await self.db.execute(stmt)
        db_finding = result.scalar_one_or_none()

        if db_finding is None:
            return None

        return self._to_pydantic(db_finding)

    async def list_findings(
        self,
        status: Optional[str] = None,
        severity: Optional[str] = None,
        finding_type: Optional[str] = None,
        entity_id: Optional[str] = None,
        tags: Optional[List[str]] = None,
        min_risk_score: Optional[float] = None,
        max_risk_score: Optional[float] = None,
        created_after: Optional[datetime] = None,
        created_before: Optional[datetime] = None,
        page: int = 1,
        page_size: int = 20,
        order_by: str = "created_at",
        order_desc: bool = True,
    ) -> RiskFindingsResponse:
        """
        List findings with filtering and pagination.

        Args:
            status: Filter by status (open, acknowledged, etc.)
            severity: Filter by severity (low, medium, high, critical)
            finding_type: Filter by type (risk_detected, threshold_breach, etc.)
            entity_id: Filter by involved entity
            tags: Filter by any of these tags
            min_risk_score: Minimum risk score
            max_risk_score: Maximum risk score
            created_after: Filter by creation date
            created_before: Filter by creation date
            page: Page number (1-indexed)
            page_size: Items per page
            order_by: Field to order by
            order_desc: Descending order

        Returns:
            RiskFindingsResponse with paginated results
        """
        # Build query
        stmt = select(FindingDB)
        count_stmt = select(func.count(FindingDB.id))

        # Apply filters
        filters = []

        if status:
            filters.append(FindingDB.status == status)
        if severity:
            filters.append(FindingDB.severity == severity)
        if finding_type:
            filters.append(FindingDB.finding_type == finding_type)
        if min_risk_score is not None:
            filters.append(FindingDB.risk_score >= min_risk_score)
        if max_risk_score is not None:
            filters.append(FindingDB.risk_score <= max_risk_score)
        if created_after:
            filters.append(FindingDB.created_at >= created_after)
        if created_before:
            filters.append(FindingDB.created_at <= created_before)

        # Entity filter requires JSON query
        if entity_id:
            # This works with PostgreSQL JSONB
            filters.append(
                FindingDB.entities_involved.contains([{"entity_id": entity_id}])
            )

        # Tag filter (any match)
        if tags:
            filters.append(FindingDB.tags.overlap(tags))

        if filters:
            stmt = stmt.where(and_(*filters))
            count_stmt = count_stmt.where(and_(*filters))

        # Get total count
        total_result = await self.db.execute(count_stmt)
        total = total_result.scalar() or 0

        # Apply ordering
        order_column = getattr(FindingDB, order_by, FindingDB.created_at)
        if order_desc:
            stmt = stmt.order_by(order_column.desc())
        else:
            stmt = stmt.order_by(order_column.asc())

        # Apply pagination
        offset = (page - 1) * page_size
        stmt = stmt.offset(offset).limit(page_size)

        # Execute
        result = await self.db.execute(stmt)
        db_findings = result.scalars().all()

        # Convert to summaries
        summaries = [self._to_summary(f) for f in db_findings]

        return RiskFindingsResponse(
            findings=summaries,
            total=total,
            page=page,
            page_size=page_size,
            has_more=(offset + len(summaries)) < total,
        )

    async def get_by_entity(
        self,
        entity_id: str,
        include_resolved: bool = False,
    ) -> List[RiskFinding]:
        """
        Get all findings involving a specific entity.

        Args:
            entity_id: Entity identifier
            include_resolved: Include resolved findings

        Returns:
            List of RiskFinding objects
        """
        stmt = select(FindingDB).where(
            FindingDB.entities_involved.contains([{"entity_id": entity_id}])
        )

        if not include_resolved:
            stmt = stmt.where(
                FindingDB.status.notin_(["resolved", "false_positive"])
            )

        stmt = stmt.order_by(FindingDB.created_at.desc())

        result = await self.db.execute(stmt)
        db_findings = result.scalars().all()

        return [self._to_pydantic(f) for f in db_findings]

    async def get_statistics(self) -> Dict[str, Any]:
        """
        Get finding statistics for dashboard.

        Returns:
            Dictionary with counts by status, severity, etc.
        """
        # Status counts
        status_stmt = select(
            FindingDB.status, func.count(FindingDB.id)
        ).group_by(FindingDB.status)
        status_result = await self.db.execute(status_stmt)
        status_counts = dict(status_result.all())

        # Severity counts
        severity_stmt = select(
            FindingDB.severity, func.count(FindingDB.id)
        ).group_by(FindingDB.severity)
        severity_result = await self.db.execute(severity_stmt)
        severity_counts = dict(severity_result.all())

        # Total open
        open_count = sum(
            status_counts.get(s, 0)
            for s in ["open", "acknowledged", "in_progress"]
        )

        # Average risk score of open findings
        avg_stmt = select(func.avg(FindingDB.risk_score)).where(
            FindingDB.status.in_(["open", "acknowledged", "in_progress"])
        )
        avg_result = await self.db.execute(avg_stmt)
        avg_risk_score = avg_result.scalar() or 0.0

        return {
            "total_open": open_count,
            "by_status": status_counts,
            "by_severity": severity_counts,
            "average_risk_score": round(avg_risk_score, 3),
            "calculated_at": datetime.now(timezone.utc).isoformat(),
        }

    # =========================================================================
    # Update Operations
    # =========================================================================

    async def update(
        self,
        finding_id: str,
        updates: Dict[str, Any],
    ) -> Optional[RiskFinding]:
        """
        Update a finding.

        Args:
            finding_id: Finding identifier
            updates: Dictionary of fields to update

        Returns:
            Updated RiskFinding if found, None otherwise
        """
        # Remove immutable fields
        updates.pop("finding_id", None)
        updates.pop("id", None)
        updates.pop("created_at", None)

        # Always update updated_at
        updates["updated_at"] = datetime.now(timezone.utc)

        stmt = (
            update(FindingDB)
            .where(FindingDB.finding_id == finding_id)
            .values(**updates)
            .returning(FindingDB)
        )

        result = await self.db.execute(stmt)
        db_finding = result.scalar_one_or_none()

        if db_finding is None:
            return None

        await self.db.flush()
        logger.info(f"Updated finding: {finding_id}")

        return self._to_pydantic(db_finding)

    async def acknowledge(
        self,
        finding_id: str,
        user_id: str,
    ) -> Optional[RiskFinding]:
        """
        Acknowledge a finding.

        Args:
            finding_id: Finding identifier
            user_id: User acknowledging the finding

        Returns:
            Updated RiskFinding if found
        """
        return await self.update(
            finding_id,
            {
                "status": FindingStatus.ACKNOWLEDGED.value,
                "assigned_to": user_id,
            },
        )

    async def start_progress(
        self,
        finding_id: str,
        user_id: str,
    ) -> Optional[RiskFinding]:
        """
        Mark a finding as in progress.

        Args:
            finding_id: Finding identifier
            user_id: User working on the finding

        Returns:
            Updated RiskFinding if found
        """
        return await self.update(
            finding_id,
            {
                "status": FindingStatus.IN_PROGRESS.value,
                "assigned_to": user_id,
            },
        )

    async def resolve(
        self,
        finding_id: str,
        user_id: str,
        resolution_notes: Optional[str] = None,
    ) -> Optional[RiskFinding]:
        """
        Resolve a finding.

        Args:
            finding_id: Finding identifier
            user_id: User resolving the finding
            resolution_notes: Optional notes about resolution

        Returns:
            Updated RiskFinding if found
        """
        updates = {
            "status": FindingStatus.RESOLVED.value,
            "assigned_to": user_id,
            "resolved_at": datetime.now(timezone.utc),
        }

        if resolution_notes:
            # Get current finding to append to metadata
            finding = await self.get(finding_id)
            if finding:
                metadata = finding.metadata.copy()
                metadata["resolution_notes"] = resolution_notes
                updates["metadata"] = metadata

        return await self.update(finding_id, updates)

    async def mark_false_positive(
        self,
        finding_id: str,
        user_id: str,
        reason: Optional[str] = None,
    ) -> Optional[RiskFinding]:
        """
        Mark a finding as false positive.

        Args:
            finding_id: Finding identifier
            user_id: User marking as false positive
            reason: Reason for marking as false positive

        Returns:
            Updated RiskFinding if found
        """
        updates = {
            "status": FindingStatus.FALSE_POSITIVE.value,
            "assigned_to": user_id,
            "resolved_at": datetime.now(timezone.utc),
        }

        if reason:
            finding = await self.get(finding_id)
            if finding:
                metadata = finding.metadata.copy()
                metadata["false_positive_reason"] = reason
                updates["metadata"] = metadata

        return await self.update(finding_id, updates)

    async def add_tags(
        self,
        finding_id: str,
        tags: List[str],
    ) -> Optional[RiskFinding]:
        """
        Add tags to a finding.

        Args:
            finding_id: Finding identifier
            tags: Tags to add

        Returns:
            Updated RiskFinding if found
        """
        finding = await self.get(finding_id)
        if finding is None:
            return None

        new_tags = list(set(finding.tags + tags))
        return await self.update(finding_id, {"tags": new_tags})

    # =========================================================================
    # Delete Operations
    # =========================================================================

    async def delete(self, finding_id: str) -> bool:
        """
        Delete a finding.

        Args:
            finding_id: Finding identifier

        Returns:
            True if deleted, False if not found
        """
        stmt = delete(FindingDB).where(FindingDB.finding_id == finding_id)
        result = await self.db.execute(stmt)

        if result.rowcount > 0:
            logger.info(f"Deleted finding: {finding_id}")
            return True
        return False

    # =========================================================================
    # Helper Methods
    # =========================================================================

    async def _get_previous_score(self, entity_id: str) -> Optional[float]:
        """Get the most recent previous score for an entity."""
        stmt = (
            select(ScoreHistoryDB.composite_score)
            .where(ScoreHistoryDB.entity_id == entity_id)
            .order_by(ScoreHistoryDB.calculated_at.desc())
            .limit(1)
        )

        result = await self.db.execute(stmt)
        row = result.scalar_one_or_none()
        return row

    async def _record_score_history(
        self,
        result: ScoringResult,
        entity_type: str,
    ) -> None:
        """Record a score in history for trend tracking."""
        history = ScoreHistoryDB(
            entity_id=result.entity_id,
            entity_type=entity_type,
            composite_score=result.composite_score,
            exposure_score=result.exposure_score,
            volatility_score=result.volatility_score,
            sensitivity_score=result.sensitivity_likelihood,
            factors={
                "external_connections": result.factors.external_connection_factor,
                "ai_integrations": result.factors.ai_integration_factor,
                "data_volume": result.factors.data_volume_factor,
                "privilege_level": result.factors.privilege_level_factor,
                "public_exposure": result.factors.public_exposure_factor,
            },
            scoring_version=result.scoring_version,
            calculated_at=result.calculated_at,
        )

        self.db.add(history)
        await self.db.flush()

    def _to_pydantic(self, db_finding: FindingDB) -> RiskFinding:
        """Convert database model to Pydantic model."""
        from shared.schemas.findings import EntityRef, EventRef, Recommendation

        return RiskFinding(
            finding_id=db_finding.finding_id,
            title=db_finding.title,
            description=db_finding.description,
            finding_type=db_finding.finding_type,
            severity=FindingSeverity(db_finding.severity),
            risk_score=db_finding.risk_score,
            exposure_score=db_finding.exposure_score,
            volatility_score=db_finding.volatility_score,
            sensitivity_score=db_finding.sensitivity_score,
            entities_involved=[
                EntityRef(**e) for e in (db_finding.entities_involved or [])
            ],
            exposure_path=db_finding.exposure_path or [],
            evidence=[EventRef(**e) for e in (db_finding.evidence or [])],
            recommendations=[
                Recommendation(**r) for r in (db_finding.recommendations or [])
            ],
            status=FindingStatus(db_finding.status),
            assigned_to=db_finding.assigned_to,
            resolved_at=db_finding.resolved_at,
            tags=db_finding.tags or [],
            metadata=db_finding.metadata or {},
            created_at=db_finding.created_at,
            updated_at=db_finding.updated_at,
        )

    def _to_summary(self, db_finding: FindingDB) -> RiskFindingSummary:
        """Convert database model to summary model."""
        return RiskFindingSummary(
            finding_id=db_finding.finding_id,
            title=db_finding.title,
            severity=FindingSeverity(db_finding.severity),
            risk_score=db_finding.risk_score,
            status=FindingStatus(db_finding.status),
            entity_count=len(db_finding.entities_involved or []),
            created_at=db_finding.created_at,
            updated_at=db_finding.updated_at,
        )
