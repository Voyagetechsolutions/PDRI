"""
Platform Gateway API
====================

6 REST endpoints for the Platform layer to consume PDRI:
    1. GET  /risk/findings           - List findings (paginated, filterable)
    2. GET  /risk/findings/{id}      - Finding detail + evidence
    3. PUT  /risk/findings/{id}/status - Update finding status
    4. GET  /entities/{id}/risk-score - Entity score + explain
    5. GET  /graph/entities          - Subgraph around a center entity
    6. GET  /dashboard/overview      - Tenant dashboard metrics

Author: PDRI Team
Version: 1.0.0
"""

import logging
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field
from sqlalchemy import select, func, and_
from sqlalchemy.ext.asyncio import AsyncSession

from pdri.db.models import (
    EntityDB,
    EdgeDB,
    SecurityEventDB,
    RiskScoreDB,
    MVPFindingDB,
    FindingsEvidenceDB,
)
from pdri.db.session import get_db

logger = logging.getLogger(__name__)

router = APIRouter(tags=["Platform Gateway"])


# =============================================================================
# Response Models
# =============================================================================


class FindingSummary(BaseModel):
    id: str
    title: str
    finding_type: str
    severity: str
    risk_score: float
    status: str
    primary_entity_id: Optional[str] = None
    created_at: Optional[str] = None

    class Config:
        from_attributes = True


class FindingsListResponse(BaseModel):
    findings: list[FindingSummary]
    total: int
    page: int
    page_size: int
    has_more: bool


class EvidenceItem(BaseModel):
    id: str
    evidence_type: str
    summary: str
    event_id: Optional[str] = None
    data: dict = Field(default_factory=dict)

    class Config:
        from_attributes = True


class FindingDetailResponse(BaseModel):
    id: str
    title: str
    description: str
    finding_type: str
    severity: str
    risk_score: float
    status: str
    primary_entity_id: Optional[str] = None
    affected_entities: list = Field(default_factory=list)
    recommendations: list = Field(default_factory=list)
    tags: list = Field(default_factory=list)
    sla_due_at: Optional[str] = None
    acknowledged_by: Optional[str] = None
    resolved_at: Optional[str] = None
    created_at: Optional[str] = None
    updated_at: Optional[str] = None
    evidence: list[EvidenceItem] = Field(default_factory=list)

    class Config:
        from_attributes = True


class StatusUpdateRequest(BaseModel):
    status: str = Field(..., pattern="^(acknowledged|in_progress|resolved|false_positive)$")
    acknowledged_by: Optional[str] = None
    reason: Optional[str] = None


class EntityScoreResponse(BaseModel):
    entity_id: str
    name: str
    entity_type: str
    composite_score: float
    exposure_score: float
    sensitivity_score: float
    volatility_score: float
    confidence: float
    risk_level: str
    explain: dict
    calculated_at: Optional[str] = None


class GraphNode(BaseModel):
    id: str
    external_id: str
    entity_type: str
    name: str
    risk_level: Optional[str] = None
    composite_score: Optional[float] = None

    class Config:
        from_attributes = True


class GraphEdge(BaseModel):
    id: str
    src_id: str
    dst_id: str
    relation_type: str
    weight: float

    class Config:
        from_attributes = True


class SubgraphResponse(BaseModel):
    center: GraphNode
    nodes: list[GraphNode]
    edges: list[GraphEdge]


class DashboardResponse(BaseModel):
    total_entities: int
    risk_distribution: dict
    open_findings: int
    findings_by_severity: dict
    top_risks: list
    recent_findings: list
    trend: dict


# =============================================================================
# 1. GET /risk/findings
# =============================================================================


@router.get("/risk/findings", response_model=FindingsListResponse)
async def list_findings(
    tenant_id: str = Query(...),
    status: Optional[str] = Query(None),
    severity: Optional[str] = Query(None),
    finding_type: Optional[str] = Query(None),
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
    db: AsyncSession = Depends(get_db),
):
    """List findings with filtering and pagination."""
    q = select(MVPFindingDB).where(MVPFindingDB.tenant_id == tenant_id)

    if status:
        q = q.where(MVPFindingDB.status == status)
    if severity:
        q = q.where(MVPFindingDB.severity == severity)
    if finding_type:
        q = q.where(MVPFindingDB.finding_type == finding_type)

    # Count total
    count_q = select(func.count()).select_from(q.subquery())
    total = (await db.execute(count_q)).scalar() or 0

    # Paginate
    offset = (page - 1) * page_size
    q = q.order_by(MVPFindingDB.created_at.desc()).offset(offset).limit(page_size)
    result = await db.execute(q)
    rows = result.scalars().all()

    findings = [
        FindingSummary(
            id=f.id,
            title=f.title,
            finding_type=f.finding_type,
            severity=f.severity,
            risk_score=f.risk_score,
            status=f.status,
            primary_entity_id=f.primary_entity_id,
            created_at=f.created_at.isoformat() if f.created_at else None,
        )
        for f in rows
    ]

    return FindingsListResponse(
        findings=findings,
        total=total,
        page=page,
        page_size=page_size,
        has_more=(offset + page_size) < total,
    )


# =============================================================================
# 2. GET /risk/findings/{id}
# =============================================================================


@router.get("/risk/findings/{finding_id}", response_model=FindingDetailResponse)
async def get_finding(
    finding_id: str,
    tenant_id: str = Query(...),
    db: AsyncSession = Depends(get_db),
):
    """Get full finding detail with evidence."""
    result = await db.execute(
        select(MVPFindingDB)
        .where(MVPFindingDB.id == finding_id)
        .where(MVPFindingDB.tenant_id == tenant_id)
    )
    finding = result.scalar_one_or_none()
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")

    # Fetch evidence
    ev_result = await db.execute(
        select(FindingsEvidenceDB)
        .where(FindingsEvidenceDB.finding_id == finding_id)
        .where(FindingsEvidenceDB.tenant_id == tenant_id)
    )
    evidence_rows = ev_result.scalars().all()

    evidence = [
        EvidenceItem(
            id=e.id,
            evidence_type=e.evidence_type,
            summary=e.summary,
            event_id=e.event_id,
            data=e.data,
        )
        for e in evidence_rows
    ]

    return FindingDetailResponse(
        id=finding.id,
        title=finding.title,
        description=finding.description,
        finding_type=finding.finding_type,
        severity=finding.severity,
        risk_score=finding.risk_score,
        status=finding.status,
        primary_entity_id=finding.primary_entity_id,
        affected_entities=finding.affected_entities,
        recommendations=finding.recommendations,
        tags=finding.tags,
        sla_due_at=finding.sla_due_at.isoformat() if finding.sla_due_at else None,
        acknowledged_by=finding.acknowledged_by,
        resolved_at=finding.resolved_at.isoformat() if finding.resolved_at else None,
        created_at=finding.created_at.isoformat() if finding.created_at else None,
        updated_at=finding.updated_at.isoformat() if finding.updated_at else None,
        evidence=evidence,
    )


# =============================================================================
# 3. PUT /risk/findings/{id}/status
# =============================================================================


@router.put("/risk/findings/{finding_id}/status")
async def update_finding_status(
    finding_id: str,
    body: StatusUpdateRequest,
    tenant_id: str = Query(...),
    db: AsyncSession = Depends(get_db),
):
    """Update finding status (acknowledge, resolve, mark as false positive)."""
    result = await db.execute(
        select(MVPFindingDB)
        .where(MVPFindingDB.id == finding_id)
        .where(MVPFindingDB.tenant_id == tenant_id)
    )
    finding = result.scalar_one_or_none()
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")

    finding.status = body.status
    if body.acknowledged_by:
        finding.acknowledged_by = body.acknowledged_by
    if body.status == "resolved":
        from datetime import datetime, timezone
        finding.resolved_at = datetime.now(timezone.utc)

    await db.flush()

    return {
        "id": finding.id,
        "status": finding.status,
        "acknowledged_by": finding.acknowledged_by,
        "resolved_at": finding.resolved_at.isoformat() if finding.resolved_at else None,
    }


# =============================================================================
# 4. GET /entities/{id}/risk-score
# =============================================================================


@router.get("/entities/{entity_id}/risk-score", response_model=EntityScoreResponse)
async def get_entity_score(
    entity_id: str,
    tenant_id: str = Query(...),
    db: AsyncSession = Depends(get_db),
):
    """Get risk score with full explain breakdown for an entity."""
    # Find entity
    ent_result = await db.execute(
        select(EntityDB)
        .where(EntityDB.tenant_id == tenant_id)
        .where((EntityDB.id == entity_id) | (EntityDB.external_id == entity_id))
    )
    entity = ent_result.scalar_one_or_none()
    if not entity:
        raise HTTPException(status_code=404, detail="Entity not found")

    # Find score
    score_result = await db.execute(
        select(RiskScoreDB)
        .where(RiskScoreDB.entity_id == entity.id)
        .where(RiskScoreDB.tenant_id == tenant_id)
    )
    score = score_result.scalar_one_or_none()
    if not score:
        raise HTTPException(status_code=404, detail="Score not computed yet")

    return EntityScoreResponse(
        entity_id=entity.id,
        name=entity.name,
        entity_type=entity.entity_type,
        composite_score=score.composite_score,
        exposure_score=score.exposure_score,
        sensitivity_score=score.sensitivity_score,
        volatility_score=score.volatility_score,
        confidence=score.confidence,
        risk_level=score.risk_level,
        explain=score.explain,
        calculated_at=score.calculated_at.isoformat() if score.calculated_at else None,
    )


# =============================================================================
# 5. GET /graph/entities
# =============================================================================


@router.get("/graph/entities", response_model=SubgraphResponse)
async def get_subgraph(
    center_id: str = Query(...),
    tenant_id: str = Query(...),
    depth: int = Query(1, ge=1, le=2),
    db: AsyncSession = Depends(get_db),
):
    """Get subgraph around a center entity (depth 1 or 2)."""
    # Get center entity
    center_result = await db.execute(
        select(EntityDB)
        .where(EntityDB.tenant_id == tenant_id)
        .where((EntityDB.id == center_id) | (EntityDB.external_id == center_id))
    )
    center = center_result.scalar_one_or_none()
    if not center:
        raise HTTPException(status_code=404, detail="Center entity not found")

    # BFS to collect nodes and edges
    visited_ids = {center.id}
    frontier = [center.id]
    all_nodes = {center.id: center}
    all_edges = []

    for _ in range(depth):
        if not frontier:
            break
        next_frontier = []
        for node_id in frontier:
            edges_result = await db.execute(
                select(EdgeDB)
                .where(EdgeDB.tenant_id == tenant_id)
                .where((EdgeDB.src_id == node_id) | (EdgeDB.dst_id == node_id))
            )
            for edge in edges_result.scalars().all():
                all_edges.append(edge)
                other_id = edge.dst_id if edge.src_id == node_id else edge.src_id
                if other_id not in visited_ids:
                    visited_ids.add(other_id)
                    next_frontier.append(other_id)
                    ent_result = await db.execute(
                        select(EntityDB).where(EntityDB.id == other_id)
                    )
                    ent = ent_result.scalar_one_or_none()
                    if ent:
                        all_nodes[ent.id] = ent
        frontier = next_frontier

    # Fetch scores for all nodes
    scores_map = {}
    if all_nodes:
        scores_result = await db.execute(
            select(RiskScoreDB)
            .where(RiskScoreDB.tenant_id == tenant_id)
            .where(RiskScoreDB.entity_id.in_(list(all_nodes.keys())))
        )
        for s in scores_result.scalars().all():
            scores_map[s.entity_id] = s

    def _node(e: EntityDB) -> GraphNode:
        sc = scores_map.get(e.id)
        return GraphNode(
            id=e.id,
            external_id=e.external_id,
            entity_type=e.entity_type,
            name=e.name,
            risk_level=sc.risk_level if sc else None,
            composite_score=sc.composite_score if sc else None,
        )

    # Dedupe edges
    seen_edge_ids = set()
    unique_edges = []
    for e in all_edges:
        if e.id not in seen_edge_ids:
            seen_edge_ids.add(e.id)
            unique_edges.append(e)

    return SubgraphResponse(
        center=_node(center),
        nodes=[_node(n) for n in all_nodes.values() if n.id != center.id],
        edges=[
            GraphEdge(
                id=e.id,
                src_id=e.src_id,
                dst_id=e.dst_id,
                relation_type=e.relation_type,
                weight=e.weight,
            )
            for e in unique_edges
        ],
    )


# =============================================================================
# 6. GET /dashboard/overview
# =============================================================================


@router.get("/dashboard/overview", response_model=DashboardResponse)
async def dashboard_overview(
    tenant_id: str = Query(...),
    db: AsyncSession = Depends(get_db),
):
    """Tenant dashboard with risk distribution, findings summary, and top risks."""

    # Total entities
    total = (await db.execute(
        select(func.count(EntityDB.id)).where(EntityDB.tenant_id == tenant_id)
    )).scalar() or 0

    # Risk distribution
    dist = {}
    for level in ["critical", "high", "medium", "low", "minimal"]:
        count = (await db.execute(
            select(func.count(RiskScoreDB.id))
            .where(RiskScoreDB.tenant_id == tenant_id)
            .where(RiskScoreDB.risk_level == level)
        )).scalar() or 0
        dist[level] = count

    # Open findings count
    open_count = (await db.execute(
        select(func.count(MVPFindingDB.id))
        .where(MVPFindingDB.tenant_id == tenant_id)
        .where(MVPFindingDB.status.in_(["open", "acknowledged", "in_progress"]))
    )).scalar() or 0

    # Findings by severity
    findings_sev = {}
    for sev in ["critical", "high", "medium", "low"]:
        c = (await db.execute(
            select(func.count(MVPFindingDB.id))
            .where(MVPFindingDB.tenant_id == tenant_id)
            .where(MVPFindingDB.severity == sev)
            .where(MVPFindingDB.status.in_(["open", "acknowledged", "in_progress"]))
        )).scalar() or 0
        findings_sev[sev] = c

    # Top 5 highest risk entities
    top_result = await db.execute(
        select(RiskScoreDB, EntityDB)
        .join(EntityDB, RiskScoreDB.entity_id == EntityDB.id)
        .where(RiskScoreDB.tenant_id == tenant_id)
        .order_by(RiskScoreDB.composite_score.desc())
        .limit(5)
    )
    top_risks = [
        {
            "entity_id": score.entity_id,
            "name": entity.name,
            "entity_type": entity.entity_type,
            "composite_score": round(score.composite_score, 4),
            "risk_level": score.risk_level,
        }
        for score, entity in top_result.all()
    ]

    # Recent findings (last 10)
    recent_result = await db.execute(
        select(MVPFindingDB)
        .where(MVPFindingDB.tenant_id == tenant_id)
        .order_by(MVPFindingDB.created_at.desc())
        .limit(10)
    )
    recent = [
        {
            "id": f.id,
            "title": f.title,
            "severity": f.severity,
            "finding_type": f.finding_type,
            "status": f.status,
            "created_at": f.created_at.isoformat() if f.created_at else None,
        }
        for f in recent_result.scalars().all()
    ]

    # Trend: entities with increasing/decreasing/stable scores (simplified)
    trend = {"scores_increasing": 0, "scores_decreasing": 0, "stable": total}

    return DashboardResponse(
        total_entities=total,
        risk_distribution=dist,
        open_findings=open_count,
        findings_by_severity=findings_sev,
        top_risks=top_risks,
        recent_findings=recent,
        trend=trend,
    )
