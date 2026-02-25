"""
Findings API Routes
===================

REST API endpoints for risk findings CRUD and lifecycle management.

All endpoints under /api/v1/findings require authentication.

Author: PDRI Team
Version: 1.0.0
"""

import logging
from datetime import datetime
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, Field
from sqlalchemy.ext.asyncio import AsyncSession

from pdri.db import get_db
from pdri.api.auth import get_current_user, require_role
from pdri.findings.service import FindingsService
from shared.schemas.findings import (
    FindingSeverity,
    FindingStatus,
    RiskFinding,
    RiskFindingsResponse,
)


logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/v1/findings",
    tags=["Findings"],
    responses={401: {"description": "Unauthorized"}},
)


# =============================================================================
# Request/Response Models
# =============================================================================


class FindingUpdateRequest(BaseModel):
    """Request model for updating a finding."""

    assigned_to: Optional[str] = Field(None, description="User/team to assign")
    tags: Optional[List[str]] = Field(None, description="Replace tags")


class AcknowledgeRequest(BaseModel):
    """Request model for acknowledging a finding."""

    user_id: str = Field(..., description="User acknowledging the finding")


class ResolveRequest(BaseModel):
    """Request model for resolving a finding."""

    user_id: str = Field(..., description="User resolving the finding")
    resolution_notes: Optional[str] = Field(None, description="Notes about resolution")


class FalsePositiveRequest(BaseModel):
    """Request model for marking a finding as false positive."""

    user_id: str = Field(..., description="User marking as false positive")
    reason: Optional[str] = Field(None, description="Reason for false positive")


class AddTagsRequest(BaseModel):
    """Request model for adding tags."""

    tags: List[str] = Field(..., description="Tags to add")


class FindingStatistics(BaseModel):
    """Response model for finding statistics."""

    total_open: int
    by_status: Dict[str, int]
    by_severity: Dict[str, int]
    average_risk_score: float
    calculated_at: str


# =============================================================================
# List & Query Endpoints
# =============================================================================


@router.get(
    "",
    response_model=RiskFindingsResponse,
    summary="List risk findings",
    description="Query risk findings with filtering and pagination.",
)
async def list_findings(
    status: Optional[str] = Query(
        None,
        description="Filter by status: open, acknowledged, in_progress, resolved, false_positive",
    ),
    severity: Optional[str] = Query(
        None,
        description="Filter by severity: low, medium, high, critical",
    ),
    finding_type: Optional[str] = Query(
        None,
        description="Filter by type: risk_detected, threshold_breach, ai_exposure, anomaly",
    ),
    entity_id: Optional[str] = Query(
        None,
        description="Filter by involved entity ID",
    ),
    tags: Optional[str] = Query(
        None,
        description="Comma-separated tags to filter by (any match)",
    ),
    min_risk_score: Optional[float] = Query(
        None,
        ge=0.0,
        le=1.0,
        description="Minimum risk score",
    ),
    max_risk_score: Optional[float] = Query(
        None,
        ge=0.0,
        le=1.0,
        description="Maximum risk score",
    ),
    created_after: Optional[datetime] = Query(
        None,
        description="Filter findings created after this date (ISO format)",
    ),
    created_before: Optional[datetime] = Query(
        None,
        description="Filter findings created before this date (ISO format)",
    ),
    page: int = Query(1, ge=1, description="Page number"),
    page_size: int = Query(20, ge=1, le=100, description="Items per page"),
    order_by: str = Query(
        "created_at",
        description="Field to order by: created_at, risk_score, severity",
    ),
    order_desc: bool = Query(True, description="Descending order"),
    db: AsyncSession = Depends(get_db),
    _user: dict = Depends(get_current_user),
):
    """
    List risk findings with optional filtering.

    Returns paginated results with summary view of each finding.
    Use GET /api/v1/findings/{finding_id} for full details.
    """
    service = FindingsService(db)

    # Parse tags
    tag_list = None
    if tags:
        tag_list = [t.strip() for t in tags.split(",") if t.strip()]

    return await service.list_findings(
        status=status,
        severity=severity,
        finding_type=finding_type,
        entity_id=entity_id,
        tags=tag_list,
        min_risk_score=min_risk_score,
        max_risk_score=max_risk_score,
        created_after=created_after,
        created_before=created_before,
        page=page,
        page_size=page_size,
        order_by=order_by,
        order_desc=order_desc,
    )


@router.get(
    "/statistics",
    response_model=FindingStatistics,
    summary="Get finding statistics",
    description="Get aggregate statistics about findings for dashboards.",
)
async def get_statistics(
    db: AsyncSession = Depends(get_db),
    _user: dict = Depends(get_current_user),
):
    """
    Get finding statistics for dashboards.

    Returns counts by status, severity, and average risk score.
    """
    service = FindingsService(db)
    stats = await service.get_statistics()
    return FindingStatistics(**stats)


@router.get(
    "/entity/{entity_id}",
    response_model=List[RiskFinding],
    summary="Get findings for entity",
    description="Get all findings involving a specific entity.",
)
async def get_findings_for_entity(
    entity_id: str,
    include_resolved: bool = Query(
        False,
        description="Include resolved and false positive findings",
    ),
    db: AsyncSession = Depends(get_db),
    _user: dict = Depends(get_current_user),
):
    """
    Get all findings involving a specific entity.

    Returns full finding details (not summaries).
    """
    service = FindingsService(db)
    return await service.get_by_entity(
        entity_id=entity_id,
        include_resolved=include_resolved,
    )


# =============================================================================
# Single Finding Endpoints
# =============================================================================


@router.get(
    "/{finding_id}",
    response_model=RiskFinding,
    summary="Get finding details",
    description="Get full details of a specific finding.",
)
async def get_finding(
    finding_id: str,
    db: AsyncSession = Depends(get_db),
    _user: dict = Depends(get_current_user),
):
    """
    Get full details of a specific finding.

    Includes all entities, evidence, recommendations, and metadata.
    """
    service = FindingsService(db)
    finding = await service.get(finding_id)

    if finding is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Finding not found: {finding_id}",
        )

    return finding


@router.patch(
    "/{finding_id}",
    response_model=RiskFinding,
    summary="Update finding",
    description="Update finding properties (assigned_to, tags).",
)
async def update_finding(
    finding_id: str,
    request: FindingUpdateRequest,
    db: AsyncSession = Depends(get_db),
    _user: dict = Depends(require_role(["admin", "analyst"])),
):
    """
    Update finding properties.

    Only certain fields can be updated directly. Use specific
    endpoints for status transitions.
    """
    service = FindingsService(db)

    updates = {}
    if request.assigned_to is not None:
        updates["assigned_to"] = request.assigned_to
    if request.tags is not None:
        updates["tags"] = request.tags

    if not updates:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="No valid updates provided",
        )

    finding = await service.update(finding_id, updates)

    if finding is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Finding not found: {finding_id}",
        )

    return finding


@router.delete(
    "/{finding_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Delete finding",
    description="Delete a finding (admin only).",
)
async def delete_finding(
    finding_id: str,
    db: AsyncSession = Depends(get_db),
    _user: dict = Depends(require_role(["admin"])),
):
    """
    Delete a finding.

    This action is permanent. Consider marking as false positive instead.
    """
    service = FindingsService(db)
    deleted = await service.delete(finding_id)

    if not deleted:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Finding not found: {finding_id}",
        )


# =============================================================================
# Status Transition Endpoints
# =============================================================================


@router.post(
    "/{finding_id}/acknowledge",
    response_model=RiskFinding,
    summary="Acknowledge finding",
    description="Acknowledge a finding, indicating it has been reviewed.",
)
async def acknowledge_finding(
    finding_id: str,
    request: AcknowledgeRequest,
    db: AsyncSession = Depends(get_db),
    _user: dict = Depends(require_role(["admin", "analyst"])),
):
    """
    Acknowledge a finding.

    Transitions status from 'open' to 'acknowledged'.
    Assigns the finding to the acknowledging user.
    """
    service = FindingsService(db)
    finding = await service.acknowledge(finding_id, request.user_id)

    if finding is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Finding not found: {finding_id}",
        )

    return finding


@router.post(
    "/{finding_id}/start-progress",
    response_model=RiskFinding,
    summary="Start progress on finding",
    description="Mark a finding as actively being worked on.",
)
async def start_progress(
    finding_id: str,
    request: AcknowledgeRequest,
    db: AsyncSession = Depends(get_db),
    _user: dict = Depends(require_role(["admin", "analyst"])),
):
    """
    Start progress on a finding.

    Transitions status to 'in_progress'.
    """
    service = FindingsService(db)
    finding = await service.start_progress(finding_id, request.user_id)

    if finding is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Finding not found: {finding_id}",
        )

    return finding


@router.post(
    "/{finding_id}/resolve",
    response_model=RiskFinding,
    summary="Resolve finding",
    description="Mark a finding as resolved.",
)
async def resolve_finding(
    finding_id: str,
    request: ResolveRequest,
    db: AsyncSession = Depends(get_db),
    _user: dict = Depends(require_role(["admin", "analyst"])),
):
    """
    Resolve a finding.

    Transitions status to 'resolved' and records resolution time.
    """
    service = FindingsService(db)
    finding = await service.resolve(
        finding_id,
        request.user_id,
        request.resolution_notes,
    )

    if finding is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Finding not found: {finding_id}",
        )

    return finding


@router.post(
    "/{finding_id}/false-positive",
    response_model=RiskFinding,
    summary="Mark as false positive",
    description="Mark a finding as a false positive.",
)
async def mark_false_positive(
    finding_id: str,
    request: FalsePositiveRequest,
    db: AsyncSession = Depends(get_db),
    _user: dict = Depends(require_role(["admin", "analyst"])),
):
    """
    Mark a finding as false positive.

    This helps improve the system by identifying inaccurate findings.
    """
    service = FindingsService(db)
    finding = await service.mark_false_positive(
        finding_id,
        request.user_id,
        request.reason,
    )

    if finding is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Finding not found: {finding_id}",
        )

    return finding


# =============================================================================
# Tag Management
# =============================================================================


@router.post(
    "/{finding_id}/tags",
    response_model=RiskFinding,
    summary="Add tags to finding",
    description="Add tags to a finding for categorization.",
)
async def add_tags(
    finding_id: str,
    request: AddTagsRequest,
    db: AsyncSession = Depends(get_db),
    _user: dict = Depends(require_role(["admin", "analyst"])),
):
    """
    Add tags to a finding.

    Tags are additive - existing tags are preserved.
    Use PATCH to replace all tags.
    """
    service = FindingsService(db)
    finding = await service.add_tags(finding_id, request.tags)

    if finding is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Finding not found: {finding_id}",
        )

    return finding
