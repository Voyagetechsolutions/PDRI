"""
PDRI Risk Velocity Routes
=========================

API endpoints for temporal risk trend analysis.

These endpoints provide:
    - Risk velocity calculation per entity
    - High velocity entity discovery
    - Threshold breach predictions
    - Historical trend data

Author: PDRI Team
Version: 1.0.0
"""

from typing import Any, Dict, List, Optional
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field

from pdri.api.dependencies import ServiceContainer, get_db
from pdri.db import AsyncSession
from pdri.scoring.velocity import RiskVelocityService, TrendDirection


router = APIRouter(prefix="/api/v1/velocity", tags=["Risk Velocity"])


# =============================================================================
# Response Models
# =============================================================================

class VelocityWindow(BaseModel):
    """Velocity for a specific time window."""
    day_7: float = Field(alias="7_day", description="Score change over 7 days")
    day_30: float = Field(alias="30_day", description="Score change over 30 days")
    day_90: float = Field(alias="90_day", description="Score change over 90 days")


class ProjectionWindow(BaseModel):
    """Projected score for a future time."""
    score: float = Field(description="Projected score (0-1)")
    severity: str = Field(description="Projected severity level")


class Projections(BaseModel):
    """All future projections."""
    day_7: ProjectionWindow = Field(alias="7_day")
    day_14: ProjectionWindow = Field(alias="14_day")
    day_30: ProjectionWindow = Field(alias="30_day")


class ThresholdPredictions(BaseModel):
    """Predictions for reaching risk thresholds."""
    days_to_critical: Optional[int] = Field(
        description="Days until CRITICAL threshold (0.85)"
    )
    days_to_high: Optional[int] = Field(
        description="Days until HIGH threshold (0.70)"
    )


class HistoryPoint(BaseModel):
    """A point in score history."""
    timestamp: str
    score: float
    exposure: float
    volatility: float
    sensitivity: float


class VelocityResponse(BaseModel):
    """Full velocity analysis response."""
    entity_id: str
    current_score: float
    velocity: VelocityWindow
    trend: str = Field(description="Trend direction: increasing, decreasing, stable, volatile")
    volatility: float = Field(description="Score volatility (std deviation)")
    projections: Projections
    threshold_predictions: ThresholdPredictions
    confidence: float = Field(description="Prediction confidence (R-squared)")
    data_points: int = Field(description="Number of historical data points")
    history: List[HistoryPoint]


class HighVelocityEntity(BaseModel):
    """Entity with high risk velocity."""
    entity_id: str
    current_score: float
    velocity_7d: float
    trend: str
    projected_severity_14d: str
    days_to_critical: Optional[int]


class ApproachingThresholdEntity(BaseModel):
    """Entity approaching a risk threshold."""
    entity_id: str
    current_score: float
    current_severity: str
    target_threshold: float
    target_severity: str
    days_to_breach: int
    velocity_7d: float
    confidence: float


class VelocitySummary(BaseModel):
    """Summary of velocity metrics across entities."""
    total_analyzed: int
    high_velocity_count: int
    approaching_critical_count: int
    approaching_high_count: int
    avg_velocity_7d: float
    trend_distribution: Dict[str, int]


# =============================================================================
# Endpoints
# =============================================================================

@router.get(
    "/{entity_id}",
    response_model=VelocityResponse,
    summary="Get Risk Velocity",
    description="Calculate risk velocity and projections for an entity.",
)
async def get_velocity(
    entity_id: str,
    lookback_days: int = Query(90, ge=7, le=365),
    db: AsyncSession = Depends(get_db),
) -> VelocityResponse:
    """
    Get detailed velocity analysis for an entity.

    Returns:
        - Current score and velocity across time windows
        - Trend direction and volatility
        - Projected future scores
        - Days until threshold breaches
        - Historical score data for visualization
    """
    service = RiskVelocityService(db)
    metrics = await service.calculate_velocity(entity_id, lookback_days)

    if metrics is None:
        raise HTTPException(
            status_code=404,
            detail=f"No score history found for entity {entity_id}"
        )

    result = metrics.to_dict()

    return VelocityResponse(
        entity_id=result["entity_id"],
        current_score=result["current_score"],
        velocity=VelocityWindow(**result["velocity"]),
        trend=result["trend"],
        volatility=result["volatility"],
        projections=Projections(**{
            "7_day": ProjectionWindow(**result["projections"]["7_day"]),
            "14_day": ProjectionWindow(**result["projections"]["14_day"]),
            "30_day": ProjectionWindow(**result["projections"]["30_day"]),
        }),
        threshold_predictions=ThresholdPredictions(**result["threshold_predictions"]),
        confidence=result["confidence"],
        data_points=result["data_points"],
        history=[HistoryPoint(**h) for h in result["history"]],
    )


@router.get(
    "/high-velocity",
    response_model=List[HighVelocityEntity],
    summary="Get High Velocity Entities",
    description="Find entities with rapidly increasing risk.",
)
async def get_high_velocity(
    threshold: float = Query(0.10, ge=0.01, le=0.5, description="Minimum 7-day velocity"),
    limit: int = Query(50, ge=1, le=200),
    db: AsyncSession = Depends(get_db),
) -> List[HighVelocityEntity]:
    """
    Find entities with high risk velocity.

    These are entities where risk is increasing rapidly,
    requiring proactive attention.
    """
    service = RiskVelocityService(db)
    entities = await service.get_high_velocity_entities(threshold, limit)

    return [HighVelocityEntity(**e) for e in entities]


@router.get(
    "/approaching-threshold",
    response_model=List[ApproachingThresholdEntity],
    summary="Get Entities Approaching Threshold",
    description="Find entities projected to breach a risk threshold.",
)
async def get_approaching_threshold(
    threshold: float = Query(0.70, ge=0.5, le=0.95, description="Target threshold"),
    max_days: int = Query(14, ge=1, le=90, description="Maximum days to breach"),
    limit: int = Query(50, ge=1, le=200),
    db: AsyncSession = Depends(get_db),
) -> List[ApproachingThresholdEntity]:
    """
    Find entities projected to breach a risk threshold.

    Returns entities currently below the threshold but trending
    toward breaching it within the specified time window.
    """
    service = RiskVelocityService(db)
    entities = await service.get_entities_approaching_threshold(
        threshold, max_days, limit
    )

    return [ApproachingThresholdEntity(**e) for e in entities]


@router.get(
    "/summary",
    response_model=VelocitySummary,
    summary="Get Velocity Summary",
    description="Get aggregate velocity metrics across all entities.",
)
async def get_velocity_summary(
    db: AsyncSession = Depends(get_db),
) -> VelocitySummary:
    """
    Get summary of velocity metrics across all entities.

    Provides dashboard-level metrics for risk trajectory.
    """
    service = RiskVelocityService(db)

    # Get high velocity entities
    high_velocity = await service.get_high_velocity_entities(threshold=0.10, limit=1000)

    # Get entities approaching thresholds
    approaching_critical = await service.get_entities_approaching_threshold(
        threshold=0.85, max_days=14, limit=1000
    )
    approaching_high = await service.get_entities_approaching_threshold(
        threshold=0.70, max_days=14, limit=1000
    )

    # Calculate averages and distributions
    velocities = [e["velocity_7d"] for e in high_velocity]
    avg_velocity = sum(velocities) / len(velocities) if velocities else 0.0

    trend_counts = {"increasing": 0, "decreasing": 0, "stable": 0, "volatile": 0}
    for e in high_velocity:
        trend = e.get("trend", "stable")
        if trend in trend_counts:
            trend_counts[trend] += 1

    return VelocitySummary(
        total_analyzed=len(high_velocity),
        high_velocity_count=len([e for e in high_velocity if e["velocity_7d"] >= 0.15]),
        approaching_critical_count=len(approaching_critical),
        approaching_high_count=len(approaching_high),
        avg_velocity_7d=round(avg_velocity, 4),
        trend_distribution=trend_counts,
    )


@router.get(
    "/predictions/critical",
    response_model=List[ApproachingThresholdEntity],
    summary="Get Critical Risk Predictions",
    description="Find entities predicted to reach CRITICAL severity.",
)
async def get_critical_predictions(
    max_days: int = Query(30, ge=1, le=90),
    limit: int = Query(50, ge=1, le=200),
    db: AsyncSession = Depends(get_db),
) -> List[ApproachingThresholdEntity]:
    """
    Find entities predicted to reach CRITICAL severity.

    Critical threshold is 0.85 risk score.
    """
    service = RiskVelocityService(db)
    return [
        ApproachingThresholdEntity(**e)
        for e in await service.get_entities_approaching_threshold(
            threshold=0.85, max_days=max_days, limit=limit
        )
    ]
