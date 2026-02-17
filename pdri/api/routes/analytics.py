"""
PDRI Analytics Routes
=====================

REST API endpoints for risk analytics and graph intelligence.

Author: PDRI Team
Version: 1.0.0
"""

from typing import Any, Dict, List

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field

from pdri.api.dependencies import require_graph_engine, require_scoring_engine
from pdri.graph.engine import GraphEngine
from pdri.scoring.engine import ScoringEngine


router = APIRouter(prefix="/analytics", tags=["Analytics"])


# =============================================================================
# Response Models
# =============================================================================

class RiskDistributionItem(BaseModel):
    """Risk distribution by level."""
    risk_level: str
    count: int


class HighRiskEntityResponse(BaseModel):
    """High risk entity data."""
    id: str
    name: str
    type: str
    exposure_score: float
    volatility_score: float
    sensitivity_likelihood: float


class ExposurePathResponse(BaseModel):
    """Exposure path data."""
    path_length: int
    node_ids: List[str]
    relationship_types: List[str]


class AIExposureResponse(BaseModel):
    """AI exposure path data."""
    data_store_id: str
    data_store_name: str
    sensitivity: float
    ai_tool_id: str
    ai_tool_name: str
    is_sanctioned: bool
    path_length: int


class RiskSummaryResponse(BaseModel):
    """Overall risk summary."""
    total_entities: int
    high_risk_count: int
    medium_risk_count: int
    low_risk_count: int
    top_risks: List[HighRiskEntityResponse]
    calculated_at: str


# =============================================================================
# Risk Distribution Endpoints
# =============================================================================

@router.get(
    "/distribution",
    response_model=List[RiskDistributionItem],
    summary="Risk Distribution",
    description="Get distribution of entities across risk levels."
)
async def get_risk_distribution(
    graph: GraphEngine = Depends(require_graph_engine)
) -> List[Dict[str, Any]]:
    """
    Get risk distribution across all entities.
    
    Returns counts for each risk level:
    - critical (>= 0.8)
    - high (>= 0.6)
    - medium (>= 0.4)
    - low (>= 0.2)
    - minimal (< 0.2)
    """
    try:
        distribution = await graph.get_risk_distribution()
        return distribution
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get(
    "/high-risk",
    response_model=List[HighRiskEntityResponse],
    summary="High Risk Entities",
    description="Get entities with highest risk scores."
)
async def get_high_risk_entities(
    threshold: float = Query(0.6, ge=0.0, le=1.0),
    limit: int = Query(20, ge=1, le=100),
    graph: GraphEngine = Depends(require_graph_engine)
) -> List[Dict[str, Any]]:
    """
    Get entities with exposure score above threshold.
    
    Ordered by exposure score descending.
    """
    try:
        entities = await graph.get_high_risk_nodes(
            threshold=threshold,
            limit=limit
        )
        return entities
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get(
    "/summary",
    response_model=RiskSummaryResponse,
    summary="Risk Summary",
    description="Get overall risk summary for the graph."
)
async def get_risk_summary(
    scoring: ScoringEngine = Depends(require_scoring_engine)
) -> Dict[str, Any]:
    """
    Get comprehensive risk summary.
    
    Includes distribution, high risk entities, and statistics.
    """
    try:
        summary = await scoring.get_risk_summary()
        
        # Count by risk level
        distribution = summary.get("distribution", [])
        counts = {d.get("risk_level"): d.get("count", 0) for d in distribution}
        
        return {
            "total_entities": sum(counts.values()),
            "high_risk_count": counts.get("critical", 0) + counts.get("high", 0),
            "medium_risk_count": counts.get("medium", 0),
            "low_risk_count": counts.get("low", 0) + counts.get("minimal", 0),
            "top_risks": summary.get("high_risk_entities", []),
            "calculated_at": summary.get("calculated_at")
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# =============================================================================
# Exposure Path Endpoints
# =============================================================================

@router.get(
    "/exposure-paths/{entity_id}",
    response_model=List[ExposurePathResponse],
    summary="Find Exposure Paths",
    description="Find paths from entity to external/AI exposure points."
)
async def find_exposure_paths(
    entity_id: str,
    max_depth: int = Query(5, ge=1, le=10),
    limit: int = Query(10, ge=1, le=50),
    graph: GraphEngine = Depends(require_graph_engine)
) -> List[Dict[str, Any]]:
    """
    Find paths from a node to external exposure points.
    
    Exposure points include:
    - External entities
    - AI tools
    - Public APIs
    """
    try:
        paths = await graph.find_exposure_paths(
            source_id=entity_id,
            max_depth=max_depth,
            limit=limit
        )
        return paths
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get(
    "/ai-exposure",
    response_model=List[AIExposureResponse],
    summary="AI Exposure Paths",
    description="Find all paths from data stores to AI tools."
)
async def find_ai_exposure_paths(
    min_sensitivity: float = Query(0.5, ge=0.0, le=1.0),
    max_depth: int = Query(4, ge=1, le=8),
    limit: int = Query(20, ge=1, le=100),
    graph: GraphEngine = Depends(require_graph_engine)
) -> List[Dict[str, Any]]:
    """
    Find all paths from sensitive data stores to AI tools.
    
    Critical for understanding AI data exposure risk.
    """
    try:
        paths = await graph.find_ai_exposure_paths(
            min_sensitivity=min_sensitivity,
            max_depth=max_depth,
            limit=limit
        )
        return paths
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get(
    "/external-exposures",
    summary="External Exposures",
    description="Get all external exposure points."
)
async def get_external_exposures(
    limit: int = Query(50, ge=1, le=200),
    graph: GraphEngine = Depends(require_graph_engine)
) -> List[Dict[str, Any]]:
    """
    Get all internal resources exposed to external entities.
    
    Includes exposures to:
    - External services
    - AI tools
    - Public endpoints
    """
    try:
        exposures = await graph.get_external_exposures(limit=limit)
        return exposures
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# =============================================================================
# Graph Metrics Endpoints
# =============================================================================

@router.get(
    "/metrics",
    summary="Graph Metrics",
    description="Get graph-level metrics and statistics."
)
async def get_graph_metrics(
    graph: GraphEngine = Depends(require_graph_engine)
) -> Dict[str, Any]:
    """
    Get overall graph metrics.
    
    Returns node counts by type and connectivity statistics.
    """
    try:
        from pdri.graph.models import NodeType
        
        node_counts = {}
        for node_type in NodeType:
            nodes = await graph.get_nodes_by_type(node_type, limit=1)
            # Use a count query in production
            all_nodes = await graph.get_nodes_by_type(node_type, limit=10000)
            node_counts[node_type.value] = len(all_nodes)
        
        total_nodes = sum(node_counts.values())
        
        return {
            "total_nodes": total_nodes,
            "node_counts": node_counts,
            "timestamp": __import__("datetime").datetime.now(timezone.utc).isoformat()
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
