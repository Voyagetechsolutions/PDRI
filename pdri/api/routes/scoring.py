"""
PDRI Scoring Routes
===================

REST API endpoints for risk scoring operations.

Author: PDRI Team
Version: 1.0.0
"""

from typing import Any, Dict, List

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field

from pdri.api.dependencies import get_graph_engine, get_scoring_engine
from pdri.graph.engine import GraphEngine
from pdri.scoring.engine import ScoringEngine, ScoringResult


router = APIRouter(prefix="/scoring", tags=["Risk Scoring"])


# =============================================================================
# Response Models
# =============================================================================

class ScoreResponse(BaseModel):
    """Response model for scoring result."""
    entity_id: str
    exposure_score: float = Field(..., ge=0.0, le=1.0)
    volatility_score: float = Field(..., ge=0.0, le=1.0)
    sensitivity_likelihood: float = Field(..., ge=0.0, le=1.0)
    composite_score: float = Field(..., ge=0.0, le=1.0)
    risk_level: str
    scoring_version: str
    calculated_at: str


class ScoreExplanationResponse(BaseModel):
    """Response model for score explanation."""
    entity_id: str
    risk_level: str
    composite_score: float
    summary: str
    top_risk_factors: List[str]
    factor_breakdown: Dict[str, float]
    score_breakdown: Dict[str, float]
    recommendations: List[str]


class BatchScoreRequest(BaseModel):
    """Request model for batch scoring."""
    node_type: str = Field(..., description="Node type to score")
    max_entities: int = Field(default=100, ge=1, le=1000)
    update_graph: bool = Field(default=True)


class BatchScoreResponse(BaseModel):
    """Response model for batch scoring."""
    node_type: str
    total_scored: int
    results: List[ScoreResponse]


# =============================================================================
# Scoring Endpoints
# =============================================================================

@router.get(
    "/{entity_id}",
    response_model=ScoreResponse,
    summary="Score Entity",
    description="Calculate risk scores for a specific entity."
)
async def score_entity(
    entity_id: str,
    update_graph: bool = Query(True, description="Update node with new scores"),
    scoring: ScoringEngine = Depends(get_scoring_engine)
) -> Dict[str, Any]:
    """
    Calculate and return risk scores for an entity.
    
    - **exposure_score**: How exposed is the entity to external threats
    - **volatility_score**: How unstable is the risk profile
    - **sensitivity_likelihood**: Probability of containing sensitive data
    - **composite_score**: Weighted overall risk score
    """
    try:
        result = await scoring.score_entity(
            entity_id=entity_id,
            update_graph=update_graph
        )
        
        return {
            "entity_id": result.entity_id,
            "exposure_score": result.exposure_score,
            "volatility_score": result.volatility_score,
            "sensitivity_likelihood": result.sensitivity_likelihood,
            "composite_score": result.composite_score,
            "risk_level": result.risk_level,
            "scoring_version": result.scoring_version,
            "calculated_at": result.calculated_at.isoformat()
        }
        
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get(
    "/{entity_id}/explain",
    response_model=ScoreExplanationResponse,
    summary="Explain Score",
    description="Get a human-readable explanation of an entity's risk score."
)
async def explain_score(
    entity_id: str,
    scoring: ScoringEngine = Depends(get_scoring_engine)
) -> Dict[str, Any]:
    """
    Get detailed explanation of risk scores.
    
    Includes:
    - Summary text
    - Top contributing risk factors
    - Factor breakdown with values
    - Recommendations for risk reduction
    """
    try:
        result = await scoring.score_entity(
            entity_id=entity_id,
            update_graph=False
        )
        
        explanation = scoring.explain_score(result)
        return explanation
        
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post(
    "/batch",
    response_model=BatchScoreResponse,
    summary="Batch Score",
    description="Score all entities of a given type."
)
async def batch_score(
    request: BatchScoreRequest,
    scoring: ScoringEngine = Depends(get_scoring_engine)
) -> Dict[str, Any]:
    """
    Batch score all entities of a type.
    
    Useful for periodic rescoring or bulk operations.
    """
    try:
        results = await scoring.score_entities_by_type(
            node_type=request.node_type,
            max_entities=request.max_entities,
            update_graph=request.update_graph
        )
        
        return {
            "node_type": request.node_type,
            "total_scored": len(results),
            "results": [
                {
                    "entity_id": r.entity_id,
                    "exposure_score": r.exposure_score,
                    "volatility_score": r.volatility_score,
                    "sensitivity_likelihood": r.sensitivity_likelihood,
                    "composite_score": r.composite_score,
                    "risk_level": r.risk_level,
                    "scoring_version": r.scoring_version,
                    "calculated_at": r.calculated_at.isoformat()
                }
                for r in results
            ]
        }
        
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post(
    "/all",
    summary="Score All Entities",
    description="Score all entities in the graph."
)
async def score_all(
    update_graph: bool = Query(True),
    scoring: ScoringEngine = Depends(get_scoring_engine)
) -> Dict[str, Any]:
    """
    Score all entities in the risk graph.
    
    Returns summary with counts per node type.
    """
    try:
        all_results = await scoring.score_all_entities(
            update_graph=update_graph
        )
        
        summary = {}
        for node_type, results in all_results.items():
            summary[node_type] = {
                "count": len(results),
                "avg_composite": (
                    sum(r.composite_score for r in results) / len(results)
                    if results else 0
                )
            }
        
        return {
            "total_entities": sum(
                len(r) for r in all_results.values()
            ),
            "by_type": summary
        }
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
