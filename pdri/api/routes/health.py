"""
PDRI Health Routes
==================

Health check endpoints for monitoring and orchestration.

Author: PDRI Team
Version: 1.0.0
"""

from datetime import datetime
from typing import Any, Dict

from fastapi import APIRouter, Depends

from pdri.config import settings
from pdri.api.dependencies import get_graph_engine
from pdri.graph.engine import GraphEngine


router = APIRouter(prefix="/health", tags=["Health"])


@router.get(
    "",
    summary="Basic Health Check",
    description="Returns basic health status of the PDRI API."
)
async def health_check() -> Dict[str, Any]:
    """
    Basic health check endpoint.
    
    Returns API status without checking dependencies.
    """
    return {
        "status": "healthy",
        "service": settings.app_name,
        "version": settings.app_version,
        "timestamp": datetime.utcnow().isoformat()
    }


@router.get(
    "/ready",
    summary="Readiness Check",
    description="Checks if the service is ready to handle requests."
)
async def readiness_check(
    graph: GraphEngine = Depends(get_graph_engine)
) -> Dict[str, Any]:
    """
    Readiness check including dependency status.
    
    Verifies:
    - Neo4j graph database connectivity
    """
    # Check graph database
    graph_health = await graph.health_check()
    
    all_healthy = graph_health.get("status") == "healthy"
    
    return {
        "status": "ready" if all_healthy else "not_ready",
        "timestamp": datetime.utcnow().isoformat(),
        "dependencies": {
            "neo4j": graph_health
        }
    }


@router.get(
    "/live",
    summary="Liveness Check",
    description="Simple liveness probe for container orchestration."
)
async def liveness_check() -> Dict[str, str]:
    """
    Simple liveness probe.
    
    Returns 200 if the process is running.
    """
    return {"status": "alive"}
