"""
PDRI Health Routes
==================

Health check endpoints for monitoring and orchestration.
Supports degraded mode when backing services are unavailable.

Author: PDRI Team
Version: 1.1.0
"""

from datetime import datetime, timezone
from typing import Any, Dict, Optional

from fastapi import APIRouter

from pdri.config import settings
from pdri.api.dependencies import ServiceContainer


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
    container = ServiceContainer.get_instance()
    mode = "healthy" if container.graph_available else "degraded"
    
    return {
        "status": mode,
        "service": settings.app_name,
        "version": settings.app_version,
        "timestamp": datetime.now(timezone.utc).isoformat()
    }


@router.get(
    "/ready",
    summary="Readiness Check",
    description="Checks if the service is ready to handle requests."
)
async def readiness_check() -> Dict[str, Any]:
    """
    Readiness check including dependency status.
    
    Verifies:
    - Neo4j graph database connectivity
    """
    container = ServiceContainer.get_instance()
    
    # Check graph database
    graph_health: Dict[str, Any]
    if container.graph_available and container.graph_engine:
        try:
            graph_health = await container.graph_engine.health_check()
        except Exception as e:
            graph_health = {"status": "error", "error": str(e)}
    else:
        graph_health = {
            "status": "unavailable",
            "detail": "Neo4j not connected (degraded mode)"
        }
    
    graph_ok = graph_health.get("status") == "healthy"
    
    return {
        "status": "ready" if graph_ok else "degraded",
        "timestamp": datetime.now(timezone.utc).isoformat(),
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

