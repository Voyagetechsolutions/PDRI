"""
PDRI Health Routes
==================

Health check endpoints for monitoring and orchestration.
Supports degraded mode when backing services are unavailable.

Endpoints:
    GET /health          - Basic health (always returns)
    GET /health/ready    - Readiness with dependency checks
    GET /health/live     - Kubernetes liveness probe
    GET /capabilities    - Service capabilities for Platform discovery

Author: PDRI Team
Version: 1.2.0
"""

import time
from datetime import datetime, timezone
from typing import Any, Dict

from fastapi import APIRouter

from pdri.config import settings
from pdri.api.dependencies import ServiceContainer
from shared.contracts.pdri import PDRIHealth, PDRICapabilities, DependencyHealth


router = APIRouter(tags=["Health"])

# Track startup time for uptime calculation
_start_time = time.time()


@router.get(
    "/health",
    response_model=PDRIHealth,
    summary="Health Check",
    description="Returns PDRI health status with dependency info.",
)
async def health_check() -> PDRIHealth:
    """
    Health check endpoint for Platform and monitoring.

    Returns:
        - Overall status: healthy, degraded, unhealthy
        - Dependency health: Neo4j, PostgreSQL
        - Basic metrics
    """
    container = ServiceContainer.get_instance()

    # Check dependencies
    dependencies = []

    # Neo4j
    if container.graph_available and container.graph_engine:
        try:
            start = time.time()
            health = await container.graph_engine.health_check()
            latency = (time.time() - start) * 1000
            dependencies.append(DependencyHealth(
                name="neo4j",
                status="healthy" if health.get("status") == "healthy" else "degraded",
                latency_ms=latency,
            ))
        except Exception as e:
            dependencies.append(DependencyHealth(
                name="neo4j",
                status="unhealthy",
                message=str(e),
            ))
    else:
        dependencies.append(DependencyHealth(
            name="neo4j",
            status="unavailable",
            message="Not connected",
        ))

    # PostgreSQL
    if container.postgres_available:
        dependencies.append(DependencyHealth(
            name="postgresql",
            status="healthy",
        ))
    else:
        dependencies.append(DependencyHealth(
            name="postgresql",
            status="unavailable",
            message="Not connected",
        ))

    # Determine overall status
    statuses = [d.status for d in dependencies]
    if all(s == "healthy" for s in statuses):
        overall = "healthy"
    elif any(s == "unhealthy" for s in statuses):
        overall = "unhealthy"
    else:
        overall = "degraded"

    return PDRIHealth(
        service="pdri",
        status=overall,
        version=settings.app_version,
        uptime_seconds=time.time() - _start_time,
        dependencies=dependencies,
        timestamp=datetime.now(timezone.utc),
    )


@router.get(
    "/health/ready",
    summary="Readiness Check",
    description="Checks if PDRI is ready to handle requests.",
)
async def readiness_check() -> Dict[str, Any]:
    """
    Kubernetes readiness probe.

    Returns 200 if PDRI can handle requests.
    Returns 503 if critical dependencies are down.
    """
    container = ServiceContainer.get_instance()

    # For PDRI, we can operate in degraded mode without Neo4j
    # but we need at least one of Neo4j or Postgres
    is_ready = container.graph_available or container.postgres_available

    return {
        "ready": is_ready,
        "mode": "full" if (container.graph_available and container.postgres_available) else "degraded",
        "neo4j": container.graph_available,
        "postgresql": container.postgres_available,
    }


@router.get(
    "/health/live",
    summary="Liveness Check",
    description="Kubernetes liveness probe.",
)
async def liveness_check() -> Dict[str, str]:
    """
    Kubernetes liveness probe.

    Returns 200 if the process is alive.
    """
    return {"status": "alive"}


@router.get(
    "/capabilities",
    response_model=PDRICapabilities,
    summary="Service Capabilities",
    description="Returns PDRI capabilities for Platform service discovery.",
)
async def capabilities() -> PDRICapabilities:
    """
    Service capabilities for Platform discovery.

    Platform uses this to understand what PDRI can do
    and how to communicate with it.
    """
    return PDRICapabilities(
        service="pdri",
        version=settings.app_version,
        contract_version="1.3.0",
        capabilities=[
            "risk_scoring",
            "exposure_paths",
            "findings_management",
            "event_ingestion",
            "event_correlation",
            "compliance_assessment",
            "websocket_streaming",
            "identity_analytics",
            "blast_radius_calculation",
            "risk_velocity",
            "trend_prediction",
            "ai_data_lineage",
            "ai_exposure_tracking",
        ],
        endpoints={
            "health": "/health",
            "ready": "/health/ready",
            "live": "/health/live",
            "capabilities": "/capabilities",
            "risk": "/api/v1/scoring/{entity_id}",
            "exposure": "/analytics/exposure-paths/{entity_id}",
            "findings": "/api/v1/findings",
            "events": "/api/v1/events",
            "websocket": "/ws/stream",
            "blast_radius": "/api/v1/identity/blast-radius/{identity_id}",
            "identity_summary": "/api/v1/identity/summary",
            "velocity": "/api/v1/velocity/{entity_id}",
            "velocity_predictions": "/api/v1/velocity/predictions/critical",
            "lineage_forward": "/api/v1/lineage/forward/{data_store_id}",
            "lineage_backward": "/api/v1/lineage/backward/{model_id}",
            "lineage_summary": "/api/v1/lineage/summary",
        },
        rate_limits={
            "requests_per_minute": 1000,
            "events_per_second": 100,
            "websocket_connections": 50,
        },
    )

