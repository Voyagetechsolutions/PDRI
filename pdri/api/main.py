"""
PDRI API Main Application
=========================

FastAPI application entry point for the PDRI REST API.

Features:
    - OpenAPI documentation at /docs
    - Health, nodes, scoring, and analytics endpoints
    - CORS middleware for cross-origin requests
    - Async lifespan management

Usage:
    # Development:
    uvicorn pdri.api.main:app --reload
    
    # Production:
    uvicorn pdri.api.main:app --host 0.0.0.0 --port 8000

Author: PDRI Team
Version: 1.0.0
"""

import logging
from contextlib import asynccontextmanager
from typing import AsyncGenerator

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware

try:
    from slowapi import Limiter, _rate_limit_exceeded_handler
    from slowapi.util import get_remote_address
    from slowapi.errors import RateLimitExceeded

    _limiter = Limiter(key_func=get_remote_address, default_limits=["100/minute"])
    HAS_SLOWAPI = True
except ImportError:
    _limiter = None
    HAS_SLOWAPI = False

from pdri.config import settings
from pdri.api.dependencies import ServiceContainer
from pdri.api.auth import get_current_user, require_role
from pdri.api.routes import (
    nodes_router,
    scoring_router,
    analytics_router,
    health_router,
)


# Configure structured logging
from pdri.logging import setup_logging, get_logger, RequestLoggingMiddleware
setup_logging(level=settings.log_level, json_output=not getattr(settings, 'debug', False))
logger = get_logger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    """
    Application lifespan context manager.
    
    Handles startup and shutdown of services.
    """
    logger.info("Starting PDRI API...")
    
    # Initialize services
    container = ServiceContainer.get_instance()
    await container.initialize()
    
    logger.info("PDRI API started successfully")
    
    yield
    
    # Shutdown services
    logger.info("Shutting down PDRI API...")
    await container.shutdown()
    logger.info("PDRI API shutdown complete")


def create_app() -> FastAPI:
    """
    Create and configure the FastAPI application.
    
    Returns:
        Configured FastAPI instance
    """
    app = FastAPI(
        title="PDRI API",
        description=(
            "Predictive Data Risk Infrastructure API\n\n"
            "The PDRI platform provides:\n"
            "- Risk graph modeling and analysis\n"
            "- Real-time risk scoring\n"
            "- AI exposure path detection\n"
            "- Predictive risk analytics\n\n"
            "## Authentication\n"
            "All endpoints except `/health/*` require a valid JWT token. "
            "Include `Authorization: Bearer <token>` in request headers.\n\n"
            "Roles: `admin`, `analyst`, `viewer`"
        ),
        version=settings.app_version,
        lifespan=lifespan,
        docs_url="/docs",
        redoc_url="/redoc",
        openapi_url="/openapi.json"
    )
    
    # Add CORS middleware
    allowed_origins = (
        settings.cors_allowed_origins.split(",")
        if hasattr(settings, "cors_allowed_origins") and settings.cors_allowed_origins
        else ["*"]
    )
    app.add_middleware(
        CORSMiddleware,
        allow_origins=allowed_origins,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )
    
    # Add rate limiting
    if HAS_SLOWAPI and _limiter:
        app.state.limiter = _limiter
        app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)
    
    # Add audit middleware for mutation logging
    from pdri.api.audit_middleware import AuditMiddleware
    app.add_middleware(AuditMiddleware)
    
    # Add structured request logging middleware
    app.add_middleware(RequestLoggingMiddleware)
    
    # Add mTLS middleware (enabled via PDRI_MTLS_ENABLED env var)
    from pdri.api.mtls import get_mtls_config_from_env, MTLSMiddleware
    mtls_config = get_mtls_config_from_env()
    if mtls_config.enabled:
        app.add_middleware(MTLSMiddleware, config=mtls_config)
        logger.info("mTLS middleware enabled")
    
    # Add Prometheus metrics
    from pdri.api.metrics import HAS_PROMETHEUS, metrics_endpoint
    if HAS_PROMETHEUS:
        from pdri.api.metrics import MetricsMiddleware
        app.add_middleware(MetricsMiddleware)
        app.add_route("/metrics", metrics_endpoint, methods=["GET"])
    
    # Initialize OpenTelemetry tracing
    from pdri.api.tracing import setup_tracing, instrument_fastapi
    tracer = setup_tracing(service_name="pdri-api", service_version=settings.app_version)
    if tracer:
        instrument_fastapi(app)
    
    # Register routers
    app.include_router(health_router)
    app.include_router(nodes_router)
    app.include_router(scoring_router)
    app.include_router(analytics_router)
    
    # WebSocket for real-time risk events
    from pdri.api.websocket import router as ws_router
    app.include_router(ws_router)

    @app.get("/", tags=["Root"])
    async def root():
        """Root endpoint returning API info."""
        return {
            "service": settings.app_name,
            "version": settings.app_version,
            "description": "Predictive Data Risk Infrastructure API",
            "docs": "/docs"
        }
    
    return app


# Create the application instance
app = create_app()


if __name__ == "__main__":
    import uvicorn
    
    uvicorn.run(
        "pdri.api.main:app",
        host=settings.api_host,
        port=settings.api_port,
        reload=settings.debug
    )
