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

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from pdri.config import settings
from pdri.api.dependencies import ServiceContainer
from pdri.api.routes import (
    nodes_router,
    scoring_router,
    analytics_router,
    health_router,
)


# Configure logging
logging.basicConfig(
    level=getattr(logging, settings.log_level.upper()),
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)


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
            "Currently open for development. "
            "Production will require API key authentication."
        ),
        version=settings.app_version,
        lifespan=lifespan,
        docs_url="/docs",
        redoc_url="/redoc",
        openapi_url="/openapi.json"
    )
    
    # Add CORS middleware
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],  # Configure for production
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )
    
    # Register routers
    app.include_router(health_router)
    app.include_router(nodes_router)
    app.include_router(scoring_router)
    app.include_router(analytics_router)
    
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
