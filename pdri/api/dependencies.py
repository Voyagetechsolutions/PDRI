"""
PDRI API Dependencies
=====================

FastAPI dependency injection for shared resources.

Provides lazy-initialized singletons for:
    - GraphEngine connection
    - ScoringEngine instance

The container starts in **degraded mode** when backing services
(Neo4j, Kafka, Redis) are unavailable, allowing the API to serve
endpoints that don't require those services.

Author: PDRI Team
Version: 1.1.0
"""

import logging
from typing import AsyncGenerator, Optional
from contextlib import asynccontextmanager

from pdri.config import settings
from pdri.graph.engine import GraphEngine
from pdri.scoring.engine import ScoringEngine


logger = logging.getLogger(__name__)


class ServiceContainer:
    """
    Singleton container for shared services.
    
    Manages lifecycle of graph engine and scoring engine.
    Supports degraded mode when backing services are unavailable.
    """
    
    _instance: Optional["ServiceContainer"] = None
    
    def __init__(self):
        self._graph_engine: Optional[GraphEngine] = None
        self._scoring_engine: Optional[ScoringEngine] = None
        self._initialized = False
        self.graph_available = False
    
    @classmethod
    def get_instance(cls) -> "ServiceContainer":
        """Get or create the singleton instance."""
        if cls._instance is None:
            cls._instance = ServiceContainer()
        return cls._instance
    
    async def initialize(self) -> None:
        """Initialize all services (graceful degradation on failure)."""
        if self._initialized:
            return
        
        logger.info("Initializing service container...")
        
        # ── Neo4j (optional) ──────────────────────────────────
        try:
            self._graph_engine = GraphEngine()
            await self._graph_engine.connect()
            self.graph_available = True
            logger.info("Neo4j graph engine connected")
        except Exception as e:
            logger.warning(
                f"Neo4j unavailable — running in DEGRADED mode: {e}"
            )
            self._graph_engine = None
            self.graph_available = False
        
        # ── Scoring engine (requires graph) ───────────────────
        if self.graph_available and self._graph_engine:
            self._scoring_engine = ScoringEngine(self._graph_engine)
            logger.info("Scoring engine initialized")
        else:
            self._scoring_engine = None
            logger.warning(
                "Scoring engine skipped (no graph connection)"
            )
        
        self._initialized = True
        
        if self.graph_available:
            logger.info("Service container fully initialized")
        else:
            logger.warning(
                "Service container initialized in DEGRADED mode — "
                "graph/scoring endpoints will return 503"
            )
    
    async def shutdown(self) -> None:
        """Shutdown all services."""
        logger.info("Shutting down service container...")
        
        if self._graph_engine:
            try:
                await self._graph_engine.disconnect()
            except Exception as e:
                logger.warning(f"Error disconnecting graph engine: {e}")
            self._graph_engine = None
        
        self._scoring_engine = None
        self._initialized = False
        self.graph_available = False
        
        logger.info("Service container shutdown complete")
    
    @property
    def graph_engine(self) -> Optional[GraphEngine]:
        """Get the graph engine instance (None if unavailable)."""
        return self._graph_engine
    
    @property
    def scoring_engine(self) -> Optional[ScoringEngine]:
        """Get the scoring engine instance (None if unavailable)."""
        return self._scoring_engine


# Dependency functions for FastAPI
async def get_graph_engine() -> Optional[GraphEngine]:
    """
    FastAPI dependency for graph engine.
    
    Returns None if Neo4j is not available (degraded mode).
    """
    container = ServiceContainer.get_instance()
    return container.graph_engine


async def get_scoring_engine() -> Optional[ScoringEngine]:
    """
    FastAPI dependency for scoring engine.
    
    Returns None if scoring engine is not available (degraded mode).
    """
    container = ServiceContainer.get_instance()
    return container.scoring_engine


async def require_graph_engine() -> GraphEngine:
    """
    FastAPI dependency that **requires** a live graph engine.
    
    Raises HTTP 503 in degraded mode so route handlers don't need
    to check for None themselves.
    """
    from fastapi import HTTPException

    engine = await get_graph_engine()
    if engine is None:
        raise HTTPException(
            status_code=503,
            detail="Graph database unavailable (Neo4j not connected). "
                   "Start Neo4j or run: docker compose up -d neo4j",
        )
    return engine


async def require_scoring_engine() -> ScoringEngine:
    """
    FastAPI dependency that **requires** a live scoring engine.
    
    Raises HTTP 503 in degraded mode.
    """
    from fastapi import HTTPException

    engine = await get_scoring_engine()
    if engine is None:
        raise HTTPException(
            status_code=503,
            detail="Scoring engine unavailable (Neo4j not connected). "
                   "Start Neo4j or run: docker compose up -d neo4j",
        )
    return engine


@asynccontextmanager
async def lifespan_manager():
    """
    Async context manager for application lifespan.
    
    Initializes and shuts down services.
    """
    container = ServiceContainer.get_instance()
    await container.initialize()
    try:
        yield
    finally:
        await container.shutdown()


