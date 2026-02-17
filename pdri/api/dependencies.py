"""
PDRI API Dependencies
=====================

FastAPI dependency injection for shared resources.

Provides lazy-initialized singletons for:
    - GraphEngine connection
    - ScoringEngine instance
    - PostgreSQL session

Author: PDRI Team
Version: 1.0.0
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
    """
    
    _instance: Optional["ServiceContainer"] = None
    
    def __init__(self):
        self._graph_engine: Optional[GraphEngine] = None
        self._scoring_engine: Optional[ScoringEngine] = None
        self._initialized = False
    
    @classmethod
    def get_instance(cls) -> "ServiceContainer":
        """Get or create the singleton instance."""
        if cls._instance is None:
            cls._instance = ServiceContainer()
        return cls._instance
    
    async def initialize(self) -> None:
        """Initialize all services."""
        if self._initialized:
            return
        
        logger.info("Initializing service container...")
        
        # Initialize graph engine
        self._graph_engine = GraphEngine()
        await self._graph_engine.connect()
        
        # Initialize scoring engine
        self._scoring_engine = ScoringEngine(self._graph_engine)
        
        self._initialized = True
        logger.info("Service container initialized")
    
    async def shutdown(self) -> None:
        """Shutdown all services."""
        logger.info("Shutting down service container...")
        
        if self._graph_engine:
            await self._graph_engine.disconnect()
            self._graph_engine = None
        
        self._scoring_engine = None
        self._initialized = False
        
        logger.info("Service container shutdown complete")
    
    @property
    def graph_engine(self) -> GraphEngine:
        """Get the graph engine instance."""
        if not self._graph_engine:
            raise RuntimeError("Graph engine not initialized")
        return self._graph_engine
    
    @property
    def scoring_engine(self) -> ScoringEngine:
        """Get the scoring engine instance."""
        if not self._scoring_engine:
            raise RuntimeError("Scoring engine not initialized")
        return self._scoring_engine


# Dependency functions for FastAPI
async def get_graph_engine() -> GraphEngine:
    """
    FastAPI dependency for graph engine.
    
    Usage:
        @app.get("/nodes")
        async def get_nodes(graph: GraphEngine = Depends(get_graph_engine)):
            ...
    """
    container = ServiceContainer.get_instance()
    return container.graph_engine


async def get_scoring_engine() -> ScoringEngine:
    """
    FastAPI dependency for scoring engine.
    
    Usage:
        @app.post("/score/{entity_id}")
        async def score(
            entity_id: str,
            scoring: ScoringEngine = Depends(get_scoring_engine)
        ):
            ...
    """
    container = ServiceContainer.get_instance()
    return container.scoring_engine


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
