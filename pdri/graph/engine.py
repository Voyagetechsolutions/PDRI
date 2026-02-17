"""
PDRI Graph Engine
=================

Neo4j graph database operations for the PDRI risk graph.

This module provides:
    - Connection management with async support
    - CRUD operations for nodes and edges
    - Graph traversal and pathfinding
    - Risk analytics queries

Usage:
    from pdri.graph.engine import GraphEngine
    
    async with GraphEngine() as engine:
        node = await engine.create_node(DataStoreNode(...))
        paths = await engine.find_exposure_paths("node-123")

Author: PDRI Team
Version: 1.0.0
"""

import logging
from contextlib import asynccontextmanager
from typing import Any, Dict, List, Optional, Type, TypeVar
from neo4j import AsyncGraphDatabase, AsyncDriver, AsyncSession
from neo4j.exceptions import Neo4jError

from pdri.config import settings
from pdri.graph.models import (
    BaseNode,
    NodeType,
    EdgeType,
    GraphEdge,
    DataStoreNode,
    ServiceNode,
    AIToolNode,
    IdentityNode,
    APINode,
)
from pdri.graph.queries import NodeQueries, EdgeQueries, PathQueries, AnalyticsQueries


# Type variable for generic node operations
T = TypeVar('T', bound=BaseNode)

# Configure logging
logger = logging.getLogger(__name__)


class GraphEngineError(Exception):
    """Base exception for graph engine errors."""
    pass


class NodeNotFoundError(GraphEngineError):
    """Raised when a node is not found."""
    pass


class EdgeNotFoundError(GraphEngineError):
    """Raised when an edge is not found."""
    pass


class GraphEngine:
    """
    Neo4j graph engine for PDRI risk graph operations.
    
    Provides async context manager interface for database connections
    and methods for all graph operations.
    
    Attributes:
        uri: Neo4j connection URI
        user: Neo4j username
        password: Neo4j password
        
    Example:
        async with GraphEngine() as engine:
            # Create a data store node
            node = await engine.create_node(DataStoreNode(
                id="ds-001",
                name="Production Database",
                store_type="database",
                technology="PostgreSQL"
            ))
            
            # Find exposure paths
            paths = await engine.find_exposure_paths("ds-001")
    """
    
    # Mapping from NodeType to model class
    NODE_TYPE_MAP: Dict[NodeType, Type[BaseNode]] = {
        NodeType.DATA_STORE: DataStoreNode,
        NodeType.SERVICE: ServiceNode,
        NodeType.AI_TOOL: AIToolNode,
        NodeType.IDENTITY: IdentityNode,
        NodeType.API: APINode,
    }
    
    def __init__(
        self,
        uri: Optional[str] = None,
        user: Optional[str] = None,
        password: Optional[str] = None
    ):
        """
        Initialize the graph engine.
        
        Args:
            uri: Neo4j connection URI (defaults to config)
            user: Neo4j username (defaults to config)
            password: Neo4j password (defaults to config)
        """
        self.uri = uri or settings.neo4j_uri
        self.user = user or settings.neo4j_user
        self.password = password or settings.neo4j_password
        self._driver: Optional[AsyncDriver] = None
    
    async def connect(self) -> None:
        """
        Establish connection to Neo4j.
        
        Creates the async driver if not already connected.
        """
        if self._driver is None:
            logger.info(f"Connecting to Neo4j at {self.uri}")
            self._driver = AsyncGraphDatabase.driver(
                self.uri,
                auth=(self.user, self.password)
            )
            # Verify connectivity
            await self._driver.verify_connectivity()
            logger.info("Neo4j connection established")
    
    async def disconnect(self) -> None:
        """
        Close connection to Neo4j.
        """
        if self._driver is not None:
            await self._driver.close()
            self._driver = None
            logger.info("Neo4j connection closed")
    
    async def __aenter__(self) -> "GraphEngine":
        """Async context manager entry."""
        await self.connect()
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb) -> None:
        """Async context manager exit."""
        await self.disconnect()
    
    @asynccontextmanager
    async def _session(self) -> AsyncSession:
        """
        Get a database session.
        
        Yields:
            Async Neo4j session
        """
        if self._driver is None:
            await self.connect()
        async with self._driver.session() as session:
            yield session
    
    # =========================================================================
    # Node Operations
    # =========================================================================
    
    async def create_node(self, node: BaseNode) -> BaseNode:
        """
        Create a new node in the graph.
        
        Args:
            node: Node to create
            
        Returns:
            Created node with any server-side updates
            
        Raises:
            GraphEngineError: If creation fails
        """
        label = node.node_type.value
        properties = node.to_neo4j_properties()
        
        query = NodeQueries.MERGE_NODE.format(label=label)
        
        try:
            async with self._session() as session:
                result = await session.run(
                    query,
                    id=node.id,
                    properties=properties
                )
                record = await result.single()
                
                if record is None:
                    raise GraphEngineError(f"Failed to create node: {node.id}")
                
                logger.info(f"Created node: {node.id} ({label})")
                return node
                
        except Neo4jError as e:
            logger.error(f"Neo4j error creating node: {e}")
            raise GraphEngineError(f"Failed to create node: {e}") from e
    
    async def get_node(self, node_id: str) -> Optional[Dict[str, Any]]:
        """
        Get a node by ID.
        
        Args:
            node_id: Node identifier
            
        Returns:
            Node properties dictionary or None if not found
        """
        try:
            async with self._session() as session:
                result = await session.run(
                    NodeQueries.GET_NODE_BY_ID,
                    id=node_id
                )
                record = await result.single()
                
                if record is None:
                    return None
                
                node = record["n"]
                return dict(node)
                
        except Neo4jError as e:
            logger.error(f"Neo4j error getting node: {e}")
            raise GraphEngineError(f"Failed to get node: {e}") from e
    
    async def get_node_with_relationships(
        self, 
        node_id: str
    ) -> Optional[Dict[str, Any]]:
        """
        Get a node with its relationships.
        
        Args:
            node_id: Node identifier
            
        Returns:
            Dictionary with node properties and relationships
        """
        try:
            async with self._session() as session:
                result = await session.run(
                    NodeQueries.GET_NODE_WITH_RELATIONSHIPS,
                    id=node_id
                )
                record = await result.single()
                
                if record is None:
                    return None
                
                return {
                    "node": dict(record["n"]),
                    "relationships": record["relationships"]
                }
                
        except Neo4jError as e:
            logger.error(f"Neo4j error getting node with relationships: {e}")
            raise GraphEngineError(f"Failed to get node: {e}") from e
    
    async def update_node(
        self, 
        node_id: str, 
        properties: Dict[str, Any]
    ) -> Optional[Dict[str, Any]]:
        """
        Update node properties.
        
        Args:
            node_id: Node identifier
            properties: Properties to update
            
        Returns:
            Updated node properties or None if not found
        """
        try:
            async with self._session() as session:
                result = await session.run(
                    NodeQueries.UPDATE_NODE,
                    id=node_id,
                    properties=properties
                )
                record = await result.single()
                
                if record is None:
                    return None
                
                logger.info(f"Updated node: {node_id}")
                return dict(record["n"])
                
        except Neo4jError as e:
            logger.error(f"Neo4j error updating node: {e}")
            raise GraphEngineError(f"Failed to update node: {e}") from e
    
    async def update_risk_scores(
        self,
        node_id: str,
        exposure_score: float,
        volatility_score: float,
        sensitivity_likelihood: float
    ) -> Optional[Dict[str, Any]]:
        """
        Update risk scores for a node.
        
        This is a specialized update for the scoring engine.
        
        Args:
            node_id: Node identifier
            exposure_score: New exposure score (0-1)
            volatility_score: New volatility score (0-1)
            sensitivity_likelihood: New sensitivity likelihood (0-1)
            
        Returns:
            Updated node properties or None if not found
        """
        try:
            async with self._session() as session:
                result = await session.run(
                    NodeQueries.UPDATE_RISK_SCORES,
                    id=node_id,
                    exposure_score=exposure_score,
                    volatility_score=volatility_score,
                    sensitivity_likelihood=sensitivity_likelihood
                )
                record = await result.single()
                
                if record is None:
                    return None
                
                logger.debug(f"Updated risk scores for: {node_id}")
                return dict(record["n"])
                
        except Neo4jError as e:
            logger.error(f"Neo4j error updating risk scores: {e}")
            raise GraphEngineError(f"Failed to update risk scores: {e}") from e
    
    async def delete_node(self, node_id: str) -> bool:
        """
        Delete a node and all its relationships.
        
        Args:
            node_id: Node identifier
            
        Returns:
            True if deleted, False if not found
        """
        try:
            async with self._session() as session:
                result = await session.run(
                    NodeQueries.DELETE_NODE,
                    id=node_id
                )
                summary = await result.consume()
                
                deleted = summary.counters.nodes_deleted > 0
                if deleted:
                    logger.info(f"Deleted node: {node_id}")
                return deleted
                
        except Neo4jError as e:
            logger.error(f"Neo4j error deleting node: {e}")
            raise GraphEngineError(f"Failed to delete node: {e}") from e
    
    async def get_nodes_by_type(
        self,
        node_type: NodeType,
        skip: int = 0,
        limit: int = 100
    ) -> List[Dict[str, Any]]:
        """
        Get all nodes of a specific type.
        
        Args:
            node_type: Type of nodes to retrieve
            skip: Number of results to skip (pagination)
            limit: Maximum number of results
            
        Returns:
            List of node property dictionaries
        """
        query = NodeQueries.GET_NODES_BY_TYPE.format(label=node_type.value)
        
        try:
            async with self._session() as session:
                result = await session.run(
                    query,
                    skip=skip,
                    limit=limit
                )
                records = await result.data()
                return [dict(r["n"]) for r in records]
                
        except Neo4jError as e:
            logger.error(f"Neo4j error getting nodes by type: {e}")
            raise GraphEngineError(f"Failed to get nodes: {e}") from e
    
    # =========================================================================
    # Edge Operations
    # =========================================================================
    
    async def create_edge(self, edge: GraphEdge) -> GraphEdge:
        """
        Create an edge between two nodes.
        
        Args:
            edge: Edge to create
            
        Returns:
            Created edge
        """
        query = EdgeQueries.MERGE_EDGE.format(rel_type=edge.edge_type.value)
        properties = edge.to_neo4j_properties()
        
        try:
            async with self._session() as session:
                result = await session.run(
                    query,
                    source_id=edge.source_id,
                    target_id=edge.target_id,
                    properties=properties
                )
                record = await result.single()
                
                if record is None:
                    raise GraphEngineError(
                        f"Failed to create edge: {edge.source_id} -> {edge.target_id}"
                    )
                
                logger.info(
                    f"Created edge: {edge.source_id} -[{edge.edge_type.value}]-> "
                    f"{edge.target_id}"
                )
                return edge
                
        except Neo4jError as e:
            logger.error(f"Neo4j error creating edge: {e}")
            raise GraphEngineError(f"Failed to create edge: {e}") from e
    
    async def get_edges_from_node(
        self, 
        node_id: str
    ) -> List[Dict[str, Any]]:
        """
        Get all outgoing edges from a node.
        
        Args:
            node_id: Source node identifier
            
        Returns:
            List of edge data with target information
        """
        try:
            async with self._session() as session:
                result = await session.run(
                    EdgeQueries.GET_EDGES_FROM_NODE,
                    node_id=node_id
                )
                return await result.data()
                
        except Neo4jError as e:
            logger.error(f"Neo4j error getting edges: {e}")
            raise GraphEngineError(f"Failed to get edges: {e}") from e
    
    async def delete_edge(
        self,
        source_id: str,
        target_id: str,
        edge_type: EdgeType
    ) -> bool:
        """
        Delete an edge between two nodes.
        
        Args:
            source_id: Source node identifier
            target_id: Target node identifier
            edge_type: Type of edge
            
        Returns:
            True if deleted, False if not found
        """
        query = EdgeQueries.DELETE_EDGE.format(rel_type=edge_type.value)
        
        try:
            async with self._session() as session:
                result = await session.run(
                    query,
                    source_id=source_id,
                    target_id=target_id
                )
                summary = await result.consume()
                
                return summary.counters.relationships_deleted > 0
                
        except Neo4jError as e:
            logger.error(f"Neo4j error deleting edge: {e}")
            raise GraphEngineError(f"Failed to delete edge: {e}") from e
    
    # =========================================================================
    # Path Finding
    # =========================================================================
    
    async def find_exposure_paths(
        self,
        source_id: str,
        max_depth: int = 5,
        limit: int = 10
    ) -> List[Dict[str, Any]]:
        """
        Find paths from a node to external/AI exposure points.
        
        Args:
            source_id: Starting node identifier
            max_depth: Maximum path length
            limit: Maximum number of paths to return
            
        Returns:
            List of path data including nodes and relationships
        """
        query = PathQueries.FIND_EXPOSURE_PATHS.format(max_depth=max_depth)
        
        try:
            async with self._session() as session:
                result = await session.run(
                    query,
                    source_id=source_id,
                    limit=limit
                )
                return await result.data()
                
        except Neo4jError as e:
            logger.error(f"Neo4j error finding exposure paths: {e}")
            raise GraphEngineError(f"Failed to find paths: {e}") from e
    
    async def find_ai_exposure_paths(
        self,
        min_sensitivity: float = 0.5,
        max_depth: int = 4,
        limit: int = 20
    ) -> List[Dict[str, Any]]:
        """
        Find all paths from data stores to AI tools.
        
        Args:
            min_sensitivity: Minimum sensitivity likelihood filter
            max_depth: Maximum path length
            limit: Maximum number of paths to return
            
        Returns:
            List of AI exposure path data
        """
        query = PathQueries.FIND_AI_EXPOSURE_PATHS.format(max_depth=max_depth)
        
        try:
            async with self._session() as session:
                result = await session.run(
                    query,
                    min_sensitivity=min_sensitivity,
                    limit=limit
                )
                return await result.data()
                
        except Neo4jError as e:
            logger.error(f"Neo4j error finding AI exposure paths: {e}")
            raise GraphEngineError(f"Failed to find AI paths: {e}") from e
    
    async def get_neighbors(
        self,
        node_id: str,
        limit: int = 50
    ) -> List[Dict[str, Any]]:
        """
        Get neighboring nodes.
        
        Args:
            node_id: Center node identifier
            limit: Maximum number of neighbors
            
        Returns:
            List of neighbor data with relationship info
        """
        try:
            async with self._session() as session:
                result = await session.run(
                    PathQueries.GET_NEIGHBORS,
                    node_id=node_id,
                    limit=limit
                )
                return await result.data()
                
        except Neo4jError as e:
            logger.error(f"Neo4j error getting neighbors: {e}")
            raise GraphEngineError(f"Failed to get neighbors: {e}") from e
    
    # =========================================================================
    # Analytics
    # =========================================================================
    
    async def get_high_risk_nodes(
        self,
        threshold: float = 0.7,
        limit: int = 20
    ) -> List[Dict[str, Any]]:
        """
        Get nodes with high risk scores.
        
        Args:
            threshold: Minimum exposure score
            limit: Maximum number of results
            
        Returns:
            List of high-risk node data
        """
        try:
            async with self._session() as session:
                result = await session.run(
                    AnalyticsQueries.GET_HIGH_RISK_NODES,
                    threshold=threshold,
                    limit=limit
                )
                return await result.data()
                
        except Neo4jError as e:
            logger.error(f"Neo4j error getting high risk nodes: {e}")
            raise GraphEngineError(f"Failed to get high risk nodes: {e}") from e
    
    async def get_risk_distribution(self) -> List[Dict[str, Any]]:
        """
        Get distribution of nodes across risk levels.
        
        Returns:
            List of risk level counts
        """
        try:
            async with self._session() as session:
                result = await session.run(
                    AnalyticsQueries.GET_RISK_DISTRIBUTION
                )
                return await result.data()
                
        except Neo4jError as e:
            logger.error(f"Neo4j error getting risk distribution: {e}")
            raise GraphEngineError(f"Failed to get distribution: {e}") from e
    
    async def get_external_exposures(
        self,
        limit: int = 50
    ) -> List[Dict[str, Any]]:
        """
        Get all external exposure points.
        
        Returns data about internal resources exposed to
        external entities, AI tools, or public endpoints.
        
        Args:
            limit: Maximum number of results
            
        Returns:
            List of exposure data
        """
        try:
            async with self._session() as session:
                result = await session.run(
                    AnalyticsQueries.GET_EXTERNAL_EXPOSURES,
                    limit=limit
                )
                return await result.data()
                
        except Neo4jError as e:
            logger.error(f"Neo4j error getting external exposures: {e}")
            raise GraphEngineError(f"Failed to get exposures: {e}") from e
    
    # =========================================================================
    # Health Check
    # =========================================================================
    
    async def health_check(self) -> Dict[str, Any]:
        """
        Check database connectivity and basic stats.
        
        Returns:
            Health status dictionary
        """
        try:
            async with self._session() as session:
                # Simple query to verify connectivity
                result = await session.run("RETURN 1 as connected")
                await result.single()
                
                # Get node counts
                counts = {}
                for node_type in NodeType:
                    query = NodeQueries.COUNT_NODES_BY_TYPE.format(
                        label=node_type.value
                    )
                    result = await session.run(query)
                    record = await result.single()
                    counts[node_type.value] = record["count"] if record else 0
                
                return {
                    "status": "healthy",
                    "connected": True,
                    "node_counts": counts
                }
                
        except Neo4jError as e:
            logger.error(f"Health check failed: {e}")
            return {
                "status": "unhealthy",
                "connected": False,
                "error": str(e)
            }
