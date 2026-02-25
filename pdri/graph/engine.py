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
    RoleNode,
    PermissionNode,
    GroupNode,
    AIModelNode,
    TrainingDatasetNode,
    InferenceEndpointNode,
    ModelOutputNode,
)
from pdri.graph.queries import (
    NodeQueries,
    EdgeQueries,
    PathQueries,
    AnalyticsQueries,
    IdentityQueries,
    AILineageQueries,
)


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
        NodeType.ROLE: RoleNode,
        NodeType.PERMISSION: PermissionNode,
        NodeType.GROUP: GroupNode,
        NodeType.AI_MODEL: AIModelNode,
        NodeType.TRAINING_DATASET: TrainingDatasetNode,
        NodeType.INFERENCE_ENDPOINT: InferenceEndpointNode,
        NodeType.MODEL_OUTPUT: ModelOutputNode,
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

    # =========================================================================
    # Identity Analytics & Blast Radius
    # =========================================================================

    async def calculate_blast_radius(
        self,
        identity_id: str,
        include_downstream: bool = False
    ) -> Dict[str, Any]:
        """
        Calculate blast radius for an identity compromise.

        Blast radius measures how many resources and sensitive assets
        would be exposed if a specific identity is compromised.

        Args:
            identity_id: Identity to analyze
            include_downstream: Include resources exposed by accessible resources

        Returns:
            Blast radius metrics and affected resource list
        """
        query = (
            IdentityQueries.CALCULATE_BLAST_RADIUS_WITH_DOWNSTREAM
            if include_downstream
            else IdentityQueries.CALCULATE_BLAST_RADIUS
        )

        try:
            async with self._session() as session:
                result = await session.run(query, identity_id=identity_id)
                record = await result.single()

                if record is None:
                    return {
                        "identity_id": identity_id,
                        "found": False,
                        "blast_radius": 0,
                        "message": "Identity not found"
                    }

                # Build response based on query type
                if include_downstream:
                    return {
                        "identity_id": record["identity_id"],
                        "identity_name": record["identity_name"],
                        "found": True,
                        "direct_blast_radius": record["direct_blast_radius"],
                        "downstream_exposure_count": record["downstream_exposure_count"],
                        "total_blast_radius": (
                            record["direct_blast_radius"] +
                            record["downstream_exposure_count"]
                        ),
                        "accessible_resources": record["accessible_resources"],
                        "external_exposures": record["external_exposures"],
                    }
                else:
                    return {
                        "identity_id": record["identity_id"],
                        "identity_name": record["identity_name"],
                        "privilege_level": record["privilege_level"],
                        "found": True,
                        "blast_radius": record["total_resources"],
                        "breakdown": {
                            "data_stores": record["data_stores"],
                            "services": record["services"],
                            "ai_tools": record["ai_tools"],
                        },
                        "risk_metrics": {
                            "critical_resources": record["critical_resources"],
                            "sensitive_resources": record["sensitive_resources"],
                            "avg_sensitivity": record["avg_sensitivity"],
                            "max_sensitivity": record["max_sensitivity"],
                        },
                        "resource_ids": record["resource_ids"],
                    }

        except Neo4jError as e:
            logger.error(f"Neo4j error calculating blast radius: {e}")
            raise GraphEngineError(f"Failed to calculate blast radius: {e}") from e

    async def find_identity_access_paths(
        self,
        identity_id: str,
        limit: int = 50
    ) -> List[Dict[str, Any]]:
        """
        Find all access paths for an identity (via roles and permissions).

        Args:
            identity_id: Identity to analyze
            limit: Maximum paths to return

        Returns:
            List of access paths with permission details
        """
        try:
            async with self._session() as session:
                result = await session.run(
                    IdentityQueries.FIND_IDENTITY_ACCESS_PATHS,
                    identity_id=identity_id,
                    limit=limit
                )
                return await result.data()

        except Neo4jError as e:
            logger.error(f"Neo4j error finding identity access paths: {e}")
            raise GraphEngineError(f"Failed to find access paths: {e}") from e

    async def get_privileged_identities(
        self,
        limit: int = 50
    ) -> List[Dict[str, Any]]:
        """
        Get all identities with privileged roles.

        Returns identities that have admin/elevated access,
        useful for security audits.

        Args:
            limit: Maximum results

        Returns:
            List of privileged identities with their roles
        """
        try:
            async with self._session() as session:
                result = await session.run(
                    IdentityQueries.GET_PRIVILEGED_IDENTITIES,
                    limit=limit
                )
                return await result.data()

        except Neo4jError as e:
            logger.error(f"Neo4j error getting privileged identities: {e}")
            raise GraphEngineError(f"Failed to get privileged identities: {e}") from e

    async def get_over_permissioned_identities(
        self,
        limit: int = 50
    ) -> List[Dict[str, Any]]:
        """
        Find identities with more permissions than they use.

        Identifies potential security risks where identities have
        access they don't actually use (principle of least privilege).

        Args:
            limit: Maximum results

        Returns:
            List of over-permissioned identities with utilization metrics
        """
        try:
            async with self._session() as session:
                result = await session.run(
                    IdentityQueries.GET_OVER_PERMISSIONED_IDENTITIES,
                    limit=limit
                )
                return await result.data()

        except Neo4jError as e:
            logger.error(f"Neo4j error finding over-permissioned identities: {e}")
            raise GraphEngineError(f"Failed to find over-permissioned: {e}") from e

    async def get_group_blast_radius(
        self,
        limit: int = 20
    ) -> List[Dict[str, Any]]:
        """
        Get blast radius for all groups.

        Calculates aggregate blast radius for each group based on
        the combined access of all members.

        Args:
            limit: Maximum results

        Returns:
            List of groups with their blast radius metrics
        """
        try:
            async with self._session() as session:
                result = await session.run(
                    IdentityQueries.GET_GROUP_BLAST_RADIUS,
                    limit=limit
                )
                return await result.data()

        except Neo4jError as e:
            logger.error(f"Neo4j error getting group blast radius: {e}")
            raise GraphEngineError(f"Failed to get group blast radius: {e}") from e

    async def find_unauthorized_access_paths(
        self,
        limit: int = 50
    ) -> List[Dict[str, Any]]:
        """
        Find direct access that bypasses role permissions.

        Identifies potential compliance issues where identities
        access resources without proper role/permission paths.

        Args:
            limit: Maximum results

        Returns:
            List of unauthorized access paths
        """
        try:
            async with self._session() as session:
                result = await session.run(
                    IdentityQueries.FIND_UNAUTHORIZED_ACCESS_PATHS,
                    limit=limit
                )
                return await result.data()

        except Neo4jError as e:
            logger.error(f"Neo4j error finding unauthorized access: {e}")
            raise GraphEngineError(f"Failed to find unauthorized access: {e}") from e

    # =========================================================================
    # AI Data Lineage
    # =========================================================================

    async def trace_data_to_ai(
        self,
        data_store_id: str,
        limit: int = 50
    ) -> List[Dict[str, Any]]:
        """
        Trace how data flows from a data store into AI systems.

        Forward lineage: DataStore → Dataset → Model

        Args:
            data_store_id: Source data store ID
            limit: Maximum paths to return

        Returns:
            List of lineage paths showing AI consumption
        """
        try:
            async with self._session() as session:
                result = await session.run(
                    AILineageQueries.TRACE_DATA_TO_AI,
                    data_store_id=data_store_id,
                    limit=limit
                )
                return await result.data()

        except Neo4jError as e:
            logger.error(f"Neo4j error tracing data to AI: {e}")
            raise GraphEngineError(f"Failed to trace data to AI: {e}") from e

    async def trace_full_ai_lineage(
        self,
        min_sensitivity: float = 0.5,
        limit: int = 50
    ) -> List[Dict[str, Any]]:
        """
        Trace complete AI data lineage end-to-end.

        Full chain: Source → Dataset → Model → Endpoint → Output → External

        Args:
            min_sensitivity: Minimum source sensitivity to include
            limit: Maximum paths to return

        Returns:
            Complete lineage paths through AI systems
        """
        try:
            async with self._session() as session:
                result = await session.run(
                    AILineageQueries.TRACE_FULL_AI_LINEAGE,
                    min_sensitivity=min_sensitivity,
                    limit=limit
                )
                return await result.data()

        except Neo4jError as e:
            logger.error(f"Neo4j error tracing full AI lineage: {e}")
            raise GraphEngineError(f"Failed to trace AI lineage: {e}") from e

    async def trace_model_training_sources(
        self,
        model_id: str
    ) -> Dict[str, Any]:
        """
        Trace backward to find all data sources for a model.

        Backward lineage: Model → Dataset → DataStore sources

        Args:
            model_id: AI model ID

        Returns:
            Model info with all contributing data sources
        """
        try:
            async with self._session() as session:
                result = await session.run(
                    AILineageQueries.TRACE_MODEL_TRAINING_SOURCES,
                    model_id=model_id
                )
                record = await result.single()
                return dict(record) if record else {}

        except Neo4jError as e:
            logger.error(f"Neo4j error tracing model sources: {e}")
            raise GraphEngineError(f"Failed to trace model sources: {e}") from e

    async def find_sensitive_data_in_ai(
        self,
        min_sensitivity: float = 0.5,
        limit: int = 50
    ) -> List[Dict[str, Any]]:
        """
        Find sensitive data being used by AI systems.

        Identifies data stores with high sensitivity that feed
        into AI training or inference.

        Args:
            min_sensitivity: Minimum sensitivity threshold
            limit: Maximum results

        Returns:
            List of sensitive data → AI relationships
        """
        try:
            async with self._session() as session:
                result = await session.run(
                    AILineageQueries.FIND_SENSITIVE_DATA_IN_AI,
                    min_sensitivity=min_sensitivity,
                    limit=limit
                )
                return await result.data()

        except Neo4jError as e:
            logger.error(f"Neo4j error finding sensitive AI data: {e}")
            raise GraphEngineError(f"Failed to find sensitive AI data: {e}") from e

    async def find_external_ai_exposure(
        self,
        limit: int = 50
    ) -> List[Dict[str, Any]]:
        """
        Find data exposed to external AI systems.

        Identifies internal data that flows to third-party
        AI services (OpenAI, Anthropic, etc.).

        Args:
            limit: Maximum results

        Returns:
            List of internal data → external AI exposures
        """
        try:
            async with self._session() as session:
                result = await session.run(
                    AILineageQueries.FIND_EXTERNAL_AI_EXPOSURE,
                    limit=limit
                )
                return await result.data()

        except Neo4jError as e:
            logger.error(f"Neo4j error finding external AI exposure: {e}")
            raise GraphEngineError(f"Failed to find external AI exposure: {e}") from e

    async def calculate_data_ai_blast_radius(
        self,
        data_store_id: str
    ) -> Dict[str, Any]:
        """
        Calculate AI-specific blast radius for a data source.

        If this data source is compromised, which AI systems
        could be affected?

        Args:
            data_store_id: Data store ID

        Returns:
            Blast radius metrics for AI impact
        """
        try:
            async with self._session() as session:
                result = await session.run(
                    AILineageQueries.CALCULATE_DATA_AI_BLAST_RADIUS,
                    data_store_id=data_store_id
                )
                record = await result.single()
                return dict(record) if record else {}

        except Neo4jError as e:
            logger.error(f"Neo4j error calculating AI blast radius: {e}")
            raise GraphEngineError(f"Failed to calculate AI blast radius: {e}") from e

    async def get_ai_data_inventory(self) -> List[Dict[str, Any]]:
        """
        Get inventory of all data used in AI systems.

        Returns comprehensive view of training datasets,
        their sources, and which models use them.

        Returns:
            AI data inventory list
        """
        try:
            async with self._session() as session:
                result = await session.run(AILineageQueries.GET_AI_DATA_INVENTORY)
                return await result.data()

        except Neo4jError as e:
            logger.error(f"Neo4j error getting AI data inventory: {e}")
            raise GraphEngineError(f"Failed to get AI inventory: {e}") from e

    async def get_models_by_data_sensitivity(
        self,
        limit: int = 50
    ) -> List[Dict[str, Any]]:
        """
        Get AI models grouped by training data sensitivity.

        Helps identify models trained on sensitive data
        that may require additional controls.

        Args:
            limit: Maximum results

        Returns:
            Models with their data sensitivity levels
        """
        try:
            async with self._session() as session:
                result = await session.run(
                    AILineageQueries.GET_MODELS_BY_DATA_SENSITIVITY,
                    limit=limit
                )
                return await result.data()

        except Neo4jError as e:
            logger.error(f"Neo4j error getting models by sensitivity: {e}")
            raise GraphEngineError(f"Failed to get models by sensitivity: {e}") from e
