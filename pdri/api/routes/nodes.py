"""
PDRI Node Routes
================

REST API endpoints for graph node operations.

Author: PDRI Team
Version: 1.0.0
"""

from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field

from pdri.api.dependencies import get_graph_engine
from pdri.graph.engine import GraphEngine, GraphEngineError
from pdri.graph.models import (
    NodeType,
    EdgeType,
    DataStoreNode,
    ServiceNode,
    AIToolNode,
    IdentityNode,
    APINode,
    GraphEdge,
)


router = APIRouter(prefix="/nodes", tags=["Nodes"])


# =============================================================================
# Request/Response Models
# =============================================================================

class CreateDataStoreRequest(BaseModel):
    """Request model for creating a data store node."""
    id: str = Field(..., description="Unique identifier")
    name: str = Field(..., description="Human-readable name")
    store_type: str = Field(..., description="Type: database, filesystem, warehouse")
    technology: str = Field(default="unknown", description="Technology stack")
    is_encrypted: bool = Field(default=False)
    data_classification: str = Field(default="unclassified")
    tags: List[str] = Field(default_factory=list)
    metadata: Dict[str, Any] = Field(default_factory=dict)


class CreateServiceRequest(BaseModel):
    """Request model for creating a service node."""
    id: str
    name: str
    service_type: str = Field(default="application")
    is_internal: bool = Field(default=True)
    environment: str = Field(default="production")
    owner_team: Optional[str] = None
    tags: List[str] = Field(default_factory=list)


class CreateAIToolRequest(BaseModel):
    """Request model for creating an AI tool node."""
    id: str
    name: str
    vendor: str
    tool_name: str
    is_sanctioned: bool = Field(default=False)
    access_level: str = Field(default="read")
    can_learn_from_data: bool = Field(default=False)
    sends_data_external: bool = Field(default=True)
    tags: List[str] = Field(default_factory=list)


class CreateEdgeRequest(BaseModel):
    """Request model for creating an edge."""
    source_id: str
    target_id: str
    edge_type: EdgeType
    weight: float = Field(default=1.0, ge=0.0)
    metadata: Dict[str, Any] = Field(default_factory=dict)


class NodeResponse(BaseModel):
    """Response model for node data."""
    id: str
    name: str
    node_type: str
    exposure_score: float = 0.0
    volatility_score: float = 0.0
    sensitivity_likelihood: float = 0.0
    created_at: str
    updated_at: str
    tags: List[str] = []
    metadata: Dict[str, Any] = {}


# =============================================================================
# Data Store Endpoints
# =============================================================================

@router.post(
    "/datastores",
    response_model=NodeResponse,
    summary="Create Data Store",
    description="Create a new data store node in the risk graph."
)
async def create_data_store(
    request: CreateDataStoreRequest,
    graph: GraphEngine = Depends(get_graph_engine)
) -> Dict[str, Any]:
    """Create a data store node."""
    node = DataStoreNode(
        id=request.id,
        name=request.name,
        store_type=request.store_type,
        technology=request.technology,
        is_encrypted=request.is_encrypted,
        data_classification=request.data_classification,
        tags=request.tags,
        metadata=request.metadata
    )
    
    try:
        await graph.create_node(node)
        return node.to_neo4j_properties()
    except GraphEngineError as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get(
    "/datastores",
    response_model=List[NodeResponse],
    summary="List Data Stores",
    description="Get all data store nodes."
)
async def list_data_stores(
    skip: int = Query(0, ge=0),
    limit: int = Query(100, ge=1, le=1000),
    graph: GraphEngine = Depends(get_graph_engine)
) -> List[Dict[str, Any]]:
    """List all data store nodes with pagination."""
    try:
        nodes = await graph.get_nodes_by_type(
            node_type=NodeType.DATA_STORE,
            skip=skip,
            limit=limit
        )
        return nodes
    except GraphEngineError as e:
        raise HTTPException(status_code=500, detail=str(e))


# =============================================================================
# Service Endpoints
# =============================================================================

@router.post(
    "/services",
    response_model=NodeResponse,
    summary="Create Service",
    description="Create a new service node in the risk graph."
)
async def create_service(
    request: CreateServiceRequest,
    graph: GraphEngine = Depends(get_graph_engine)
) -> Dict[str, Any]:
    """Create a service node."""
    node = ServiceNode(
        id=request.id,
        name=request.name,
        service_type=request.service_type,
        is_internal=request.is_internal,
        environment=request.environment,
        owner_team=request.owner_team,
        tags=request.tags
    )
    
    try:
        await graph.create_node(node)
        return node.to_neo4j_properties()
    except GraphEngineError as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get(
    "/services",
    response_model=List[NodeResponse],
    summary="List Services"
)
async def list_services(
    skip: int = Query(0, ge=0),
    limit: int = Query(100, ge=1, le=1000),
    graph: GraphEngine = Depends(get_graph_engine)
) -> List[Dict[str, Any]]:
    """List all service nodes."""
    try:
        return await graph.get_nodes_by_type(
            node_type=NodeType.SERVICE,
            skip=skip,
            limit=limit
        )
    except GraphEngineError as e:
        raise HTTPException(status_code=500, detail=str(e))


# =============================================================================
# AI Tool Endpoints
# =============================================================================

@router.post(
    "/aitools",
    response_model=NodeResponse,
    summary="Create AI Tool",
    description="Create a new AI tool node in the risk graph."
)
async def create_ai_tool(
    request: CreateAIToolRequest,
    graph: GraphEngine = Depends(get_graph_engine)
) -> Dict[str, Any]:
    """Create an AI tool node."""
    node = AIToolNode(
        id=request.id,
        name=request.name,
        vendor=request.vendor,
        tool_name=request.tool_name,
        is_sanctioned=request.is_sanctioned,
        access_level=request.access_level,
        can_learn_from_data=request.can_learn_from_data,
        sends_data_external=request.sends_data_external,
        tags=request.tags
    )
    
    try:
        await graph.create_node(node)
        return node.to_neo4j_properties()
    except GraphEngineError as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get(
    "/aitools",
    response_model=List[NodeResponse],
    summary="List AI Tools"
)
async def list_ai_tools(
    skip: int = Query(0, ge=0),
    limit: int = Query(100, ge=1, le=1000),
    graph: GraphEngine = Depends(get_graph_engine)
) -> List[Dict[str, Any]]:
    """List all AI tool nodes."""
    try:
        return await graph.get_nodes_by_type(
            node_type=NodeType.AI_TOOL,
            skip=skip,
            limit=limit
        )
    except GraphEngineError as e:
        raise HTTPException(status_code=500, detail=str(e))


# =============================================================================
# Generic Node Endpoints
# =============================================================================

@router.get(
    "/{node_id}",
    summary="Get Node",
    description="Get a node by ID with all properties."
)
async def get_node(
    node_id: str,
    include_relationships: bool = Query(False),
    graph: GraphEngine = Depends(get_graph_engine)
) -> Dict[str, Any]:
    """Get a node by ID."""
    try:
        if include_relationships:
            result = await graph.get_node_with_relationships(node_id)
        else:
            result = await graph.get_node(node_id)
        
        if result is None:
            raise HTTPException(
                status_code=404,
                detail=f"Node not found: {node_id}"
            )
        
        return result
    except GraphEngineError as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.patch(
    "/{node_id}",
    summary="Update Node",
    description="Update node properties."
)
async def update_node(
    node_id: str,
    properties: Dict[str, Any],
    graph: GraphEngine = Depends(get_graph_engine)
) -> Dict[str, Any]:
    """Update node properties."""
    try:
        result = await graph.update_node(node_id, properties)
        
        if result is None:
            raise HTTPException(
                status_code=404,
                detail=f"Node not found: {node_id}"
            )
        
        return result
    except GraphEngineError as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.delete(
    "/{node_id}",
    summary="Delete Node",
    description="Delete a node and all its relationships."
)
async def delete_node(
    node_id: str,
    graph: GraphEngine = Depends(get_graph_engine)
) -> Dict[str, bool]:
    """Delete a node."""
    try:
        deleted = await graph.delete_node(node_id)
        
        if not deleted:
            raise HTTPException(
                status_code=404,
                detail=f"Node not found: {node_id}"
            )
        
        return {"deleted": True}
    except GraphEngineError as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get(
    "/{node_id}/neighbors",
    summary="Get Neighbors",
    description="Get neighboring nodes with relationship info."
)
async def get_neighbors(
    node_id: str,
    limit: int = Query(50, ge=1, le=200),
    graph: GraphEngine = Depends(get_graph_engine)
) -> List[Dict[str, Any]]:
    """Get neighboring nodes."""
    try:
        return await graph.get_neighbors(node_id, limit=limit)
    except GraphEngineError as e:
        raise HTTPException(status_code=500, detail=str(e))


# =============================================================================
# Edge Endpoints
# =============================================================================

@router.post(
    "/edges",
    summary="Create Edge",
    description="Create a relationship between two nodes."
)
async def create_edge(
    request: CreateEdgeRequest,
    graph: GraphEngine = Depends(get_graph_engine)
) -> Dict[str, Any]:
    """Create an edge between nodes."""
    import uuid
    
    edge = GraphEdge(
        id=str(uuid.uuid4()),
        edge_type=request.edge_type,
        source_id=request.source_id,
        target_id=request.target_id,
        weight=request.weight,
        metadata=request.metadata
    )
    
    try:
        result = await graph.create_edge(edge)
        return result.to_neo4j_properties()
    except GraphEngineError as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get(
    "/{node_id}/edges",
    summary="Get Node Edges",
    description="Get all edges connected to a node."
)
async def get_node_edges(
    node_id: str,
    direction: str = Query("all", enum=["incoming", "outgoing", "all"]),
    graph: GraphEngine = Depends(get_graph_engine)
) -> List[Dict[str, Any]]:
    """Get edges for a node."""
    try:
        if direction == "outgoing":
            return await graph.get_edges_from_node(node_id)
        else:
            # For now, return all edges (incoming + outgoing)
            from pdri.graph.queries import EdgeQueries
            async with graph._session() as session:
                result = await session.run(
                    EdgeQueries.GET_ALL_EDGES_FOR_NODE,
                    node_id=node_id
                )
                return await result.data()
    except GraphEngineError as e:
        raise HTTPException(status_code=500, detail=str(e))
