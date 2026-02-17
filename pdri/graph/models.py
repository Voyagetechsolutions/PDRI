"""
PDRI Graph Models
=================

Node and edge type definitions for the PDRI risk graph.

The risk graph models the relationships between:
    - DataStores: Databases, file systems, data warehouses
    - Services: Applications and microservices
    - AITools: AI/ML tools and services
    - Identities: Users and service accounts
    - APIs: API endpoints

Graph Structure:
    Nodes represent entities that can contain or access data.
    Edges represent access patterns, integrations, and data flows.

Author: PDRI Team
Version: 1.0.0
"""

from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class NodeType(str, Enum):
    """
    Types of nodes in the risk graph.
    
    Each node type has specific properties and risk characteristics.
    """
    
    DATA_STORE = "DataStore"
    """Database, file system, or data warehouse"""
    
    SERVICE = "Service"
    """Application or microservice"""
    
    AI_TOOL = "AITool"
    """AI/ML tool or service (ChatGPT, Copilot, etc.)"""
    
    IDENTITY = "Identity"
    """User or service account"""
    
    API = "API"
    """API endpoint"""
    
    EXTERNAL = "External"
    """External entity (vendor, partner, etc.)"""


class EdgeType(str, Enum):
    """
    Types of edges (relationships) in the risk graph.
    
    Edges define how entities interact and how data flows.
    """
    
    ACCESSES = "ACCESSES"
    """Identity accesses a DataStore or Service"""
    
    INTEGRATES_WITH = "INTEGRATES_WITH"
    """Service integrates with an AITool or external API"""
    
    MOVES_DATA_TO = "MOVES_DATA_TO"
    """Data flows from one entity to another"""
    
    EXPOSES = "EXPOSES"
    """Entity exposes data to an external endpoint"""
    
    AUTHENTICATES_TO = "AUTHENTICATES_TO"
    """Identity authenticates to a service"""
    
    MANAGES = "MANAGES"
    """Identity has management access to an entity"""
    
    CONTAINS = "CONTAINS"
    """DataStore contains sensitive data categories"""


class BaseNode(BaseModel):
    """
    Base class for all graph nodes.
    
    Provides common properties shared by all node types.
    """
    
    id: str = Field(..., description="Unique node identifier")
    name: str = Field(..., description="Human-readable name")
    node_type: NodeType = Field(..., description="Type of this node")
    
    # Risk scores (updated by scoring engine)
    exposure_score: float = Field(
        default=0.0,
        ge=0.0,
        le=1.0,
        description="Current exposure level"
    )
    volatility_score: float = Field(
        default=0.0,
        ge=0.0,
        le=1.0,
        description="Risk stability measure"
    )
    sensitivity_likelihood: float = Field(
        default=0.0,
        ge=0.0,
        le=1.0,
        description="Probability of containing sensitive data"
    )
    
    # Metadata
    created_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        description="When this node was created"
    )
    updated_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        description="Last update timestamp"
    )
    tags: List[str] = Field(
        default_factory=list,
        description="Classification tags"
    )
    metadata: Dict[str, Any] = Field(
        default_factory=dict,
        description="Additional node-specific data"
    )
    
    def to_neo4j_properties(self) -> Dict[str, Any]:
        """
        Convert node to Neo4j property dictionary.
        
        Returns:
            Dictionary of properties for Neo4j
        """
        props = self.model_dump()
        # Convert datetime to ISO format
        props['created_at'] = self.created_at.isoformat()
        props['updated_at'] = self.updated_at.isoformat()
        # Convert node_type to string
        props['node_type'] = self.node_type.value
        return props


class DataStoreNode(BaseNode):
    """
    Data storage entity (database, file system, warehouse).
    
    DataStores are primary risk carriers as they contain actual data.
    """
    
    node_type: NodeType = Field(default=NodeType.DATA_STORE)
    
    store_type: str = Field(
        ...,
        description="Type: 'database', 'filesystem', 'warehouse', 'cache'"
    )
    technology: str = Field(
        default="unknown",
        description="Technology stack (PostgreSQL, S3, etc.)"
    )
    is_encrypted: bool = Field(
        default=False,
        description="Whether data at rest is encrypted"
    )
    has_backup: bool = Field(
        default=False,
        description="Whether backups are configured"
    )
    data_classification: str = Field(
        default="unclassified",
        description="Data classification level"
    )
    estimated_record_count: Optional[int] = Field(
        default=None,
        description="Estimated number of records"
    )
    
    # Connections
    connected_services_count: int = Field(
        default=0,
        description="Number of services with access"
    )
    connected_ai_tools_count: int = Field(
        default=0,
        description="Number of AI tools with access"
    )


class ServiceNode(BaseNode):
    """
    Application or microservice entity.
    
    Services process data and act as intermediaries in the graph.
    """
    
    node_type: NodeType = Field(default=NodeType.SERVICE)
    
    service_type: str = Field(
        default="application",
        description="Type: 'application', 'microservice', 'lambda', 'batch'"
    )
    is_internal: bool = Field(
        default=True,
        description="Whether this is an internal service"
    )
    api_endpoint_count: int = Field(
        default=0,
        description="Number of API endpoints exposed"
    )
    environment: str = Field(
        default="production",
        description="Deployment environment"
    )
    owner_team: Optional[str] = Field(
        default=None,
        description="Team responsible for this service"
    )
    
    # Security posture
    authentication_required: bool = Field(
        default=True,
        description="Whether authentication is required"
    )
    has_rate_limiting: bool = Field(
        default=False,
        description="Whether rate limiting is configured"
    )


class AIToolNode(BaseNode):
    """
    AI/ML tool or service entity.
    
    AI tools are high-risk entities due to their data ingestion capabilities.
    """
    
    node_type: NodeType = Field(default=NodeType.AI_TOOL)
    
    vendor: str = Field(..., description="Vendor name (OpenAI, Anthropic, etc.)")
    tool_name: str = Field(..., description="Specific tool name")
    is_sanctioned: bool = Field(
        default=False,
        description="Whether this tool is approved for use"
    )
    access_level: str = Field(
        default="read",
        description="Access level: 'read', 'write', 'admin'"
    )
    data_retention: Optional[str] = Field(
        default=None,
        description="Vendor's data retention policy"
    )
    
    # Risk factors specific to AI
    can_learn_from_data: bool = Field(
        default=False,
        description="Whether the tool can learn from input data"
    )
    sends_data_external: bool = Field(
        default=True,
        description="Whether data is sent to external servers"
    )
    has_audit_logging: bool = Field(
        default=False,
        description="Whether usage is audit logged"
    )


class IdentityNode(BaseNode):
    """
    User or service account identity.
    
    Identities represent actors that access resources.
    """
    
    node_type: NodeType = Field(default=NodeType.IDENTITY)
    
    identity_type: str = Field(
        ...,
        description="Type: 'user', 'service_account', 'api_key'"
    )
    privilege_level: str = Field(
        default="standard",
        description="Privilege level: 'read', 'write', 'admin', 'super_admin'"
    )
    department: Optional[str] = Field(
        default=None,
        description="Department or team"
    )
    is_active: bool = Field(
        default=True,
        description="Whether this identity is active"
    )
    
    # Access patterns
    last_active: Optional[datetime] = Field(
        default=None,
        description="Last activity timestamp"
    )
    access_count_30d: int = Field(
        default=0,
        description="Number of accesses in last 30 days"
    )
    
    # Risk indicators
    has_mfa: bool = Field(
        default=False,
        description="Whether MFA is enabled"
    )
    has_api_keys: bool = Field(
        default=False,
        description="Whether this identity has API keys"
    )


class APINode(BaseNode):
    """
    API endpoint entity.
    
    APIs are access points that expose services and data.
    """
    
    node_type: NodeType = Field(default=NodeType.API)
    
    endpoint: str = Field(..., description="API endpoint path")
    http_methods: List[str] = Field(
        default_factory=list,
        description="Supported HTTP methods"
    )
    authentication_type: str = Field(
        default="none",
        description="Auth type: 'none', 'api_key', 'oauth', 'jwt'"
    )
    is_public: bool = Field(
        default=False,
        description="Whether this API is publicly accessible"
    )
    rate_limit: Optional[int] = Field(
        default=None,
        description="Rate limit per minute"
    )
    
    # Traffic patterns
    request_count_24h: int = Field(
        default=0,
        description="Requests in last 24 hours"
    )
    error_rate: float = Field(
        default=0.0,
        ge=0.0,
        le=1.0,
        description="Error rate in last 24 hours"
    )


class GraphEdge(BaseModel):
    """
    Edge (relationship) between graph nodes.
    
    Edges carry metadata about the nature of the connection.
    """
    
    id: str = Field(..., description="Unique edge identifier")
    edge_type: EdgeType = Field(..., description="Type of relationship")
    source_id: str = Field(..., description="Source node ID")
    target_id: str = Field(..., description="Target node ID")
    
    # Edge properties
    weight: float = Field(
        default=1.0,
        ge=0.0,
        description="Relationship strength/importance"
    )
    created_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        description="When this edge was created"
    )
    last_activity: Optional[datetime] = Field(
        default=None,
        description="Last activity on this edge"
    )
    
    # Access patterns (for ACCESSES edges)
    access_frequency: Optional[str] = Field(
        default=None,
        description="'hourly', 'daily', 'weekly', 'monthly', 'rare'"
    )
    access_count_30d: int = Field(
        default=0,
        description="Access count in last 30 days"
    )
    
    # Data flow properties (for MOVES_DATA_TO edges)
    data_volume_bytes: Optional[int] = Field(
        default=None,
        description="Total data volume transferred"
    )
    data_direction: Optional[str] = Field(
        default=None,
        description="'unidirectional' or 'bidirectional'"
    )
    
    metadata: Dict[str, Any] = Field(
        default_factory=dict,
        description="Additional edge-specific data"
    )
    
    def to_neo4j_properties(self) -> Dict[str, Any]:
        """
        Convert edge to Neo4j property dictionary.
        
        Returns:
            Dictionary of properties for Neo4j
        """
        props = self.model_dump()
        props['created_at'] = self.created_at.isoformat()
        if self.last_activity:
            props['last_activity'] = self.last_activity.isoformat()
        props['edge_type'] = self.edge_type.value
        return props
