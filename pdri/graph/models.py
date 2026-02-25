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

    # Identity graph node types
    ROLE = "Role"
    """Role defining a set of permissions"""

    PERMISSION = "Permission"
    """Permission to perform actions on resources"""

    GROUP = "Group"
    """Group of identities with shared roles"""

    # AI Lineage node types
    AI_MODEL = "AIModel"
    """AI/ML model trained on data"""

    TRAINING_DATASET = "TrainingDataset"
    """Dataset used for training AI models"""

    INFERENCE_ENDPOINT = "InferenceEndpoint"
    """API endpoint serving AI model predictions"""

    MODEL_OUTPUT = "ModelOutput"
    """Output/prediction storage from AI models"""


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

    # Identity graph edges
    HAS_ROLE = "HAS_ROLE"
    """Identity has a role assigned"""

    GRANTS_PERMISSION = "GRANTS_PERMISSION"
    """Role grants a permission"""

    APPLIES_TO = "APPLIES_TO"
    """Permission applies to a resource (DataStore, Service, etc.)"""

    MEMBER_OF = "MEMBER_OF"
    """Identity is member of a group/team"""

    DELEGATES_TO = "DELEGATES_TO"
    """Identity delegates access to another identity"""

    # AI Lineage edges
    TRAINED_ON = "TRAINED_ON"
    """AI model trained on a dataset"""

    DERIVES_FROM = "DERIVES_FROM"
    """Data derived from another source"""

    SERVES = "SERVES"
    """Inference endpoint serves a model"""

    PRODUCES = "PRODUCES"
    """Model produces outputs"""

    FEEDS_INTO = "FEEDS_INTO"
    """Data feeds into another process/model"""

    FINE_TUNED_FROM = "FINE_TUNED_FROM"
    """Model fine-tuned from another model"""

    EXPORTS_TO = "EXPORTS_TO"
    """Data exported to external destination"""


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


class RoleNode(BaseNode):
    """
    Role entity defining a set of permissions.

    Roles aggregate permissions and are assigned to identities.
    Used for identity-aware path analysis and blast radius calculation.
    """

    node_type: NodeType = Field(default=NodeType.ROLE)

    role_name: str = Field(..., description="Unique role name")
    description: str = Field(
        default="",
        description="Human-readable description of the role"
    )
    scope: str = Field(
        default="organization",
        description="Scope: 'organization', 'team', 'project', 'resource'"
    )
    is_privileged: bool = Field(
        default=False,
        description="Whether this is a privileged/admin role"
    )
    is_builtin: bool = Field(
        default=False,
        description="Whether this is a built-in system role"
    )

    # Risk factors
    permission_count: int = Field(
        default=0,
        description="Number of permissions granted"
    )
    identity_count: int = Field(
        default=0,
        description="Number of identities with this role"
    )
    data_access_scope: str = Field(
        default="none",
        description="Data access level: 'none', 'read', 'write', 'admin', 'all'"
    )


class PermissionNode(BaseNode):
    """
    Permission entity defining actions on resources.

    Permissions are granted by roles and apply to specific resources.
    """

    node_type: NodeType = Field(default=NodeType.PERMISSION)

    permission_name: str = Field(..., description="Unique permission identifier")
    action: str = Field(
        ...,
        description="Action type: 'read', 'write', 'delete', 'admin', 'execute'"
    )
    resource_type: str = Field(
        ...,
        description="Type of resource: 'datastore', 'service', 'api', 'config'"
    )
    is_wildcard: bool = Field(
        default=False,
        description="Whether this grants access to all resources of type"
    )

    # Risk factors
    sensitivity_impact: str = Field(
        default="low",
        description="Impact level: 'low', 'medium', 'high', 'critical'"
    )
    requires_approval: bool = Field(
        default=False,
        description="Whether using this permission requires approval"
    )


class GroupNode(BaseNode):
    """
    Group of identities with shared access.

    Groups simplify permission management by aggregating identities.
    """

    node_type: NodeType = Field(default=NodeType.GROUP)

    group_name: str = Field(..., description="Unique group name")
    description: str = Field(
        default="",
        description="Human-readable description"
    )
    is_dynamic: bool = Field(
        default=False,
        description="Whether membership is dynamically computed"
    )
    membership_rule: Optional[str] = Field(
        default=None,
        description="Rule for dynamic membership (if applicable)"
    )

    # Risk factors
    member_count: int = Field(
        default=0,
        description="Number of members"
    )
    role_count: int = Field(
        default=0,
        description="Number of roles assigned to this group"
    )
    includes_privileged: bool = Field(
        default=False,
        description="Whether group has any privileged roles"
    )


# =============================================================================
# AI Lineage Node Types
# =============================================================================


class AIModelNode(BaseNode):
    """
    AI/ML model entity for lineage tracking.

    Tracks the lifecycle of AI models including:
    - What data they were trained on
    - What outputs they produce
    - Where they are deployed
    """

    node_type: NodeType = Field(default=NodeType.AI_MODEL)

    model_name: str = Field(..., description="Model identifier/name")
    model_type: str = Field(
        ...,
        description="Type: 'llm', 'classifier', 'regression', 'embedding', 'generative'"
    )
    vendor: Optional[str] = Field(
        default=None,
        description="Vendor if external (OpenAI, Anthropic, etc.)"
    )
    version: str = Field(default="1.0", description="Model version")
    is_external: bool = Field(
        default=False,
        description="Whether this is a third-party model"
    )

    # Training info
    training_date: Optional[datetime] = Field(
        default=None,
        description="When model was trained"
    )
    training_data_sensitivity: str = Field(
        default="unknown",
        description="Sensitivity of training data: 'public', 'internal', 'confidential', 'restricted'"
    )

    # Risk factors
    can_memorize_data: bool = Field(
        default=True,
        description="Whether model can memorize/regurgitate training data"
    )
    outputs_to_external: bool = Field(
        default=False,
        description="Whether outputs are sent externally"
    )
    has_guardrails: bool = Field(
        default=False,
        description="Whether model has output filtering/guardrails"
    )


class TrainingDatasetNode(BaseNode):
    """
    Training dataset for AI model lineage.

    Represents datasets used to train or fine-tune AI models.
    """

    node_type: NodeType = Field(default=NodeType.TRAINING_DATASET)

    dataset_name: str = Field(..., description="Dataset identifier")
    source_type: str = Field(
        ...,
        description="Source: 'internal_db', 'logs', 'documents', 'external', 'synthetic'"
    )
    data_classification: str = Field(
        default="internal",
        description="Classification: 'public', 'internal', 'confidential', 'restricted'"
    )

    # Content info
    record_count: Optional[int] = Field(
        default=None,
        description="Number of records/samples"
    )
    contains_pii: bool = Field(
        default=False,
        description="Whether dataset contains PII"
    )
    contains_secrets: bool = Field(
        default=False,
        description="Whether dataset may contain secrets/credentials"
    )
    data_categories: List[str] = Field(
        default_factory=list,
        description="Categories: 'user_data', 'financial', 'health', 'credentials', etc."
    )

    # Lineage
    source_datastores: List[str] = Field(
        default_factory=list,
        description="IDs of source DataStore nodes"
    )
    extraction_date: Optional[datetime] = Field(
        default=None,
        description="When data was extracted"
    )


class InferenceEndpointNode(BaseNode):
    """
    AI model inference endpoint.

    Represents where AI models are served for predictions.
    """

    node_type: NodeType = Field(default=NodeType.INFERENCE_ENDPOINT)

    endpoint_url: str = Field(..., description="Endpoint URL/path")
    model_id: str = Field(..., description="ID of the model being served")
    environment: str = Field(
        default="production",
        description="Environment: 'development', 'staging', 'production'"
    )

    # Access
    is_public: bool = Field(
        default=False,
        description="Whether endpoint is publicly accessible"
    )
    authentication_required: bool = Field(
        default=True,
        description="Whether authentication is required"
    )
    rate_limit: Optional[int] = Field(
        default=None,
        description="Requests per minute limit"
    )

    # Monitoring
    request_count_24h: int = Field(
        default=0,
        description="Requests in last 24 hours"
    )
    avg_latency_ms: Optional[float] = Field(
        default=None,
        description="Average response latency"
    )

    # Risk factors
    logs_prompts: bool = Field(
        default=False,
        description="Whether prompts are logged"
    )
    logs_responses: bool = Field(
        default=False,
        description="Whether responses are logged"
    )


class ModelOutputNode(BaseNode):
    """
    AI model output/prediction storage.

    Tracks where model outputs are stored and how they're used.
    """

    node_type: NodeType = Field(default=NodeType.MODEL_OUTPUT)

    output_name: str = Field(..., description="Output storage identifier")
    output_type: str = Field(
        ...,
        description="Type: 'predictions', 'embeddings', 'generated_content', 'analysis'"
    )
    storage_location: str = Field(
        ...,
        description="Where outputs are stored (DataStore ID or external)"
    )

    # Content risk
    may_contain_sensitive: bool = Field(
        default=False,
        description="Whether outputs may contain sensitive data"
    )
    retention_days: Optional[int] = Field(
        default=None,
        description="How long outputs are retained"
    )

    # Downstream usage
    used_for_training: bool = Field(
        default=False,
        description="Whether outputs are used to train other models"
    )
    shared_externally: bool = Field(
        default=False,
        description="Whether outputs are shared externally"
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
