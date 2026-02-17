"""
PDRI Security Event Schemas
============================

Core event schemas for the PDRI platform. These schemas define the structure
of all security telemetry flowing through the system.

Key Components:
    - SecurityEvent: Primary event schema consumed from Kafka
    - SecurityEventType: Enumeration of all supported event types
    - SensitivityTag: Data sensitivity classification tags
    - ExposureDirection: Direction of data/access exposure

Usage:
    from shared.schemas.events import SecurityEvent, SecurityEventType
    
    event = SecurityEvent(
        event_id="evt-123",
        event_type=SecurityEventType.AI_DATA_ACCESS,
        source_system_id="system-456",
        ...
    )

Author: PDRI Team
Version: 1.0.0
"""

from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field, field_validator
import uuid


class SecurityEventType(str, Enum):
    """
    Enumeration of all security event types processed by PDRI.
    
    Categories:
        - AI_* : Events related to AI tool usage and data access
        - SYSTEM_* : General system access events
        - DATA_* : Data movement and handling events
    """
    
    # AI-related events (from Shadow AI)
    AI_DATA_ACCESS = "AI_DATA_ACCESS"
    """AI tool accessed an internal data source"""
    
    AI_PROMPT_SENSITIVE = "AI_PROMPT_SENSITIVE"
    """Prompt sent to AI contains likely sensitive information"""
    
    AI_API_INTEGRATION = "AI_API_INTEGRATION"
    """System connected to an external AI API"""
    
    AI_AGENT_PRIV_ACCESS = "AI_AGENT_PRIV_ACCESS"
    """AI agent used elevated privileges"""
    
    UNSANCTIONED_AI_TOOL = "UNSANCTIONED_AI_TOOL"
    """Unknown/unapproved AI tool interacting with systems"""
    
    # General system events
    SYSTEM_ACCESS = "SYSTEM_ACCESS"
    """Standard system access event"""
    
    SYSTEM_AUTH_FAILURE = "SYSTEM_AUTH_FAILURE"
    """Authentication failure event"""
    
    PRIVILEGE_ESCALATION = "PRIVILEGE_ESCALATION"
    """Privilege escalation detected"""
    
    # Data movement events
    DATA_MOVEMENT = "DATA_MOVEMENT"
    """Data transferred between systems"""
    
    DATA_EXPORT = "DATA_EXPORT"
    """Data exported from internal system"""
    
    DATA_AGGREGATION = "DATA_AGGREGATION"
    """Multiple data sources aggregated"""


class ExposureDirection(str, Enum):
    """
    Direction of data exposure or access flow.
    
    Used to classify the risk vector of an event based on
    where data is flowing to/from.
    """
    
    INTERNAL_TO_EXTERNAL = "internal_to_external"
    """Data or access flowing from internal systems to external"""
    
    INTERNAL_TO_AI = "internal_to_ai"
    """Data flowing to an AI tool or service"""
    
    AI_TO_INTERNAL = "ai_to_internal"
    """AI tool writing to or modifying internal systems"""
    
    EXTERNAL_TO_INTERNAL = "external_to_internal"
    """External entity accessing internal systems"""
    
    INTERNAL_TO_INTERNAL = "internal_to_internal"
    """Movement between internal systems (lateral)"""


class SensitivityTag(str, Enum):
    """
    Data sensitivity classification tags.
    
    These are likelihood-based tags indicating the probable sensitivity
    of data involved in an event. They are not confirmations but hints
    for risk scoring.
    """
    
    FINANCIAL = "financial_related"
    """Likely involves financial data (accounts, transactions, etc.)"""
    
    HEALTH = "health_related"
    """Likely involves health/medical data (PHI, diagnoses, etc.)"""
    
    IDENTITY = "identity_related"
    """Likely involves PII (names, SSN, addresses, etc.)"""
    
    INTELLECTUAL_PROPERTY = "intellectual_property"
    """Likely involves trade secrets, patents, proprietary code"""
    
    CREDENTIALS = "credentials_related"
    """Likely involves passwords, API keys, tokens"""
    
    REGULATED = "regulated_data"
    """Likely subject to regulatory compliance (GDPR, HIPAA, etc.)"""


class EntityType(str, Enum):
    """
    Types of entities in the PDRI risk graph.
    """
    
    DATA_STORE = "data_store"
    """Database, file system, data warehouse"""
    
    SERVICE = "service"
    """Application or microservice"""
    
    AI_TOOL = "ai_tool"
    """AI/ML tool or service"""
    
    IDENTITY = "identity"
    """User or service account"""
    
    API = "api"
    """API endpoint"""
    
    EXTERNAL = "external"
    """External entity (vendor, partner, etc.)"""


class SecurityEvent(BaseModel):
    """
    Primary security event schema for PDRI.
    
    This is the core data structure consumed from Kafka and processed
    by the PDRI ingestion layer. All sensors (Shadow AI, scanners, etc.)
    must emit events conforming to this schema.
    
    Attributes:
        event_id: Unique identifier for deduplication
        event_type: Classification of the event
        timestamp: When the event occurred
        source_system_id: System that generated the event
        target_entity_id: Entity affected by the event (optional)
        identity_id: User/service identity involved (optional)
        sensitivity_tags: Likelihood-based sensitivity hints
        exposure_direction: Direction of exposure
        data_volume_estimate: Estimated bytes involved (optional)
        privilege_level: Privilege level used in the access
        metadata: Additional event-specific data
    
    Example:
        >>> event = SecurityEvent(
        ...     event_id="evt-abc-123",
        ...     event_type=SecurityEventType.AI_DATA_ACCESS,
        ...     timestamp=datetime.utcnow(),
        ...     source_system_id="shadow-ai-001",
        ...     target_entity_id="datastore:prod-db",
        ...     identity_id="service:chatgpt-integration",
        ...     sensitivity_tags=[SensitivityTag.FINANCIAL],
        ...     exposure_direction=ExposureDirection.INTERNAL_TO_AI,
        ...     privilege_level="read",
        ...     metadata={"query_type": "SELECT", "table": "transactions"}
        ... )
    """
    
    event_id: str = Field(
        default_factory=lambda: str(uuid.uuid4()),
        description="Unique event identifier for deduplication"
    )
    
    event_type: SecurityEventType = Field(
        ...,
        description="Classification of the security event"
    )
    
    timestamp: datetime = Field(
        default_factory=datetime.utcnow,
        description="UTC timestamp when the event occurred"
    )
    
    source_system_id: str = Field(
        ...,
        description="ID of the system that generated this event"
    )
    
    target_entity_id: Optional[str] = Field(
        default=None,
        description="ID of the entity affected by this event"
    )
    
    identity_id: Optional[str] = Field(
        default=None,
        description="User or service identity involved in the event"
    )
    
    sensitivity_tags: List[SensitivityTag] = Field(
        default_factory=list,
        description="Likelihood-based sensitivity classification hints"
    )
    
    exposure_direction: ExposureDirection = Field(
        ...,
        description="Direction of data/access exposure"
    )
    
    data_volume_estimate: Optional[int] = Field(
        default=None,
        ge=0,
        description="Estimated data volume in bytes"
    )
    
    privilege_level: str = Field(
        default="standard",
        description="Privilege level used (e.g., read, write, admin)"
    )
    
    metadata: Dict[str, Any] = Field(
        default_factory=dict,
        description="Additional event-specific metadata"
    )
    
    @field_validator('event_id')
    @classmethod
    def validate_event_id(cls, v: str) -> str:
        """Ensure event_id is not empty."""
        if not v or not v.strip():
            raise ValueError("event_id cannot be empty")
        return v.strip()
    
    @field_validator('source_system_id')
    @classmethod
    def validate_source_system_id(cls, v: str) -> str:
        """Ensure source_system_id is not empty."""
        if not v or not v.strip():
            raise ValueError("source_system_id cannot be empty")
        return v.strip()
    
    def to_kafka_message(self) -> Dict[str, Any]:
        """
        Serialize event for Kafka message.
        
        Returns:
            Dictionary suitable for JSON serialization to Kafka
        """
        data = self.model_dump()
        # Convert datetime to ISO format string
        data['timestamp'] = self.timestamp.isoformat()
        # Convert enums to values
        data['event_type'] = self.event_type.value
        data['exposure_direction'] = self.exposure_direction.value
        data['sensitivity_tags'] = [tag.value for tag in self.sensitivity_tags]
        return data
    
    @classmethod
    def from_kafka_message(cls, data: Dict[str, Any]) -> "SecurityEvent":
        """
        Deserialize event from Kafka message.
        
        Args:
            data: Dictionary from Kafka message JSON
            
        Returns:
            SecurityEvent instance
        """
        # Parse datetime from ISO format
        if isinstance(data.get('timestamp'), str):
            data['timestamp'] = datetime.fromisoformat(data['timestamp'])
        return cls(**data)


class RiskScore(BaseModel):
    """
    Risk score for a graph entity.
    
    Combines multiple risk dimensions into a composite score.
    
    Attributes:
        entity_id: The entity this score applies to
        exposure_score: Current exposure level (0-1)
        volatility_score: Risk instability measure (0-1)
        sensitivity_likelihood: Probability of sensitive data (0-1)
        composite_score: Weighted overall score (0-1)
        scoring_version: Version of the scoring algorithm
        calculated_at: When this score was computed
    """
    
    entity_id: str = Field(..., description="Entity identifier")
    
    exposure_score: float = Field(
        ...,
        ge=0.0,
        le=1.0,
        description="Current exposure level (0=safe, 1=critical)"
    )
    
    volatility_score: float = Field(
        ...,
        ge=0.0,
        le=1.0,
        description="Risk instability measure (0=stable, 1=volatile)"
    )
    
    sensitivity_likelihood: float = Field(
        ...,
        ge=0.0,
        le=1.0,
        description="Probability of containing sensitive data"
    )
    
    composite_score: float = Field(
        ...,
        ge=0.0,
        le=1.0,
        description="Weighted overall risk score"
    )
    
    scoring_version: str = Field(
        default="1.0.0",
        description="Version of scoring algorithm used"
    )
    
    calculated_at: datetime = Field(
        default_factory=datetime.utcnow,
        description="When this score was calculated"
    )
    
    factors: Dict[str, float] = Field(
        default_factory=dict,
        description="Individual factor contributions to the score"
    )


class RiskTrajectory(BaseModel):
    """
    Risk trajectory analysis for an entity over time.
    
    Tracks how risk is changing and predicts future direction.
    """
    
    entity_id: str = Field(..., description="Entity identifier")
    
    window_days: int = Field(..., description="Analysis window in days")
    
    trend_direction: str = Field(
        ...,
        description="'increasing', 'stable', or 'decreasing'"
    )
    
    start_score: float = Field(
        ...,
        ge=0.0,
        le=1.0,
        description="Score at start of window"
    )
    
    end_score: float = Field(
        ...,
        ge=0.0,
        le=1.0,
        description="Score at end of window"
    )
    
    score_delta: float = Field(
        ...,
        description="Change in score (can be negative)"
    )
    
    daily_volatility: float = Field(
        ...,
        ge=0.0,
        description="Average daily score variation"
    )
    
    calculated_at: datetime = Field(
        default_factory=datetime.utcnow,
        description="When this trajectory was calculated"
    )
