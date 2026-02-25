"""
PDRI Contract Models
====================

Request/Response models for Platform → PDRI communication.

These are the STABLE contracts. Platform depends on these.
Do NOT change field names or types without versioning.

Author: PDRI Team
Version: 1.0.0
"""

from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


# =============================================================================
# Enums
# =============================================================================


class Severity(str, Enum):
    """Risk severity levels."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class FindingStatus(str, Enum):
    """Finding lifecycle status."""
    OPEN = "open"
    ACKNOWLEDGED = "acknowledged"
    IN_PROGRESS = "in_progress"
    RESOLVED = "resolved"
    FALSE_POSITIVE = "false_positive"


# =============================================================================
# Risk Scoring Contracts
# =============================================================================


class RiskFactor(BaseModel):
    """Individual risk factor contribution."""
    name: str = Field(..., description="Factor name (e.g., 'ai_integration')")
    value: float = Field(..., ge=0.0, le=1.0, description="Factor value 0-1")
    weight: float = Field(..., ge=0.0, le=1.0, description="Weight in composite")
    description: Optional[str] = Field(None, description="Human-readable explanation")


class EntityRiskRequest(BaseModel):
    """
    Request: Get risk score for an entity.

    Platform calls: GET /api/v1/risk/{entity_id}
    """
    entity_id: str = Field(..., description="Entity identifier")
    entity_type: Optional[str] = Field(None, description="Entity type hint")
    tenant_id: str = Field(default="default", description="Tenant for multi-tenancy")
    include_factors: bool = Field(default=True, description="Include factor breakdown")
    include_paths: bool = Field(default=True, description="Include exposure paths")
    max_path_depth: int = Field(default=5, ge=1, le=10, description="Max path traversal depth")


class EntityRiskResponse(BaseModel):
    """
    Response: Risk score for an entity.

    This is what Platform displays in dashboards.
    """
    entity_id: str
    entity_type: str
    tenant_id: str

    # Scores
    risk_score: float = Field(..., ge=0.0, le=1.0, description="Composite risk 0-1")
    exposure_score: float = Field(..., ge=0.0, le=1.0)
    volatility_score: float = Field(..., ge=0.0, le=1.0)
    sensitivity_score: float = Field(..., ge=0.0, le=1.0)

    # Classification
    severity: Severity
    risk_level: str = Field(..., description="Human label: critical/high/medium/low/minimal")

    # Breakdown
    factors: List[RiskFactor] = Field(default_factory=list)
    exposure_paths: List["ExposurePath"] = Field(default_factory=list)

    # Metadata
    computed_at: datetime
    cache_ttl_seconds: int = Field(default=300, description="How long to cache this")
    schema_version: str = Field(default="1.0.0")
    producer_version: str = Field(default="1.0.0")


# =============================================================================
# Exposure Path Contracts
# =============================================================================


class ExposurePath(BaseModel):
    """A path showing how data flows to external/AI exposure."""
    path_id: str = Field(..., description="Unique path identifier")
    source_id: str = Field(..., description="Starting entity (usually data store)")
    source_type: str
    target_id: str = Field(..., description="Ending entity (external/AI)")
    target_type: str
    path: List[str] = Field(..., description="Ordered list of entity IDs")
    path_length: int = Field(..., ge=1)
    risk_contribution: float = Field(..., ge=0.0, le=1.0, description="How much this path contributes to risk")
    sensitivity_tags: List[str] = Field(default_factory=list)


class ExposurePathsRequest(BaseModel):
    """
    Request: Get all exposure paths for an entity.

    Platform calls: GET /api/v1/exposure/{entity_id}/paths
    """
    entity_id: str
    tenant_id: str = Field(default="default")
    max_depth: int = Field(default=5, ge=1, le=10)
    target_types: Optional[List[str]] = Field(
        None, description="Filter by target type (ai_tool, external, etc.)"
    )


class ExposurePathsResponse(BaseModel):
    """Response: All exposure paths from an entity."""
    entity_id: str
    paths: List[ExposurePath]
    total_paths: int
    max_risk_path: Optional[ExposurePath] = Field(
        None, description="The highest risk path"
    )
    computed_at: datetime
    schema_version: str = Field(default="1.0.0")


# =============================================================================
# Finding Contracts
# =============================================================================


class RecommendedAction(BaseModel):
    """Action recommended to remediate a finding."""
    action: str = Field(..., description="Action type (e.g., 'restrict_access')")
    target: str = Field(..., description="Target entity ID")
    target_type: str
    description: str
    priority: str = Field(default="medium", description="low/medium/high/critical")
    risk_reduction_estimate: Optional[float] = Field(
        None, ge=0.0, le=1.0, description="Expected risk reduction if action taken"
    )


class FindingRequest(BaseModel):
    """
    Request: Get a specific finding.

    Platform calls: GET /api/v1/findings/{finding_id}
    """
    finding_id: str
    tenant_id: str = Field(default="default")


class FindingResponse(BaseModel):
    """
    Response: Full finding details.

    This is the canonical finding format Platform consumes.
    """
    # Identity
    finding_id: str
    tenant_id: str
    fingerprint: str = Field(..., description="Deduplication key")
    correlation_id: Optional[str] = Field(None, description="Link to event correlation")

    # Classification
    title: str
    description: str
    finding_type: str
    severity: Severity
    risk_score: float = Field(..., ge=0.0, le=1.0)

    # Entity context
    primary_entity_id: str
    primary_entity_type: str
    entities_involved: List[Dict[str, Any]] = Field(default_factory=list)
    exposure_path: List[str] = Field(default_factory=list)

    # Evidence
    evidence_refs: List[Dict[str, Any]] = Field(
        default_factory=list,
        description="References to events that triggered this finding"
    )
    evidence_count: int = Field(default=0)

    # Recommendations
    recommended_actions: List[RecommendedAction] = Field(default_factory=list)

    # Lifecycle
    status: FindingStatus
    status_reason: Optional[str] = None
    assigned_to: Optional[str] = None
    sla_due_at: Optional[datetime] = None
    sla_breached: bool = False

    # Timestamps
    first_seen_at: datetime
    last_seen_at: datetime
    created_at: datetime
    updated_at: datetime
    resolved_at: Optional[datetime] = None
    occurrence_count: int = Field(default=1)

    # Metadata
    tags: List[str] = Field(default_factory=list)
    schema_version: str = Field(default="1.0.0")
    producer_version: str = Field(default="1.0.0")


class FindingsListRequest(BaseModel):
    """
    Request: List findings with filters.

    Platform calls: GET /api/v1/findings
    """
    tenant_id: str = Field(default="default")
    status: Optional[str] = None
    severity: Optional[str] = None
    entity_id: Optional[str] = None
    tags: Optional[List[str]] = None
    min_risk_score: Optional[float] = Field(None, ge=0.0, le=1.0)
    created_after: Optional[datetime] = None
    created_before: Optional[datetime] = None
    page: int = Field(default=1, ge=1)
    page_size: int = Field(default=20, ge=1, le=100)
    order_by: str = Field(default="created_at")
    order_desc: bool = Field(default=True)


class FindingSummary(BaseModel):
    """Lightweight finding for list views."""
    finding_id: str
    title: str
    severity: Severity
    risk_score: float
    status: FindingStatus
    primary_entity_id: str
    occurrence_count: int
    sla_breached: bool
    created_at: datetime
    updated_at: datetime


class FindingsListResponse(BaseModel):
    """Response: Paginated list of findings."""
    findings: List[FindingSummary]
    total: int
    page: int
    page_size: int
    has_more: bool
    schema_version: str = Field(default="1.0.0")


class FindingStatusUpdate(BaseModel):
    """
    Request: Update finding status.

    Platform calls: PATCH /api/v1/findings/{finding_id}/status
    """
    status: FindingStatus
    reason: Optional[str] = Field(None, description="Why status changed")
    assigned_to: Optional[str] = None
    user_id: str = Field(..., description="Who is making this change")


# =============================================================================
# Event Ingestion Contracts
# =============================================================================


class EventIngestionRequest(BaseModel):
    """
    Request: Ingest security events.

    Platform calls: POST /api/v1/events
    Can also come via Kafka topic.
    """
    events: List[Dict[str, Any]] = Field(
        ..., description="List of SecurityEvent objects"
    )
    source: str = Field(default="platform", description="Where events came from")
    tenant_id: str = Field(default="default")


class EventIngestionResult(BaseModel):
    """Result for a single event."""
    event_id: str
    status: str  # accepted, duplicate, invalid, failed
    correlation_id: Optional[str] = None
    finding_id: Optional[str] = None
    error: Optional[str] = None


class EventIngestionResponse(BaseModel):
    """Response: Event ingestion results."""
    accepted: int
    rejected: int
    duplicates: int
    results: List[EventIngestionResult]
    schema_version: str = Field(default="1.0.0")


# =============================================================================
# Health Contracts
# =============================================================================


class DependencyHealth(BaseModel):
    """Health of a dependency."""
    name: str
    status: str  # healthy, degraded, unhealthy
    latency_ms: Optional[float] = None
    message: Optional[str] = None


class PDRIHealth(BaseModel):
    """
    PDRI health status.

    Platform calls: GET /health
    """
    service: str = Field(default="pdri")
    status: str  # healthy, degraded, unhealthy
    version: str
    uptime_seconds: float
    dependencies: List[DependencyHealth]
    timestamp: datetime

    # Metrics snapshot
    findings_open: Optional[int] = None
    events_processed_24h: Optional[int] = None
    avg_scoring_latency_ms: Optional[float] = None


class PDRICapabilities(BaseModel):
    """
    PDRI capabilities for service discovery.

    Platform calls: GET /capabilities
    """
    service: str = Field(default="pdri")
    version: str
    contract_version: str = Field(default="1.0.0")

    # What PDRI can do
    capabilities: List[str] = Field(
        default_factory=lambda: [
            "risk_scoring",
            "exposure_paths",
            "findings_management",
            "event_ingestion",
            "compliance_assessment",
            "websocket_streaming",
        ]
    )

    # Endpoints
    endpoints: Dict[str, str] = Field(
        default_factory=lambda: {
            "health": "/health",
            "risk": "/api/v1/risk/{entity_id}",
            "exposure": "/api/v1/exposure/{entity_id}/paths",
            "findings": "/api/v1/findings",
            "events": "/api/v1/events",
            "websocket": "/ws/stream",
        }
    )

    # Rate limits
    rate_limits: Dict[str, int] = Field(
        default_factory=lambda: {
            "requests_per_minute": 1000,
            "events_per_second": 100,
            "websocket_connections": 50,
        }
    )


# Forward reference resolution
EntityRiskResponse.model_rebuild()
