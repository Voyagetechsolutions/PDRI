"""
Risk Finding Schema
===================

Canonical output schema for PDRI risk findings.

This is the primary output contract for PDRI. The Platform layer
consumes these findings via REST API or WebSocket stream.

Author: PDRI Team
Version: 1.0.0
"""

from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional
from uuid import uuid4

from pydantic import BaseModel, Field


class FindingSeverity(str, Enum):
    """Risk finding severity levels."""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class FindingStatus(str, Enum):
    """Risk finding lifecycle status."""
    OPEN = "open"
    ACKNOWLEDGED = "acknowledged"
    IN_PROGRESS = "in_progress"
    RESOLVED = "resolved"
    FALSE_POSITIVE = "false_positive"


class EntityRef(BaseModel):
    """Reference to an entity involved in a finding."""
    entity_id: str = Field(..., description="Unique entity identifier")
    entity_type: str = Field(..., description="Entity type: data_store, service, ai_tool, identity, api")
    name: Optional[str] = Field(None, description="Human-readable entity name")
    role: Optional[str] = Field(None, description="Role in finding: source, target, accessor, etc.")


class EventRef(BaseModel):
    """Reference to an event that contributed to a finding."""
    event_id: str = Field(..., description="Original event ID")
    event_type: str = Field(..., description="Event type")
    timestamp: datetime = Field(..., description="When the event occurred")
    summary: Optional[str] = Field(None, description="Brief event summary")


class Recommendation(BaseModel):
    """Structured recommendation for addressing a finding."""
    action: str = Field(..., description="Recommended action (e.g., 'restrict_access', 'review_permissions')")
    description: str = Field(..., description="Human-readable description")
    priority: str = Field(default="medium", description="Priority: low, medium, high")
    effort: Optional[str] = Field(None, description="Estimated effort: low, medium, high")


class RiskFinding(BaseModel):
    """
    Canonical PDRI Risk Finding.

    This is the primary output schema that the Platform layer consumes.
    PDRI produces these findings from ingested SecurityEvents and
    exposes them via:
        - GET /risk-findings
        - GET /risk-findings/{finding_id}
        - WebSocket /ws/stream (real-time)

    Example:
        {
            "finding_id": "f-12345678",
            "title": "AI Tool Accessing Customer Database",
            "description": "ChatGPT integration detected accessing customer-db with PII exposure risk.",
            "severity": "high",
            "risk_score": 0.85,
            "entities_involved": [
                {"entity_id": "chatgpt-prod", "entity_type": "ai_tool", "role": "accessor"},
                {"entity_id": "customer-db", "entity_type": "data_store", "role": "target"}
            ],
            "exposure_path": ["customer-db", "api-gateway", "chatgpt-prod"],
            "evidence": [...],
            "recommendations": [...],
            "status": "open",
            "created_at": "2024-01-15T10:30:00Z",
            "updated_at": "2024-01-15T10:30:00Z"
        }
    """

    # Identity
    finding_id: str = Field(
        default_factory=lambda: f"f-{uuid4().hex[:8]}",
        description="Unique finding identifier"
    )

    # Classification
    title: str = Field(..., description="Concise finding title")
    description: str = Field(..., description="Detailed finding description")
    finding_type: str = Field(
        default="risk_detected",
        description="Finding type: risk_detected, threshold_breach, anomaly, compliance_gap"
    )
    severity: FindingSeverity = Field(
        default=FindingSeverity.MEDIUM,
        description="Severity level"
    )

    # Risk Metrics
    risk_score: float = Field(
        ...,
        ge=0.0,
        le=1.0,
        description="Composite risk score (0.0 - 1.0)"
    )
    exposure_score: Optional[float] = Field(
        None,
        ge=0.0,
        le=1.0,
        description="Exposure component score"
    )
    volatility_score: Optional[float] = Field(
        None,
        ge=0.0,
        le=1.0,
        description="Volatility component score"
    )
    sensitivity_score: Optional[float] = Field(
        None,
        ge=0.0,
        le=1.0,
        description="Sensitivity component score"
    )

    # Entities & Relationships
    entities_involved: List[EntityRef] = Field(
        default_factory=list,
        description="Entities involved in this finding"
    )
    exposure_path: List[str] = Field(
        default_factory=list,
        description="Ordered path of entity IDs showing exposure flow"
    )

    # Evidence
    evidence: List[EventRef] = Field(
        default_factory=list,
        description="Events that contributed to this finding"
    )

    # Recommendations
    recommendations: List[Recommendation] = Field(
        default_factory=list,
        description="Structured recommendations for remediation"
    )

    # Lifecycle
    status: FindingStatus = Field(
        default=FindingStatus.OPEN,
        description="Current finding status"
    )
    assigned_to: Optional[str] = Field(
        None,
        description="User/team assigned to handle this finding"
    )

    # Metadata
    tags: List[str] = Field(
        default_factory=list,
        description="Searchable tags (e.g., 'pii', 'ai-exposure', 'compliance')"
    )
    metadata: Dict[str, Any] = Field(
        default_factory=dict,
        description="Additional context and raw data"
    )

    # Timestamps
    created_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        description="When the finding was created"
    )
    updated_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        description="When the finding was last updated"
    )
    resolved_at: Optional[datetime] = Field(
        None,
        description="When the finding was resolved (if applicable)"
    )

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization."""
        return self.model_dump(mode="json")

    def to_event(self) -> Dict[str, Any]:
        """Convert to event format for WebSocket streaming."""
        return {
            "event_type": "RISK_FINDING",
            "finding_id": self.finding_id,
            "severity": self.severity.value,
            "risk_score": self.risk_score,
            "title": self.title,
            "status": self.status.value,
            "created_at": self.created_at.isoformat(),
        }


class RiskFindingSummary(BaseModel):
    """
    Summary view of risk findings for dashboard/listing.
    """
    finding_id: str
    title: str
    severity: FindingSeverity
    risk_score: float
    status: FindingStatus
    entity_count: int = Field(default=0, description="Number of entities involved")
    created_at: datetime
    updated_at: datetime

    @classmethod
    def from_finding(cls, finding: RiskFinding) -> "RiskFindingSummary":
        """Create summary from full finding."""
        return cls(
            finding_id=finding.finding_id,
            title=finding.title,
            severity=finding.severity,
            risk_score=finding.risk_score,
            status=finding.status,
            entity_count=len(finding.entities_involved),
            created_at=finding.created_at,
            updated_at=finding.updated_at,
        )


class RiskFindingsResponse(BaseModel):
    """
    Paginated response for GET /risk-findings.
    """
    findings: List[RiskFindingSummary] = Field(
        default_factory=list,
        description="List of finding summaries"
    )
    total: int = Field(default=0, description="Total number of findings matching query")
    page: int = Field(default=1, description="Current page number")
    page_size: int = Field(default=20, description="Items per page")
    has_more: bool = Field(default=False, description="Whether more pages exist")
