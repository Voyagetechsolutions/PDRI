"""
PDRI Shared Schemas Package
============================

Platform-wide event schemas and data types used across all PDRI components.

This package provides:
    - SecurityEvent: Core input schema for all security telemetry
    - RiskFinding: Core output schema for risk findings
    - Enumerations: Event types, severity, sensitivity tags, exposure directions
    - Data models: Shared Pydantic models for API and messaging

Author: PDRI Team
Version: 2.0.0
"""

from shared.schemas.events import (
    SecurityEvent,
    SecurityEventType,
    SensitivityTag,
    ExposureDirection,
    RiskScore,
    EntityType,
)

from shared.schemas.findings import (
    RiskFinding,
    RiskFindingSummary,
    RiskFindingsResponse,
    FindingSeverity,
    FindingStatus,
    EntityRef,
    EventRef,
    Recommendation,
)

__all__ = [
    # Input schema
    "SecurityEvent",
    "SecurityEventType",
    "SensitivityTag",
    "ExposureDirection",
    "RiskScore",
    "EntityType",
    # Output schema
    "RiskFinding",
    "RiskFindingSummary",
    "RiskFindingsResponse",
    "FindingSeverity",
    "FindingStatus",
    "EntityRef",
    "EventRef",
    "Recommendation",
]
