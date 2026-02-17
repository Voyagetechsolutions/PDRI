"""
PDRI Shared Schemas Package
============================

Platform-wide event schemas and data types used across all PDRI components.

This package provides:
    - SecurityEvent: Core event schema for all security telemetry
    - Enumerations: Event types, sensitivity tags, exposure directions
    - Data models: Shared Pydantic models for API and messaging

Author: PDRI Team
Version: 1.0.0
"""

from shared.schemas.events import (
    SecurityEvent,
    SecurityEventType,
    SensitivityTag,
    ExposureDirection,
    RiskScore,
    EntityType,
)

__all__ = [
    "SecurityEvent",
    "SecurityEventType", 
    "SensitivityTag",
    "ExposureDirection",
    "RiskScore",
    "EntityType",
]
