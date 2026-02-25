"""
PDRI Shared Contracts
=====================

Canonical request/response models that Platform consumes.

These contracts are the stable API surface for PDRI.
Platform imports these directly - any breaking change here
breaks Platform integration.

Version: 1.0.0
"""

from shared.contracts.pdri import (
    # Risk Scoring
    EntityRiskRequest,
    EntityRiskResponse,
    RiskFactor,
    # Exposure Paths
    ExposurePath,
    ExposurePathsRequest,
    ExposurePathsResponse,
    # Findings
    FindingRequest,
    FindingResponse,
    FindingsListRequest,
    FindingsListResponse,
    FindingStatusUpdate,
    # Events
    EventIngestionRequest,
    EventIngestionResponse,
    # Health
    PDRIHealth,
    PDRICapabilities,
)

__all__ = [
    # Risk
    "EntityRiskRequest",
    "EntityRiskResponse",
    "RiskFactor",
    # Exposure
    "ExposurePath",
    "ExposurePathsRequest",
    "ExposurePathsResponse",
    # Findings
    "FindingRequest",
    "FindingResponse",
    "FindingsListRequest",
    "FindingsListResponse",
    "FindingStatusUpdate",
    # Events
    "EventIngestionRequest",
    "EventIngestionResponse",
    # Health
    "PDRIHealth",
    "PDRICapabilities",
]

# Contract version - bump on breaking changes
CONTRACT_VERSION = "1.0.0"
