"""
Integrations Package
====================

Client libraries for PDRI ↔ external system integration.

    - ShadowAIProducer:      Shadow AI event producer
    - DmitryBackendClient:   PDRI → Dmitry AI backend
    - DmitryPDRIClient:      Dmitry → PDRI API
    - DmitryClient:          Alias for DmitryPDRIClient (backward-compat)
    - AegisClient:           PDRI → AegisAI platform

Author: PDRI Team
Version: 2.0.0
"""

from pdri.integrations.shadow_ai import ShadowAIProducer
from pdri.integrations.dmitry_client import (
    DmitryBackendClient,
    DmitryPDRIClient,
    DmitryClient,
    MockDmitryClient,
)
from pdri.integrations.aegis_client import AegisClient

__all__ = [
    "ShadowAIProducer",
    "DmitryBackendClient",
    "DmitryPDRIClient",
    "DmitryClient",
    "MockDmitryClient",
    "AegisClient",
]
