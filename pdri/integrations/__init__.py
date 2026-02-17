"""
Integration Stubs Package
=========================

Stub implementations for Shadow AI and Dmitry integrations.

These stubs allow PDRI to function independently while providing
integration points for the full platform.

Author: PDRI Team
Version: 1.0.0
"""

from pdri.integrations.shadow_ai import ShadowAIProducer
from pdri.integrations.dmitry_client import DmitryClient

__all__ = [
    "ShadowAIProducer",
    "DmitryClient",
]
