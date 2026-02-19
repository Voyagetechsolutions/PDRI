"""
Integrations Package
====================

Event producers for PDRI.

    - AegisAIProducer: Produces security events to Kafka

Note: Direct client integrations (AegisClient, DmitryClient) have been
removed. PDRI is now a standalone service. Orchestration is handled
by the Platform layer.

Author: PDRI Team
Version: 3.0.0
"""

from pdri.integrations.aegis_ai import AegisAIProducer, MockAegisAIProducer

__all__ = [
    "AegisAIProducer",
    "MockAegisAIProducer",
]
