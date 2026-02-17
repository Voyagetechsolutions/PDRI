"""
PDRI Ingestion Package
======================

Kafka event ingestion layer for the PDRI platform.

This package provides:
    - consumer: Kafka message consumer
    - handlers: Event type handlers

Author: PDRI Team
Version: 1.0.0
"""

from pdri.ingestion.consumer import EventConsumer
from pdri.ingestion.handlers import EventHandlers

__all__ = [
    "EventConsumer",
    "EventHandlers",
]
