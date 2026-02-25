"""
PDRI Ingestion Package
======================

Kafka event ingestion layer for the PDRI platform.

This package provides:
    - consumer: Kafka message consumer
    - handlers: Event type handlers
    - correlation: Event deduplication and correlation

Flow:
    SecurityEvent → Deduplication → Correlation → Graph Update → Finding

Author: PDRI Team
Version: 1.0.0
"""

from pdri.ingestion.consumer import EventConsumer
from pdri.ingestion.handlers import EventHandlers
from pdri.ingestion.correlation import (
    CorrelationService,
    compute_event_fingerprint,
    compute_correlation_fingerprint,
)

__all__ = [
    "EventConsumer",
    "EventHandlers",
    "CorrelationService",
    "compute_event_fingerprint",
    "compute_correlation_fingerprint",
]
