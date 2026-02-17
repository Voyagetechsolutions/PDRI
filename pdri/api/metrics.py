"""
Prometheus Metrics Module
=========================

Exposes application metrics for Prometheus scraping.

Metrics:
    - pdri_requests_total: Total HTTP requests (counter)
    - pdri_request_duration_seconds: Request latency (histogram)
    - pdri_events_processed_total: Kafka events processed (counter)
    - pdri_scoring_duration_seconds: Scoring operation latency (histogram)
    - pdri_active_connections: Active graph DB connections (gauge)

Author: PDRI Team
Version: 1.0.0
"""

import logging
import time
from typing import Callable

logger = logging.getLogger(__name__)

try:
    from prometheus_client import Counter, Histogram, Gauge, generate_latest, CONTENT_TYPE_LATEST
    from starlette.requests import Request
    from starlette.responses import Response
    from starlette.middleware.base import BaseHTTPMiddleware

    HAS_PROMETHEUS = True
except ImportError:
    HAS_PROMETHEUS = False
    logger.info("prometheus_client not installed — metrics disabled")


if HAS_PROMETHEUS:
    # =========================================================================
    # Metric Definitions
    # =========================================================================

    REQUEST_COUNT = Counter(
        "pdri_requests_total",
        "Total HTTP requests",
        ["method", "endpoint", "status_code"],
    )

    REQUEST_DURATION = Histogram(
        "pdri_request_duration_seconds",
        "HTTP request duration in seconds",
        ["method", "endpoint"],
        buckets=[0.01, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0],
    )

    EVENTS_PROCESSED = Counter(
        "pdri_events_processed_total",
        "Total Kafka events processed",
        ["event_type", "status"],
    )

    SCORING_DURATION = Histogram(
        "pdri_scoring_duration_seconds",
        "Risk scoring operation duration in seconds",
        ["score_type"],
        buckets=[0.01, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5],
    )

    ACTIVE_CONNECTIONS = Gauge(
        "pdri_active_connections",
        "Active database connections",
        ["database"],
    )

    RISK_SCORE_CURRENT = Gauge(
        "pdri_risk_score_current",
        "Current risk score value",
        ["entity_id", "score_type"],
    )

    # =========================================================================
    # Middleware
    # =========================================================================

    class MetricsMiddleware(BaseHTTPMiddleware):
        """Middleware to track request counts and durations."""

        async def dispatch(self, request: Request, call_next: Callable) -> Response:
            method = request.method
            path = request.url.path

            # Skip metrics endpoint itself
            if path == "/metrics":
                return await call_next(request)

            # Normalize path to avoid cardinality explosion
            endpoint = self._normalize_path(path)

            start = time.monotonic()
            response = await call_next(request)
            duration = time.monotonic() - start

            REQUEST_COUNT.labels(
                method=method,
                endpoint=endpoint,
                status_code=response.status_code,
            ).inc()

            REQUEST_DURATION.labels(
                method=method,
                endpoint=endpoint,
            ).observe(duration)

            return response

        @staticmethod
        def _normalize_path(path: str) -> str:
            """Normalize path to prevent high-cardinality labels."""
            parts = path.strip("/").split("/")
            if len(parts) >= 2:
                # Keep first two segments, replace rest with {id}
                normalized = "/" + "/".join(parts[:2])
                if len(parts) > 2:
                    normalized += "/{id}"
                return normalized
            return path or "/"

    # =========================================================================
    # Helper Functions
    # =========================================================================

    def record_event_processed(event_type: str, status: str = "success") -> None:
        """Record a Kafka event processing metric."""
        EVENTS_PROCESSED.labels(event_type=event_type, status=status).inc()

    def record_scoring_duration(score_type: str, duration: float) -> None:
        """Record scoring operation duration."""
        SCORING_DURATION.labels(score_type=score_type).observe(duration)

    def update_risk_score(entity_id: str, score_type: str, value: float) -> None:
        """Update current risk score gauge."""
        RISK_SCORE_CURRENT.labels(entity_id=entity_id, score_type=score_type).set(value)

    def set_active_connections(database: str, count: int) -> None:
        """Update active connection count."""
        ACTIVE_CONNECTIONS.labels(database=database).set(count)

    # =========================================================================
    # Endpoint Handler
    # =========================================================================

    async def metrics_endpoint(request: Request) -> Response:
        """Expose Prometheus metrics at /metrics."""
        return Response(
            content=generate_latest(),
            media_type=CONTENT_TYPE_LATEST,
        )

else:
    # Stubs when prometheus_client is not installed
    class MetricsMiddleware:
        """No-op metrics middleware."""
        pass

    def record_event_processed(event_type: str, status: str = "success") -> None:
        pass

    def record_scoring_duration(score_type: str, duration: float) -> None:
        pass

    def update_risk_score(entity_id: str, score_type: str, value: float) -> None:
        pass

    def set_active_connections(database: str, count: int) -> None:
        pass

    async def metrics_endpoint(request) -> None:
        pass
