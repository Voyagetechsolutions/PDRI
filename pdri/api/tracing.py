"""
OpenTelemetry Tracing
=====================

Distributed tracing configuration for PDRI.

Provides:
    - Tracer provider with OTLP exporter
    - FastAPI auto-instrumentation
    - Manual span helpers for scoring and graph ops
    - Graceful no-op when OTel not available

Author: PDRI Team
Version: 1.0.0
"""

import logging
import os
from functools import wraps
from typing import Any, Callable, Optional

logger = logging.getLogger(__name__)

# ── Attempt OTel imports ──────────────────────────────────────

try:
    from opentelemetry import trace
    from opentelemetry.sdk.trace import TracerProvider
    from opentelemetry.sdk.trace.export import (
        BatchSpanProcessor,
        ConsoleSpanExporter,
    )
    from opentelemetry.sdk.resources import Resource
    from opentelemetry.semconv.resource import ResourceAttributes

    HAS_OTEL = True
except ImportError:
    HAS_OTEL = False

try:
    from opentelemetry.exporter.otlp.proto.grpc.trace_exporter import (
        OTLPSpanExporter,
    )
    HAS_OTLP = True
except ImportError:
    HAS_OTLP = False

try:
    from opentelemetry.instrumentation.fastapi import FastAPIInstrumentor
    HAS_FASTAPI_INSTR = True
except ImportError:
    HAS_FASTAPI_INSTR = False


# ── Tracer singleton ─────────────────────────────────────────

_tracer: Optional[Any] = None


def setup_tracing(
    service_name: str = "pdri-api",
    service_version: str = "1.0.0",
    otlp_endpoint: Optional[str] = None,
    console_export: bool = False,
) -> Optional[Any]:
    """
    Initialize OpenTelemetry tracing.

    Args:
        service_name: Name of this service in traces
        service_version: Version string
        otlp_endpoint: OTLP collector endpoint (e.g. http://localhost:4317)
        console_export: If True, also print spans to console (dev mode)

    Returns:
        Tracer instance, or None if OTel not available
    """
    global _tracer

    if not HAS_OTEL:
        logger.info("OpenTelemetry not installed — tracing disabled")
        return None

    resource = Resource.create({
        ResourceAttributes.SERVICE_NAME: service_name,
        ResourceAttributes.SERVICE_VERSION: service_version,
        "deployment.environment": os.getenv("PDRI_ENV", "development"),
    })

    provider = TracerProvider(resource=resource)

    # OTLP exporter (Jaeger, Tempo, Datadog, etc.)
    endpoint = otlp_endpoint or os.getenv(
        "OTEL_EXPORTER_OTLP_ENDPOINT", ""
    )
    if endpoint and HAS_OTLP:
        otlp_exporter = OTLPSpanExporter(endpoint=endpoint, insecure=True)
        provider.add_span_processor(BatchSpanProcessor(otlp_exporter))
        logger.info("OTLP exporter configured → %s", endpoint)

    # Console exporter for development
    if console_export:
        provider.add_span_processor(
            BatchSpanProcessor(ConsoleSpanExporter())
        )

    trace.set_tracer_provider(provider)
    _tracer = trace.get_tracer(service_name, service_version)

    logger.info(
        "OpenTelemetry tracing initialized (service=%s, version=%s)",
        service_name,
        service_version,
    )
    return _tracer


def instrument_fastapi(app: Any) -> None:
    """
    Auto-instrument a FastAPI application.

    Adds spans for every HTTP request automatically.

    Args:
        app: FastAPI application instance
    """
    if not HAS_FASTAPI_INSTR:
        logger.debug("FastAPI OTel instrumentation not available")
        return

    FastAPIInstrumentor.instrument_app(
        app,
        excluded_urls="health,metrics",
    )
    logger.info("FastAPI auto-instrumented with OpenTelemetry")


def get_tracer() -> Any:
    """Get the global tracer instance."""
    global _tracer

    if _tracer is not None:
        return _tracer

    if HAS_OTEL:
        return trace.get_tracer("pdri")

    # Return a no-op tracer-like object
    return _NoOpTracer()


class _NoOpSpan:
    """No-op span when OTel is not available."""

    def set_attribute(self, key: str, value: Any) -> None:
        pass

    def set_status(self, status: Any) -> None:
        pass

    def record_exception(self, exc: Exception) -> None:
        pass

    def __enter__(self):
        return self

    def __exit__(self, *args):
        pass


class _NoOpTracer:
    """No-op tracer when OTel is not available."""

    def start_as_current_span(self, name: str, **kwargs) -> _NoOpSpan:
        return _NoOpSpan()

    def start_span(self, name: str, **kwargs) -> _NoOpSpan:
        return _NoOpSpan()


# ── Span helpers ─────────────────────────────────────────────

def traced(
    span_name: Optional[str] = None,
    attributes: Optional[dict] = None,
) -> Callable:
    """
    Decorator to trace a function/method.

    Args:
        span_name: Name for the span (defaults to function name)
        attributes: Static attributes to attach to the span

    Usage:
        @traced("scoring.score_entity")
        async def score_entity(self, entity_id: str):
            ...
    """
    def decorator(func: Callable) -> Callable:
        name = span_name or f"{func.__module__}.{func.__qualname__}"

        @wraps(func)
        async def async_wrapper(*args, **kwargs):
            tracer = get_tracer()
            with tracer.start_as_current_span(name) as span:
                if attributes:
                    for k, v in attributes.items():
                        span.set_attribute(k, v)
                try:
                    result = await func(*args, **kwargs)
                    return result
                except Exception as e:
                    span.record_exception(e)
                    raise

        @wraps(func)
        def sync_wrapper(*args, **kwargs):
            tracer = get_tracer()
            with tracer.start_as_current_span(name) as span:
                if attributes:
                    for k, v in attributes.items():
                        span.set_attribute(k, v)
                try:
                    result = func(*args, **kwargs)
                    return result
                except Exception as e:
                    span.record_exception(e)
                    raise

        import asyncio
        if asyncio.iscoroutinefunction(func):
            return async_wrapper
        return sync_wrapper

    return decorator
