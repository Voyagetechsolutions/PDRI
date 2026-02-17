"""
Structured Logging
==================

JSON-structured logging with request context, correlation IDs,
and per-module logger factory.

Uses structlog for structured, machine-readable log output.

Author: PDRI Team
Version: 1.0.0
"""

import logging
import sys
import uuid
from contextvars import ContextVar
from datetime import datetime, timezone
from typing import Any, Dict, Optional

try:
    import structlog
    HAS_STRUCTLOG = True
except ImportError:
    HAS_STRUCTLOG = False

# Context variable for request correlation
_correlation_id: ContextVar[str] = ContextVar("correlation_id", default="")
_request_user: ContextVar[str] = ContextVar("request_user", default="anonymous")


def set_correlation_id(correlation_id: Optional[str] = None) -> str:
    """Set correlation ID for current context. Returns the ID."""
    cid = correlation_id or str(uuid.uuid4())[:12]
    _correlation_id.set(cid)
    return cid


def set_request_user(user: str) -> None:
    """Set the current request user for logging context."""
    _request_user.set(user)


def get_correlation_id() -> str:
    """Get current correlation ID."""
    return _correlation_id.get()


def _add_correlation_id(logger: Any, method_name: str, event_dict: Dict) -> Dict:
    """Structlog processor to inject correlation ID."""
    cid = _correlation_id.get()
    if cid:
        event_dict["correlation_id"] = cid
    return event_dict


def _add_request_user(logger: Any, method_name: str, event_dict: Dict) -> Dict:
    """Structlog processor to inject request user."""
    user = _request_user.get()
    if user and user != "anonymous":
        event_dict["user"] = user
    return event_dict


def _add_service_info(logger: Any, method_name: str, event_dict: Dict) -> Dict:
    """Structlog processor to inject service metadata."""
    event_dict["service"] = "pdri"
    return event_dict


def setup_logging(
    level: str = "INFO",
    json_output: bool = True,
    log_file: Optional[str] = None,
) -> None:
    """
    Configure structured logging for the PDRI application.

    Args:
        level: Logging level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
        json_output: If True, output JSON; otherwise human-readable
        log_file: Optional path to write logs to a file
    """
    log_level = getattr(logging, level.upper(), logging.INFO)

    if HAS_STRUCTLOG:
        # Structlog pipeline
        shared_processors = [
            structlog.contextvars.merge_contextvars,
            structlog.stdlib.add_log_level,
            structlog.stdlib.add_logger_name,
            structlog.processors.TimeStamper(fmt="iso"),
            _add_correlation_id,
            _add_request_user,
            _add_service_info,
            structlog.processors.StackInfoRenderer(),
            structlog.processors.format_exc_info,
            structlog.processors.UnicodeDecoder(),
        ]

        if json_output:
            renderer = structlog.processors.JSONRenderer()
        else:
            renderer = structlog.dev.ConsoleRenderer(colors=True)

        structlog.configure(
            processors=shared_processors + [
                structlog.stdlib.ProcessorFormatter.wrap_for_formatter,
            ],
            context_class=dict,
            logger_factory=structlog.stdlib.LoggerFactory(),
            wrapper_class=structlog.stdlib.BoundLogger,
            cache_logger_on_first_use=True,
        )

        formatter = structlog.stdlib.ProcessorFormatter(
            processor=renderer,
            foreign_pre_chain=shared_processors,
        )

        # Configure root handler
        handler = logging.StreamHandler(sys.stdout)
        handler.setFormatter(formatter)

        root_logger = logging.getLogger()
        root_logger.handlers.clear()
        root_logger.addHandler(handler)
        root_logger.setLevel(log_level)

        # Optional file handler
        if log_file:
            file_handler = logging.FileHandler(log_file)
            file_handler.setFormatter(formatter)
            root_logger.addHandler(file_handler)

    else:
        # Fallback to standard logging with JSON-like format
        log_format = (
            '{"timestamp":"%(asctime)s","level":"%(levelname)s",'
            '"logger":"%(name)s","message":"%(message)s"}'
        )
        handlers = [logging.StreamHandler(sys.stdout)]

        if log_file:
            handlers.append(logging.FileHandler(log_file))

        logging.basicConfig(
            level=log_level,
            format=log_format,
            handlers=handlers,
        )

    # Silence noisy third-party loggers
    logging.getLogger("uvicorn.access").setLevel(logging.WARNING)
    logging.getLogger("uvicorn.error").setLevel(logging.WARNING)
    logging.getLogger("httpcore").setLevel(logging.WARNING)
    logging.getLogger("httpx").setLevel(logging.WARNING)


def get_logger(name: str) -> Any:
    """
    Get a structured logger for a module.

    Args:
        name: Module name (typically __name__)

    Returns:
        Structured logger instance
    """
    if HAS_STRUCTLOG:
        return structlog.get_logger(name)
    return logging.getLogger(name)


class RequestLoggingMiddleware:
    """
    ASGI middleware that logs every request with structured data.

    Logs: method, path, status, duration, correlation_id, user.
    """

    def __init__(self, app: Any):
        self.app = app
        self.logger = get_logger("pdri.api.requests")

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        # Generate correlation ID from header or new
        from starlette.requests import Request
        request = Request(scope, receive)
        cid = request.headers.get("X-Correlation-ID", "")
        cid = set_correlation_id(cid or None)

        start = datetime.now(timezone.utc)
        status_code = 500  # Default in case of error

        async def send_wrapper(message):
            nonlocal status_code
            if message["type"] == "http.response.start":
                status_code = message["status"]
                # Inject correlation ID header into response
                headers = list(message.get("headers", []))
                headers.append(
                    (b"x-correlation-id", cid.encode())
                )
                message["headers"] = headers
            await send(message)

        try:
            await self.app(scope, receive, send_wrapper)
        finally:
            duration_ms = (
                datetime.now(timezone.utc) - start
            ).total_seconds() * 1000

            self.logger.info(
                "request_completed",
                method=scope.get("method", ""),
                path=scope.get("path", ""),
                status=status_code,
                duration_ms=round(duration_ms, 2),
            )
