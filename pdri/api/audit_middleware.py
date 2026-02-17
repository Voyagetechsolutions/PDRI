"""
Audit Middleware
================

FastAPI middleware that logs mutation requests (POST, PUT, DELETE, PATCH)
for security audit trail.

Captures:
    - User identity (from JWT)
    - Action type (method + path)
    - Timestamp
    - Client IP
    - Response status

Author: PDRI Team
Version: 1.0.0
"""

import logging
import time
from datetime import datetime, timezone
from typing import Any, Callable, Dict, List

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response

logger = logging.getLogger(__name__)


class AuditEntry:
    """Represents a single audit log entry."""

    __slots__ = (
        "timestamp", "user_id", "user_role", "method", "path",
        "status_code", "client_ip", "duration_ms", "request_body_size",
    )

    def __init__(
        self,
        method: str,
        path: str,
        client_ip: str,
        user_id: str = "anonymous",
        user_role: str = "unknown",
        status_code: int = 0,
        duration_ms: float = 0,
        request_body_size: int = 0,
    ):
        self.timestamp = datetime.now(timezone.utc)
        self.user_id = user_id
        self.user_role = user_role
        self.method = method
        self.path = path
        self.status_code = status_code
        self.client_ip = client_ip
        self.duration_ms = duration_ms
        self.request_body_size = request_body_size

    def to_dict(self) -> Dict[str, Any]:
        return {
            "timestamp": self.timestamp.isoformat(),
            "user_id": self.user_id,
            "user_role": self.user_role,
            "method": self.method,
            "path": self.path,
            "status_code": self.status_code,
            "client_ip": self.client_ip,
            "duration_ms": round(self.duration_ms, 2),
            "request_body_size": self.request_body_size,
        }

    def __repr__(self) -> str:
        return (
            f"AuditEntry({self.method} {self.path} "
            f"user={self.user_id} status={self.status_code})"
        )


class AuditStore:
    """
    In-memory audit store with rotation.

    In production, replace with database or external audit service.
    """

    def __init__(self, max_entries: int = 10_000):
        self._entries: List[AuditEntry] = []
        self._max = max_entries

    def add(self, entry: AuditEntry) -> None:
        self._entries.append(entry)
        if len(self._entries) > self._max:
            self._entries = self._entries[-self._max:]

    def get_recent(self, limit: int = 100) -> List[Dict[str, Any]]:
        return [e.to_dict() for e in self._entries[-limit:]]

    def get_by_user(self, user_id: str, limit: int = 50) -> List[Dict[str, Any]]:
        return [
            e.to_dict()
            for e in reversed(self._entries)
            if e.user_id == user_id
        ][:limit]

    @property
    def count(self) -> int:
        return len(self._entries)


# Global audit store instance
audit_store = AuditStore()

# Methods that represent mutations
MUTATION_METHODS = {"POST", "PUT", "DELETE", "PATCH"}

# Paths to exclude from audit logging
EXCLUDED_PATHS = {"/health", "/health/ready", "/health/live", "/metrics", "/docs", "/openapi.json"}


class AuditMiddleware(BaseHTTPMiddleware):
    """
    Middleware that logs all mutation requests to the audit trail.

    Non-mutation requests (GET, OPTIONS, HEAD) are not logged
    unless they fail with 4xx/5xx status codes.
    """

    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        # Skip excluded paths
        if request.url.path in EXCLUDED_PATHS:
            return await call_next(request)

        start = time.monotonic()
        method = request.method.upper()

        # Execute the request
        response = await call_next(request)

        duration_ms = (time.monotonic() - start) * 1000

        # Only log mutations, or errors on any method
        should_log = method in MUTATION_METHODS or response.status_code >= 400

        if should_log:
            # Extract user info from request state (set by auth dependency)
            user_id = "anonymous"
            user_role = "unknown"
            if hasattr(request.state, "user"):
                user = request.state.user
                user_id = getattr(user, "user_id", "anonymous")
                user_role = getattr(user, "role", "unknown")
            else:
                # Try authorization header for basic identification
                auth = request.headers.get("authorization", "")
                if auth.startswith("Bearer "):
                    user_id = "authenticated"

            entry = AuditEntry(
                method=method,
                path=request.url.path,
                client_ip=request.client.host if request.client else "unknown",
                user_id=user_id,
                user_role=user_role,
                status_code=response.status_code,
                duration_ms=duration_ms,
                request_body_size=int(request.headers.get("content-length", 0)),
            )

            audit_store.add(entry)

            # Log mutations at INFO level, errors at WARNING
            if response.status_code >= 400:
                logger.warning(f"AUDIT: {entry}")
            else:
                logger.info(f"AUDIT: {entry}")

        return response
