"""
mTLS Configuration
==================

Mutual TLS configuration for inter-service communication.

Provides:
    - TLS context factory for server/client
    - Certificate validation middleware
    - Helper for generating self-signed certs (dev/test)

Author: PDRI Team
Version: 1.0.0
"""

import logging
import ssl
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, Optional

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse

logger = logging.getLogger(__name__)


@dataclass
class MTLSConfig:
    """mTLS configuration."""
    enabled: bool = False
    ca_cert_path: str = "/etc/pdri/certs/ca.pem"
    server_cert_path: str = "/etc/pdri/certs/server.pem"
    server_key_path: str = "/etc/pdri/certs/server-key.pem"
    client_cert_path: str = "/etc/pdri/certs/client.pem"
    client_key_path: str = "/etc/pdri/certs/client-key.pem"
    verify_client: bool = True
    min_tls_version: str = "TLSv1.2"
    allowed_dns: list = field(default_factory=lambda: [
        "pdri-api", "pdri-worker", "pdri-ml", "pdri-federation",
    ])


def create_server_ssl_context(config: MTLSConfig) -> Optional[ssl.SSLContext]:
    """
    Create SSL context for the PDRI API server.

    Requires client certificate verification when verify_client=True.

    Args:
        config: mTLS configuration

    Returns:
        Configured SSLContext or None if disabled
    """
    if not config.enabled:
        return None

    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)

    # Minimum TLS version
    if config.min_tls_version == "TLSv1.3":
        ctx.minimum_version = ssl.TLSVersion.TLSv1_3
    else:
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2

    # Load server certificate and key
    ctx.load_cert_chain(
        certfile=config.server_cert_path,
        keyfile=config.server_key_path,
    )

    # Load CA certificate for client verification
    if config.verify_client:
        ctx.load_verify_locations(cafile=config.ca_cert_path)
        ctx.verify_mode = ssl.CERT_REQUIRED
    else:
        ctx.verify_mode = ssl.CERT_NONE

    # Secure cipher suite
    ctx.set_ciphers(
        "ECDHE+AESGCM:ECDHE+CHACHA20:DHE+AESGCM:DHE+CHACHA20"
        ":!aNULL:!MD5:!DSS:!RC4"
    )

    logger.info(
        "Server SSL context created (verify_client=%s, min_tls=%s)",
        config.verify_client,
        config.min_tls_version,
    )
    return ctx


def create_client_ssl_context(config: MTLSConfig) -> Optional[ssl.SSLContext]:
    """
    Create SSL context for outbound inter-service calls.

    Used by PDRI services to authenticate to other PDRI services.

    Args:
        config: mTLS configuration

    Returns:
        Configured SSLContext or None if disabled
    """
    if not config.enabled:
        return None

    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)

    if config.min_tls_version == "TLSv1.3":
        ctx.minimum_version = ssl.TLSVersion.TLSv1_3
    else:
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2

    # Load client certificate for mutual auth
    ctx.load_cert_chain(
        certfile=config.client_cert_path,
        keyfile=config.client_key_path,
    )

    # Verify server certificate
    ctx.load_verify_locations(cafile=config.ca_cert_path)
    ctx.verify_mode = ssl.CERT_REQUIRED
    ctx.check_hostname = True

    ctx.set_ciphers(
        "ECDHE+AESGCM:ECDHE+CHACHA20:DHE+AESGCM:DHE+CHACHA20"
        ":!aNULL:!MD5:!DSS:!RC4"
    )

    logger.info("Client SSL context created for mTLS")
    return ctx


class MTLSMiddleware(BaseHTTPMiddleware):
    """
    Middleware to validate client certificate attributes.

    Even when TLS termination happens at the load balancer,
    this middleware can validate forwarded client cert headers
    (X-Forwarded-Client-Cert).
    """

    def __init__(self, app: Any, config: MTLSConfig):
        super().__init__(app)
        self.config = config
        self.allowed_dns = set(config.allowed_dns)

    async def dispatch(self, request: Request, call_next):
        if not self.config.enabled:
            return await call_next(request)

        # Check for forwarded client cert (common in Envoy/Istio)
        client_cert_header = request.headers.get("X-Forwarded-Client-Cert", "")

        if not client_cert_header:
            # Also check direct TLS info if available
            transport = request.scope.get("transport")
            if transport:
                peercert = getattr(transport, "get_extra_info", lambda _: None)(
                    "peercert"
                )
                if peercert:
                    subject = dict(x[0] for x in peercert.get("subject", ()))
                    cn = subject.get("commonName", "")
                    if cn not in self.allowed_dns:
                        logger.warning("Rejected client cert CN=%s", cn)
                        return JSONResponse(
                            status_code=403,
                            content={"detail": "Client certificate not authorized"},
                        )
                    return await call_next(request)

            # If mTLS is enforced but no cert presented
            if self.config.verify_client:
                # Allow health checks without cert
                if request.url.path in ("/health", "/api/v2/health"):
                    return await call_next(request)

                logger.warning("No client certificate presented")
                return JSONResponse(
                    status_code=403,
                    content={"detail": "Client certificate required"},
                )

        else:
            # Parse XFCC header (Envoy format)
            # Example: By=...;Hash=...;DNS=pdri-worker
            parts = dict(
                kv.split("=", 1) for kv in client_cert_header.split(";")
                if "=" in kv
            )
            dns = parts.get("DNS", "")
            if dns and dns not in self.allowed_dns:
                logger.warning("Rejected forwarded cert DNS=%s", dns)
                return JSONResponse(
                    status_code=403,
                    content={"detail": "Client certificate not authorized"},
                )

        return await call_next(request)


def get_mtls_config_from_env() -> MTLSConfig:
    """Load mTLS configuration from environment variables."""
    import os

    return MTLSConfig(
        enabled=os.getenv("PDRI_MTLS_ENABLED", "false").lower() == "true",
        ca_cert_path=os.getenv("PDRI_MTLS_CA_CERT", "/etc/pdri/certs/ca.pem"),
        server_cert_path=os.getenv("PDRI_MTLS_SERVER_CERT", "/etc/pdri/certs/server.pem"),
        server_key_path=os.getenv("PDRI_MTLS_SERVER_KEY", "/etc/pdri/certs/server-key.pem"),
        client_cert_path=os.getenv("PDRI_MTLS_CLIENT_CERT", "/etc/pdri/certs/client.pem"),
        client_key_path=os.getenv("PDRI_MTLS_CLIENT_KEY", "/etc/pdri/certs/client-key.pem"),
        verify_client=os.getenv("PDRI_MTLS_VERIFY_CLIENT", "true").lower() == "true",
        min_tls_version=os.getenv("PDRI_MTLS_MIN_VERSION", "TLSv1.2"),
    )
