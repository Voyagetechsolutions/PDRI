"""
PDRI Service Registration
=========================

Registers PDRI with Platform on startup and maintains heartbeat.

When Platform starts, it discovers PDRI through:
1. PDRI registers itself on startup
2. PDRI sends heartbeats every 10 seconds
3. Platform tracks PDRI health and availability

Author: PDRI Team
Version: 1.0.0
"""

import asyncio
import logging
from datetime import datetime, timezone
from typing import Optional

import httpx

from pdri.config import settings


logger = logging.getLogger(__name__)


class PlatformRegistry:
    """
    Registers PDRI with Platform and maintains heartbeat.

    Usage:
        registry = PlatformRegistry()
        await registry.register()
        await registry.start_heartbeat()
        # ... app runs ...
        await registry.deregister()
    """

    def __init__(
        self,
        platform_url: Optional[str] = None,
        heartbeat_interval: int = 10,
    ):
        """
        Initialize registry.

        Args:
            platform_url: Platform base URL (default from settings)
            heartbeat_interval: Seconds between heartbeats
        """
        self.platform_url = platform_url or getattr(settings, "platform_url", None)
        self.heartbeat_interval = heartbeat_interval
        self._heartbeat_task: Optional[asyncio.Task] = None
        self._registered = False
        self._should_register = bool(self.platform_url)

    @property
    def service_info(self) -> dict:
        """Service registration payload."""
        return {
            "service_name": "pdri",
            "service_type": "pdri",
            "base_url": f"http://{settings.host}:{settings.port}",
            "version": settings.app_version,
            "health_endpoint": "/health",
            "capabilities": [
                "risk_scoring",
                "exposure_paths",
                "findings_management",
                "event_ingestion",
                "compliance_assessment",
                "websocket_streaming",
            ],
            "contract_version": "1.0.0",
            "endpoints": {
                "health": "/health",
                "ready": "/health/ready",
                "capabilities": "/capabilities",
                "risk": "/api/v1/risk/{entity_id}",
                "findings": "/api/v1/findings",
                "events": "/api/v1/events",
                "websocket": "/ws/stream",
            },
        }

    async def register(self) -> bool:
        """
        Register PDRI with Platform.

        Returns:
            True if registration successful or skipped (no Platform URL)
        """
        if not self._should_register:
            logger.info("Platform URL not configured, skipping registration")
            return True

        try:
            async with httpx.AsyncClient(timeout=10.0) as client:
                response = await client.post(
                    f"{self.platform_url}/api/v1/services/register",
                    json=self.service_info,
                )

                if response.is_success:
                    self._registered = True
                    logger.info(
                        "Registered with Platform at %s",
                        self.platform_url,
                    )
                    return True

                logger.warning(
                    "Platform registration failed: %s %s",
                    response.status_code,
                    response.text,
                )
                return False

        except httpx.ConnectError:
            logger.warning(
                "Platform not reachable at %s, will retry via heartbeat",
                self.platform_url,
            )
            return False
        except Exception as e:
            logger.error("Registration error: %s", e)
            return False

    async def start_heartbeat(self) -> None:
        """Start background heartbeat task."""
        if not self._should_register:
            return

        self._heartbeat_task = asyncio.create_task(
            self._heartbeat_loop(),
            name="pdri-heartbeat",
        )
        logger.info("Started heartbeat task (interval=%ds)", self.heartbeat_interval)

    async def _heartbeat_loop(self) -> None:
        """Send periodic heartbeats to Platform."""
        consecutive_failures = 0
        max_failures = 5

        while True:
            try:
                await asyncio.sleep(self.heartbeat_interval)

                # Try to register if not registered yet
                if not self._registered:
                    await self.register()
                    continue

                async with httpx.AsyncClient(timeout=5.0) as client:
                    response = await client.post(
                        f"{self.platform_url}/api/v1/services/heartbeat",
                        json={
                            "service_name": "pdri",
                            "status": "healthy",
                            "timestamp": datetime.now(timezone.utc).isoformat(),
                            "version": settings.app_version,
                        },
                    )

                    if response.is_success:
                        consecutive_failures = 0
                    else:
                        consecutive_failures += 1
                        logger.warning(
                            "Heartbeat failed: %s (failures: %d)",
                            response.status_code,
                            consecutive_failures,
                        )

            except asyncio.CancelledError:
                logger.info("Heartbeat task cancelled")
                break

            except Exception as e:
                consecutive_failures += 1
                logger.warning(
                    "Heartbeat error: %s (failures: %d)",
                    e,
                    consecutive_failures,
                )

                # If Platform seems down, mark as not registered
                # so we re-register when it comes back
                if consecutive_failures >= max_failures:
                    self._registered = False
                    consecutive_failures = 0
                    logger.warning(
                        "Platform unreachable, will re-register when available"
                    )

    async def deregister(self) -> None:
        """Deregister from Platform on shutdown."""
        # Cancel heartbeat
        if self._heartbeat_task:
            self._heartbeat_task.cancel()
            try:
                await self._heartbeat_task
            except asyncio.CancelledError:
                pass
            self._heartbeat_task = None

        # Send deregistration
        if self._registered and self._should_register:
            try:
                async with httpx.AsyncClient(timeout=5.0) as client:
                    await client.post(
                        f"{self.platform_url}/api/v1/services/deregister",
                        json={"service_name": "pdri"},
                    )
                logger.info("Deregistered from Platform")
            except Exception as e:
                logger.warning("Deregistration failed: %s", e)

        self._registered = False


# Global registry instance
_registry: Optional[PlatformRegistry] = None


def get_registry() -> PlatformRegistry:
    """Get or create the registry singleton."""
    global _registry
    if _registry is None:
        _registry = PlatformRegistry()
    return _registry
