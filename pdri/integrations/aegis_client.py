"""
AegisAI Integration Client
============================

HTTP client for PDRI to communicate with AegisAI —
the parent security platform.

Features:
    - Push risk summaries to Aegis dashboard
    - Pull threat intelligence feeds
    - Sync entity catalogs for cross-platform correlation
    - Report incidents to Aegis response pipeline

Author: PDRI Team
Version: 1.0.0
"""

import logging
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

import httpx

from pdri.config import settings

logger = logging.getLogger(__name__)


# =============================================================================
# Circuit Breaker
# =============================================================================


class CircuitBreakerOpen(Exception):
    """Raised when the circuit breaker is open and requests are blocked."""
    pass


class CircuitBreaker:
    """
    Simple circuit breaker for HTTP clients.
    
    Opens after `failure_threshold` consecutive failures.
    Stays open for `cooldown_seconds`, then transitions to half-open.
    A single success in half-open closes the circuit.
    """
    
    def __init__(
        self,
        failure_threshold: int = 5,
        cooldown_seconds: float = 60.0,
    ):
        self.failure_threshold = failure_threshold
        self.cooldown_seconds = cooldown_seconds
        self._failure_count = 0
        self._last_failure_time: Optional[datetime] = None
        self._state = "closed"  # closed, open, half-open
    
    @property
    def state(self) -> str:
        """Current circuit state."""
        if self._state == "open" and self._last_failure_time:
            elapsed = (datetime.now(timezone.utc) - self._last_failure_time).total_seconds()
            if elapsed >= self.cooldown_seconds:
                self._state = "half-open"
        return self._state
    
    def check(self) -> None:
        """Check if request is allowed. Raises CircuitBreakerOpen if not."""
        if self.state == "open":
            raise CircuitBreakerOpen(
                f"Circuit breaker is open — {self._failure_count} consecutive failures. "
                f"Retry after {self.cooldown_seconds}s cooldown."
            )
    
    def record_success(self) -> None:
        """Record a successful request."""
        self._failure_count = 0
        self._state = "closed"
    
    def record_failure(self) -> None:
        """Record a failed request."""
        self._failure_count += 1
        self._last_failure_time = datetime.now(timezone.utc)
        if self._failure_count >= self.failure_threshold:
            self._state = "open"
            logger.warning(
                f"Circuit breaker opened after {self._failure_count} failures"
            )


class AegisClient:
    """
    Async HTTP client for AegisAI integration.
    
    Handles bidirectional communication between PDRI and AegisAI:
    - PDRI → Aegis: risk summaries, incidents, entity catalog
    - Aegis → PDRI: threat intelligence, policy updates
    
    Usage:
        async with AegisClient() as aegis:
            await aegis.push_risk_summary(summary_data)
            threats = await aegis.pull_threat_intel()
    """
    
    def __init__(
        self,
        base_url: Optional[str] = None,
        api_key: Optional[str] = None,
        timeout: float = 30.0,
        circuit_failure_threshold: int = 5,
        circuit_cooldown_seconds: float = 60.0,
    ):
        """
        Initialize AegisAI client.
        
        Args:
            base_url: AegisAI API URL (defaults to config)
            api_key: API key for authentication (defaults to config)
            timeout: Request timeout in seconds
            circuit_failure_threshold: Failures before circuit opens
            circuit_cooldown_seconds: Seconds before circuit resets
        """
        self.base_url = (base_url or settings.aegis_api_url).rstrip("/")
        self.api_key = api_key or settings.aegis_api_key
        self.timeout = timeout
        self._client: Optional[httpx.AsyncClient] = None
        self._circuit = CircuitBreaker(
            failure_threshold=circuit_failure_threshold,
            cooldown_seconds=circuit_cooldown_seconds,
        )
    
    async def _get_client(self) -> httpx.AsyncClient:
        """Get or create HTTP client with auth headers."""
        if self._client is None or self._client.is_closed:
            self._client = httpx.AsyncClient(
                base_url=self.base_url,
                timeout=self.timeout,
                headers={
                    "Authorization": f"Bearer {self.api_key}",
                    "Content-Type": "application/json",
                    "X-Source": "pdri",
                    "X-PDRI-Version": settings.app_version,
                },
            )
        return self._client
    
    async def close(self):
        """Close the HTTP client."""
        if self._client:
            await self._client.aclose()
    
    async def __aenter__(self):
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        await self.close()
    
    # =========================================================================
    # Push Operations (PDRI → Aegis)
    # =========================================================================
    
    async def push_risk_summary(
        self,
        summary: Dict[str, Any],
    ) -> Dict[str, Any]:
        """
        Push overall risk summary to AegisAI dashboard.
        
        Args:
            summary: Risk summary (total entities, distribution, top risks)
            
        Returns:
            Acknowledgement from Aegis
        """
        client = await self._get_client()
        payload = {
            "source": "pdri",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "summary": summary,
        }
        
        try:
            self._circuit.check()
            response = await client.post("/api/v1/integrations/risk-summary", json=payload)
            response.raise_for_status()
            self._circuit.record_success()
            logger.info("Pushed risk summary to AegisAI")
            return response.json()
        except CircuitBreakerOpen as e:
            logger.warning(f"Aegis circuit open — skipping risk summary push: {e}")
            return {"status": "circuit_open", "error": str(e)}
        except httpx.HTTPStatusError as e:
            self._circuit.record_failure()
            logger.error(f"Aegis risk summary push failed: {e.response.status_code}")
            raise
        except httpx.ConnectError as e:
            self._circuit.record_failure()
            logger.warning(f"Aegis unreachable: {e}")
            return {"status": "unreachable", "error": str(e)}
    
    async def report_incident(
        self,
        incident: Dict[str, Any],
    ) -> Dict[str, Any]:
        """
        Report a security incident to Aegis response pipeline.
        
        Args:
            incident: Incident details (entity_id, type, severity, description)
            
        Returns:
            Incident ticket ID from Aegis
        """
        client = await self._get_client()
        payload = {
            "source": "pdri",
            "reported_at": datetime.now(timezone.utc).isoformat(),
            **incident,
        }
        
        try:
            self._circuit.check()
            response = await client.post("/api/v1/incidents", json=payload)
            response.raise_for_status()
            result = response.json()
            self._circuit.record_success()
            logger.info(f"Reported incident to Aegis: {result.get('ticket_id', 'unknown')}")
            return result
        except CircuitBreakerOpen as e:
            logger.warning(f"Aegis circuit open — skipping incident report: {e}")
            return {"status": "circuit_open", "ticket_id": None}
        except httpx.HTTPStatusError as e:
            self._circuit.record_failure()
            logger.error(f"Aegis incident report failed: {e.response.status_code}")
            raise
        except httpx.ConnectError:
            self._circuit.record_failure()
            return {"status": "unreachable", "ticket_id": None}
    
    async def sync_entity_catalog(
        self,
        entities: List[Dict[str, Any]],
    ) -> Dict[str, Any]:
        """
        Sync entity catalog with AegisAI for cross-platform correlation.
        
        Args:
            entities: List of entity dicts (id, name, type, risk_level)
            
        Returns:
            Sync result with matched/new entity counts
        """
        client = await self._get_client()
        payload = {
            "source": "pdri",
            "synced_at": datetime.now(timezone.utc).isoformat(),
            "entities": entities,
        }
        
        try:
            self._circuit.check()
            response = await client.post("/api/v1/integrations/entity-sync", json=payload)
            response.raise_for_status()
            result = response.json()
            self._circuit.record_success()
            logger.info(
                f"Synced {len(entities)} entities with Aegis: "
                f"{result.get('matched', 0)} matched, {result.get('new', 0)} new"
            )
            return result
        except CircuitBreakerOpen as e:
            logger.warning(f"Aegis circuit open — skipping entity sync: {e}")
            return {"status": "circuit_open", "matched": 0, "new": 0}
        except httpx.HTTPStatusError as e:
            self._circuit.record_failure()
            logger.error(f"Aegis entity sync failed: {e.response.status_code}")
            raise
        except httpx.ConnectError:
            self._circuit.record_failure()
            return {"status": "unreachable", "matched": 0, "new": 0}
    
    # =========================================================================
    # Pull Operations (Aegis → PDRI)
    # =========================================================================
    
    async def pull_threat_intel(
        self,
        since: Optional[datetime] = None,
        limit: int = 100,
    ) -> List[Dict[str, Any]]:
        """
        Pull threat intelligence from AegisAI.
        
        Args:
            since: Only fetch threats after this timestamp
            limit: Maximum number of threat items
            
        Returns:
            List of threat intelligence items
        """
        client = await self._get_client()
        params: Dict[str, Any] = {"limit": limit}
        if since:
            params["since"] = since.isoformat()
        
        try:
            self._circuit.check()
            response = await client.get("/api/v1/threat-intel", params=params)
            response.raise_for_status()
            threats = response.json()
            self._circuit.record_success()
            logger.info(f"Pulled {len(threats)} threat intel items from Aegis")
            return threats
        except CircuitBreakerOpen as e:
            logger.warning(f"Aegis circuit open — skipping threat intel pull: {e}")
            return []
        except httpx.HTTPStatusError as e:
            self._circuit.record_failure()
            logger.error(f"Aegis threat intel pull failed: {e.response.status_code}")
            raise
        except httpx.ConnectError:
            self._circuit.record_failure()
            logger.warning("Aegis unreachable for threat intel pull")
            return []
    
    async def pull_policy_updates(self) -> Dict[str, Any]:
        """
        Pull latest security policy updates from AegisAI.
        
        Returns:
            Policy update payload (frameworks, thresholds, rules)
        """
        client = await self._get_client()
        
        try:
            self._circuit.check()
            response = await client.get("/api/v1/policies/latest")
            response.raise_for_status()
            self._circuit.record_success()
            return response.json()
        except CircuitBreakerOpen as e:
            logger.warning(f"Aegis circuit open — skipping policy pull: {e}")
            return {"status": "circuit_open"}
        except httpx.HTTPStatusError as e:
            self._circuit.record_failure()
            logger.error(f"Aegis policy pull failed: {e.response.status_code}")
            raise
        except httpx.ConnectError:
            self._circuit.record_failure()
            return {"status": "unreachable"}
    
    # =========================================================================
    # Health Check
    # =========================================================================
    
    async def check_health(self) -> Dict[str, Any]:
        """
        Check AegisAI API health.
        
        Returns:
            Health status
        """
        client = await self._get_client()
        
        try:
            response = await client.get("/health")
            response.raise_for_status()
            return response.json()
        except Exception as e:
            return {"status": "unreachable", "error": str(e)}
