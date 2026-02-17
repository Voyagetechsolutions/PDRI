"""
Dmitry Integration — Bidirectional Client
==========================================

Two clients for the PDRI ↔ Dmitry AI integration:

    1. DmitryBackendClient  (NEW)
       PDRI → Dmitry backend at http://127.0.0.1:8765
       Methods: send_message, switch_mode, get_status, get_logs,
                analyze_threat, get_strategic_advice, check_compliance,
                assess_ai_model_risk, lookup_threat_intelligence, etc.

    2. DmitryPDRIClient  (existing, renamed for clarity)
       Dmitry → PDRI API at http://localhost:8000
       Methods: get_risk_summary, get_entity_score, explain_entity_risk,
                find_exposure_paths, format_risk_summary_for_user, etc.

Author: PDRI Team
Version: 2.0.0
"""

import json
import logging
import time
from datetime import datetime, timezone
from typing import Any, Callable, Dict, List, Optional

import httpx

from pdri.config import settings

logger = logging.getLogger(__name__)


# =============================================================================
# Circuit Breaker (shared with AegisClient pattern)
# =============================================================================


class CircuitBreakerOpen(Exception):
    """Raised when the circuit breaker is open."""
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
        self._state = "closed"

    @property
    def state(self) -> str:
        if self._state == "open" and self._last_failure_time:
            elapsed = (
                datetime.now(timezone.utc) - self._last_failure_time
            ).total_seconds()
            if elapsed >= self.cooldown_seconds:
                self._state = "half-open"
        return self._state

    def check(self) -> None:
        if self.state == "open":
            raise CircuitBreakerOpen(
                f"Circuit breaker open — {self._failure_count} consecutive "
                f"failures. Retry after {self.cooldown_seconds}s."
            )

    def record_success(self) -> None:
        self._failure_count = 0
        self._state = "closed"

    def record_failure(self) -> None:
        self._failure_count += 1
        self._last_failure_time = datetime.now(timezone.utc)
        if self._failure_count >= self.failure_threshold:
            self._state = "open"
            logger.warning(
                f"Dmitry circuit breaker opened after "
                f"{self._failure_count} failures"
            )


# =============================================================================
# DmitryBackendClient — PDRI calls Dmitry AI backend
# =============================================================================


class DmitryBackendClient:
    """
    Async HTTP client for PDRI → Dmitry AI backend communication.

    Connects to Dmitry's AgentServer (MarkX/agent/server.py) to
    leverage NLP, strategic advisory, and security operations.

    Endpoints:
        POST /message  — send query/command
        POST /mode     — switch cognitive mode
        GET  /status   — connection health
        GET  /logs     — action history

    Usage:
        client = DmitryBackendClient()

        # Health check
        status = await client.get_status()

        # Analyze a threat
        analysis = await client.analyze_threat("Suspicious login attempts")

        # Get strategic advice
        advice = await client.get_strategic_advice(
            context="Cloud migration",
            question="Multi-cloud vs single?"
        )
    """

    VALID_MODES = frozenset(
        ["utility", "general", "design", "developer", "research",
         "security", "simulation"]
    )

    def __init__(
        self,
        base_url: Optional[str] = None,
        timeout_message: float = 30.0,
        timeout_default: float = 10.0,
        circuit_failure_threshold: int = 5,
        circuit_cooldown_seconds: float = 60.0,
    ):
        """
        Initialize Dmitry backend client.

        Args:
            base_url: Dmitry server URL (defaults to config)
            timeout_message: Timeout for /message calls (LLM processing)
            timeout_default: Timeout for /status, /mode, /logs calls
            circuit_failure_threshold: Failures before circuit opens
            circuit_cooldown_seconds: Seconds before circuit resets
        """
        self.base_url = (base_url or settings.dmitry_api_url).rstrip("/")
        self.timeout_message = timeout_message
        self.timeout_default = timeout_default
        self._client: Optional[httpx.AsyncClient] = None
        self._circuit = CircuitBreaker(
            failure_threshold=circuit_failure_threshold,
            cooldown_seconds=circuit_cooldown_seconds,
        )
        self._current_mode = "general"

    async def _get_client(self) -> httpx.AsyncClient:
        """Get or create HTTP client."""
        if self._client is None or self._client.is_closed:
            self._client = httpx.AsyncClient(
                base_url=self.base_url,
                timeout=self.timeout_default,
                headers={
                    "Content-Type": "application/json",
                    "User-Agent": "PDRI-DmitryClient/2.0",
                },
            )
        return self._client

    async def close(self) -> None:
        """Close the HTTP client."""
        if self._client:
            await self._client.aclose()
            self._client = None

    async def __aenter__(self) -> "DmitryBackendClient":
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb) -> None:
        await self.close()

    # =========================================================================
    # Core API Methods
    # =========================================================================

    async def send_message(self, message: str) -> Dict[str, Any]:
        """
        Send a natural language message to Dmitry and get a response.

        Args:
            message: Query or command in natural language

        Returns:
            Response dict with keys:
                text, intent, mode, tool_executed, tool_result, log
        """
        client = await self._get_client()
        try:
            self._circuit.check()
            response = await client.post(
                "/message",
                json={"message": message},
                timeout=self.timeout_message,
            )
            response.raise_for_status()
            self._circuit.record_success()
            return response.json()
        except CircuitBreakerOpen as e:
            logger.warning(f"Dmitry circuit open — skipping message: {e}")
            return {"text": str(e), "intent": "error", "error": str(e)}
        except httpx.HTTPStatusError as e:
            self._circuit.record_failure()
            logger.error(f"Dmitry message failed: {e.response.status_code}")
            return {
                "text": f"HTTP {e.response.status_code}",
                "intent": "error",
                "error": str(e),
            }
        except (httpx.ConnectError, httpx.TimeoutException) as e:
            self._circuit.record_failure()
            logger.warning(f"Dmitry unreachable: {e}")
            return {
                "text": f"Connection error: {e}",
                "intent": "error",
                "error": str(e),
            }

    async def switch_mode(self, mode: str) -> Dict[str, Any]:
        """
        Switch Dmitry's cognitive mode.

        Args:
            mode: One of utility, general, design, developer,
                  research, security, simulation

        Returns:
            Dict with success, message, and mode
        """
        if mode not in self.VALID_MODES:
            return {
                "success": False,
                "error": f"Invalid mode '{mode}'. Valid: {sorted(self.VALID_MODES)}",
            }

        client = await self._get_client()
        try:
            self._circuit.check()
            response = await client.post("/mode", json={"mode": mode})
            response.raise_for_status()
            result = response.json()
            self._circuit.record_success()
            if result.get("success"):
                self._current_mode = mode
            return result
        except CircuitBreakerOpen as e:
            return {"success": False, "error": str(e)}
        except (httpx.HTTPStatusError, httpx.ConnectError, httpx.TimeoutException) as e:
            self._circuit.record_failure()
            return {"success": False, "error": str(e)}

    async def get_status(self) -> Dict[str, Any]:
        """
        Get Dmitry's current operational status.

        Returns:
            Dict with connected, mode, pending_confirmations, timestamp
        """
        client = await self._get_client()
        try:
            self._circuit.check()
            response = await client.get("/status", timeout=5.0)
            response.raise_for_status()
            self._circuit.record_success()
            return response.json()
        except CircuitBreakerOpen:
            return {"connected": False, "error": "circuit_open"}
        except (httpx.HTTPStatusError, httpx.ConnectError, httpx.TimeoutException) as e:
            self._circuit.record_failure()
            return {"connected": False, "error": str(e)}

    async def get_logs(self, limit: int = 50) -> Dict[str, Any]:
        """
        Get recent action logs from Dmitry.

        Args:
            limit: Maximum number of log entries

        Returns:
            Dict with logs list and total count
        """
        client = await self._get_client()
        try:
            self._circuit.check()
            response = await client.get("/logs", params={"limit": limit})
            response.raise_for_status()
            self._circuit.record_success()
            return response.json()
        except CircuitBreakerOpen:
            return {"logs": [], "total": 0, "error": "circuit_open"}
        except (httpx.HTTPStatusError, httpx.ConnectError, httpx.TimeoutException) as e:
            self._circuit.record_failure()
            return {"logs": [], "total": 0, "error": str(e)}

    # =========================================================================
    # Strategic Advisor Methods
    # =========================================================================

    async def analyze_threat(self, threat_description: str) -> Dict[str, Any]:
        """
        Analyze a security threat using Dmitry's security mode.

        Automatically switches to security mode, sends the threat
        description, and returns Dmitry's analysis with classification,
        risk level, and recommended mitigations.

        Args:
            threat_description: Description of the threat

        Returns:
            Dmitry's analysis response
        """
        await self.switch_mode("security")

        prompt = (
            "Analyze this security threat and provide:\n"
            "1. Threat classification\n"
            "2. Risk level\n"
            "3. Recommended actions\n"
            "4. Mitigation strategies\n\n"
            f"Threat: {threat_description}"
        )
        return await self.send_message(prompt)

    async def get_strategic_advice(
        self, context: str, question: str
    ) -> Dict[str, Any]:
        """
        Get strategic advice from Dmitry.

        Args:
            context: Business/technical context
            question: Specific question

        Returns:
            Strategic recommendations
        """
        prompt = (
            f"Context: {context}\n\n"
            f"Question: {question}\n\n"
            "Provide strategic advice with:\n"
            "1. Analysis\n"
            "2. Options\n"
            "3. Recommendations\n"
            "4. Risks and considerations"
        )
        return await self.send_message(prompt)

    async def explain_technical_concept(
        self, concept: str, audience: str = "executive"
    ) -> Dict[str, Any]:
        """
        Explain a technical concept for a specific audience.

        Args:
            concept: Technical concept to explain
            audience: Target audience (executive, technical, general)

        Returns:
            Tailored explanation
        """
        prompt = (
            f"Explain this technical concept for a {audience} audience:\n\n"
            f"{concept}\n\n"
            "Use appropriate language and examples."
        )
        return await self.send_message(prompt)

    async def generate_report_summary(
        self, report_data: Dict[str, Any]
    ) -> str:
        """
        Generate an executive summary from report data.

        Args:
            report_data: Raw report data dictionary

        Returns:
            Executive summary text
        """
        prompt = (
            "Generate an executive summary from this data:\n\n"
            f"{json.dumps(report_data, indent=2)}\n\n"
            "Focus on:\n"
            "- Key findings\n"
            "- Critical issues\n"
            "- Recommendations\n"
            "- Next steps"
        )
        result = await self.send_message(prompt)
        return result.get("text", "")

    async def format_for_natural_language(
        self, data: Dict[str, Any]
    ) -> str:
        """
        Format structured data for natural language presentation.

        Args:
            data: Structured data dictionary

        Returns:
            Human-readable formatted string
        """
        prompt = (
            "Format this data in clear, natural language:\n\n"
            f"{json.dumps(data, indent=2)}\n\n"
            "Make it readable and professional."
        )
        result = await self.send_message(prompt)
        return result.get("text", "")

    # =========================================================================
    # Security Operations
    # =========================================================================

    async def lookup_threat_intelligence(
        self, ioc: str, ioc_type: str = "auto"
    ) -> Dict[str, Any]:
        """
        Lookup threat intelligence for an Indicator of Compromise.

        Args:
            ioc: IP, domain, hash, or other IOC
            ioc_type: IOC type or "auto" for detection

        Returns:
            Threat intelligence data
        """
        await self.switch_mode("security")

        prompt = (
            "Lookup threat intelligence for this IOC:\n\n"
            f"IOC: {ioc}\n"
            f"Type: {ioc_type}\n\n"
            "Provide:\n"
            "- Reputation\n"
            "- Known associations\n"
            "- Threat level\n"
            "- Recommendations"
        )
        return await self.send_message(prompt)

    async def check_compliance(
        self, framework: str, system_config: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Check compliance against a security framework.

        Args:
            framework: soc2, iso27001, nist, pci_dss, etc.
            system_config: System configuration to evaluate

        Returns:
            Compliance assessment
        """
        await self.switch_mode("security")

        prompt = (
            f"Check compliance against {framework}:\n\n"
            "System Configuration:\n"
            f"{json.dumps(system_config, indent=2)}\n\n"
            "Provide:\n"
            "- Compliance status\n"
            "- Gaps identified\n"
            "- Recommendations\n"
            "- Priority actions"
        )
        return await self.send_message(prompt)

    async def analyze_vulnerability(
        self, vulnerability_data: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Analyze a vulnerability and provide remediation advice.

        Args:
            vulnerability_data: Vulnerability details

        Returns:
            Analysis with remediation steps
        """
        await self.switch_mode("security")

        prompt = (
            "Analyze this vulnerability:\n\n"
            f"{json.dumps(vulnerability_data, indent=2)}\n\n"
            "Provide:\n"
            "- Severity assessment\n"
            "- Exploitability\n"
            "- Impact analysis\n"
            "- Remediation steps\n"
            "- Priority level"
        )
        return await self.send_message(prompt)

    async def assess_ai_model_risk(
        self, model_config: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Assess AI model security risks.

        Args:
            model_config: AI model configuration

        Returns:
            Risk assessment against OWASP LLM Top 10
        """
        await self.switch_mode("security")

        prompt = (
            "Assess AI model security risks:\n\n"
            "Model Configuration:\n"
            f"{json.dumps(model_config, indent=2)}\n\n"
            "Evaluate:\n"
            "- Prompt injection vulnerabilities\n"
            "- Data poisoning risks\n"
            "- Model bias\n"
            "- Security controls\n"
            "- OWASP LLM Top 10 compliance"
        )
        return await self.send_message(prompt)

    # =========================================================================
    # Utility Methods
    # =========================================================================

    async def is_connected(self) -> bool:
        """Check if Dmitry backend is connected and responsive."""
        status = await self.get_status()
        return status.get("connected", False)

    async def health_check(self) -> Dict[str, Any]:
        """
        Full health check with latency measurement.

        Returns:
            Dict with healthy, mode, latency_ms
        """
        start = time.monotonic()
        status = await self.get_status()
        latency_ms = int((time.monotonic() - start) * 1000)

        return {
            "healthy": status.get("connected", False),
            "mode": status.get("mode", "unknown"),
            "latency_ms": latency_ms,
            "circuit_state": self._circuit.state,
        }

    @property
    def current_mode(self) -> str:
        """Last known cognitive mode."""
        return self._current_mode


# =============================================================================
# DmitryPDRIClient — Dmitry queries PDRI
# =============================================================================


class DmitryPDRIClient:
    """
    HTTP client for Dmitry to query PDRI risk data.

    This is the "reverse" direction — Dmitry calls PDRI's API
    to retrieve risk scores, summaries, and exposure paths.

    Usage:
        client = DmitryPDRIClient()
        summary = await client.get_risk_summary()
        explanation = await client.explain_entity_risk("customer-db")
    """

    def __init__(
        self,
        base_url: Optional[str] = None,
        timeout: float = 30.0,
    ):
        """
        Initialize the PDRI-querying client.

        Args:
            base_url: PDRI API base URL (defaults to localhost:8000)
            timeout: Request timeout in seconds
        """
        self.base_url = base_url or f"http://localhost:{settings.api_port}"
        self.timeout = timeout
        self._client: Optional[httpx.AsyncClient] = None

    async def _get_client(self) -> httpx.AsyncClient:
        if self._client is None or self._client.is_closed:
            self._client = httpx.AsyncClient(
                base_url=self.base_url,
                timeout=self.timeout,
            )
        return self._client

    async def close(self) -> None:
        if self._client:
            await self._client.aclose()
            self._client = None

    async def __aenter__(self) -> "DmitryPDRIClient":
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb) -> None:
        await self.close()

    # ── Health ────────────────────────────────────────────────────────────

    async def check_health(self) -> Dict[str, Any]:
        """Check PDRI API health."""
        client = await self._get_client()
        response = await client.get("/health/ready")
        response.raise_for_status()
        return response.json()

    # ── Risk Queries ─────────────────────────────────────────────────────

    async def get_entity_score(self, entity_id: str) -> Dict[str, Any]:
        """Get risk scores for an entity."""
        client = await self._get_client()
        response = await client.get(f"/scoring/{entity_id}")
        response.raise_for_status()
        return response.json()

    async def explain_entity_risk(self, entity_id: str) -> Dict[str, Any]:
        """Get human-readable risk explanation."""
        client = await self._get_client()
        response = await client.get(f"/scoring/{entity_id}/explain")
        response.raise_for_status()
        return response.json()

    async def get_risk_summary(self) -> Dict[str, Any]:
        """Get overall risk summary."""
        client = await self._get_client()
        response = await client.get("/analytics/risk-summary")
        response.raise_for_status()
        return response.json()

    async def get_high_risk_entities(
        self, threshold: float = 0.6, limit: int = 10
    ) -> List[Dict[str, Any]]:
        """Get entities with high risk scores."""
        client = await self._get_client()
        response = await client.get(
            "/analytics/high-risk",
            params={"threshold": threshold, "limit": limit},
        )
        response.raise_for_status()
        return response.json()

    async def find_exposure_paths(
        self, entity_id: str, max_depth: int = 5
    ) -> List[Dict[str, Any]]:
        """Find paths from entity to external exposure."""
        client = await self._get_client()
        response = await client.get(
            f"/analytics/exposure-paths/{entity_id}",
            params={"max_depth": max_depth},
        )
        response.raise_for_status()
        return response.json()

    async def get_ai_exposures(
        self, min_sensitivity: float = 0.5
    ) -> List[Dict[str, Any]]:
        """Get all AI exposure paths."""
        client = await self._get_client()
        response = await client.get(
            "/analytics/ai-exposure",
            params={"min_sensitivity": min_sensitivity},
        )
        response.raise_for_status()
        return response.json()

    # ── Node Queries ─────────────────────────────────────────────────────

    async def get_node(
        self, node_id: str, include_relationships: bool = False
    ) -> Dict[str, Any]:
        """Get node details."""
        client = await self._get_client()
        response = await client.get(
            f"/nodes/{node_id}",
            params={"include_relationships": include_relationships},
        )
        response.raise_for_status()
        return response.json()

    async def get_ai_tools(self, limit: int = 100) -> List[Dict[str, Any]]:
        """Get all AI tool nodes."""
        client = await self._get_client()
        response = await client.get("/nodes/ai-tools", params={"limit": limit})
        response.raise_for_status()
        return response.json()

    async def get_data_stores(self, limit: int = 100) -> List[Dict[str, Any]]:
        """Get all data store nodes."""
        client = await self._get_client()
        response = await client.get(
            "/nodes/data-stores", params={"limit": limit}
        )
        response.raise_for_status()
        return response.json()

    # ── Natural Language Formatters ──────────────────────────────────────

    @staticmethod
    def format_risk_summary_for_user(summary: Dict[str, Any]) -> str:
        """Format risk summary for natural language output."""
        high_risk = summary.get("high_risk_count", 0)
        medium_risk = summary.get("medium_risk_count", 0)
        total = summary.get("total_entities", 0)

        text = f"📊 **Risk Overview**\n\nI've analyzed {total} entities.\n\n"

        if high_risk > 0:
            text += f"⚠️ **{high_risk}** entities require immediate attention\n"
        if medium_risk > 0:
            text += f"⚡ **{medium_risk}** entities have moderate risk\n"

        top_risks = summary.get("top_risks", [])
        if top_risks:
            text += "\n**Top Concerns:**\n"
            for i, risk in enumerate(top_risks[:3], 1):
                name = risk.get("name", risk.get("id"))
                score = risk.get("exposure_score", 0)
                text += f"{i}. {name} (exposure: {score:.0%})\n"

        return text

    @staticmethod
    def format_explanation_for_user(explanation: Dict[str, Any]) -> str:
        """Format risk explanation for natural language output."""
        entity_id = explanation.get("entity_id", "Unknown")
        risk_level = explanation.get("risk_level", "unknown")

        emoji = {
            "critical": "🔴", "high": "🟠", "medium": "🟡",
            "low": "🟢", "minimal": "⚪",
        }.get(risk_level, "⚪")

        text = f"{emoji} **Risk Analysis: {entity_id}**\n\n"
        text += f"{explanation.get('summary', '')}\n\n"

        for factor in explanation.get("top_risk_factors", []):
            text += f"• {factor}\n"

        recs = explanation.get("recommendations", [])
        if recs:
            text += "\n**Recommendations:**\n"
            for rec in recs[:3]:
                text += f"→ {rec}\n"

        return text

    @staticmethod
    def format_exposure_paths_for_user(
        paths: List[Dict[str, Any]], entity_name: str
    ) -> str:
        """Format exposure paths for natural language output."""
        if not paths:
            return f"✅ No direct exposure paths found from {entity_name}."

        text = f"🔍 **Exposure Paths from {entity_name}**\n\n"
        text += f"Found {len(paths)} path(s):\n\n"

        for i, path in enumerate(paths[:5], 1):
            nodes = path.get("node_ids", [])
            length = path.get("path_length", len(nodes))
            text += f"**Path {i}** ({length} hops):\n"
            text += " → ".join(nodes[:5])
            if len(nodes) > 5:
                text += f" → ... (+{len(nodes) - 5} more)"
            text += "\n\n"

        return text

    # ── Simulation & Compliance ──────────────────────────────────────────

    async def run_simulation(
        self, scenario: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Run a risk simulation scenario."""
        client = await self._get_client()
        response = await client.post("/simulation/run", json=scenario)
        response.raise_for_status()
        return response.json()

    async def get_compliance_status(
        self, framework: str = "general"
    ) -> Dict[str, Any]:
        """Get compliance status for a framework."""
        client = await self._get_client()
        response = await client.get(f"/compliance/{framework}")
        response.raise_for_status()
        return response.json()

    async def get_score_history(
        self, entity_id: str, days: int = 30
    ) -> List[Dict[str, Any]]:
        """Get historical scores for an entity."""
        client = await self._get_client()
        response = await client.get(
            f"/scoring/{entity_id}/history",
            params={"days": days},
        )
        response.raise_for_status()
        return response.json()


# =============================================================================
# Backward-compatible alias
# =============================================================================

# The original module exported `DmitryClient` — keep the alias
# so existing imports don't break
DmitryClient = DmitryPDRIClient


class MockDmitryClient(DmitryPDRIClient):
    """Mock client for testing without PDRI API running."""

    def __init__(self):
        super().__init__()
        self._mock_data = {
            "health": {"status": "ready"},
            "summary": {
                "total_entities": 42,
                "high_risk_count": 5,
                "medium_risk_count": 12,
                "low_risk_count": 25,
                "top_risks": [
                    {
                        "id": "customer-db",
                        "name": "Customer Database",
                        "exposure_score": 0.85,
                    },
                    {
                        "id": "analytics-api",
                        "name": "Analytics API",
                        "exposure_score": 0.72,
                    },
                ],
                "calculated_at": datetime.now(timezone.utc).isoformat(),
            },
        }

    async def check_health(self) -> Dict[str, Any]:
        return self._mock_data["health"]

    async def get_risk_summary(self) -> Dict[str, Any]:
        return self._mock_data["summary"]

    async def get_entity_score(self, entity_id: str) -> Dict[str, Any]:
        return {
            "entity_id": entity_id,
            "exposure_score": 0.65,
            "volatility_score": 0.30,
            "sensitivity_likelihood": 0.80,
            "composite_score": 0.58,
            "risk_level": "medium",
            "scoring_version": "1.0.0",
            "calculated_at": datetime.now(timezone.utc).isoformat(),
        }

    async def explain_entity_risk(self, entity_id: str) -> Dict[str, Any]:
        return {
            "entity_id": entity_id,
            "risk_level": "medium",
            "composite_score": 0.58,
            "summary": f"{entity_id} has moderate risk due to AI integrations.",
            "top_risk_factors": ["AI integrations", "External connections"],
            "factor_breakdown": {
                "ai_integrations": 0.7,
                "external_connections": 0.5,
            },
            "score_breakdown": {
                "exposure": 0.65,
                "volatility": 0.30,
                "sensitivity": 0.80,
            },
            "recommendations": [
                "Review AI tool permissions",
                "Add monitoring",
            ],
        }
