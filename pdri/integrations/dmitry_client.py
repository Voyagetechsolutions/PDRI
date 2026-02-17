"""
Dmitry Integration - PDRI Client
================================

Client library for Dmitry to interact with PDRI.

Dmitry is the AI assistant that explains risk to users and
takes action on their behalf. This client provides methods for
Dmitry to query risk data from PDRI.

Features:
    - Risk score queries
    - Score explanations
    - Exposure path analysis
    - High-risk entity alerts
    - Natural language formatting

Author: PDRI Team
Version: 1.0.0
"""

import logging
from datetime import datetime
from typing import Any, Dict, List, Optional

import httpx

from pdri.config import settings


logger = logging.getLogger(__name__)


class DmitryClient:
    """
    HTTP client for Dmitry to query PDRI.
    
    Provides high-level methods for risk queries with
    formatting suitable for natural language responses.
    
    Usage:
        client = DmitryClient()
        
        # Get risk summary
        summary = await client.get_risk_summary()
        
        # Explain entity risk
        explanation = await client.explain_entity_risk("customer-db")
    """
    
    def __init__(
        self,
        base_url: Optional[str] = None,
        timeout: float = 30.0
    ):
        """
        Initialize the Dmitry client.
        
        Args:
            base_url: PDRI API base URL (defaults to config)
            timeout: Request timeout in seconds
        """
        self.base_url = base_url or f"http://localhost:{settings.api_port}"
        self.timeout = timeout
        self._client: Optional[httpx.AsyncClient] = None
    
    async def _get_client(self) -> httpx.AsyncClient:
        """Get or create HTTP client."""
        if self._client is None:
            self._client = httpx.AsyncClient(
                base_url=self.base_url,
                timeout=self.timeout
            )
        return self._client
    
    async def close(self) -> None:
        """Close the HTTP client."""
        if self._client:
            await self._client.aclose()
            self._client = None
    
    async def __aenter__(self) -> "DmitryClient":
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb) -> None:
        await self.close()
    
    # =========================================================================
    # Health and Status
    # =========================================================================
    
    async def check_health(self) -> Dict[str, Any]:
        """
        Check PDRI API health.
        
        Returns:
            Health status information
        """
        client = await self._get_client()
        response = await client.get("/health/ready")
        response.raise_for_status()
        return response.json()
    
    # =========================================================================
    # Risk Queries
    # =========================================================================
    
    async def get_entity_score(self, entity_id: str) -> Dict[str, Any]:
        """
        Get risk scores for an entity.
        
        Args:
            entity_id: Entity to score
            
        Returns:
            Risk score data
        """
        client = await self._get_client()
        response = await client.get(f"/scoring/{entity_id}")
        response.raise_for_status()
        return response.json()
    
    async def explain_entity_risk(self, entity_id: str) -> Dict[str, Any]:
        """
        Get human-readable risk explanation.
        
        Args:
            entity_id: Entity to explain
            
        Returns:
            Explanation with recommendations
        """
        client = await self._get_client()
        response = await client.get(f"/scoring/{entity_id}/explain")
        response.raise_for_status()
        return response.json()
    
    async def get_risk_summary(self) -> Dict[str, Any]:
        """
        Get overall risk summary.
        
        Returns:
            Summary of risk across the graph
        """
        client = await self._get_client()
        response = await client.get("/analytics/summary")
        response.raise_for_status()
        return response.json()
    
    async def get_high_risk_entities(
        self,
        threshold: float = 0.6,
        limit: int = 10
    ) -> List[Dict[str, Any]]:
        """
        Get entities with high risk scores.
        
        Args:
            threshold: Minimum risk score
            limit: Maximum entities to return
            
        Returns:
            List of high-risk entities
        """
        client = await self._get_client()
        response = await client.get(
            "/analytics/high-risk",
            params={"threshold": threshold, "limit": limit}
        )
        response.raise_for_status()
        return response.json()
    
    async def find_exposure_paths(
        self,
        entity_id: str,
        max_depth: int = 5
    ) -> List[Dict[str, Any]]:
        """
        Find paths from entity to external exposure.
        
        Args:
            entity_id: Starting entity
            max_depth: Maximum path length
            
        Returns:
            List of exposure paths
        """
        client = await self._get_client()
        response = await client.get(
            f"/analytics/exposure-paths/{entity_id}",
            params={"max_depth": max_depth}
        )
        response.raise_for_status()
        return response.json()
    
    async def get_ai_exposures(
        self,
        min_sensitivity: float = 0.5
    ) -> List[Dict[str, Any]]:
        """
        Get all AI exposure paths.
        
        Args:
            min_sensitivity: Minimum sensitivity filter
            
        Returns:
            List of AI exposure paths
        """
        client = await self._get_client()
        response = await client.get(
            "/analytics/ai-exposure",
            params={"min_sensitivity": min_sensitivity}
        )
        response.raise_for_status()
        return response.json()
    
    # =========================================================================
    # Node Queries
    # =========================================================================
    
    async def get_node(
        self, 
        node_id: str,
        include_relationships: bool = False
    ) -> Dict[str, Any]:
        """
        Get node details.
        
        Args:
            node_id: Node identifier
            include_relationships: Include connected nodes
            
        Returns:
            Node data
        """
        client = await self._get_client()
        response = await client.get(
            f"/nodes/{node_id}",
            params={"include_relationships": include_relationships}
        )
        response.raise_for_status()
        return response.json()
    
    async def get_ai_tools(self, limit: int = 100) -> List[Dict[str, Any]]:
        """
        Get all AI tool nodes.
        
        Returns:
            List of AI tools in the graph
        """
        client = await self._get_client()
        response = await client.get(
            "/nodes/aitools",
            params={"limit": limit}
        )
        response.raise_for_status()
        return response.json()
    
    async def get_data_stores(self, limit: int = 100) -> List[Dict[str, Any]]:
        """
        Get all data store nodes.
        
        Returns:
            List of data stores in the graph
        """
        client = await self._get_client()
        response = await client.get(
            "/nodes/datastores",
            params={"limit": limit}
        )
        response.raise_for_status()
        return response.json()
    
    # =========================================================================
    # Natural Language Formatting for Dmitry
    # =========================================================================
    
    def format_risk_summary_for_user(
        self, 
        summary: Dict[str, Any]
    ) -> str:
        """
        Format risk summary for natural language output.
        
        Args:
            summary: Risk summary data
            
        Returns:
            Human-readable summary text
        """
        high_risk = summary.get("high_risk_count", 0)
        medium_risk = summary.get("medium_risk_count", 0)
        total = summary.get("total_entities", 0)
        
        text = f"📊 **Risk Overview**\n\n"
        text += f"I've analyzed {total} entities in your data infrastructure.\n\n"
        
        if high_risk > 0:
            text += f"⚠️ **{high_risk}** entities require immediate attention (high risk)\n"
        
        if medium_risk > 0:
            text += f"⚡ **{medium_risk}** entities have moderate risk levels\n"
        
        # Top risks
        top_risks = summary.get("top_risks", [])
        if top_risks:
            text += "\n**Top Concerns:**\n"
            for i, risk in enumerate(top_risks[:3], 1):
                text += f"{i}. {risk.get('name', risk.get('id'))} "
                text += f"(exposure: {risk.get('exposure_score', 0):.0%})\n"
        
        return text
    
    def format_explanation_for_user(
        self, 
        explanation: Dict[str, Any]
    ) -> str:
        """
        Format risk explanation for natural language output.
        
        Args:
            explanation: Score explanation data
            
        Returns:
            Human-readable explanation
        """
        entity_id = explanation.get("entity_id", "Unknown")
        risk_level = explanation.get("risk_level", "unknown")
        score = explanation.get("composite_score", 0)
        
        # Risk level emoji
        emoji = {
            "critical": "🔴",
            "high": "🟠",
            "medium": "🟡",
            "low": "🟢",
            "minimal": "⚪"
        }.get(risk_level, "⚪")
        
        text = f"{emoji} **Risk Analysis: {entity_id}**\n\n"
        text += f"{explanation.get('summary', '')}\n\n"
        
        # Top factors
        top_factors = explanation.get("top_risk_factors", [])
        if top_factors:
            text += "**Key Risk Factors:**\n"
            for factor in top_factors:
                text += f"• {factor}\n"
            text += "\n"
        
        # Recommendations
        recommendations = explanation.get("recommendations", [])
        if recommendations:
            text += "**Recommendations:**\n"
            for rec in recommendations[:3]:
                text += f"→ {rec}\n"
        
        return text
    
    def format_exposure_paths_for_user(
        self,
        paths: List[Dict[str, Any]],
        entity_name: str
    ) -> str:
        """
        Format exposure paths for natural language output.
        
        Args:
            paths: List of exposure path data
            entity_name: Name of source entity
            
        Returns:
            Human-readable path description
        """
        if not paths:
            return f"✅ No direct exposure paths found from {entity_name}."
        
        text = f"🔍 **Exposure Paths from {entity_name}**\n\n"
        text += f"Found {len(paths)} path(s) to external exposure:\n\n"
        
        for i, path in enumerate(paths[:5], 1):
            nodes = path.get("node_ids", [])
            length = path.get("path_length", len(nodes))
            
            text += f"**Path {i}** ({length} hops):\n"
            text += " → ".join(nodes[:5])
            if len(nodes) > 5:
                text += f" → ... (+{len(nodes)-5} more)"
            text += "\n\n"
        
        return text


class MockDmitryClient(DmitryClient):
    """
    Mock client for testing without PDRI API.
    
    Returns mock data instead of making HTTP requests.
    """
    
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
                    {"id": "customer-db", "name": "Customer Database", "exposure_score": 0.85},
                    {"id": "analytics-api", "name": "Analytics API", "exposure_score": 0.72}
                ],
                "calculated_at": datetime.utcnow().isoformat()
            }
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
            "calculated_at": datetime.utcnow().isoformat()
        }
    
    async def explain_entity_risk(self, entity_id: str) -> Dict[str, Any]:
        return {
            "entity_id": entity_id,
            "risk_level": "medium",
            "composite_score": 0.58,
            "summary": f"{entity_id} has moderate risk due to AI integrations.",
            "top_risk_factors": ["AI integrations", "External connections"],
            "factor_breakdown": {"ai_integrations": 0.7, "external_connections": 0.5},
            "score_breakdown": {"exposure": 0.65, "volatility": 0.30, "sensitivity": 0.80},
            "recommendations": ["Review AI tool permissions", "Add monitoring"]
        }
