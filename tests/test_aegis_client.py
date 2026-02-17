"""
Tests for AegisAI Client
==========================

Tests AegisClient operations with mocked HTTP responses.
"""

import sys
from unittest.mock import MagicMock, AsyncMock, patch

# Mock neo4j before any PDRI imports
if "neo4j" not in sys.modules:
    sys.modules["neo4j"] = MagicMock()
    sys.modules["neo4j.exceptions"] = MagicMock()

import pytest
import httpx
from pdri.integrations.aegis_client import AegisClient


# =============================================================================
# Fixtures
# =============================================================================

@pytest.fixture
def aegis():
    """Create AegisClient with test configuration."""
    return AegisClient(
        base_url="http://localhost:8003",
        api_key="test-aegis-key",
        timeout=5.0,
    )


@pytest.fixture
def mock_response():
    """Create a mock HTTP response."""
    resp = MagicMock(spec=httpx.Response)
    resp.status_code = 200
    resp.raise_for_status = MagicMock()
    return resp


# =============================================================================
# Tests
# =============================================================================

class TestAegisClientInit:
    """Test AegisClient initialization."""
    
    def test_init_defaults(self, aegis):
        """Test client initializes with correct params."""
        assert aegis.base_url == "http://localhost:8003"
        assert aegis.api_key == "test-aegis-key"
        assert aegis.timeout == 5.0
    
    def test_strips_trailing_slash(self):
        """Test URL stripping."""
        client = AegisClient(base_url="http://aegis.example.com/")
        assert client.base_url == "http://aegis.example.com"


class TestAegisClientPush:
    """Test push operations."""
    
    @pytest.mark.asyncio
    async def test_push_risk_summary(self, aegis, mock_response):
        """Test pushing risk summary to Aegis."""
        mock_response.json.return_value = {"status": "accepted", "id": "summary-123"}
        
        mock_client = AsyncMock()
        mock_client.post = AsyncMock(return_value=mock_response)
        mock_client.is_closed = False
        aegis._client = mock_client
        
        summary = {
            "total_entities": 42,
            "high_risk_count": 5,
            "medium_risk_count": 12,
        }
        
        result = await aegis.push_risk_summary(summary)
        assert result["status"] == "accepted"
        mock_client.post.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_report_incident(self, aegis, mock_response):
        """Test reporting an incident."""
        mock_response.json.return_value = {"ticket_id": "INC-001", "status": "open"}
        
        mock_client = AsyncMock()
        mock_client.post = AsyncMock(return_value=mock_response)
        mock_client.is_closed = False
        aegis._client = mock_client
        
        incident = {
            "entity_id": "customer-db",
            "type": "data_breach",
            "severity": "critical",
            "description": "Unauthorized data access detected",
        }
        
        result = await aegis.report_incident(incident)
        assert result["ticket_id"] == "INC-001"
    
    @pytest.mark.asyncio
    async def test_sync_entity_catalog(self, aegis, mock_response):
        """Test syncing entity catalog."""
        mock_response.json.return_value = {"matched": 10, "new": 5}
        
        mock_client = AsyncMock()
        mock_client.post = AsyncMock(return_value=mock_response)
        mock_client.is_closed = False
        aegis._client = mock_client
        
        entities = [
            {"id": "db-1", "name": "Customer DB", "type": "DataStore", "risk_level": "high"},
            {"id": "api-1", "name": "API Gateway", "type": "Service", "risk_level": "medium"},
        ]
        
        result = await aegis.sync_entity_catalog(entities)
        assert result["matched"] == 10
        assert result["new"] == 5


class TestAegisClientPull:
    """Test pull operations."""
    
    @pytest.mark.asyncio
    async def test_pull_threat_intel(self, aegis, mock_response):
        """Test pulling threat intelligence."""
        threats = [
            {"id": "threat-1", "type": "ransomware", "severity": "critical"},
            {"id": "threat-2", "type": "phishing", "severity": "high"},
        ]
        mock_response.json.return_value = threats
        
        mock_client = AsyncMock()
        mock_client.get = AsyncMock(return_value=mock_response)
        mock_client.is_closed = False
        aegis._client = mock_client
        
        result = await aegis.pull_threat_intel(limit=10)
        assert len(result) == 2
        assert result[0]["type"] == "ransomware"
    
    @pytest.mark.asyncio
    async def test_pull_policy_updates(self, aegis, mock_response):
        """Test pulling policy updates."""
        mock_response.json.return_value = {
            "frameworks": ["GDPR", "SOX"],
            "updated_at": "2026-02-17T00:00:00Z",
        }
        
        mock_client = AsyncMock()
        mock_client.get = AsyncMock(return_value=mock_response)
        mock_client.is_closed = False
        aegis._client = mock_client
        
        result = await aegis.pull_policy_updates()
        assert "frameworks" in result
        assert "GDPR" in result["frameworks"]


class TestAegisClientHealth:
    """Test health check."""
    
    @pytest.mark.asyncio
    async def test_check_health_success(self, aegis, mock_response):
        """Test health check when Aegis is up."""
        mock_response.json.return_value = {"status": "healthy"}
        
        mock_client = AsyncMock()
        mock_client.get = AsyncMock(return_value=mock_response)
        mock_client.is_closed = False
        aegis._client = mock_client
        
        result = await aegis.check_health()
        assert result["status"] == "healthy"
    
    @pytest.mark.asyncio
    async def test_check_health_unreachable(self, aegis):
        """Test health check when Aegis is down."""
        mock_client = AsyncMock()
        mock_client.get = AsyncMock(side_effect=httpx.ConnectError("unreachable"))
        mock_client.is_closed = False
        aegis._client = mock_client
        
        result = await aegis.check_health()
        assert result["status"] == "unreachable"


class TestAegisContextManager:
    """Test async context manager."""
    
    @pytest.mark.asyncio
    async def test_context_manager(self):
        """Test AegisClient as async context manager."""
        async with AegisClient(base_url="http://test") as client:
            assert client is not None
            assert isinstance(client, AegisClient)
