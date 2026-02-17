"""
Tests for Redis Score Cache
============================

Tests ScoreCache operations: get, set, invalidate, fallback.
All tests mock Redis to avoid needing a running instance.
"""

import sys
from unittest.mock import MagicMock, AsyncMock, patch

# Mock neo4j before any PDRI imports
if "neo4j" not in sys.modules:
    sys.modules["neo4j"] = MagicMock()
    sys.modules["neo4j.exceptions"] = MagicMock()

import json
import pytest
from pdri.scoring.score_cache import ScoreCache


# =============================================================================
# Fixtures
# =============================================================================

@pytest.fixture
def cache():
    """Create a ScoreCache instance with mocked Redis."""
    c = ScoreCache(redis_url="redis://localhost:6379/0", default_ttl=300)
    return c


@pytest.fixture
def mock_redis():
    """Create a mock async Redis client."""
    redis = AsyncMock()
    redis.ping = AsyncMock(return_value=True)
    redis.get = AsyncMock(return_value=None)
    redis.setex = AsyncMock(return_value=True)
    redis.delete = AsyncMock(return_value=1)
    redis.close = AsyncMock()
    return redis


@pytest.fixture
def sample_score_data():
    """Sample score data for caching."""
    return {
        "entity_id": "node-001",
        "exposure_score": 0.75,
        "volatility_score": 0.30,
        "sensitivity_likelihood": 0.60,
        "composite_score": 0.55,
        "risk_level": "medium",
        "scoring_version": "1.0.0",
        "calculated_at": "2026-02-17T12:00:00+00:00",
        "factors": {
            "external_connection_factor": 0.6,
            "ai_integration_factor": 0.8,
            "data_volume_factor": 0.4,
            "privilege_level_factor": 0.3,
            "public_exposure_factor": 0.5,
            "name_heuristic_factor": 0.2,
            "data_classification_factor": 0.7,
            "sensitivity_tag_factor": 0.6,
        },
    }


# =============================================================================
# Tests
# =============================================================================

class TestScoreCache:
    """Test suite for ScoreCache."""
    
    def test_cache_init(self, cache):
        """Test cache initializes with correct defaults."""
        assert cache.default_ttl == 300
        assert cache.redis_url == "redis://localhost:6379/0"
        assert cache.is_available is False
    
    @pytest.mark.asyncio
    async def test_cache_miss(self, cache):
        """Test cache miss returns None when not available."""
        result = await cache.get("nonexistent-entity")
        assert result is None
    
    @pytest.mark.asyncio
    async def test_set_when_unavailable(self, cache, sample_score_data):
        """Test set returns False when cache is unavailable."""
        result = await cache.set("node-001", sample_score_data)
        assert result is False
    
    @pytest.mark.asyncio
    async def test_invalidate_when_unavailable(self, cache):
        """Test invalidate returns False when cache is unavailable."""
        result = await cache.invalidate("node-001")
        assert result is False
    
    @pytest.mark.asyncio
    async def test_invalidate_all_when_unavailable(self, cache):
        """Test invalidate_all returns 0 when cache is unavailable."""
        result = await cache.invalidate_all()
        assert result == 0
    
    @pytest.mark.asyncio
    async def test_stats_when_unavailable(self, cache):
        """Test stats returns unavailable when cache is down."""
        result = await cache.stats()
        assert result == {"available": False}
    
    @pytest.mark.asyncio
    async def test_cache_hit(self, cache, mock_redis, sample_score_data):
        """Test cache hit returns stored data."""
        cache._redis = mock_redis
        cache._available = True
        mock_redis.get = AsyncMock(return_value=json.dumps(sample_score_data))
        
        result = await cache.get("node-001")
        assert result is not None
        assert result["entity_id"] == "node-001"
        assert result["exposure_score"] == 0.75
        assert result["risk_level"] == "medium"
    
    @pytest.mark.asyncio
    async def test_cache_set(self, cache, mock_redis, sample_score_data):
        """Test setting cache stores data correctly."""
        cache._redis = mock_redis
        cache._available = True
        
        result = await cache.set("node-001", sample_score_data, ttl=600)
        assert result is True
        mock_redis.setex.assert_called_once()
        
        # Verify the key format
        call_args = mock_redis.setex.call_args
        assert call_args[0][0] == "pdri:score:node-001"
        assert call_args[0][1] == 600
    
    @pytest.mark.asyncio
    async def test_cache_invalidate(self, cache, mock_redis):
        """Test invalidation deletes the key."""
        cache._redis = mock_redis
        cache._available = True
        
        result = await cache.invalidate("node-001")
        assert result is True
        mock_redis.delete.assert_called_once_with("pdri:score:node-001")
    
    @pytest.mark.asyncio
    async def test_cache_default_ttl(self, cache, mock_redis, sample_score_data):
        """Test set uses default TTL when none specified."""
        cache._redis = mock_redis
        cache._available = True
        
        await cache.set("node-001", sample_score_data)
        call_args = mock_redis.setex.call_args
        assert call_args[0][1] == 300  # default_ttl
    
    @pytest.mark.asyncio
    async def test_cache_get_error_handling(self, cache, mock_redis):
        """Test cache gracefully handles Redis errors on get."""
        cache._redis = mock_redis
        cache._available = True
        mock_redis.get = AsyncMock(side_effect=ConnectionError("Redis down"))
        
        result = await cache.get("node-001")
        assert result is None
    
    @pytest.mark.asyncio
    async def test_cache_set_error_handling(self, cache, mock_redis, sample_score_data):
        """Test cache gracefully handles Redis errors on set."""
        cache._redis = mock_redis
        cache._available = True
        mock_redis.setex = AsyncMock(side_effect=ConnectionError("Redis down"))
        
        result = await cache.set("node-001", sample_score_data)
        assert result is False
    
    def test_cache_prefix(self):
        """Test that cache uses correct key prefix."""
        assert ScoreCache.PREFIX == "pdri:score:"
