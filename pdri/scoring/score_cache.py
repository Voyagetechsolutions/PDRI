"""
Redis Score Cache
=================

Caching layer for risk scores to avoid repeated graph queries.

Features:
    - Async Redis via redis.asyncio
    - Configurable TTL per entity
    - Graceful fallback when Redis unavailable
    - Cache invalidation on score updates

Author: PDRI Team
Version: 1.0.0
"""

import json
import logging
from datetime import datetime, timezone
from typing import Any, Dict, Optional

logger = logging.getLogger(__name__)

try:
    import redis.asyncio as aioredis
    HAS_REDIS = True
except ImportError:
    HAS_REDIS = False
    aioredis = None  # type: ignore


class ScoreCache:
    """
    Redis-backed score cache with graceful fallback.
    
    When Redis is unavailable, all operations become no-ops
    (cache miss on get, success on set/invalidate).
    
    Usage:
        cache = ScoreCache(redis_url="redis://localhost:6379")
        await cache.connect()
        
        # Check cache before scoring
        cached = await cache.get("entity-123")
        if cached:
            return cached
        
        # Score and cache
        result = await engine.score_entity("entity-123")
        await cache.set("entity-123", result_dict, ttl=300)
    """
    
    PREFIX = "pdri:score:"
    
    def __init__(
        self,
        redis_url: str = "redis://localhost:6379/0",
        default_ttl: int = 300,
    ):
        """
        Initialize score cache.
        
        Args:
            redis_url: Redis connection URL
            default_ttl: Default time-to-live in seconds
        """
        self.redis_url = redis_url
        self.default_ttl = default_ttl
        self._redis: Optional[Any] = None
        self._available = False
    
    async def connect(self) -> bool:
        """
        Connect to Redis.
        
        Returns:
            True if connected successfully
        """
        if not HAS_REDIS:
            logger.warning("redis package not installed — score cache disabled")
            return False
        
        try:
            self._redis = aioredis.from_url(
                self.redis_url,
                decode_responses=True,
                socket_connect_timeout=5,
                socket_timeout=5,
            )
            await self._redis.ping()
            self._available = True
            logger.info("Score cache connected to Redis")
            return True
        except Exception as e:
            logger.warning(f"Redis unavailable — score cache disabled: {e}")
            self._available = False
            return False
    
    async def close(self):
        """Close Redis connection."""
        if self._redis:
            await self._redis.close()
            self._available = False
    
    @property
    def is_available(self) -> bool:
        """Whether cache is operational."""
        return self._available
    
    async def get(self, entity_id: str) -> Optional[Dict[str, Any]]:
        """
        Get cached score for an entity.
        
        Args:
            entity_id: Entity identifier
            
        Returns:
            Cached score dict if found, None otherwise
        """
        if not self._available:
            return None
        
        try:
            key = f"{self.PREFIX}{entity_id}"
            data = await self._redis.get(key)
            if data:
                logger.debug(f"Cache HIT: {entity_id}")
                return json.loads(data)
            logger.debug(f"Cache MISS: {entity_id}")
            return None
        except Exception as e:
            logger.warning(f"Cache get error for {entity_id}: {e}")
            return None
    
    async def set(
        self,
        entity_id: str,
        score_data: Dict[str, Any],
        ttl: Optional[int] = None,
    ) -> bool:
        """
        Cache a score result.
        
        Args:
            entity_id: Entity identifier
            score_data: Score data to cache
            ttl: Time-to-live in seconds (uses default if None)
            
        Returns:
            True if cached successfully
        """
        if not self._available:
            return False
        
        try:
            key = f"{self.PREFIX}{entity_id}"
            payload = json.dumps(score_data, default=str)
            await self._redis.setex(key, ttl or self.default_ttl, payload)
            logger.debug(f"Cache SET: {entity_id} (ttl={ttl or self.default_ttl}s)")
            return True
        except Exception as e:
            logger.warning(f"Cache set error for {entity_id}: {e}")
            return False
    
    async def invalidate(self, entity_id: str) -> bool:
        """
        Invalidate cached score for an entity.
        
        Args:
            entity_id: Entity to invalidate
            
        Returns:
            True if invalidated successfully
        """
        if not self._available:
            return False
        
        try:
            key = f"{self.PREFIX}{entity_id}"
            await self._redis.delete(key)
            logger.debug(f"Cache INVALIDATED: {entity_id}")
            return True
        except Exception as e:
            logger.warning(f"Cache invalidate error: {e}")
            return False
    
    async def invalidate_all(self) -> int:
        """
        Invalidate all cached scores.
        
        Returns:
            Number of keys invalidated
        """
        if not self._available:
            return 0
        
        try:
            keys = []
            async for key in self._redis.scan_iter(f"{self.PREFIX}*"):
                keys.append(key)
            if keys:
                await self._redis.delete(*keys)
            logger.info(f"Cache FLUSH: {len(keys)} keys invalidated")
            return len(keys)
        except Exception as e:
            logger.warning(f"Cache flush error: {e}")
            return 0
    
    async def stats(self) -> Dict[str, Any]:
        """
        Get cache statistics.
        
        Returns:
            Dict with hit/miss counts, key count, memory usage
        """
        if not self._available:
            return {"available": False}
        
        try:
            info = await self._redis.info("stats", "memory", "keyspace")
            key_count = 0
            async for _ in self._redis.scan_iter(f"{self.PREFIX}*"):
                key_count += 1
            
            return {
                "available": True,
                "cached_scores": key_count,
                "used_memory_human": info.get("used_memory_human", "unknown"),
                "total_commands": info.get("total_commands_processed", 0),
                "connected_clients": info.get("connected_clients", 0),
            }
        except Exception as e:
            return {"available": False, "error": str(e)}
