"""
Score History Store
===================

PostgreSQL-backed score history tracking with in-memory fallback.

Tracks entity risk scores over time for:
    - Trend analysis
    - Volatility calculation
    - Audit trail

Author: PDRI Team
Version: 1.0.0
"""

import logging
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)


@dataclass
class ScoreRecord:
    """A single score record."""
    entity_id: str
    score: float
    score_type: str  # "composite", "exposure", "volatility", "sensitivity"
    recorded_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "entity_id": self.entity_id,
            "score": self.score,
            "score_type": self.score_type,
            "recorded_at": self.recorded_at.isoformat(),
            "metadata": self.metadata,
        }


class ScoreHistoryStore:
    """
    Persistent score history with PostgreSQL backend.

    Falls back to in-memory storage when PostgreSQL is unavailable.

    Usage:
        store = ScoreHistoryStore(dsn="postgresql://...")
        await store.initialize()
        await store.record_score("node-1", 72.5, "composite")
        history = await store.get_history("node-1", limit=30)
    """

    CREATE_TABLE_SQL = """
    CREATE TABLE IF NOT EXISTS score_history (
        id SERIAL PRIMARY KEY,
        entity_id VARCHAR(255) NOT NULL,
        score DOUBLE PRECISION NOT NULL,
        score_type VARCHAR(50) NOT NULL DEFAULT 'composite',
        recorded_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        metadata JSONB DEFAULT '{}',
        CONSTRAINT score_history_entity_idx UNIQUE (entity_id, score_type, recorded_at)
    );
    CREATE INDEX IF NOT EXISTS idx_score_history_entity
        ON score_history (entity_id, score_type, recorded_at DESC);
    """

    def __init__(self, dsn: Optional[str] = None, max_memory_records: int = 1000):
        self._dsn = dsn
        self._pool = None
        self._use_pg = False
        self._max_memory = max_memory_records
        # In-memory fallback: {entity_id -> {score_type -> [ScoreRecord]}}
        self._memory: Dict[str, Dict[str, List[ScoreRecord]]] = defaultdict(
            lambda: defaultdict(list)
        )

    async def initialize(self) -> None:
        """Connect to PostgreSQL and create tables if needed."""
        if not self._dsn:
            logger.info("No PostgreSQL DSN — using in-memory score history")
            return

        try:
            import asyncpg
            self._pool = await asyncpg.create_pool(self._dsn, min_size=1, max_size=5)
            async with self._pool.acquire() as conn:
                await conn.execute(self.CREATE_TABLE_SQL)
            self._use_pg = True
            logger.info("Score history store connected to PostgreSQL")
        except Exception as e:
            logger.warning(f"PostgreSQL unavailable, using in-memory fallback: {e}")
            self._use_pg = False

    async def close(self) -> None:
        if self._pool:
            await self._pool.close()

    # =========================================================================
    # Write
    # =========================================================================

    async def record_score(
        self,
        entity_id: str,
        score: float,
        score_type: str = "composite",
        metadata: Optional[Dict[str, Any]] = None,
    ) -> ScoreRecord:
        """Record a new score for an entity."""
        record = ScoreRecord(
            entity_id=entity_id,
            score=score,
            score_type=score_type,
            metadata=metadata or {},
        )

        if self._use_pg:
            await self._pg_insert(record)
        else:
            self._memory_insert(record)

        return record

    async def _pg_insert(self, record: ScoreRecord) -> None:
        import json
        async with self._pool.acquire() as conn:
            await conn.execute(
                """
                INSERT INTO score_history (entity_id, score, score_type, recorded_at, metadata)
                VALUES ($1, $2, $3, $4, $5)
                ON CONFLICT (entity_id, score_type, recorded_at) DO UPDATE
                SET score = EXCLUDED.score, metadata = EXCLUDED.metadata
                """,
                record.entity_id,
                record.score,
                record.score_type,
                record.recorded_at,
                json.dumps(record.metadata),
            )

    def _memory_insert(self, record: ScoreRecord) -> None:
        bucket = self._memory[record.entity_id][record.score_type]
        bucket.append(record)
        if len(bucket) > self._max_memory:
            self._memory[record.entity_id][record.score_type] = bucket[-self._max_memory:]

    # =========================================================================
    # Read
    # =========================================================================

    async def get_history(
        self,
        entity_id: str,
        score_type: str = "composite",
        limit: int = 30,
    ) -> List[ScoreRecord]:
        """Get score history for an entity, most recent first."""
        if self._use_pg:
            return await self._pg_get_history(entity_id, score_type, limit)
        return self._memory_get_history(entity_id, score_type, limit)

    async def _pg_get_history(
        self, entity_id: str, score_type: str, limit: int
    ) -> List[ScoreRecord]:
        import json
        async with self._pool.acquire() as conn:
            rows = await conn.fetch(
                """
                SELECT entity_id, score, score_type, recorded_at, metadata
                FROM score_history
                WHERE entity_id = $1 AND score_type = $2
                ORDER BY recorded_at DESC
                LIMIT $3
                """,
                entity_id, score_type, limit,
            )
        return [
            ScoreRecord(
                entity_id=r["entity_id"],
                score=r["score"],
                score_type=r["score_type"],
                recorded_at=r["recorded_at"],
                metadata=json.loads(r["metadata"]) if r["metadata"] else {},
            )
            for r in rows
        ]

    def _memory_get_history(
        self, entity_id: str, score_type: str, limit: int
    ) -> List[ScoreRecord]:
        bucket = self._memory.get(entity_id, {}).get(score_type, [])
        return list(reversed(bucket[-limit:]))

    # =========================================================================
    # Analytics
    # =========================================================================

    async def get_trend(
        self,
        entity_id: str,
        score_type: str = "composite",
        window: int = 7,
    ) -> Dict[str, Any]:
        """
        Calculate score trend over a window of records.

        Returns:
            dict with keys: direction, change_pct, avg, min, max
        """
        history = await self.get_history(entity_id, score_type, limit=window)
        if len(history) < 2:
            return {"direction": "stable", "change_pct": 0.0, "avg": 0.0, "min": 0.0, "max": 0.0}

        scores = [r.score for r in reversed(history)]  # chronological order
        avg = sum(scores) / len(scores)
        change = scores[-1] - scores[0]
        pct = (change / scores[0] * 100) if scores[0] != 0 else 0

        if change > 2:
            direction = "increasing"
        elif change < -2:
            direction = "decreasing"
        else:
            direction = "stable"

        return {
            "direction": direction,
            "change_pct": round(pct, 2),
            "avg": round(avg, 2),
            "min": round(min(scores), 2),
            "max": round(max(scores), 2),
        }

    async def get_volatility(
        self,
        entity_id: str,
        score_type: str = "composite",
        window: int = 30,
    ) -> float:
        """Calculate score volatility (std dev) over a window."""
        history = await self.get_history(entity_id, score_type, limit=window)
        if len(history) < 2:
            return 0.0
        scores = [r.score for r in history]
        mean = sum(scores) / len(scores)
        variance = sum((s - mean) ** 2 for s in scores) / len(scores)
        return round(variance ** 0.5, 4)
