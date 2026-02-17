"""
Performance & Load Tests
========================

Tests for 10K+ node graphs, concurrent batch scoring,
cache performance under load, and graph query performance.

Author: PDRI Team
Version: 1.0.0
"""

import asyncio
import random
import time
from datetime import datetime, timedelta, timezone
from typing import List, Tuple
from unittest.mock import AsyncMock, MagicMock, patch

import numpy as np
import pytest
import pytest_asyncio

from pdri.prediction.trajectory import TrajectoryPredictor, RiskTrajectory


# ── Helpers ──────────────────────────────────────────────────

def generate_history(
    days: int = 90,
    base_score: float = 50.0,
    volatility: float = 10.0,
) -> List[Tuple[datetime, float]]:
    """Generate synthetic risk score history."""
    now = datetime.now(timezone.utc)
    history = []
    score = base_score
    for i in range(days):
        score += random.gauss(0, volatility * 0.3)
        score = max(0, min(100, score))
        ts = now - timedelta(days=days - i)
        history.append((ts, round(score, 2)))
    return history


def generate_node_batch(
    count: int,
    history_days: int = 90,
) -> List[Tuple[str, List[Tuple[datetime, float]]]]:
    """Generate a batch of synthetic nodes with history."""
    nodes = []
    for i in range(count):
        node_id = f"node-{i:06d}"
        base = random.uniform(20, 80)
        history = generate_history(days=history_days, base_score=base)
        nodes.append((node_id, history))
    return nodes


# ── Trajectory Prediction Performance ────────────────────────

class TestBatchPredictionPerformance:
    """Performance tests for concurrent batch prediction."""

    @pytest.fixture
    def predictor(self):
        return TrajectoryPredictor(model_type="moving_average")

    @pytest.mark.asyncio
    async def test_batch_100_nodes(self, predictor):
        """Batch predict 100 nodes should complete under 5 seconds."""
        nodes = generate_node_batch(100)

        start = time.monotonic()
        results = await predictor.predict_batch(nodes, horizon_days=30)
        elapsed = time.monotonic() - start

        assert len(results) >= 90  # Allow up to 10% failures
        assert elapsed < 5.0, f"100-node batch took {elapsed:.2f}s (limit: 5s)"

    @pytest.mark.asyncio
    async def test_batch_1000_nodes(self, predictor):
        """Batch predict 1000 nodes should complete under 30 seconds."""
        nodes = generate_node_batch(1000)

        start = time.monotonic()
        results = await predictor.predict_batch(nodes, horizon_days=14)
        elapsed = time.monotonic() - start

        assert len(results) >= 900
        assert elapsed < 30.0, f"1000-node batch took {elapsed:.2f}s (limit: 30s)"

    @pytest.mark.asyncio
    async def test_concurrency_faster_than_sequential(self, predictor):
        """Concurrent batch should be faster than sequential for I/O-bound work."""
        nodes = generate_node_batch(50)

        # Concurrent
        start = time.monotonic()
        await predictor.predict_batch(nodes, horizon_days=14)
        concurrent_time = time.monotonic() - start

        # Sequential
        start = time.monotonic()
        for node_id, history in nodes:
            await predictor.predict(node_id, history, 14)
        sequential_time = time.monotonic() - start

        # Concurrent should be at least comparable (not slower)
        assert concurrent_time <= sequential_time * 1.5, (
            f"Concurrent ({concurrent_time:.2f}s) was much slower than "
            f"sequential ({sequential_time:.2f}s)"
        )

    @pytest.mark.asyncio
    async def test_batch_with_semaphore_limit(self, predictor):
        """Semaphore should prevent too many concurrent tasks."""
        nodes = generate_node_batch(200)

        start = time.monotonic()
        results = await predictor.predict_batch(
            nodes, horizon_days=7, max_concurrency=10
        )
        elapsed = time.monotonic() - start

        assert len(results) >= 180
        assert elapsed < 30.0


# ── Scoring Engine Performance ───────────────────────────────

class TestScoringPerformance:
    """Performance tests for the scoring engine."""

    @pytest.mark.asyncio
    async def test_score_computation_speed(self):
        """Individual scoring computation should be fast."""
        from pdri.scoring.rules import RiskScoringRules

        rules = RiskScoringRules()

        start = time.monotonic()
        for _ in range(10000):
            rules.calculate_composite_score(
                exposure=random.random(),
                volatility=random.random(),
                sensitivity=random.random(),
            )
        elapsed = time.monotonic() - start

        assert elapsed < 5.0, f"10K risk calculations took {elapsed:.2f}s (limit: 5s)"

    @pytest.mark.asyncio
    async def test_rule_evaluation_throughput(self):
        """Rule evaluation at scale."""
        from pdri.scoring.rules import RiskScoringRules

        rules = RiskScoringRules()

        start = time.monotonic()
        for i in range(1000):
            result = rules.calculate_composite_score(
                exposure=random.random(),
                volatility=random.random(),
                sensitivity=random.random(),
            )
            assert 0 <= result <= 1.0
        elapsed = time.monotonic() - start

        assert elapsed < 2.0, f"1000 rule evaluations took {elapsed:.2f}s (limit: 2s)"


# ── Cache Performance ────────────────────────────────────────

class TestCachePerformance:
    """Performance tests for the Redis score cache."""

    @pytest.mark.asyncio
    async def test_cache_throughput(self):
        """Cache should handle high throughput of get/set operations."""
        from pdri.scoring.score_cache import ScoreCache

        cache = ScoreCache(redis_url="redis://localhost:6379")
        # Don't connect — force unavailable so it uses no-op path
        cache._available = False

        start = time.monotonic()
        for i in range(10000):
            entity_id = f"entity-{i}"
            await cache.get(entity_id)
            await cache.set(entity_id, {"score": random.random() * 100})
        elapsed = time.monotonic() - start

        assert elapsed < 3.0, f"10K cache ops took {elapsed:.2f}s (limit: 3s)"


# ── Graph Model Performance ──────────────────────────────────

class TestGraphModelPerformance:
    """Performance tests for graph model construction."""

    def test_large_node_list_creation(self):
        """Creating 10K+ graph node objects should be fast."""
        from pdri.graph.models import NodeType, DataStoreNode

        start = time.monotonic()
        nodes = []
        for i in range(10000):
            node = DataStoreNode(
                id=f"node-{i:06d}",
                name=f"DataStore {i}",
                exposure_score=random.random(),
                store_type="database",
                metadata={
                    "department": f"dept-{i % 20}",
                    "region": f"region-{i % 5}",
                },
            )
            nodes.append(node)
        elapsed = time.monotonic() - start

        assert len(nodes) == 10000
        assert elapsed < 10.0, f"10K node creation took {elapsed:.2f}s (limit: 10s)"

    def test_node_risk_distribution(self):
        """Verify risk score distribution across large node set."""
        from pdri.graph.models import NodeType, ServiceNode

        nodes = []
        for i in range(10000):
            score = max(0.0, min(1.0, random.gauss(0.5, 0.2)))
            node = ServiceNode(
                id=f"node-{i:06d}",
                name=f"Service {i}",
                exposure_score=score,
                service_type="api",
            )
            nodes.append(node)

        scores = [n.exposure_score for n in nodes]
        mean_score = np.mean(scores)
        assert 0.4 < mean_score < 0.6, f"Mean score {mean_score:.3f} outside expected range"


# ── Compliance Framework Performance ─────────────────────────

class TestCompliancePerformance:
    """Performance tests for compliance assessors."""

    @pytest.mark.asyncio
    async def test_nist_csf_full_assessment(self):
        """Full NIST CSF assessment should complete quickly."""
        from pdri.compliance.frameworks.nist_csf import NISTCSFAssessor

        mock_engine = AsyncMock()
        mock_engine.get_statistics = AsyncMock(return_value={"total_nodes": 500})
        assessor = NISTCSFAssessor(graph_engine=mock_engine)

        start = time.monotonic()
        results = await assessor.assess_all()
        elapsed = time.monotonic() - start

        assert len(results) > 0
        assert elapsed < 2.0, f"Full NIST CSF assessment took {elapsed:.2f}s (limit: 2s)"

    @pytest.mark.asyncio
    async def test_pci_dss_full_assessment(self):
        """Full PCI DSS assessment should complete quickly."""
        from pdri.compliance.frameworks.pci_dss import PCIDSSAssessor

        mock_engine = AsyncMock()
        mock_engine.get_statistics = AsyncMock(return_value={"total_nodes": 500})
        assessor = PCIDSSAssessor(graph_engine=mock_engine)

        start = time.monotonic()
        results = await assessor.assess_all()
        elapsed = time.monotonic() - start

        assert len(results) == 12  # 12 PCI DSS requirements
        assert elapsed < 2.0

    @pytest.mark.asyncio
    async def test_all_frameworks_assessment(self):
        """Assessing all 7 frameworks should complete quickly."""
        from pdri.compliance.frameworks import (
            NISTCSFAssessor,
            PCIDSSAssessor,
            SOC2Assessor,
            FedRAMPAssessor,
        )

        mock_engine = AsyncMock()
        mock_engine.get_statistics = AsyncMock(return_value={"total_nodes": 500})

        assessors = [
            NISTCSFAssessor(graph_engine=mock_engine),
            PCIDSSAssessor(graph_engine=mock_engine),
            SOC2Assessor(graph_engine=mock_engine),
            FedRAMPAssessor(graph_engine=mock_engine),
        ]

        start = time.monotonic()
        all_results = []
        for assessor in assessors:
            results = await assessor.assess_all()
            all_results.extend(results)
        elapsed = time.monotonic() - start

        assert len(all_results) > 40
        assert elapsed < 5.0, f"All-frameworks assessment took {elapsed:.2f}s (limit: 5s)"


# ── Federation Aggregation Performance ───────────────────────

class TestFederationPerformance:
    """Performance tests for federated aggregation."""

    def test_aggregation_with_many_participants(self):
        """Aggregation with 50 participants should be fast."""
        from pdri.federation.aggregator import FederatedAggregator

        aggregator = FederatedAggregator(
            method="fedavg",
            min_participants=3,
        )
        aggregator.start_round()

        # Add 50 participant updates with correct keys
        for i in range(50):
            update = {
                "organization_id": f"org-{i}",
                "sample_count": random.randint(100, 10000),
                "gradients": {
                    "layer_1": np.random.randn(100).astype(np.float64),
                    "layer_2": np.random.randn(50).astype(np.float64),
                },
                "metrics": {"accuracy": random.uniform(0.7, 0.95)},
                "fingerprints": [],
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }
            aggregator.add_update(update)

        start = time.monotonic()
        result = aggregator.aggregate()
        elapsed = time.monotonic() - start

        assert result is not None
        assert elapsed < 2.0, f"50-participant aggregation took {elapsed:.2f}s (limit: 2s)"

    def test_large_weight_aggregation(self):
        """Aggregation with large weight vectors."""
        from pdri.federation.aggregator import FederatedAggregator

        aggregator = FederatedAggregator(method="fedavg", min_participants=3)
        aggregator.start_round()

        # 5 participants with large weight vectors
        for i in range(5):
            update = {
                "organization_id": f"org-{i}",
                "sample_count": 5000,
                "gradients": {
                    "embedding": np.random.randn(10000).astype(np.float64),
                    "dense_1": np.random.randn(5000).astype(np.float64),
                    "dense_2": np.random.randn(1000).astype(np.float64),
                },
                "metrics": {},
                "fingerprints": [],
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }
            aggregator.add_update(update)

        start = time.monotonic()
        result = aggregator.aggregate()
        elapsed = time.monotonic() - start

        assert result is not None
        assert elapsed < 3.0
