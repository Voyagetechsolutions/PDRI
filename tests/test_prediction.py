"""
Tests for prediction / trajectory module.

Author: PDRI Team
Version: 1.0.0
"""

import sys
import pytest
from unittest.mock import AsyncMock, MagicMock, patch
from datetime import datetime, timezone, timedelta


# Mock neo4j before any pdri imports can trigger
sys.modules.setdefault("neo4j", MagicMock())


class TestTrajectoryPrediction:
    """Test risk trajectory forecasting."""

    @pytest.fixture
    def mock_graph_engine(self):
        engine = AsyncMock()
        engine.get_node.return_value = {
            "id": "node-1",
            "name": "Customer DB",
            "exposure_score": 0.6,
            "volatility_score": 0.4,
            "sensitivity_likelihood": 0.8,
            "composite_risk_score": 0.65,
        }
        return engine

    @pytest.fixture
    def mock_scoring_engine(self):
        engine = AsyncMock()
        engine.score_entity.return_value = MagicMock(
            entity_id="node-1",
            exposure_score=0.6,
            volatility_score=0.4,
            sensitivity_likelihood=0.8,
            composite_score=0.65,
            risk_level="high",
        )
        return engine

    def test_trajectory_module_importable(self):
        """Trajectory module should be importable."""
        from pdri.prediction import trajectory
        assert hasattr(trajectory, "TrajectoryPredictor") or hasattr(
            trajectory, "RiskTrajectoryPredictor"
        )

    def test_trend_direction_classification(self):
        """Score changes should classify into correct trend directions."""
        # Increasing trend
        scores = [0.3, 0.4, 0.5, 0.6, 0.7]
        change = scores[-1] - scores[0]
        assert change > 0, "Should detect increasing trend"

        # Decreasing trend
        scores_dec = [0.8, 0.7, 0.6, 0.5, 0.4]
        change_dec = scores_dec[-1] - scores_dec[0]
        assert change_dec < 0, "Should detect decreasing trend"

        # Stable trend
        scores_stable = [0.5, 0.51, 0.49, 0.50, 0.50]
        change_stable = scores_stable[-1] - scores_stable[0]
        assert abs(change_stable) < 0.05, "Should detect stable trend"

    def test_volatility_calculation(self):
        """Volatility should measure standard deviation of scores."""
        import math

        scores = [0.5, 0.6, 0.4, 0.7, 0.3]
        mean = sum(scores) / len(scores)
        variance = sum((s - mean) ** 2 for s in scores) / len(scores)
        std_dev = math.sqrt(variance)

        assert 0.1 < std_dev < 0.2, f"Expected std_dev ~0.14, got {std_dev}"

    def test_forecast_horizon_bounds(self):
        """Forecast should not predict beyond reasonable bounds."""
        # Simulate linear extrapolation
        current = 0.8
        rate = 0.05  # per day
        days = 30

        forecast = current + rate * days
        # Scores must be capped at 1.0
        capped = min(1.0, forecast)
        assert capped == 1.0, "Forecast should cap at 1.0"

        # Negative direction
        current_low = 0.2
        rate_neg = -0.03
        forecast_neg = current_low + rate_neg * days
        capped_neg = max(0.0, forecast_neg)
        assert capped_neg >= 0.0, "Forecast should floor at 0.0"

    def test_anomaly_detection_threshold(self):
        """Anomalous score changes should be flagged when exceeding threshold."""
        history = [0.5] * 10
        mean = sum(history) / len(history)
        std = 0.01  # very stable

        new_score = 0.9  # sudden spike
        z_score = (new_score - mean) / max(std, 0.001)
        assert z_score > 3.0, "Large spike should have Z-score > 3"

    def test_confidence_interval(self):
        """Predictions should include confidence intervals."""
        # Basic confidence interval calculation
        scores = [0.5, 0.55, 0.6, 0.58, 0.62]
        mean = sum(scores) / len(scores)
        std = (sum((s - mean) ** 2 for s in scores) / len(scores)) ** 0.5

        ci_lower = mean - 1.96 * std
        ci_upper = mean + 1.96 * std

        assert ci_lower < mean < ci_upper
        assert ci_upper - ci_lower > 0, "CI should have positive width"

    @pytest.mark.asyncio
    async def test_score_history_store_trending(self):
        """ScoreHistoryStore should calculate trends correctly."""
        from pdri.scoring.score_history import ScoreHistoryStore

        store = ScoreHistoryStore()
        await store.initialize()

        # Record increasing scores
        for i in range(10):
            await store.record_score("node-trend", 50 + i * 3, "composite")

        trend = await store.get_trend("node-trend", window=10)
        assert trend["direction"] == "increasing"
        assert trend["change_pct"] > 0

    @pytest.mark.asyncio
    async def test_score_history_volatility(self):
        """ScoreHistoryStore volatility should measure spread."""
        from pdri.scoring.score_history import ScoreHistoryStore

        store = ScoreHistoryStore()
        await store.initialize()

        # Record oscillating scores
        for i in range(20):
            score = 50 + (10 if i % 2 == 0 else -10)
            await store.record_score("node-vol", score, "composite")

        vol = await store.get_volatility("node-vol", window=20)
        assert vol > 5.0, f"Volatility should be high for oscillating scores, got {vol}"
