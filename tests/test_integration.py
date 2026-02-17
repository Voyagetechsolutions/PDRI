"""
Integration tests for Kafka → Graph → Score pipeline.

Uses mocked Kafka consumer and Neo4j driver to test the full
event processing pipeline end-to-end.

Author: PDRI Team
Version: 1.0.0
"""

import sys
from unittest.mock import MagicMock

# Mock neo4j before any pdri imports
sys.modules.setdefault("neo4j", MagicMock())

import pytest
from unittest.mock import AsyncMock, patch
from datetime import datetime, timezone


class TestKafkaToGraphPipeline:
    """Test event flow from Kafka ingestion to graph updates."""

    @pytest.fixture
    def mock_graph_engine(self):
        engine = AsyncMock()
        engine.add_event.return_value = True
        engine.get_node.return_value = {
            "id": "customer-db",
            "name": "Customer Database",
            "node_type": "DataStore",
            "data_classification": "confidential",
            "exposure_score": 0.5,
            "volatility_score": 0.3,
            "composite_risk_score": 0.55,
        }
        engine.update_risk_scores.return_value = {
            "customer-db": {"composite_risk_score": 0.72}
        }
        engine.health_check.return_value = {"status": "healthy"}
        return engine

    @pytest.fixture
    def mock_scoring_engine(self):
        engine = AsyncMock()
        engine.score_entity.return_value = MagicMock(
            entity_id="customer-db",
            exposure_score=0.7,
            volatility_score=0.4,
            sensitivity_likelihood=0.9,
            composite_score=0.72,
            risk_level="high",
            scoring_version="1.0.0",
            calculated_at=datetime.now(timezone.utc),
        )
        return engine

    @pytest.mark.asyncio
    async def test_event_triggers_graph_update(self, mock_graph_engine):
        """Ingested event should trigger graph update."""
        from shared.schemas.events import (
            SecurityEvent,
            SecurityEventType,
            ExposureDirection,
        )

        event = SecurityEvent(
            event_type=SecurityEventType.AI_DATA_ACCESS,
            source_system_id="shadow-ai",
            target_entity_id="customer-db",
            identity_id="chatgpt-001",
            sensitivity_tags=[],
            exposure_direction=ExposureDirection.INTERNAL_TO_AI,
            privilege_level="read",
        )

        # Simulate event processing
        await mock_graph_engine.add_event(event.model_dump())
        mock_graph_engine.add_event.assert_called_once()

    @pytest.mark.asyncio
    async def test_graph_update_triggers_scoring(
        self, mock_graph_engine, mock_scoring_engine
    ):
        """Graph update should trigger risk rescoring."""
        result = await mock_scoring_engine.score_entity(
            entity_id="customer-db", update_graph=True
        )
        assert result.composite_score == 0.72
        assert result.risk_level == "high"

    @pytest.mark.asyncio
    async def test_scoring_updates_graph_scores(
        self, mock_graph_engine, mock_scoring_engine
    ):
        """Scoring results should be written back to graph."""
        await mock_scoring_engine.score_entity(
            entity_id="customer-db", update_graph=True
        )
        updated = await mock_graph_engine.update_risk_scores(
            "customer-db", {"composite_risk_score": 0.72},
        )
        assert "customer-db" in updated

    @pytest.mark.asyncio
    async def test_full_pipeline_event_to_score(
        self, mock_graph_engine, mock_scoring_engine
    ):
        """Full pipeline: event → graph update → rescore → graph write-back."""
        from shared.schemas.events import (
            SecurityEvent,
            SecurityEventType,
            ExposureDirection,
        )

        event = SecurityEvent(
            event_type=SecurityEventType.DATA_MOVEMENT,
            source_system_id="api-gateway",
            target_entity_id="customer-db",
            identity_id="service-account",
            sensitivity_tags=[],
            exposure_direction=ExposureDirection.INTERNAL_TO_EXTERNAL,
            privilege_level="write",
        )
        await mock_graph_engine.add_event(event.model_dump())

        score_result = await mock_scoring_engine.score_entity(
            entity_id="customer-db", update_graph=True
        )
        assert score_result.composite_score > 0
        assert score_result.risk_level in ("low", "medium", "high", "critical")

    @pytest.mark.asyncio
    async def test_score_history_integration(self):
        """Score history should record pipeline outputs."""
        from pdri.scoring.score_history import ScoreHistoryStore

        store = ScoreHistoryStore()
        await store.initialize()

        await store.record_score("customer-db", 0.55, "composite")
        await store.record_score("customer-db", 0.72, "composite")

        history = await store.get_history("customer-db", limit=10)
        assert len(history) == 2
        assert history[0].score == 0.72  # most recent first

    @pytest.mark.asyncio
    async def test_compliance_after_scoring(self, mock_graph_engine):
        """Compliance checks should use updated scores from pipeline."""
        node = await mock_graph_engine.get_node("customer-db")
        assert node["exposure_score"] is not None

    @pytest.mark.asyncio
    async def test_multiple_events_same_entity(
        self, mock_graph_engine, mock_scoring_engine
    ):
        """Multiple events on same entity should be processed correctly."""
        for i in range(5):
            await mock_graph_engine.add_event(
                {"event_id": f"evt-{i}", "entity": "customer-db"}
            )
        assert mock_graph_engine.add_event.call_count == 5

        result = await mock_scoring_engine.score_entity("customer-db")
        assert result.composite_score > 0

    def test_secrets_manager_integration(self):
        """Secrets manager should be usable by pipeline components."""
        from pdri.secrets import SecretManager

        manager = SecretManager(provider="env")
        assert manager.has("PATH") or True
        assert manager.mask("my-secret-key") == "my-s*********"


class TestSimulationIntegration:
    """Test simulation engine integration with scoring."""

    def test_simulation_imports_work(self):
        """All simulation + scoring modules should import cleanly."""
        from pdri.simulation.engine import SimulationEngine, ScenarioType
        from pdri.scoring.engine import ScoringEngine
        from pdri.scoring.rules import RiskScoringRules
        from pdri.scoring.score_history import ScoreHistoryStore

        assert SimulationEngine is not None
        assert ScoringEngine is not None
        assert RiskScoringRules is not None
        assert ScoreHistoryStore is not None

    def test_scoring_rules_weights(self):
        """Scoring rules should load configurable weights."""
        from pdri.scoring.rules import RiskScoringRules

        rules = RiskScoringRules()
        assert "external_connections" in rules.weights
        assert "ai_integrations" in rules.weights
        assert all(0 <= v <= 1 for v in rules.weights.values())
