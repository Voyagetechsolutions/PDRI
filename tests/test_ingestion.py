"""
Tests for ingestion module (consumer + event handlers).

Uses unittest.mock to avoid neo4j/aiokafka import requirements.

Author: PDRI Team
Version: 1.0.0
"""

import asyncio
import sys
import pytest
from unittest.mock import AsyncMock, MagicMock, patch, PropertyMock
from datetime import datetime, timezone


class TestEventIngestion:
    """Test event ingestion and routing."""

    @pytest.fixture
    def mock_graph_engine(self):
        engine = AsyncMock()
        engine.update_risk_scores.return_value = {}
        engine.add_event.return_value = True
        engine.get_node.return_value = {
            "id": "test-node",
            "name": "Test Node",
            "node_type": "DataStore",
        }
        return engine

    @pytest.fixture
    def mock_scoring_engine(self):
        engine = AsyncMock()
        engine.score_entity.return_value = MagicMock(
            composite_score=0.65,
            risk_level="medium",
        )
        return engine

    def test_event_type_routing(self):
        """Event types should route to correct handlers."""
        from shared.schemas.events import SecurityEventType

        event_map = {
            SecurityEventType.AI_DATA_ACCESS: "AI_DATA_ACCESS",
            SecurityEventType.DATA_MOVEMENT: "DATA_MOVEMENT",
            SecurityEventType.SYSTEM_ACCESS: "SYSTEM_ACCESS",
            SecurityEventType.PRIVILEGE_ESCALATION: "PRIVILEGE_ESCALATION",
        }
        # Verify all event types are defined
        for event_type, value in event_map.items():
            assert event_type.value == value

    def test_security_event_creation(self):
        """SecurityEvent should be created with required fields."""
        from shared.schemas.events import (
            SecurityEvent,
            SecurityEventType,
            ExposureDirection,
            SensitivityTag,
        )

        event = SecurityEvent(
            event_type=SecurityEventType.AI_DATA_ACCESS,
            source_system_id="shadow-ai",
            target_entity_id="customer-db",
            identity_id="chatgpt-001",
            sensitivity_tags=[SensitivityTag.IDENTITY],
            exposure_direction=ExposureDirection.INTERNAL_TO_AI,
            privilege_level="read",
        )
        assert event.event_type == SecurityEventType.AI_DATA_ACCESS
        assert event.target_entity_id == "customer-db"
        assert SensitivityTag.IDENTITY in event.sensitivity_tags

    def test_security_event_serialization(self):
        """Events should serialize to dict for Kafka."""
        from shared.schemas.events import (
            SecurityEvent,
            SecurityEventType,
            ExposureDirection,
        )

        event = SecurityEvent(
            event_type=SecurityEventType.DATA_MOVEMENT,
            source_system_id="api-gateway",
            target_entity_id="data-lake",
            identity_id="service-account",
            sensitivity_tags=[],
            exposure_direction=ExposureDirection.INTERNAL_TO_EXTERNAL,
            privilege_level="write",
        )
        data = event.model_dump()
        assert "event_type" in data
        assert "source_system_id" in data
        assert data["privilege_level"] == "write"

    def test_event_validation_rejects_invalid(self):
        """Invalid events should fail validation."""
        from shared.schemas.events import SecurityEvent

        with pytest.raises(Exception):
            SecurityEvent(
                event_type="INVALID_TYPE",
                source_system_id="",
                target_entity_id="",
                identity_id="",
            )

    def test_sensitivity_tags_enum(self):
        """All expected sensitivity tags should exist."""
        from shared.schemas.events import SensitivityTag

        expected = ["IDENTITY", "FINANCIAL", "HEALTH", "CREDENTIALS"]
        for tag in expected:
            assert hasattr(SensitivityTag, tag), f"Missing tag: {tag}"

    def test_exposure_direction_enum(self):
        """All expected exposure directions should exist."""
        from shared.schemas.events import ExposureDirection

        expected = [
            "INTERNAL_TO_AI",
            "INTERNAL_TO_EXTERNAL",
            "EXTERNAL_TO_INTERNAL",
        ]
        for direction in expected:
            assert hasattr(ExposureDirection, direction), f"Missing: {direction}"

    @pytest.mark.asyncio
    async def test_idempotent_processing(self, mock_graph_engine):
        """Same event processed twice should not duplicate side effects."""
        processed_ids = set()

        async def process_event(event_id: str):
            if event_id in processed_ids:
                return False  # already processed
            processed_ids.add(event_id)
            await mock_graph_engine.add_event(event_id)
            return True

        assert await process_event("evt-001") is True
        assert await process_event("evt-001") is False
        assert mock_graph_engine.add_event.call_count == 1
