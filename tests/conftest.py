"""
pytest configuration and fixtures.

Author: PDRI Team
Version: 1.0.0
"""

import pytest
import asyncio
from unittest.mock import AsyncMock, MagicMock


@pytest.fixture(scope="session")
def event_loop():
    """Create event loop for async tests."""
    loop = asyncio.get_event_loop_policy().new_event_loop()
    yield loop
    loop.close()


@pytest.fixture
def mock_graph_engine():
    """Create mock GraphEngine for testing."""
    from pdri.graph.engine import GraphEngine
    
    engine = AsyncMock(spec=GraphEngine)
    engine.get_node.return_value = {
        "id": "test-node",
        "name": "Test Node",
        "exposure_score": 0.5
    }
    engine.get_node_with_relationships.return_value = {
        "node": {
            "id": "test-node",
            "name": "Test Node",
            "node_type": "DataStore"
        },
        "relationships": []
    }
    engine.update_risk_scores.return_value = {}
    engine.health_check.return_value = {"status": "healthy"}
    
    return engine


@pytest.fixture
def sample_security_event():
    """Create sample security event for testing."""
    from shared.schemas.events import (
        SecurityEvent, 
        SecurityEventType,
        ExposureDirection,
        SensitivityTag
    )
    
    return SecurityEvent(
        event_type=SecurityEventType.AI_DATA_ACCESS,
        source_system_id="shadow-ai",
        target_entity_id="customer-db",
        identity_id="chatgpt-001",
        sensitivity_tags=[SensitivityTag.IDENTITY],
        exposure_direction=ExposureDirection.INTERNAL_TO_AI,
        privilege_level="read"
    )


@pytest.fixture
def sample_data_store_node():
    """Create sample data store node."""
    from pdri.graph.models import DataStoreNode
    
    return DataStoreNode(
        id="ds-test-001",
        name="Test Database",
        store_type="database",
        technology="PostgreSQL",
        data_classification="internal"
    )


@pytest.fixture
def sample_ai_tool_node():
    """Create sample AI tool node."""
    from pdri.graph.models import AIToolNode
    
    return AIToolNode(
        id="ai-test-001",
        name="Test AI",
        vendor="TestVendor",
        tool_name="TestTool",
        is_sanctioned=True
    )
