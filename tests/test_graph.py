"""
Graph Engine Tests
==================

Unit tests for the PDRI graph engine.

Author: PDRI Team
Version: 1.0.0
"""

import pytest
from datetime import datetime
from unittest.mock import AsyncMock, MagicMock, patch

from pdri.graph.models import (
    NodeType,
    EdgeType,
    DataStoreNode,
    ServiceNode,
    AIToolNode,
    GraphEdge,
)
from pdri.graph.engine import GraphEngine, GraphEngineError


class TestNodeModels:
    """Tests for graph node models."""
    
    def test_data_store_node_creation(self):
        """Test DataStoreNode creation with defaults."""
        node = DataStoreNode(
            id="ds-001",
            name="Customer Database",
            store_type="database",
            technology="PostgreSQL"
        )
        
        assert node.id == "ds-001"
        assert node.name == "Customer Database"
        assert node.node_type == NodeType.DATA_STORE
        assert node.store_type == "database"
        assert node.technology == "PostgreSQL"
        assert node.exposure_score == 0.0
        assert node.is_encrypted == False
    
    def test_ai_tool_node_creation(self):
        """Test AIToolNode creation."""
        node = AIToolNode(
            id="ai-001",
            name="ChatGPT",
            vendor="OpenAI",
            tool_name="gpt-4",
            is_sanctioned=True
        )
        
        assert node.id == "ai-001"
        assert node.node_type == NodeType.AI_TOOL
        assert node.vendor == "OpenAI"
        assert node.is_sanctioned == True
        assert node.sends_data_external == True
    
    def test_node_to_neo4j_properties(self):
        """Test conversion to Neo4j properties."""
        node = ServiceNode(
            id="svc-001",
            name="API Gateway",
            service_type="application"
        )
        
        props = node.to_neo4j_properties()
        
        assert props["id"] == "svc-001"
        assert props["name"] == "API Gateway"
        assert props["node_type"] == "Service"
        assert "created_at" in props


class TestEdgeModels:
    """Tests for graph edge models."""
    
    def test_graph_edge_creation(self):
        """Test GraphEdge creation."""
        edge = GraphEdge(
            id="edge-001",
            edge_type=EdgeType.ACCESSES,
            source_id="identity-001",
            target_id="ds-001"
        )
        
        assert edge.id == "edge-001"
        assert edge.edge_type == EdgeType.ACCESSES
        assert edge.source_id == "identity-001"
        assert edge.target_id == "ds-001"
        assert edge.weight == 1.0
    
    def test_edge_to_neo4j_properties(self):
        """Test edge conversion to Neo4j properties."""
        edge = GraphEdge(
            id="edge-001",
            edge_type=EdgeType.MOVES_DATA_TO,
            source_id="svc-001",
            target_id="ds-001",
            data_volume_bytes=1000000
        )
        
        props = edge.to_neo4j_properties()
        
        assert props["edge_type"] == "MOVES_DATA_TO"
        assert props["data_volume_bytes"] == 1000000


class TestGraphEngine:
    """Tests for GraphEngine operations."""
    
    @pytest.fixture
    def mock_driver(self):
        """Create mock Neo4j driver."""
        driver = AsyncMock()
        session = AsyncMock()
        driver.session.return_value.__aenter__.return_value = session
        return driver, session
    
    @pytest.mark.asyncio
    async def test_engine_initialization(self):
        """Test engine initialization with config."""
        engine = GraphEngine(
            uri="bolt://localhost:7687",
            user="neo4j",
            password="test"
        )
        
        assert engine.uri == "bolt://localhost:7687"
        assert engine.user == "neo4j"
    
    @pytest.mark.asyncio
    async def test_create_node(self, mock_driver):
        """Test node creation."""
        driver, session = mock_driver
        
        # Mock the result
        mock_record = MagicMock()
        mock_record.__getitem__ = MagicMock(return_value={"id": "ds-001"})
        
        result = AsyncMock()
        result.single.return_value = mock_record
        session.run.return_value = result
        
        engine = GraphEngine()
        engine._driver = driver
        
        node = DataStoreNode(
            id="ds-001",
            name="Test DB",
            store_type="database"
        )
        
        created = await engine.create_node(node)
        
        assert created.id == "ds-001"
        session.run.assert_called_once()


class TestQueryTemplates:
    """Tests for Cypher query templates."""
    
    def test_node_queries_format(self):
        """Test that node queries can be formatted."""
        from pdri.graph.queries import NodeQueries
        
        query = NodeQueries.MERGE_NODE.format(label="DataStore")
        assert "DataStore" in query
        assert "$properties" in query
    
    def test_path_queries_format(self):
        """Test that path queries can be formatted."""
        from pdri.graph.queries import PathQueries
        
        query = PathQueries.FIND_EXPOSURE_PATHS.format(max_depth=5)
        assert "*1..5" in query
