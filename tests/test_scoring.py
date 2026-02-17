"""
Scoring Engine Tests
====================

Unit tests for the PDRI scoring engine.

Author: PDRI Team
Version: 1.0.0
"""

import pytest
from unittest.mock import AsyncMock, MagicMock

from pdri.scoring.rules import RiskScoringRules, ScoringFactors, PrivilegeLevel
from pdri.scoring.engine import ScoringEngine, ScoringResult


class TestScoringRules:
    """Tests for risk scoring rules."""
    
    @pytest.fixture
    def rules(self):
        """Create scoring rules instance."""
        return RiskScoringRules()
    
    def test_privilege_level_weights(self):
        """Test privilege level weight assignments."""
        assert PrivilegeLevel.READ.weight == 0.2
        assert PrivilegeLevel.ADMIN.weight == 0.7
        assert PrivilegeLevel.SUPER_ADMIN.weight == 1.0
    
    def test_privilege_from_string(self):
        """Test privilege level parsing."""
        assert PrivilegeLevel.from_string("admin") == PrivilegeLevel.ADMIN
        assert PrivilegeLevel.from_string("ADMIN") == PrivilegeLevel.ADMIN
        assert PrivilegeLevel.from_string("unknown_level") == PrivilegeLevel.UNKNOWN
    
    def test_calculate_exposure_score_minimal(self, rules):
        """Test exposure score with minimal factors."""
        factors = ScoringFactors(
            external_connection_factor=0.0,
            ai_integration_factor=0.0,
            data_volume_factor=0.0,
            privilege_level_factor=0.0,
            public_exposure_factor=0.0
        )
        
        score = rules.calculate_exposure_score(factors)
        assert score == 0.0
    
    def test_calculate_exposure_score_high_ai(self, rules):
        """Test exposure score with high AI integration."""
        factors = ScoringFactors(
            external_connection_factor=0.3,
            ai_integration_factor=0.9,
            data_volume_factor=0.5,
            privilege_level_factor=0.4,
            public_exposure_factor=0.0
        )
        
        score = rules.calculate_exposure_score(factors)
        assert score > 0.4  # Should be elevated due to AI
    
    def test_calculate_volatility_score(self, rules):
        """Test volatility score calculation."""
        factors = ScoringFactors(
            connection_change_rate=0.5,
            access_pattern_change=0.3,
            recent_integration_factor=0.7
        )
        
        score = rules.calculate_volatility_score(factors)
        assert 0.0 <= score <= 1.0
    
    def test_calculate_sensitivity_with_tags(self, rules):
        """Test sensitivity with event tags."""
        factors = ScoringFactors(
            name_heuristic_factor=0.0,
            data_classification_factor=0.0,
            sensitivity_tag_factor=0.8  # High from tags
        )
        
        score = rules.calculate_sensitivity_likelihood(factors)
        assert score > 0.5  # Should be influenced by tags
    
    def test_name_heuristic_detection(self, rules):
        """Test sensitive name detection."""
        # Node with sensitive name
        node_data = {"name": "customer_credentials_db", "id": "ds-001"}
        
        factors = rules.calculate_factors(node_data)
        
        assert factors.name_heuristic_factor > 0.0
    
    def test_data_classification_factor(self, rules):
        """Test data classification scoring."""
        node_data = {
            "name": "generic_db",
            "id": "ds-001",
            "data_classification": "confidential"
        }
        
        factors = rules.calculate_factors(node_data)
        
        assert factors.data_classification_factor == 1.0
    
    def test_composite_score_calculation(self, rules):
        """Test composite score from components."""
        composite = rules.calculate_composite_score(
            exposure=0.8,
            volatility=0.6,
            sensitivity=0.7
        )
        
        # 0.8*0.5 + 0.6*0.3 + 0.7*0.2 = 0.4 + 0.18 + 0.14 = 0.72
        assert 0.7 <= composite <= 0.8
    
    def test_risk_level_classification(self):
        """Test risk level classification."""
        assert RiskScoringRules.classify_risk_level(0.9) == "critical"
        assert RiskScoringRules.classify_risk_level(0.7) == "high"
        assert RiskScoringRules.classify_risk_level(0.5) == "medium"
        assert RiskScoringRules.classify_risk_level(0.3) == "low"
        assert RiskScoringRules.classify_risk_level(0.1) == "minimal"


class TestScoringEngine:
    """Tests for the scoring engine."""
    
    @pytest.fixture
    def mock_graph(self):
        """Create mock graph engine."""
        graph = AsyncMock()
        return graph
    
    @pytest.fixture
    def engine(self, mock_graph):
        """Create scoring engine with mock graph."""
        return ScoringEngine(mock_graph)
    
    @pytest.mark.asyncio
    async def test_score_entity_not_found(self, engine, mock_graph):
        """Test scoring when entity not found."""
        mock_graph.get_node_with_relationships.return_value = None
        
        with pytest.raises(ValueError, match="Entity not found"):
            await engine.score_entity("nonexistent-id")
    
    @pytest.mark.asyncio
    async def test_score_entity_success(self, engine, mock_graph):
        """Test successful entity scoring."""
        mock_graph.get_node_with_relationships.return_value = {
            "node": {
                "id": "ds-001",
                "name": "Test DB",
                "node_type": "DataStore"
            },
            "relationships": []
        }
        mock_graph.update_risk_scores.return_value = {}
        
        result = await engine.score_entity("ds-001")
        
        assert isinstance(result, ScoringResult)
        assert result.entity_id == "ds-001"
        assert 0.0 <= result.exposure_score <= 1.0
        assert 0.0 <= result.composite_score <= 1.0
        assert result.risk_level in ["critical", "high", "medium", "low", "minimal"]
    
    def test_explain_score(self, engine):
        """Test score explanation generation."""
        result = ScoringResult(
            entity_id="ds-001",
            exposure_score=0.75,
            volatility_score=0.50,
            sensitivity_likelihood=0.80,
            composite_score=0.70,
            risk_level="high",
            factors=ScoringFactors(
                external_connection_factor=0.3,
                ai_integration_factor=0.8,
                data_volume_factor=0.5
            ),
            calculated_at=__import__("datetime").datetime.utcnow()
        )
        
        explanation = engine.explain_score(result)
        
        assert explanation["entity_id"] == "ds-001"
        assert explanation["risk_level"] == "high"
        assert "summary" in explanation
        assert "recommendations" in explanation
        assert len(explanation["recommendations"]) > 0


class TestScoringFactors:
    """Tests for ScoringFactors dataclass."""
    
    def test_default_values(self):
        """Test default factor values."""
        factors = ScoringFactors()
        
        assert factors.external_connection_factor == 0.0
        assert factors.ai_integration_factor == 0.0
        assert factors.data_volume_factor == 0.0
        assert factors.sensitivity_tag_factor == 0.0
