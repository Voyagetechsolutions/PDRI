"""
Tests for simulation engine — all 7 scenario types + NEW_REGULATION.

Author: PDRI Team
Version: 1.0.0
"""

import pytest
from unittest.mock import AsyncMock, MagicMock, patch
from datetime import datetime, timezone


class TestSimulationEngine:
    """Test simulation engine scenarios."""

    @pytest.fixture
    def mock_graph_engine(self):
        engine = AsyncMock()
        engine.get_node.return_value = {
            "id": "node-1",
            "name": "Customer DB",
            "data_classification": "confidential",
            "exposure_score": 0.5,
        }
        engine.get_connected_nodes = AsyncMock(return_value=[
            {"id": "node-2"}, {"id": "node-3"},
        ])
        engine.find_exposure_paths = AsyncMock(return_value=[
            ["node-1", "node-2", "node-3"],
        ])
        engine.get_risk_scores = AsyncMock(return_value={
            "node-1": 50.0, "node-2": 30.0, "node-3": 60.0,
        })
        return engine

    @pytest.fixture
    def mock_scoring_engine(self):
        engine = AsyncMock()
        score_result = MagicMock()
        score_result.total_score = 50.0
        engine.score_node.return_value = score_result
        return engine

    @pytest.fixture
    def simulation_engine(self, mock_graph_engine, mock_scoring_engine):
        from pdri.simulation.engine import SimulationEngine
        return SimulationEngine(
            graph_engine=mock_graph_engine,
            scoring_engine=mock_scoring_engine,
        )

    def test_scenario_types_exist(self):
        """All 7 scenario types should be defined."""
        from pdri.simulation.engine import ScenarioType

        expected = [
            "VENDOR_COMPROMISE",
            "DATA_BREACH",
            "AI_TOOL_DEPLOYMENT",
            "ATTACK_PATH",
            "CONFIG_CHANGE",
            "ACCESS_REVOCATION",
            "NEW_REGULATION",
        ]
        for name in expected:
            assert hasattr(ScenarioType, name), f"Missing scenario: {name}"

    def test_impact_severity_levels(self):
        """All severity levels should be defined."""
        from pdri.simulation.engine import ImpactSeverity

        expected = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "NEGLIGIBLE"]
        for level in expected:
            assert hasattr(ImpactSeverity, level), f"Missing severity: {level}"

    def test_scenario_creation(self):
        """Simulation scenarios should be creatable."""
        from pdri.simulation.engine import SimulationScenario, ScenarioType

        scenario = SimulationScenario(
            scenario_id="test-001",
            scenario_type=ScenarioType.VENDOR_COMPROMISE,
            name="Test Vendor Compromise",
            description="Testing a vendor compromise scenario",
            parameters={"vendor_id": "vendor-1", "compromised_services": ["api"]},
            target_nodes=["node-1", "node-2"],
        )
        assert scenario.scenario_type == ScenarioType.VENDOR_COMPROMISE
        assert len(scenario.target_nodes) == 2

    def test_scenario_serialization(self):
        """Scenarios should serialize to dict."""
        from pdri.simulation.engine import SimulationScenario, ScenarioType

        scenario = SimulationScenario(
            scenario_id="test-002",
            scenario_type=ScenarioType.DATA_BREACH,
            name="Test Breach",
            description="Test",
            parameters={},
            target_nodes=["node-1"],
        )
        data = scenario.to_dict()
        assert "scenario_type" in data
        assert "target_nodes" in data

    @pytest.mark.asyncio
    async def test_vendor_compromise_simulation(self, simulation_engine):
        """Vendor compromise should increase risk on affected nodes."""
        from pdri.simulation.engine import SimulationScenario, ScenarioType

        scenario = SimulationScenario(
            scenario_id="sim-vc-001",
            scenario_type=ScenarioType.VENDOR_COMPROMISE,
            name="Vendor Compromise",
            description="Test vendor compromise",
            parameters={"vendor_id": "v1"},
            target_nodes=["node-1"],
        )
        result = await simulation_engine.simulate(scenario)
        assert result.success is True
        assert len(result.node_impacts) > 0
        assert result.node_impacts[0].risk_delta >= 0

    @pytest.mark.asyncio
    async def test_data_breach_simulation(self, simulation_engine):
        """Data breach should propagate risk through connected nodes."""
        from pdri.simulation.engine import SimulationScenario, ScenarioType

        scenario = SimulationScenario(
            scenario_id="sim-db-001",
            scenario_type=ScenarioType.DATA_BREACH,
            name="Data Breach",
            description="Test data breach",
            parameters={"breach_scope": "full"},
            target_nodes=["node-1"],
        )
        result = await simulation_engine.simulate(scenario)
        assert result.success is True

    @pytest.mark.asyncio
    async def test_ai_tool_deployment_simulation(self, simulation_engine):
        """AI tool deployment should assess data exposure."""
        from pdri.simulation.engine import SimulationScenario, ScenarioType

        scenario = SimulationScenario(
            scenario_id="sim-ai-001",
            scenario_type=ScenarioType.AI_TOOL_DEPLOYMENT,
            name="AI Deployment",
            description="New AI tool",
            parameters={"tool_name": "copilot", "data_access": ["code"]},
            target_nodes=["node-1"],
        )
        result = await simulation_engine.simulate(scenario)
        assert result.success is True

    @pytest.mark.asyncio
    async def test_new_regulation_simulation(self, simulation_engine):
        """NEW_REGULATION should increase risk based on compliance gaps."""
        from pdri.simulation.engine import SimulationScenario, ScenarioType

        scenario = SimulationScenario(
            scenario_id="sim-nr-001",
            scenario_type=ScenarioType.NEW_REGULATION,
            name="GDPR Extension",
            description="New GDPR requirements",
            parameters={
                "framework_type": "gdpr",
                "affected_data_types": ["confidential", "pii"],
                "compliance_deadline_days": 30,
                "penalty_severity": 0.8,
            },
            target_nodes=["node-1"],
        )
        result = await simulation_engine.simulate(scenario)
        assert result.success is True
        assert len(result.node_impacts) > 0
        # With tight deadline and high severity, risk should increase significantly
        impact = result.node_impacts[0]
        assert impact.risk_delta > 0, "Regulation should increase risk"

    @pytest.mark.asyncio
    async def test_new_regulation_urgency_scaling(self, simulation_engine):
        """Tighter deadlines should produce higher risk increases."""
        from pdri.simulation.engine import SimulationScenario, ScenarioType

        # Short deadline
        short = SimulationScenario(
            scenario_id="sim-nr-short",
            scenario_type=ScenarioType.NEW_REGULATION,
            name="Short deadline",
            description="Urgent regulation",
            parameters={
                "affected_data_types": ["confidential"],
                "compliance_deadline_days": 7,
                "penalty_severity": 0.5,
            },
            target_nodes=["node-1"],
        )
        # Long deadline
        long = SimulationScenario(
            scenario_id="sim-nr-long",
            scenario_type=ScenarioType.NEW_REGULATION,
            name="Long deadline",
            description="Relaxed regulation",
            parameters={
                "affected_data_types": ["confidential"],
                "compliance_deadline_days": 300,
                "penalty_severity": 0.5,
            },
            target_nodes=["node-1"],
        )
        result_short = await simulation_engine.simulate(short)
        result_long = await simulation_engine.simulate(long)

        delta_short = result_short.node_impacts[0].risk_delta
        delta_long = result_long.node_impacts[0].risk_delta
        assert delta_short > delta_long, "Tighter deadline should mean higher risk"

    @pytest.mark.asyncio
    async def test_simulation_recommendations(self, simulation_engine):
        """Simulations should generate recommendations."""
        from pdri.simulation.engine import SimulationScenario, ScenarioType

        scenario = SimulationScenario(
            scenario_id="sim-rec-001",
            scenario_type=ScenarioType.NEW_REGULATION,
            name="Test",
            description="Test",
            parameters={"affected_data_types": ["pii"]},
            target_nodes=["node-1"],
        )
        result = await simulation_engine.simulate(scenario)
        assert len(result.recommendations) > 0

    @pytest.mark.asyncio
    async def test_batch_simulation(self, simulation_engine):
        """Batch simulation should run multiple scenarios."""
        from pdri.simulation.engine import SimulationScenario, ScenarioType

        scenarios = [
            SimulationScenario(
                scenario_id=f"sim-batch-{i}",
                scenario_type=ScenarioType.VENDOR_COMPROMISE,
                name=f"Scenario {i}",
                description="Test",
                parameters={},
                target_nodes=["node-1"],
            )
            for i in range(3)
        ]
        results = await simulation_engine.run_batch_simulation(scenarios)
        assert len(results) == 3
        assert all(r.success for r in results)

    def test_severity_classification(self):
        """Severity should classify based on risk delta thresholds."""
        from pdri.simulation.engine import SimulationEngine, ImpactSeverity

        engine = SimulationEngine.__new__(SimulationEngine)

        assert engine._classify_severity(50) == ImpactSeverity.CRITICAL
        assert engine._classify_severity(30) == ImpactSeverity.HIGH
        assert engine._classify_severity(15) == ImpactSeverity.MEDIUM
        assert engine._classify_severity(5) == ImpactSeverity.LOW
        assert engine._classify_severity(-5) == ImpactSeverity.NEGLIGIBLE
