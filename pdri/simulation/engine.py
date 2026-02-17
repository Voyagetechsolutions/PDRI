"""
Simulation Engine
=================

Risk scenario simulation and impact modeling.

Scenarios:
    - Vendor compromise
    - AI tool deployment
    - Attack path simulation
    - Configuration changes
    - Incident response

Author: PDRI Team
Version: 1.0.0
"""

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional
import numpy as np


class ScenarioType(Enum):
    """Types of simulation scenarios."""
    VENDOR_COMPROMISE = "vendor_compromise"
    AI_TOOL_DEPLOYMENT = "ai_tool_deployment"
    DATA_BREACH = "data_breach"
    ATTACK_PATH = "attack_path"
    CONFIG_CHANGE = "config_change"
    ACCESS_REVOCATION = "access_revocation"
    NEW_REGULATION = "new_regulation"


class ImpactSeverity(Enum):
    """Severity of simulated impact."""
    NEGLIGIBLE = "negligible"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class SimulationScenario:
    """A simulation scenario to model."""
    scenario_id: str
    scenario_type: ScenarioType
    name: str
    description: str
    parameters: Dict[str, Any]
    target_nodes: List[str]
    created_at: datetime = field(default_factory=datetime.utcnow)
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "scenario_id": self.scenario_id,
            "scenario_type": self.scenario_type.value,
            "name": self.name,
            "description": self.description,
            "parameters": self.parameters,
            "target_nodes": self.target_nodes,
            "created_at": self.created_at.isoformat(),
        }


@dataclass
class NodeImpact:
    """Impact on a single node."""
    node_id: str
    original_risk: float
    simulated_risk: float
    risk_delta: float
    severity: ImpactSeverity
    impact_path: List[str]  # How impact propagated
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "node_id": self.node_id,
            "original_risk": self.original_risk,
            "simulated_risk": self.simulated_risk,
            "risk_delta": self.risk_delta,
            "severity": self.severity.value,
            "impact_path": self.impact_path,
        }


@dataclass
class SimulationResult:
    """Result of a simulation run."""
    result_id: str
    scenario: SimulationScenario
    started_at: datetime
    completed_at: datetime
    node_impacts: List[NodeImpact]
    aggregate_impact: Dict[str, float]
    recommendations: List[str]
    success: bool
    error: Optional[str] = None
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "result_id": self.result_id,
            "scenario": self.scenario.to_dict(),
            "started_at": self.started_at.isoformat(),
            "completed_at": self.completed_at.isoformat(),
            "node_impacts": [n.to_dict() for n in self.node_impacts],
            "aggregate_impact": self.aggregate_impact,
            "recommendations": self.recommendations,
            "success": self.success,
            "error": self.error,
        }
    
    @property
    def total_nodes_affected(self) -> int:
        return len(self.node_impacts)
    
    @property
    def critical_impacts(self) -> List[NodeImpact]:
        return [n for n in self.node_impacts if n.severity == ImpactSeverity.CRITICAL]


class SimulationEngine:
    """
    Simulate risk scenarios to understand impact.
    
    Use cases:
    - What if vendor X is compromised?
    - What if we deploy AI tool Y?
    - What's the blast radius of an attack?
    - How does removing access affect risk?
    
    Example:
        engine = SimulationEngine(graph_engine, scoring_engine)
        
        scenario = SimulationScenario(
            scenario_type=ScenarioType.VENDOR_COMPROMISE,
            name="Vendor X Compromise",
            parameters={"vendor_id": "vendor-123"},
            target_nodes=["vendor-123"]
        )
        
        result = await engine.simulate(scenario)
        print(f"Affected nodes: {result.total_nodes_affected}")
    """
    
    def __init__(
        self,
        graph_engine: Any,
        scoring_engine: Any,
        max_propagation_depth: int = 5
    ):
        """
        Initialize simulation engine.
        
        Args:
            graph_engine: Graph database engine
            scoring_engine: Risk scoring engine
            max_propagation_depth: Max depth for impact propagation
        """
        self.graph_engine = graph_engine
        self.scoring_engine = scoring_engine
        self.max_propagation_depth = max_propagation_depth
        self._result_counter = 0
    
    async def simulate(self, scenario: SimulationScenario) -> SimulationResult:
        """
        Run a simulation scenario.
        
        Args:
            scenario: Scenario to simulate
        
        Returns:
            SimulationResult with impacts
        """
        self._result_counter += 1
        result_id = f"sim-{self._result_counter:06d}"
        started_at = datetime.utcnow()
        
        try:
            # Get current state
            current_risks = await self._get_current_risks(scenario.target_nodes)
            
            # Simulate based on scenario type
            if scenario.scenario_type == ScenarioType.VENDOR_COMPROMISE:
                impacts = await self._simulate_vendor_compromise(scenario, current_risks)
            elif scenario.scenario_type == ScenarioType.AI_TOOL_DEPLOYMENT:
                impacts = await self._simulate_ai_deployment(scenario, current_risks)
            elif scenario.scenario_type == ScenarioType.DATA_BREACH:
                impacts = await self._simulate_data_breach(scenario, current_risks)
            elif scenario.scenario_type == ScenarioType.ATTACK_PATH:
                impacts = await self._simulate_attack_path(scenario, current_risks)
            elif scenario.scenario_type == ScenarioType.CONFIG_CHANGE:
                impacts = await self._simulate_config_change(scenario, current_risks)
            elif scenario.scenario_type == ScenarioType.ACCESS_REVOCATION:
                impacts = await self._simulate_access_revocation(scenario, current_risks)
            else:
                impacts = await self._simulate_generic(scenario, current_risks)
            
            # Calculate aggregate metrics
            aggregate = self._calculate_aggregate_impact(impacts)
            
            # Generate recommendations
            recommendations = self._generate_recommendations(scenario, impacts)
            
            return SimulationResult(
                result_id=result_id,
                scenario=scenario,
                started_at=started_at,
                completed_at=datetime.utcnow(),
                node_impacts=impacts,
                aggregate_impact=aggregate,
                recommendations=recommendations,
                success=True,
            )
            
        except Exception as e:
            return SimulationResult(
                result_id=result_id,
                scenario=scenario,
                started_at=started_at,
                completed_at=datetime.utcnow(),
                node_impacts=[],
                aggregate_impact={},
                recommendations=[],
                success=False,
                error=str(e),
            )
    
    async def _get_current_risks(
        self,
        node_ids: List[str]
    ) -> Dict[str, float]:
        """Get current risk scores for nodes."""
        risks = {}
        for node_id in node_ids:
            try:
                if hasattr(self.scoring_engine, 'score_node'):
                    score = await self.scoring_engine.score_node(node_id)
                    risks[node_id] = score.total_score if hasattr(score, 'total_score') else 50.0
                else:
                    risks[node_id] = 50.0  # Default
            except Exception:
                risks[node_id] = 50.0
        return risks
    
    async def _simulate_vendor_compromise(
        self,
        scenario: SimulationScenario,
        current_risks: Dict[str, float]
    ) -> List[NodeImpact]:
        """Simulate vendor compromise impact."""
        impacts = []
        
        vendor_id = scenario.parameters.get("vendor_id") or scenario.target_nodes[0]
        severity_multiplier = scenario.parameters.get("severity_multiplier", 2.0)
        
        # Get nodes connected to vendor
        connected_nodes = await self._get_connected_nodes(vendor_id)
        
        for node_id in [vendor_id] + connected_nodes:
            original = current_risks.get(node_id, 50.0)
            
            # Calculate simulated risk
            if node_id == vendor_id:
                # Vendor itself is maxed
                simulated = 100.0
            else:
                # Connected nodes increase based on distance
                depth = 1 if node_id in connected_nodes[:10] else 2
                increase = (100 - original) * (severity_multiplier / (depth * 2))
                simulated = min(100, original + increase)
            
            delta = simulated - original
            severity = self._classify_severity(delta)
            
            impacts.append(NodeImpact(
                node_id=node_id,
                original_risk=original,
                simulated_risk=simulated,
                risk_delta=delta,
                severity=severity,
                impact_path=[vendor_id, node_id] if node_id != vendor_id else [vendor_id],
            ))
        
        return impacts
    
    async def _simulate_ai_deployment(
        self,
        scenario: SimulationScenario,
        current_risks: Dict[str, float]
    ) -> List[NodeImpact]:
        """Simulate AI tool deployment impact."""
        impacts = []
        
        ai_tool_risk = scenario.parameters.get("ai_tool_risk", 70.0)
        data_sensitivity = scenario.parameters.get("data_sensitivity", 0.8)
        
        # New AI tool impact
        for node_id in scenario.target_nodes:
            original = current_risks.get(node_id, 50.0)
            
            # Risk increases based on data sensitivity
            increase = ai_tool_risk * data_sensitivity * 0.5
            simulated = min(100, original + increase)
            
            impacts.append(NodeImpact(
                node_id=node_id,
                original_risk=original,
                simulated_risk=simulated,
                risk_delta=simulated - original,
                severity=self._classify_severity(simulated - original),
                impact_path=["ai_deployment", node_id],
            ))
        
        # Connected data stores
        for target in scenario.target_nodes:
            connected = await self._get_connected_nodes(target, node_type="DataStore")
            for node_id in connected:
                if node_id in [i.node_id for i in impacts]:
                    continue
                    
                original = current_risks.get(node_id, 50.0)
                increase = ai_tool_risk * data_sensitivity * 0.3
                simulated = min(100, original + increase)
                
                impacts.append(NodeImpact(
                    node_id=node_id,
                    original_risk=original,
                    simulated_risk=simulated,
                    risk_delta=simulated - original,
                    severity=self._classify_severity(simulated - original),
                    impact_path=["ai_deployment", target, node_id],
                ))
        
        return impacts
    
    async def _simulate_data_breach(
        self,
        scenario: SimulationScenario,
        current_risks: Dict[str, float]
    ) -> List[NodeImpact]:
        """Simulate data breach impact."""
        impacts = []
        
        breach_severity = scenario.parameters.get("breach_severity", 0.9)
        
        # Breached nodes are maxed
        for node_id in scenario.target_nodes:
            original = current_risks.get(node_id, 50.0)
            simulated = 100.0
            
            impacts.append(NodeImpact(
                node_id=node_id,
                original_risk=original,
                simulated_risk=simulated,
                risk_delta=simulated - original,
                severity=ImpactSeverity.CRITICAL,
                impact_path=["breach", node_id],
            ))
        
        # Propagate to connected nodes
        for target in scenario.target_nodes:
            connected = await self._get_connected_nodes(target)
            for node_id in connected[:20]:  # Limit propagation
                if node_id in [i.node_id for i in impacts]:
                    continue
                    
                original = current_risks.get(node_id, 50.0)
                increase = 50 * breach_severity
                simulated = min(100, original + increase)
                
                impacts.append(NodeImpact(
                    node_id=node_id,
                    original_risk=original,
                    simulated_risk=simulated,
                    risk_delta=simulated - original,
                    severity=self._classify_severity(simulated - original),
                    impact_path=["breach", target, node_id],
                ))
        
        return impacts
    
    async def _simulate_attack_path(
        self,
        scenario: SimulationScenario,
        current_risks: Dict[str, float]
    ) -> List[NodeImpact]:
        """Simulate attack path traversal."""
        impacts = []
        
        # Get attack path from graph
        start = scenario.parameters.get("start_node", scenario.target_nodes[0])
        end = scenario.parameters.get("end_node")
        
        if end:
            path = await self._find_attack_path(start, end)
        else:
            # Find paths to sensitive data
            path = await self._find_sensitive_paths(start)
        
        # Impact increases along path
        for i, node_id in enumerate(path):
            original = current_risks.get(node_id, 50.0)
            
            # Earlier in path = higher impact (attacker has access)
            depth_factor = 1 - (i / max(len(path), 1))
            increase = 80 * depth_factor
            simulated = min(100, original + increase)
            
            impacts.append(NodeImpact(
                node_id=node_id,
                original_risk=original,
                simulated_risk=simulated,
                risk_delta=simulated - original,
                severity=self._classify_severity(simulated - original),
                impact_path=path[:i+1],
            ))
        
        return impacts
    
    async def _simulate_config_change(
        self,
        scenario: SimulationScenario,
        current_risks: Dict[str, float]
    ) -> List[NodeImpact]:
        """Simulate configuration change impact."""
        impacts = []
        
        risk_delta = scenario.parameters.get("risk_delta", 10.0)
        
        for node_id in scenario.target_nodes:
            original = current_risks.get(node_id, 50.0)
            simulated = np.clip(original + risk_delta, 0, 100)
            
            impacts.append(NodeImpact(
                node_id=node_id,
                original_risk=original,
                simulated_risk=simulated,
                risk_delta=simulated - original,
                severity=self._classify_severity(simulated - original),
                impact_path=["config_change", node_id],
            ))
        
        return impacts
    
    async def _simulate_access_revocation(
        self,
        scenario: SimulationScenario,
        current_risks: Dict[str, float]
    ) -> List[NodeImpact]:
        """Simulate access revocation (risk reduction)."""
        impacts = []
        
        risk_reduction = scenario.parameters.get("risk_reduction", 20.0)
        
        for node_id in scenario.target_nodes:
            original = current_risks.get(node_id, 50.0)
            simulated = max(0, original - risk_reduction)
            
            impacts.append(NodeImpact(
                node_id=node_id,
                original_risk=original,
                simulated_risk=simulated,
                risk_delta=simulated - original,
                severity=ImpactSeverity.LOW if simulated < original else ImpactSeverity.NEGLIGIBLE,
                impact_path=["access_revocation", node_id],
            ))
        
        return impacts
    
    async def _simulate_generic(
        self,
        scenario: SimulationScenario,
        current_risks: Dict[str, float]
    ) -> List[NodeImpact]:
        """Generic simulation for unknown scenario types."""
        impacts = []
        
        for node_id in scenario.target_nodes:
            original = current_risks.get(node_id, 50.0)
            # Default: 20% increase
            simulated = min(100, original * 1.2)
            
            impacts.append(NodeImpact(
                node_id=node_id,
                original_risk=original,
                simulated_risk=simulated,
                risk_delta=simulated - original,
                severity=self._classify_severity(simulated - original),
                impact_path=[node_id],
            ))
        
        return impacts
    
    async def _get_connected_nodes(
        self,
        node_id: str,
        node_type: Optional[str] = None
    ) -> List[str]:
        """Get nodes connected to a given node."""
        if hasattr(self.graph_engine, 'get_connected_nodes'):
            nodes = await self.graph_engine.get_connected_nodes(node_id, node_type)
            return [n.get("id") or n.get("node_id") for n in nodes]
        return []
    
    async def _find_attack_path(
        self,
        start: str,
        end: str
    ) -> List[str]:
        """Find attack path between nodes."""
        if hasattr(self.graph_engine, 'find_shortest_path'):
            return await self.graph_engine.find_shortest_path(start, end)
        return [start, end]
    
    async def _find_sensitive_paths(self, start: str) -> List[str]:
        """Find paths from start to sensitive data."""
        if hasattr(self.graph_engine, 'find_exposure_paths'):
            paths = await self.graph_engine.find_exposure_paths(start)
            if paths:
                return paths[0]  # First path
        return [start]
    
    def _classify_severity(self, delta: float) -> ImpactSeverity:
        """Classify severity based on risk delta."""
        if delta >= 40:
            return ImpactSeverity.CRITICAL
        elif delta >= 25:
            return ImpactSeverity.HIGH
        elif delta >= 10:
            return ImpactSeverity.MEDIUM
        elif delta >= 0:
            return ImpactSeverity.LOW
        else:
            return ImpactSeverity.NEGLIGIBLE
    
    def _calculate_aggregate_impact(
        self,
        impacts: List[NodeImpact]
    ) -> Dict[str, float]:
        """Calculate aggregate impact metrics."""
        if not impacts:
            return {}
        
        deltas = [i.risk_delta for i in impacts]
        
        return {
            "total_nodes_affected": len(impacts),
            "avg_risk_increase": float(np.mean(deltas)),
            "max_risk_increase": float(np.max(deltas)),
            "total_risk_increase": float(np.sum(deltas)),
            "critical_count": len([i for i in impacts if i.severity == ImpactSeverity.CRITICAL]),
            "high_count": len([i for i in impacts if i.severity == ImpactSeverity.HIGH]),
        }
    
    def _generate_recommendations(
        self,
        scenario: SimulationScenario,
        impacts: List[NodeImpact]
    ) -> List[str]:
        """Generate mitigation recommendations."""
        recommendations = []
        
        critical_count = len([i for i in impacts if i.severity == ImpactSeverity.CRITICAL])
        
        if scenario.scenario_type == ScenarioType.VENDOR_COMPROMISE:
            recommendations.append("Review vendor access permissions and scope")
            recommendations.append("Implement network segmentation for vendor connections")
            if critical_count > 0:
                recommendations.append("URGENT: Isolate critical assets from vendor network")
        
        elif scenario.scenario_type == ScenarioType.AI_TOOL_DEPLOYMENT:
            recommendations.append("Implement data classification before AI tool access")
            recommendations.append("Enable DLP controls for AI endpoints")
            recommendations.append("Monitor AI tool data access patterns")
        
        elif scenario.scenario_type == ScenarioType.DATA_BREACH:
            recommendations.append("Activate incident response plan")
            recommendations.append("Isolate affected systems")
            recommendations.append("Notify affected parties per compliance requirements")
        
        elif scenario.scenario_type == ScenarioType.ATTACK_PATH:
            recommendations.append("Review access controls along attack path")
            recommendations.append("Implement additional monitoring at chokepoints")
            recommendations.append("Consider network micro-segmentation")
        
        if critical_count >= 3:
            recommendations.insert(0, "⚠️ HIGH BLAST RADIUS: Consider additional isolation measures")
        
        return recommendations
    
    async def run_batch_simulation(
        self,
        scenarios: List[SimulationScenario]
    ) -> List[SimulationResult]:
        """Run multiple simulations."""
        results = []
        for scenario in scenarios:
            result = await self.simulate(scenario)
            results.append(result)
        return results
