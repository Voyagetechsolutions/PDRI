"""
PDRI Scoring Engine
===================

Orchestrates risk score calculations for graph entities.

This module coordinates:
    - Factor calculation from graph data
    - Score computation using rules
    - Persistence of scores to PostgreSQL
    - Batch scoring operations

Usage:
    from pdri.scoring.engine import ScoringEngine
    
    engine = ScoringEngine(graph_engine, db_session)
    scores = await engine.score_entity("node-123")

Author: PDRI Team
Version: 1.0.0
"""

import logging
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional
from dataclasses import dataclass

from shared.schemas.events import RiskScore, RiskTrajectory
from pdri.graph.engine import GraphEngine
from pdri.scoring.rules import RiskScoringRules, ScoringFactors


logger = logging.getLogger(__name__)


@dataclass
class ScoringResult:
    """
    Complete scoring result for an entity.
    
    Includes scores, factors, and metadata.
    """
    entity_id: str
    exposure_score: float
    volatility_score: float
    sensitivity_likelihood: float
    composite_score: float
    risk_level: str
    factors: ScoringFactors
    calculated_at: datetime
    scoring_version: str = "1.0.0"
    
    def to_risk_score(self) -> RiskScore:
        """Convert to RiskScore model."""
        return RiskScore(
            entity_id=self.entity_id,
            exposure_score=self.exposure_score,
            volatility_score=self.volatility_score,
            sensitivity_likelihood=self.sensitivity_likelihood,
            composite_score=self.composite_score,
            scoring_version=self.scoring_version,
            calculated_at=self.calculated_at,
            factors={
                "external_connections": self.factors.external_connection_factor,
                "ai_integrations": self.factors.ai_integration_factor,
                "data_volume": self.factors.data_volume_factor,
                "privilege_level": self.factors.privilege_level_factor,
                "public_exposure": self.factors.public_exposure_factor,
                "name_heuristic": self.factors.name_heuristic_factor,
                "data_classification": self.factors.data_classification_factor,
                "sensitivity_tags": self.factors.sensitivity_tag_factor,
            }
        )


class ScoringEngine:
    """
    Risk scoring engine for PDRI.
    
    Coordinates the scoring process across graph queries,
    rule evaluation, and score persistence.
    
    Attributes:
        graph_engine: Neo4j graph engine instance
        rules: Risk scoring rules implementation
    
    Example:
        async with GraphEngine() as graph:
            engine = ScoringEngine(graph)
            
            # Score single entity
            result = await engine.score_entity("datastore-001")
            print(f"Risk: {result.risk_level}")
            
            # Batch score all data stores
            results = await engine.score_entities_by_type("DataStore")
    """
    
    def __init__(
        self,
        graph_engine: GraphEngine,
        rules: Optional[RiskScoringRules] = None
    ):
        """
        Initialize the scoring engine.
        
        Args:
            graph_engine: Connected GraphEngine instance
            rules: Optional custom scoring rules
        """
        self.graph = graph_engine
        self.rules = rules or RiskScoringRules()
        self._score_history: Dict[str, List[float]] = {}
    
    async def score_entity(
        self,
        entity_id: str,
        events: Optional[List[Dict[str, Any]]] = None,
        update_graph: bool = True
    ) -> ScoringResult:
        """
        Calculate and return risk scores for an entity.
        
        Args:
            entity_id: Graph node identifier
            events: Optional list of recent events for this entity
            update_graph: Whether to update node with new scores
            
        Returns:
            ScoringResult with all scores and factors
            
        Raises:
            ValueError: If entity not found
        """
        logger.debug(f"Scoring entity: {entity_id}")
        
        # Get node data with relationships from graph
        node_data = await self.graph.get_node_with_relationships(entity_id)
        
        if node_data is None:
            raise ValueError(f"Entity not found: {entity_id}")
        
        node = node_data["node"]
        relationships = node_data.get("relationships", [])
        
        # Calculate factors
        factors = self.rules.calculate_factors(
            node_data=node,
            relationships=relationships,
            events=events or []
        )
        
        # Get historical scores for volatility calculation
        historical = self._score_history.get(entity_id, [])
        
        # Calculate scores
        exposure = self.rules.calculate_exposure_score(factors)
        volatility = self.rules.calculate_volatility_score(factors, historical)
        sensitivity = self.rules.calculate_sensitivity_likelihood(factors)
        composite = self.rules.calculate_composite_score(
            exposure, volatility, sensitivity
        )
        risk_level = self.rules.classify_risk_level(composite)
        
        # Create result
        result = ScoringResult(
            entity_id=entity_id,
            exposure_score=round(exposure, 4),
            volatility_score=round(volatility, 4),
            sensitivity_likelihood=round(sensitivity, 4),
            composite_score=round(composite, 4),
            risk_level=risk_level,
            factors=factors,
            calculated_at=datetime.utcnow()
        )
        
        # Update history for volatility tracking
        self._update_score_history(entity_id, exposure)
        
        # Update graph node with new scores
        if update_graph:
            await self.graph.update_risk_scores(
                node_id=entity_id,
                exposure_score=result.exposure_score,
                volatility_score=result.volatility_score,
                sensitivity_likelihood=result.sensitivity_likelihood
            )
        
        logger.info(
            f"Scored entity {entity_id}: composite={result.composite_score:.2f} "
            f"({result.risk_level})"
        )
        
        return result
    
    async def score_entities_by_type(
        self,
        node_type: str,
        max_entities: int = 1000,
        update_graph: bool = True
    ) -> List[ScoringResult]:
        """
        Score all entities of a given type.
        
        Args:
            node_type: Node type label (e.g., "DataStore", "Service")
            max_entities: Maximum entities to score
            update_graph: Whether to update nodes with new scores
            
        Returns:
            List of ScoringResult for each entity
        """
        from pdri.graph.models import NodeType
        
        logger.info(f"Batch scoring entities of type: {node_type}")
        
        # Get all nodes of this type
        try:
            node_type_enum = NodeType(node_type)
        except ValueError:
            raise ValueError(f"Invalid node type: {node_type}")
        
        nodes = await self.graph.get_nodes_by_type(
            node_type=node_type_enum,
            limit=max_entities
        )
        
        results = []
        for node in nodes:
            try:
                result = await self.score_entity(
                    entity_id=node["id"],
                    update_graph=update_graph
                )
                results.append(result)
            except Exception as e:
                logger.error(f"Error scoring {node['id']}: {e}")
        
        logger.info(f"Scored {len(results)} entities of type {node_type}")
        return results
    
    async def score_all_entities(
        self,
        update_graph: bool = True
    ) -> Dict[str, List[ScoringResult]]:
        """
        Score all entities in the graph.
        
        Returns results grouped by node type.
        
        Args:
            update_graph: Whether to update nodes with new scores
            
        Returns:
            Dictionary mapping node types to lists of ScoringResults
        """
        from pdri.graph.models import NodeType
        
        logger.info("Scoring all entities in graph")
        
        all_results: Dict[str, List[ScoringResult]] = {}
        
        for node_type in NodeType:
            results = await self.score_entities_by_type(
                node_type=node_type.value,
                update_graph=update_graph
            )
            if results:
                all_results[node_type.value] = results
        
        total_count = sum(len(r) for r in all_results.values())
        logger.info(f"Completed scoring {total_count} total entities")
        
        return all_results
    
    async def get_risk_summary(self) -> Dict[str, Any]:
        """
        Get a summary of risk across the graph.
        
        Returns:
            Dictionary with risk distribution and statistics
        """
        # Get risk distribution from graph
        distribution = await self.graph.get_risk_distribution()
        
        # Get high risk nodes
        high_risk = await self.graph.get_high_risk_nodes(
            threshold=0.6,
            limit=10
        )
        
        return {
            "distribution": distribution,
            "high_risk_entities": high_risk,
            "calculated_at": datetime.utcnow().isoformat()
        }
    
    def explain_score(self, result: ScoringResult) -> Dict[str, Any]:
        """
        Generate human-readable explanation of scoring result.
        
        Args:
            result: ScoringResult to explain
            
        Returns:
            Dictionary with explanation text and factor breakdown
        """
        factors = result.factors
        
        # Identify top contributing factors
        factor_contributions = [
            ("External connections", factors.external_connection_factor),
            ("AI tool integrations", factors.ai_integration_factor),
            ("Data volume", factors.data_volume_factor),
            ("Privilege level", factors.privilege_level_factor),
            ("Public exposure", factors.public_exposure_factor),
        ]
        
        # Sort by contribution
        factor_contributions.sort(key=lambda x: x[1], reverse=True)
        
        # Generate explanation
        top_factors = [f[0] for f in factor_contributions[:3] if f[1] > 0.1]
        
        explanation = {
            "entity_id": result.entity_id,
            "risk_level": result.risk_level,
            "composite_score": result.composite_score,
            "summary": self._generate_summary(result),
            "top_risk_factors": top_factors,
            "factor_breakdown": {
                name: round(value, 2) 
                for name, value in factor_contributions
            },
            "score_breakdown": {
                "exposure": result.exposure_score,
                "volatility": result.volatility_score,
                "sensitivity": result.sensitivity_likelihood
            },
            "recommendations": self._generate_recommendations(result)
        }
        
        return explanation
    
    def _generate_summary(self, result: ScoringResult) -> str:
        """Generate a one-line summary of the risk."""
        level = result.risk_level
        
        if level == "critical":
            return (
                f"This entity has CRITICAL risk exposure. "
                f"Immediate attention required."
            )
        elif level == "high":
            return (
                f"This entity has HIGH risk with composite score "
                f"{result.composite_score:.2f}. Review recommended."
            )
        elif level == "medium":
            return (
                f"This entity has MODERATE risk. "
                f"Monitor for changes."
            )
        else:
            return f"This entity has {level.upper()} risk."
    
    def _generate_recommendations(
        self, 
        result: ScoringResult
    ) -> List[str]:
        """Generate recommendations based on score factors."""
        recommendations = []
        factors = result.factors
        
        if factors.external_connection_factor > 0.7:
            recommendations.append(
                "Reduce external connections or add monitoring"
            )
        
        if factors.ai_integration_factor > 0.5:
            recommendations.append(
                "Review AI tool permissions and data access"
            )
        
        if factors.public_exposure_factor > 0.5:
            recommendations.append(
                "Consider restricting public access"
            )
        
        if factors.privilege_level_factor > 0.6:
            recommendations.append(
                "Review privilege levels for least-privilege compliance"
            )
        
        if result.sensitivity_likelihood > 0.7:
            recommendations.append(
                "Implement additional data protection measures"
            )
        
        if result.volatility_score > 0.6:
            recommendations.append(
                "Investigate recent changes causing risk fluctuation"
            )
        
        if not recommendations:
            recommendations.append(
                "Continue monitoring; no immediate action required"
            )
        
        return recommendations
    
    def _update_score_history(
        self, 
        entity_id: str, 
        score: float,
        max_history: int = 30
    ) -> None:
        """
        Update score history for volatility tracking.
        
        Maintains a rolling window of historical scores.
        """
        if entity_id not in self._score_history:
            self._score_history[entity_id] = []
        
        history = self._score_history[entity_id]
        history.append(score)
        
        # Keep only last N scores
        if len(history) > max_history:
            self._score_history[entity_id] = history[-max_history:]
