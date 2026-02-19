"""
PDRI Risk Scoring Rules
=======================

Rule-based risk scoring logic for Phase 1.

This module implements heuristic and rule-based scoring factors that
contribute to the overall risk score calculation. In Phase 2, these
will be supplemented by ML-based scoring.

Scoring Philosophy:
    - Exposure Score: How exposed is this entity to external threats?
    - Volatility Score: How unstable/changing is this entity's risk profile?
    - Sensitivity Likelihood: How likely is this entity to contain sensitive data?

All scores are normalized to [0, 1] range where:
    - 0.0 = Minimal risk
    - 0.5 = Moderate risk
    - 1.0 = Critical risk

Author: PDRI Team
Version: 1.0.0
"""

import logging
import re
from typing import Any, Dict, List, Optional
from dataclasses import dataclass
from enum import Enum

from pdri.config import settings


logger = logging.getLogger(__name__)


class PrivilegeLevel(Enum):
    """
    Privilege level classifications with associated risk weights.
    """
    READ = ("read", 0.2)
    WRITE = ("write", 0.4)
    ADMIN = ("admin", 0.7)
    SUPER_ADMIN = ("super_admin", 1.0)
    UNKNOWN = ("unknown", 0.5)
    
    def __init__(self, value: str, weight: float):
        self._value_ = value
        self.weight = weight
    
    @classmethod
    def from_string(cls, value: str) -> "PrivilegeLevel":
        """Get privilege level from string, defaulting to UNKNOWN."""
        value = value.lower().strip()
        for level in cls:
            if level.value == value:
                return level
        return cls.UNKNOWN


@dataclass
class ScoringFactors:
    """
    Individual factors contributing to risk scores.
    
    Each factor is a value in [0, 1] range that contributes
    to the final weighted score.
    """
    
    # Exposure factors
    external_connection_factor: float = 0.0
    ai_integration_factor: float = 0.0
    data_volume_factor: float = 0.0
    privilege_level_factor: float = 0.0
    public_exposure_factor: float = 0.0
    
    # Volatility factors
    connection_change_rate: float = 0.0
    access_pattern_change: float = 0.0
    recent_integration_factor: float = 0.0
    
    # Sensitivity factors
    name_heuristic_factor: float = 0.0
    data_classification_factor: float = 0.0
    connected_sensitivity_factor: float = 0.0
    sensitivity_tag_factor: float = 0.0


class RiskScoringRules:
    """
    Rule-based risk scoring implementation.
    
    Contains all heuristic rules and factor calculations for
    determining risk scores of graph entities.
    
    Usage:
        rules = RiskScoringRules()
        factors = rules.calculate_factors(node_data, edge_data, events_data)
        exposure_score = rules.calculate_exposure_score(factors)
    """
    
    # =========================================================================
    # Sensitivity Keywords
    # =========================================================================
    
    # Keywords indicating likely sensitive data (case-insensitive)
    SENSITIVE_NAME_PATTERNS = [
        r"customer",
        r"user",
        r"patient",
        r"employee",
        r"personal",
        r"private",
        r"confidential",
        r"secret",
        r"credential",
        r"password",
        r"auth",
        r"payment",
        r"financial",
        r"transaction",
        r"account",
        r"ssn",
        r"social.?security",
        r"credit.?card",
        r"bank",
        r"health",
        r"medical",
        r"diagnosis",
        r"insurance",
        r"salary",
        r"tax",
        r"pii",
        r"phi",
        r"hipaa",
        r"gdpr",
    ]
    
    # Known high-value data classifications
    HIGH_SENSITIVITY_CLASSIFICATIONS = [
        "confidential",
        "secret",
        "top_secret",
        "restricted",
        "pii",
        "phi",
        "financial",
        "regulated",
    ]
    
    # =========================================================================
    # Thresholds
    # =========================================================================
    
    # Connection count thresholds
    EXTERNAL_CONNECTION_HIGH = 10
    AI_INTEGRATION_HIGH = 3
    
    # Data volume thresholds (bytes)
    VOLUME_HIGH = 100_000_000  # 100MB
    VOLUME_MEDIUM = 10_000_000   # 10MB
    
    # Access count thresholds
    ACCESS_HIGH = 1000
    ACCESS_MEDIUM = 100
    
    def __init__(self):
        """Initialize the scoring rules with configured weights."""
        self.weights = {
            "external_connections": settings.score_weight_external_connections,
            "ai_integrations": settings.score_weight_ai_integrations,
            "data_volume": settings.score_weight_data_volume,
            "privilege_level": settings.score_weight_privilege_level,
            "sensitivity": settings.score_weight_sensitivity,
        }
        
        # Compile regex patterns for efficiency
        self._sensitive_patterns = [
            re.compile(p, re.IGNORECASE) 
            for p in self.SENSITIVE_NAME_PATTERNS
        ]
    
    # =========================================================================
    # Factor Calculations
    # =========================================================================
    
    def calculate_factors(
        self,
        node_data: Dict[str, Any],
        relationships: Optional[List[Dict[str, Any]]] = None,
        events: Optional[List[Dict[str, Any]]] = None
    ) -> ScoringFactors:
        """
        Calculate all scoring factors for a node.
        
        Args:
            node_data: Node properties from graph
            relationships: List of node's relationships
            events: Recent events involving this node
            
        Returns:
            ScoringFactors with all factor values
        """
        relationships = relationships or []
        events = events or []
        
        factors = ScoringFactors()
        
        # Calculate exposure factors
        factors.external_connection_factor = self._calc_external_connection_factor(
            node_data, relationships
        )
        factors.ai_integration_factor = self._calc_ai_integration_factor(
            node_data, relationships
        )
        factors.data_volume_factor = self._calc_data_volume_factor(
            node_data, relationships, events
        )
        factors.privilege_level_factor = self._calc_privilege_level_factor(
            node_data, relationships
        )
        factors.public_exposure_factor = self._calc_public_exposure_factor(
            node_data
        )
        
        # Calculate sensitivity factors
        factors.name_heuristic_factor = self._calc_name_heuristic_factor(
            node_data
        )
        factors.data_classification_factor = self._calc_data_classification_factor(
            node_data
        )
        factors.sensitivity_tag_factor = self._calc_sensitivity_tag_factor(
            events
        )
        
        return factors
    
    def _calc_external_connection_factor(
        self,
        node_data: Dict[str, Any],
        relationships: List[Dict[str, Any]]
    ) -> float:
        """
        Calculate factor based on external/outside connections.
        
        Higher external connectivity = higher exposure risk.
        """
        external_count = 0
        
        for rel in relationships:
            connected_type = rel.get("connected_type", "")
            if connected_type in ["External", "AITool"]:
                external_count += 1
            # Also count if the edge type indicates external exposure
            if rel.get("relationship") in ["EXPOSES", "INTEGRATES_WITH"]:
                external_count += 0.5
        
        # Normalize to [0, 1]
        return min(1.0, external_count / self.EXTERNAL_CONNECTION_HIGH)
    
    def _calc_ai_integration_factor(
        self,
        node_data: Dict[str, Any],
        relationships: List[Dict[str, Any]]
    ) -> float:
        """
        Calculate factor based on AI tool integrations.
        
        AI tools are considered high-risk due to data ingestion.
        """
        ai_count = node_data.get("connected_ai_tools_count", 0)
        
        # Also count from relationships if available
        for rel in relationships:
            if rel.get("connected_type") == "AITool":
                ai_count += 1
        
        # Normalize with steep curve (AI is high risk)
        return min(1.0, ai_count / self.AI_INTEGRATION_HIGH)
    
    def _calc_data_volume_factor(
        self,
        node_data: Dict[str, Any],
        relationships: List[Dict[str, Any]],
        events: List[Dict[str, Any]]
    ) -> float:
        """
        Calculate factor based on data volume moving through node.
        
        Higher data volumes = higher potential impact if breached.
        """
        total_volume = 0
        
        # Get volume from relationships
        for rel in relationships:
            volume = rel.get("data_volume_bytes", 0) or 0
            total_volume += volume
        
        # Get volume from recent events
        for event in events:
            volume = event.get("data_volume_estimate", 0) or 0
            total_volume += volume
        
        # Normalize with high threshold
        if total_volume >= self.VOLUME_HIGH:
            return 1.0
        elif total_volume >= self.VOLUME_MEDIUM:
            return 0.5 + (total_volume - self.VOLUME_MEDIUM) / (2 * self.VOLUME_HIGH)
        else:
            return total_volume / (2 * self.VOLUME_MEDIUM)
    
    def _calc_privilege_level_factor(
        self,
        node_data: Dict[str, Any],
        relationships: List[Dict[str, Any]]
    ) -> float:
        """
        Calculate factor based on privilege levels accessing this node.
        
        Higher privilege access = higher risk if compromised.
        """
        max_privilege_weight = 0.0
        
        # Check node's own privilege level
        if "privilege_level" in node_data:
            level = PrivilegeLevel.from_string(node_data["privilege_level"])
            max_privilege_weight = max(max_privilege_weight, level.weight)
        
        # Check incoming access relationships
        for rel in relationships:
            if rel.get("relationship") in ["ACCESSES", "MANAGES"]:
                # This would ideally look up the accessor's privilege
                # For now, use a heuristic based on relationship type
                if rel.get("relationship") == "MANAGES":
                    max_privilege_weight = max(max_privilege_weight, 0.8)
        
        return max_privilege_weight
    
    def _calc_public_exposure_factor(self, node_data: Dict[str, Any]) -> float:
        """
        Calculate factor based on public accessibility.
        
        Publicly accessible = immediate exposure risk.
        """
        if node_data.get("is_public", False):
            return 1.0
        
        if node_data.get("is_internal", True):
            return 0.0
        
        return 0.5  # Unknown/ambiguous
    
    def _calc_name_heuristic_factor(self, node_data: Dict[str, Any]) -> float:
        """
        Calculate sensitivity likelihood based on entity name.
        
        Uses pattern matching against known sensitive data names.
        """
        name = node_data.get("name", "").lower()
        node_id = node_data.get("id", "").lower()
        
        combined = f"{name} {node_id}"
        
        # Count pattern matches
        matches = 0
        for pattern in self._sensitive_patterns:
            if pattern.search(combined):
                matches += 1
        
        # More matches = higher likelihood
        if matches >= 3:
            return 1.0
        elif matches >= 2:
            return 0.8
        elif matches >= 1:
            return 0.5
        
        return 0.0
    
    def _calc_data_classification_factor(
        self, 
        node_data: Dict[str, Any]
    ) -> float:
        """
        Calculate factor based on explicit data classification.
        
        Uses organizational data classification if available.
        """
        classification = node_data.get("data_classification", "").lower()
        
        if classification in self.HIGH_SENSITIVITY_CLASSIFICATIONS:
            return 1.0
        elif classification in ["internal", "private"]:
            return 0.5
        elif classification in ["public", "unclassified"]:
            return 0.1
        
        return 0.3  # Unknown = moderate
    
    def _calc_sensitivity_tag_factor(
        self, 
        events: List[Dict[str, Any]]
    ) -> float:
        """
        Calculate factor based on sensitivity tags from events.
        
        Uses tags emitted by Aegis AI and other sensors.
        """
        if not events:
            return 0.0
        
        # Count high-value sensitivity tags
        high_value_tags = {"financial_related", "health_related", "identity_related"}
        tag_counts: Dict[str, int] = {}
        
        for event in events:
            tags = event.get("sensitivity_tags", [])
            for tag in tags:
                tag_value = tag if isinstance(tag, str) else tag.get("value", tag)
                tag_counts[tag_value] = tag_counts.get(tag_value, 0) + 1
        
        # Any high-value tag = high sensitivity
        for tag in high_value_tags:
            if tag in tag_counts:
                return min(1.0, 0.5 + (tag_counts[tag] * 0.1))
        
        # Any tags at all = some sensitivity
        if tag_counts:
            return 0.3
        
        return 0.0
    
    # =========================================================================
    # Score Calculations
    # =========================================================================
    
    def calculate_exposure_score(self, factors: ScoringFactors) -> float:
        """
        Calculate overall exposure score from factors.
        
        Uses weighted average of exposure factors.
        
        Args:
            factors: Calculated scoring factors
            
        Returns:
            Exposure score in [0, 1] range
        """
        weighted_sum = (
            factors.external_connection_factor * self.weights["external_connections"] +
            factors.ai_integration_factor * self.weights["ai_integrations"] +
            factors.data_volume_factor * self.weights["data_volume"] +
            factors.privilege_level_factor * self.weights["privilege_level"] +
            factors.public_exposure_factor * 0.15  # Additional weight for public exposure
        )
        
        total_weight = sum(self.weights.values()) + 0.15
        
        score = weighted_sum / total_weight
        
        # Apply non-linear scaling to emphasize high-risk items
        # This makes the score more sensitive at higher values
        return min(1.0, score * 1.2)
    
    def calculate_volatility_score(
        self,
        factors: ScoringFactors,
        historical_scores: Optional[List[float]] = None
    ) -> float:
        """
        Calculate volatility (instability) score.
        
        Measures how much the risk profile is changing.
        
        Args:
            factors: Calculated scoring factors
            historical_scores: Previous exposure scores for variance calculation
            
        Returns:
            Volatility score in [0, 1] range
        """
        base_volatility = (
            factors.connection_change_rate * 0.4 +
            factors.access_pattern_change * 0.3 +
            factors.recent_integration_factor * 0.3
        )
        
        # Add historical variance if available
        if historical_scores and len(historical_scores) >= 2:
            variance = self._calculate_variance(historical_scores)
            # Normalize variance (assuming max reasonable variance of 0.25)
            variance_factor = min(1.0, variance / 0.25)
            base_volatility = (base_volatility + variance_factor) / 2
        
        return min(1.0, base_volatility)
    
    def calculate_sensitivity_likelihood(
        self, 
        factors: ScoringFactors
    ) -> float:
        """
        Calculate probability that entity contains sensitive data.
        
        Args:
            factors: Calculated scoring factors
            
        Returns:
            Sensitivity likelihood in [0, 1] range
        """
        # Take maximum of indicators (any single indicator is sufficient)
        max_indicator = max(
            factors.name_heuristic_factor,
            factors.data_classification_factor,
            factors.sensitivity_tag_factor
        )
        
        # Weight the average with the max (to avoid dilution by zeros)
        avg_indicator = (
            factors.name_heuristic_factor +
            factors.data_classification_factor +
            factors.sensitivity_tag_factor
        ) / 3
        
        # Combine: 70% max, 30% average
        return min(1.0, max_indicator * 0.7 + avg_indicator * 0.3)
    
    def calculate_composite_score(
        self,
        exposure: float,
        volatility: float,
        sensitivity: float
    ) -> float:
        """
        Calculate composite risk score.
        
        Combines all three score dimensions into a single metric.
        
        Args:
            exposure: Exposure score [0, 1]
            volatility: Volatility score [0, 1]
            sensitivity: Sensitivity likelihood [0, 1]
            
        Returns:
            Composite score in [0, 1] range
        """
        # Weighted: 50% exposure, 30% volatility, 20% sensitivity
        composite = (
            exposure * 0.50 +
            volatility * 0.30 +
            sensitivity * 0.20
        )
        
        return min(1.0, composite)
    
    def _calculate_variance(self, scores: List[float]) -> float:
        """Calculate variance of historical scores."""
        if len(scores) < 2:
            return 0.0
        
        mean = sum(scores) / len(scores)
        variance = sum((s - mean) ** 2 for s in scores) / len(scores)
        return variance
    
    # =========================================================================
    # Risk Level Classification
    # =========================================================================
    
    @staticmethod
    def classify_risk_level(composite_score: float) -> str:
        """
        Classify composite score into risk level.
        
        Args:
            composite_score: Score in [0, 1]
            
        Returns:
            Risk level string
        """
        if composite_score >= 0.8:
            return "critical"
        elif composite_score >= 0.6:
            return "high"
        elif composite_score >= 0.4:
            return "medium"
        elif composite_score >= 0.2:
            return "low"
        else:
            return "minimal"
