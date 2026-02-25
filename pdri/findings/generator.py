"""
Finding Generator
=================

Generates RiskFinding objects from scoring results and events.

This module contains the logic for determining when a finding
should be created based on:
    - Score thresholds
    - Score changes (delta)
    - Anomaly detection
    - Compliance gaps

Author: PDRI Team
Version: 1.0.0
"""

import logging
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from uuid import uuid4

from shared.schemas.findings import (
    EntityRef,
    EventRef,
    FindingSeverity,
    Recommendation,
    RiskFinding,
)
from pdri.scoring.engine import ScoringResult
from pdri.config import settings


logger = logging.getLogger(__name__)


# Thresholds for finding generation
CRITICAL_THRESHOLD = 0.85
HIGH_THRESHOLD = 0.70
MEDIUM_THRESHOLD = 0.50
SCORE_CHANGE_THRESHOLD = 0.15  # Generate finding if score changes by this much


class FindingGenerator:
    """
    Generates risk findings from scoring results and events.

    The generator analyzes scoring results and creates findings when:
        - Score exceeds severity thresholds
        - Score changes significantly from previous value
        - Specific risk patterns are detected
        - Compliance gaps are identified

    Example:
        generator = FindingGenerator()

        # Generate from scoring result
        finding = generator.from_scoring_result(
            result=scoring_result,
            previous_score=0.3,
            entity_name="customer-database",
            exposure_path=["db", "api", "chatgpt"]
        )
    """

    def __init__(self):
        """Initialize the finding generator."""
        self.schema_version = "1.0.0"
        self.producer_version = settings.app_version

    def from_scoring_result(
        self,
        result: ScoringResult,
        previous_score: Optional[float] = None,
        entity_type: str = "unknown",
        entity_name: Optional[str] = None,
        exposure_path: Optional[List[str]] = None,
        related_events: Optional[List[Dict[str, Any]]] = None,
    ) -> Optional[RiskFinding]:
        """
        Generate a finding from a scoring result if thresholds are met.

        Args:
            result: ScoringResult from the scoring engine
            previous_score: Previous composite score for delta detection
            entity_type: Type of the entity (data_store, service, ai_tool, etc.)
            entity_name: Human-readable name of the entity
            exposure_path: Ordered list of entity IDs showing exposure flow
            related_events: Events that contributed to this score

        Returns:
            RiskFinding if thresholds met, None otherwise
        """
        # Determine if we should generate a finding
        severity = self._determine_severity(result.composite_score, previous_score)

        if severity is None:
            logger.debug(
                f"No finding generated for {result.entity_id}: "
                f"score={result.composite_score:.2f} below threshold"
            )
            return None

        # Determine finding type
        finding_type = self._determine_finding_type(
            result, previous_score, related_events
        )

        # Build the finding
        finding = RiskFinding(
            finding_id=f"f-{uuid4().hex[:8]}",
            title=self._generate_title(
                result, entity_name or result.entity_id, finding_type
            ),
            description=self._generate_description(
                result, entity_name or result.entity_id, previous_score
            ),
            finding_type=finding_type,
            severity=severity,
            risk_score=result.composite_score,
            exposure_score=result.exposure_score,
            volatility_score=result.volatility_score,
            sensitivity_score=result.sensitivity_likelihood,
            entities_involved=[
                EntityRef(
                    entity_id=result.entity_id,
                    entity_type=entity_type,
                    name=entity_name,
                    role="primary",
                )
            ],
            exposure_path=exposure_path or [],
            evidence=self._build_evidence(related_events or []),
            recommendations=self._generate_recommendations(result),
            tags=self._generate_tags(result, entity_type),
            metadata={
                "factors": {
                    "external_connections": result.factors.external_connection_factor,
                    "ai_integrations": result.factors.ai_integration_factor,
                    "data_volume": result.factors.data_volume_factor,
                    "privilege_level": result.factors.privilege_level_factor,
                    "public_exposure": result.factors.public_exposure_factor,
                },
                "previous_score": previous_score,
                "score_delta": (
                    result.composite_score - previous_score
                    if previous_score is not None
                    else None
                ),
                "schema_version": self.schema_version,
                "producer_version": self.producer_version,
            },
        )

        logger.info(
            f"Generated {severity.value} finding for {result.entity_id}: "
            f"{finding.finding_id}"
        )

        return finding

    def from_threshold_breach(
        self,
        entity_id: str,
        entity_type: str,
        entity_name: str,
        threshold_name: str,
        threshold_value: float,
        current_value: float,
        context: Optional[Dict[str, Any]] = None,
    ) -> RiskFinding:
        """
        Generate a finding when a specific threshold is breached.

        Args:
            entity_id: Entity identifier
            entity_type: Type of entity
            entity_name: Human-readable name
            threshold_name: Name of the threshold breached
            threshold_value: The threshold that was breached
            current_value: Current value that breached the threshold
            context: Additional context about the breach

        Returns:
            RiskFinding for the threshold breach
        """
        severity = self._severity_for_value(current_value)

        return RiskFinding(
            finding_id=f"f-{uuid4().hex[:8]}",
            title=f"Threshold Breach: {threshold_name} on {entity_name}",
            description=(
                f"The {threshold_name} threshold ({threshold_value:.2f}) was breached. "
                f"Current value: {current_value:.2f}. "
                f"This indicates elevated risk requiring attention."
            ),
            finding_type="threshold_breach",
            severity=severity,
            risk_score=current_value,
            entities_involved=[
                EntityRef(
                    entity_id=entity_id,
                    entity_type=entity_type,
                    name=entity_name,
                    role="primary",
                )
            ],
            recommendations=[
                Recommendation(
                    action="investigate",
                    description=f"Investigate the cause of {threshold_name} breach",
                    priority="high",
                ),
                Recommendation(
                    action="review_config",
                    description="Review entity configuration and access patterns",
                    priority="medium",
                ),
            ],
            tags=["threshold-breach", threshold_name.lower().replace(" ", "-")],
            metadata={
                "threshold_name": threshold_name,
                "threshold_value": threshold_value,
                "current_value": current_value,
                "context": context or {},
                "schema_version": self.schema_version,
                "producer_version": self.producer_version,
            },
        )

    def from_ai_exposure(
        self,
        data_store_id: str,
        data_store_name: str,
        ai_tool_id: str,
        ai_tool_name: str,
        exposure_path: List[str],
        sensitivity_tags: List[str],
        risk_score: float,
    ) -> RiskFinding:
        """
        Generate a finding for AI tool data exposure.

        Args:
            data_store_id: ID of the exposed data store
            data_store_name: Name of the data store
            ai_tool_id: ID of the AI tool accessing data
            ai_tool_name: Name of the AI tool
            exposure_path: Path from data to AI tool
            sensitivity_tags: Sensitivity classifications
            risk_score: Calculated risk score

        Returns:
            RiskFinding for AI exposure
        """
        severity = self._severity_for_value(risk_score)

        sensitivity_str = ", ".join(sensitivity_tags) if sensitivity_tags else "unknown"

        return RiskFinding(
            finding_id=f"f-{uuid4().hex[:8]}",
            title=f"AI Tool Exposure: {ai_tool_name} accessing {data_store_name}",
            description=(
                f"The AI tool '{ai_tool_name}' has access to '{data_store_name}' "
                f"which contains {sensitivity_str} data. "
                f"Data may be sent externally for processing, creating exposure risk."
            ),
            finding_type="ai_exposure",
            severity=severity,
            risk_score=risk_score,
            entities_involved=[
                EntityRef(
                    entity_id=data_store_id,
                    entity_type="data_store",
                    name=data_store_name,
                    role="source",
                ),
                EntityRef(
                    entity_id=ai_tool_id,
                    entity_type="ai_tool",
                    name=ai_tool_name,
                    role="accessor",
                ),
            ],
            exposure_path=exposure_path,
            recommendations=[
                Recommendation(
                    action="review_permissions",
                    description=f"Review {ai_tool_name}'s access permissions to {data_store_name}",
                    priority="high",
                ),
                Recommendation(
                    action="data_masking",
                    description="Implement data masking or anonymization before AI processing",
                    priority="high" if "pii" in sensitivity_str.lower() else "medium",
                ),
                Recommendation(
                    action="audit_logging",
                    description="Enable detailed audit logging for AI tool data access",
                    priority="medium",
                ),
            ],
            tags=["ai-exposure", "data-flow"] + [
                f"sensitivity-{tag}" for tag in sensitivity_tags[:3]
            ],
            metadata={
                "sensitivity_tags": sensitivity_tags,
                "schema_version": self.schema_version,
                "producer_version": self.producer_version,
            },
        )

    def _determine_severity(
        self,
        score: float,
        previous_score: Optional[float],
    ) -> Optional[FindingSeverity]:
        """
        Determine severity based on score and change.

        Returns None if no finding should be generated.
        """
        # Check absolute thresholds
        if score >= CRITICAL_THRESHOLD:
            return FindingSeverity.CRITICAL
        elif score >= HIGH_THRESHOLD:
            return FindingSeverity.HIGH
        elif score >= MEDIUM_THRESHOLD:
            # Only generate medium findings if there's a significant change
            if previous_score is not None:
                delta = score - previous_score
                if delta >= SCORE_CHANGE_THRESHOLD:
                    return FindingSeverity.MEDIUM
            else:
                # New entity with medium score
                return FindingSeverity.MEDIUM

        # Check for significant score increase (even below medium threshold)
        if previous_score is not None:
            delta = score - previous_score
            if delta >= SCORE_CHANGE_THRESHOLD * 2:  # Double threshold for low scores
                return FindingSeverity.LOW

        return None

    def _determine_finding_type(
        self,
        result: ScoringResult,
        previous_score: Optional[float],
        events: Optional[List[Dict[str, Any]]],
    ) -> str:
        """Determine the type of finding based on context."""
        if previous_score is not None:
            delta = result.composite_score - previous_score
            if delta >= SCORE_CHANGE_THRESHOLD:
                return "risk_increase"

        if result.factors.ai_integration_factor > 0.5:
            return "ai_exposure"

        if result.volatility_score > 0.7:
            return "anomaly"

        return "risk_detected"

    def _generate_title(
        self,
        result: ScoringResult,
        entity_name: str,
        finding_type: str,
    ) -> str:
        """Generate a concise finding title."""
        level = result.risk_level.upper()

        if finding_type == "risk_increase":
            return f"Risk Increase Detected: {entity_name}"
        elif finding_type == "ai_exposure":
            return f"AI Exposure Risk: {entity_name}"
        elif finding_type == "anomaly":
            return f"Anomalous Activity: {entity_name}"
        else:
            return f"{level} Risk: {entity_name}"

    def _generate_description(
        self,
        result: ScoringResult,
        entity_name: str,
        previous_score: Optional[float],
    ) -> str:
        """Generate detailed finding description."""
        parts = [
            f"Entity '{entity_name}' has a risk score of {result.composite_score:.2f} "
            f"({result.risk_level} risk level)."
        ]

        if previous_score is not None:
            delta = result.composite_score - previous_score
            direction = "increased" if delta > 0 else "decreased"
            parts.append(
                f"Score {direction} by {abs(delta):.2f} from previous value of {previous_score:.2f}."
            )

        # Add factor insights
        if result.factors.ai_integration_factor > 0.5:
            parts.append(
                "High AI tool integration factor indicates potential data exposure to external AI services."
            )

        if result.factors.external_connection_factor > 0.6:
            parts.append(
                "Elevated external connection factor suggests broad external access."
            )

        if result.sensitivity_likelihood > 0.7:
            parts.append(
                "High sensitivity likelihood indicates this entity likely contains protected data."
            )

        return " ".join(parts)

    def _generate_recommendations(
        self,
        result: ScoringResult,
    ) -> List[Recommendation]:
        """Generate actionable recommendations based on scoring factors."""
        recommendations = []
        factors = result.factors

        if factors.external_connection_factor > 0.6:
            recommendations.append(
                Recommendation(
                    action="reduce_external_access",
                    description="Review and reduce external connections to minimize exposure surface",
                    priority="high" if factors.external_connection_factor > 0.8 else "medium",
                    effort="medium",
                )
            )

        if factors.ai_integration_factor > 0.5:
            recommendations.append(
                Recommendation(
                    action="review_ai_permissions",
                    description="Audit AI tool permissions and implement least-privilege access",
                    priority="high",
                    effort="low",
                )
            )

        if factors.privilege_level_factor > 0.6:
            recommendations.append(
                Recommendation(
                    action="enforce_least_privilege",
                    description="Review privilege levels and enforce least-privilege principle",
                    priority="high" if factors.privilege_level_factor > 0.8 else "medium",
                    effort="medium",
                )
            )

        if factors.public_exposure_factor > 0.5:
            recommendations.append(
                Recommendation(
                    action="restrict_public_access",
                    description="Consider restricting public accessibility or adding authentication",
                    priority="high",
                    effort="medium",
                )
            )

        if result.sensitivity_likelihood > 0.7:
            recommendations.append(
                Recommendation(
                    action="implement_data_protection",
                    description="Implement encryption, masking, or additional access controls for sensitive data",
                    priority="high",
                    effort="high",
                )
            )

        if result.volatility_score > 0.6:
            recommendations.append(
                Recommendation(
                    action="investigate_changes",
                    description="Investigate recent changes causing risk score volatility",
                    priority="medium",
                    effort="low",
                )
            )

        # Default recommendation if none apply
        if not recommendations:
            recommendations.append(
                Recommendation(
                    action="monitor",
                    description="Continue monitoring; schedule periodic review",
                    priority="low",
                    effort="low",
                )
            )

        return recommendations

    def _build_evidence(
        self,
        events: List[Dict[str, Any]],
    ) -> List[EventRef]:
        """Build evidence list from related events."""
        evidence = []

        for event in events[:10]:  # Limit to 10 most relevant events
            evidence.append(
                EventRef(
                    event_id=event.get("event_id", "unknown"),
                    event_type=event.get("event_type", "unknown"),
                    timestamp=event.get(
                        "timestamp",
                        datetime.now(timezone.utc),
                    ),
                    summary=event.get("summary", event.get("event_type", "")),
                )
            )

        return evidence

    def _generate_tags(
        self,
        result: ScoringResult,
        entity_type: str,
    ) -> List[str]:
        """Generate searchable tags for the finding."""
        tags = [f"entity-type-{entity_type}", result.risk_level]

        if result.factors.ai_integration_factor > 0.3:
            tags.append("ai-exposure")

        if result.sensitivity_likelihood > 0.5:
            tags.append("sensitive-data")

        if result.factors.external_connection_factor > 0.5:
            tags.append("external-exposure")

        if result.volatility_score > 0.6:
            tags.append("volatile")

        return tags

    def _severity_for_value(self, value: float) -> FindingSeverity:
        """Map a value to a severity level."""
        if value >= CRITICAL_THRESHOLD:
            return FindingSeverity.CRITICAL
        elif value >= HIGH_THRESHOLD:
            return FindingSeverity.HIGH
        elif value >= MEDIUM_THRESHOLD:
            return FindingSeverity.MEDIUM
        else:
            return FindingSeverity.LOW
