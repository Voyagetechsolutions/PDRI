"""
Risk Pattern Detection Module
============================

Detect and classify risk patterns using ML techniques.

Patterns are learned from historical data and used to:
    - Identify known risk signatures
    - Classify emerging threats
    - Correlate related risks across the graph

Author: PDRI Team
Version: 1.0.0
"""

from dataclasses import dataclass
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple
import numpy as np


class PatternType(Enum):
    """Types of risk patterns."""
    DATA_EXFILTRATION = "data_exfiltration"
    INSIDER_THREAT = "insider_threat"
    VENDOR_COMPROMISE = "vendor_compromise"
    AI_DATA_LEAK = "ai_data_leak"
    PERMISSION_CREEP = "permission_creep"
    SHADOW_IT = "shadow_it"
    COMPLIANCE_DRIFT = "compliance_drift"
    ATTACK_CHAIN = "attack_chain"


class PatternSeverity(Enum):
    """Severity levels for detected patterns."""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class RiskPattern:
    """A detected risk pattern."""
    pattern_id: str
    pattern_type: PatternType
    severity: PatternSeverity
    confidence: float  # 0-1 confidence score
    affected_nodes: List[str]
    description: str
    timestamp: datetime
    features_matched: Dict[str, float]
    recommended_actions: List[str]
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "pattern_id": self.pattern_id,
            "pattern_type": self.pattern_type.value,
            "severity": self.severity.value,
            "confidence": self.confidence,
            "affected_nodes": self.affected_nodes,
            "description": self.description,
            "timestamp": self.timestamp.isoformat(),
            "features_matched": self.features_matched,
            "recommended_actions": self.recommended_actions,
        }


@dataclass
class PatternSignature:
    """A signature that defines a known risk pattern."""
    signature_id: str
    pattern_type: PatternType
    name: str
    description: str
    feature_thresholds: Dict[str, Tuple[Optional[float], Optional[float]]]  # feature -> (min, max)
    required_features: List[str]
    severity: PatternSeverity
    recommended_actions: List[str]


class RiskPatternDetector:
    """
    Detect risk patterns using rule-based and ML techniques.
    
    The detector uses:
    1. Signature matching: Known patterns with predefined thresholds
    2. Clustering: Find similar nodes that may share risk
    3. Classification: ML model to classify new patterns
    
    Example:
        detector = RiskPatternDetector()
        patterns = await detector.detect_patterns(feature_vectors)
    """
    
    # Predefined risk signatures
    DEFAULT_SIGNATURES: List[PatternSignature] = [
        PatternSignature(
            signature_id="sig-001",
            pattern_type=PatternType.AI_DATA_LEAK,
            name="AI Tool Data Exposure",
            description="Sensitive data flowing to unvetted AI tools",
            feature_thresholds={
                "is_ai_tool": (1.0, None),
                "sensitivity_score": (0.7, None),
                "external_connection_count": (1.0, None),
            },
            required_features=["is_ai_tool", "sensitivity_score"],
            severity=PatternSeverity.HIGH,
            recommended_actions=[
                "Review AI tool data access permissions",
                "Implement data classification controls",
                "Enable data loss prevention for AI endpoints",
            ],
        ),
        PatternSignature(
            signature_id="sig-002",
            pattern_type=PatternType.DATA_EXFILTRATION,
            name="High Risk Data Exfiltration",
            description="Unusual data flow patterns suggesting exfiltration",
            feature_thresholds={
                "exposure_path_count": (10.0, None),
                "sensitivity_score": (0.8, None),
                "access_frequency_24h": (500.0, None),
            },
            required_features=["exposure_path_count", "sensitivity_score"],
            severity=PatternSeverity.CRITICAL,
            recommended_actions=[
                "Investigate recent access patterns",
                "Review user activity logs",
                "Consider temporary access revocation",
            ],
        ),
        PatternSignature(
            signature_id="sig-003",
            pattern_type=PatternType.VENDOR_COMPROMISE,
            name="Vendor Risk Escalation",
            description="Third-party vendor with elevated risk indicators",
            feature_thresholds={
                "is_external_service": (1.0, None),
                "risk_score_trend": (0.5, None),
                "current_risk_score": (70.0, None),
            },
            required_features=["is_external_service", "current_risk_score"],
            severity=PatternSeverity.HIGH,
            recommended_actions=[
                "Contact vendor security team",
                "Review vendor access scope",
                "Evaluate alternative vendors",
            ],
        ),
        PatternSignature(
            signature_id="sig-004",
            pattern_type=PatternType.PERMISSION_CREEP,
            name="Permission Escalation",
            description="Gradual increase in permissions beyond baseline",
            feature_thresholds={
                "inbound_connection_count": (50.0, None),
                "changes_last_30d": (20.0, None),
                "risk_score_7d_std": (10.0, None),
            },
            required_features=["inbound_connection_count", "changes_last_30d"],
            severity=PatternSeverity.MEDIUM,
            recommended_actions=[
                "Audit current permissions",
                "Review access request history",
                "Implement least privilege principle",
            ],
        ),
        PatternSignature(
            signature_id="sig-005",
            pattern_type=PatternType.SHADOW_IT,
            name="Unmanaged Service Detection",
            description="Detected usage of unmanaged or shadow IT services",
            feature_thresholds={
                "is_external_service": (1.0, None),
                "betweenness_centrality": (0.3, None),
                "unique_accessor_count": (10.0, None),
            },
            required_features=["is_external_service"],
            severity=PatternSeverity.MEDIUM,
            recommended_actions=[
                "Identify service owner",
                "Assess security posture",
                "Consider onboarding to managed services",
            ],
        ),
        PatternSignature(
            signature_id="sig-006",
            pattern_type=PatternType.COMPLIANCE_DRIFT,
            name="Compliance Configuration Drift",
            description="Configuration has drifted from compliance baseline",
            feature_thresholds={
                "volatility_score": (0.7, None),
                "changes_last_30d": (15.0, None),
                "risk_score_trend": (0.3, None),
            },
            required_features=["volatility_score"],
            severity=PatternSeverity.HIGH,
            recommended_actions=[
                "Compare against compliance baseline",
                "Remediate detected deviations",
                "Implement drift detection alerts",
            ],
        ),
    ]
    
    def __init__(
        self,
        signatures: Optional[List[PatternSignature]] = None,
        ml_model: Optional[Any] = None
    ):
        """
        Initialize pattern detector.
        
        Args:
            signatures: Custom signatures to use (appended to defaults)
            ml_model: Optional trained ML model for pattern classification
        """
        self.signatures = self.DEFAULT_SIGNATURES.copy()
        if signatures:
            self.signatures.extend(signatures)
        self.ml_model = ml_model
        self._pattern_counter = 0
    
    async def detect_patterns(
        self,
        feature_vectors: List[Any],  # List[FeatureVector]
        use_ml: bool = True
    ) -> List[RiskPattern]:
        """
        Detect risk patterns from feature vectors.
        
        Args:
            feature_vectors: List of FeatureVector objects
            use_ml: Whether to use ML model in addition to signatures
        
        Returns:
            List of detected RiskPatterns
        """
        patterns = []
        
        # Signature-based detection
        for vector in feature_vectors:
            for signature in self.signatures:
                if self._matches_signature(vector, signature):
                    pattern = self._create_pattern_from_signature(vector, signature)
                    patterns.append(pattern)
        
        # ML-based detection (if model available)
        if use_ml and self.ml_model is not None:
            ml_patterns = await self._detect_with_ml(feature_vectors)
            patterns.extend(ml_patterns)
        
        # Deduplicate and merge overlapping patterns
        patterns = self._deduplicate_patterns(patterns)
        
        return patterns
    
    async def detect_for_node(
        self,
        feature_vector: Any  # FeatureVector
    ) -> List[RiskPattern]:
        """
        Detect patterns for a single node.
        
        Args:
            feature_vector: FeatureVector for the node
        
        Returns:
            List of detected patterns
        """
        return await self.detect_patterns([feature_vector])
    
    def _matches_signature(
        self,
        vector: Any,  # FeatureVector
        signature: PatternSignature
    ) -> bool:
        """Check if a feature vector matches a signature."""
        features = vector.features
        
        # Check required features exist
        for required in signature.required_features:
            if required not in features:
                return False
        
        # Check thresholds
        for feature_name, (min_val, max_val) in signature.feature_thresholds.items():
            if feature_name not in features:
                continue
            
            value = features[feature_name]
            
            if min_val is not None and value < min_val:
                return False
            if max_val is not None and value > max_val:
                return False
        
        return True
    
    def _create_pattern_from_signature(
        self,
        vector: Any,  # FeatureVector
        signature: PatternSignature
    ) -> RiskPattern:
        """Create a RiskPattern from matched signature."""
        self._pattern_counter += 1
        
        # Calculate confidence based on how strongly features match
        confidence = self._calculate_signature_confidence(vector, signature)
        
        # Extract matched features
        features_matched = {}
        for feature_name in signature.feature_thresholds:
            if feature_name in vector.features:
                features_matched[feature_name] = vector.features[feature_name]
        
        return RiskPattern(
            pattern_id=f"pat-{self._pattern_counter:06d}",
            pattern_type=signature.pattern_type,
            severity=signature.severity,
            confidence=confidence,
            affected_nodes=[vector.node_id],
            description=signature.description,
            timestamp=vector.timestamp,
            features_matched=features_matched,
            recommended_actions=signature.recommended_actions,
        )
    
    def _calculate_signature_confidence(
        self,
        vector: Any,  # FeatureVector
        signature: PatternSignature
    ) -> float:
        """Calculate confidence score for signature match."""
        scores = []
        
        for feature_name, (min_val, max_val) in signature.feature_thresholds.items():
            if feature_name not in vector.features:
                continue
            
            value = vector.features[feature_name]
            
            # Calculate how far above threshold
            if min_val is not None:
                if value >= min_val:
                    # Score based on how much above threshold
                    excess = value - min_val
                    scores.append(min(1.0, 0.5 + excess * 0.5))
                else:
                    scores.append(0.0)
            
            if max_val is not None:
                if value <= max_val:
                    excess = max_val - value
                    scores.append(min(1.0, 0.5 + excess * 0.5))
                else:
                    scores.append(0.0)
        
        return float(np.mean(scores)) if scores else 0.5
    
    async def _detect_with_ml(
        self,
        feature_vectors: List[Any]
    ) -> List[RiskPattern]:
        """Detect patterns using ML model."""
        if not self.ml_model:
            return []
        
        # Prepare features for ML
        X = np.array([v.to_numpy() for v in feature_vectors])
        
        # Get predictions
        predictions = self.ml_model.predict(X)
        probabilities = self.ml_model.predict_proba(X)
        
        patterns = []
        for i, (vector, pred, prob) in enumerate(zip(feature_vectors, predictions, probabilities)):
            if pred != 0:  # 0 = no pattern
                pattern_type = PatternType(pred) if isinstance(pred, str) else PatternType.ATTACK_CHAIN
                confidence = float(max(prob))
                
                self._pattern_counter += 1
                patterns.append(RiskPattern(
                    pattern_id=f"pat-ml-{self._pattern_counter:06d}",
                    pattern_type=pattern_type,
                    severity=self._infer_severity(confidence),
                    confidence=confidence,
                    affected_nodes=[vector.node_id],
                    description=f"ML-detected {pattern_type.value} pattern",
                    timestamp=vector.timestamp,
                    features_matched=vector.features,
                    recommended_actions=["Review ML detection", "Validate findings"],
                ))
        
        return patterns
    
    def _infer_severity(self, confidence: float) -> PatternSeverity:
        """Infer severity from confidence score."""
        if confidence >= 0.9:
            return PatternSeverity.CRITICAL
        elif confidence >= 0.7:
            return PatternSeverity.HIGH
        elif confidence >= 0.5:
            return PatternSeverity.MEDIUM
        else:
            return PatternSeverity.LOW
    
    def _deduplicate_patterns(
        self,
        patterns: List[RiskPattern]
    ) -> List[RiskPattern]:
        """Remove duplicate patterns, keeping highest confidence."""
        unique = {}
        
        for pattern in patterns:
            key = (pattern.pattern_type, tuple(sorted(pattern.affected_nodes)))
            
            if key not in unique or pattern.confidence > unique[key].confidence:
                unique[key] = pattern
        
        return list(unique.values())
    
    def add_signature(self, signature: PatternSignature) -> None:
        """Add a new pattern signature."""
        self.signatures.append(signature)
    
    def get_signatures_by_type(
        self,
        pattern_type: PatternType
    ) -> List[PatternSignature]:
        """Get all signatures for a pattern type."""
        return [s for s in self.signatures if s.pattern_type == pattern_type]
