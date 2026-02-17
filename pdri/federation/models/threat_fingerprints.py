"""
Risk Fingerprinting Models
==========================

Anonymized risk signatures for cross-organization threat sharing.

Author: PDRI Team
Version: 1.0.0
"""

from dataclasses import dataclass
from datetime import datetime
from typing import Any, Dict, List, Optional
import hashlib
import json
import numpy as np


@dataclass
class ThreatFingerprint:
    """An anonymized threat/risk fingerprint."""
    fingerprint_id: str
    pattern_type: str
    feature_signature: tuple
    severity: str
    first_seen: datetime
    last_seen: datetime
    observation_count: int
    source_count: int  # Number of orgs that reported
    confidence: float
    metadata: Dict[str, Any]
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "fingerprint_id": self.fingerprint_id,
            "pattern_type": self.pattern_type,
            "feature_signature": self.feature_signature,
            "severity": self.severity,
            "first_seen": self.first_seen.isoformat(),
            "last_seen": self.last_seen.isoformat(),
            "observation_count": self.observation_count,
            "source_count": self.source_count,
            "confidence": self.confidence,
            "metadata": self.metadata,
        }


class ThreatFingerprintDatabase:
    """
    Database of known threat fingerprints.
    
    Features:
    - Store anonymized threat patterns
    - Match new observations against known threats
    - Track threat prevalence across organizations
    - Confidence scoring based on observations
    
    Example:
        db = ThreatFingerprintDatabase()
        db.add_fingerprint(fingerprint)
        matches = db.find_matches(new_features)
    """
    
    def __init__(self):
        self._fingerprints: Dict[str, ThreatFingerprint] = {}
        self._signature_index: Dict[tuple, str] = {}
    
    def add_fingerprint(
        self,
        pattern_type: str,
        feature_signature: tuple,
        severity: str = "medium",
        source_id: str = "unknown"
    ) -> ThreatFingerprint:
        """
        Add or update a threat fingerprint.
        
        Args:
            pattern_type: Type of threat pattern
            feature_signature: Tuple of feature categories
            severity: Threat severity
            source_id: Anonymized source identifier
        
        Returns:
            Created or updated ThreatFingerprint
        """
        # Create fingerprint ID from signature
        fp_id = self._create_fingerprint_id(pattern_type, feature_signature)
        
        if fp_id in self._fingerprints:
            # Update existing
            fp = self._fingerprints[fp_id]
            fp.last_seen = datetime.utcnow()
            fp.observation_count += 1
            # Increment source count if new source
            fp.source_count = min(fp.source_count + 1, 1000)  # Cap
            fp.confidence = self._compute_confidence(fp)
            return fp
        
        # Create new
        fp = ThreatFingerprint(
            fingerprint_id=fp_id,
            pattern_type=pattern_type,
            feature_signature=feature_signature,
            severity=severity,
            first_seen=datetime.utcnow(),
            last_seen=datetime.utcnow(),
            observation_count=1,
            source_count=1,
            confidence=0.5,
            metadata={"first_source": source_id[:3] + "***"},
        )
        
        self._fingerprints[fp_id] = fp
        self._signature_index[feature_signature] = fp_id
        
        return fp
    
    def _create_fingerprint_id(
        self,
        pattern_type: str,
        signature: tuple
    ) -> str:
        """Create deterministic fingerprint ID."""
        content = json.dumps({
            "type": pattern_type,
            "sig": signature,
        }, sort_keys=True)
        return hashlib.sha256(content.encode()).hexdigest()[:16]
    
    def _compute_confidence(self, fp: ThreatFingerprint) -> float:
        """Compute confidence based on observations."""
        # More observations = higher confidence
        obs_factor = min(1.0, fp.observation_count / 100)
        
        # More sources = higher confidence
        source_factor = min(1.0, fp.source_count / 10)
        
        # Recent = higher confidence
        age_days = (datetime.utcnow() - fp.last_seen).days
        recency_factor = max(0, 1 - age_days / 365)
        
        return 0.3 * obs_factor + 0.5 * source_factor + 0.2 * recency_factor
    
    def find_matches(
        self,
        features: np.ndarray,
        top_k: int = 5
    ) -> List[ThreatFingerprint]:
        """
        Find fingerprints matching given features.
        
        Args:
            features: Feature array to match
            top_k: Maximum matches to return
        
        Returns:
            List of matching fingerprints
        """
        # Create signature from features
        signature = self._features_to_signature(features)
        
        # Exact match
        if signature in self._signature_index:
            fp_id = self._signature_index[signature]
            return [self._fingerprints[fp_id]]
        
        # Fuzzy match - find similar signatures
        matches = []
        for sig, fp_id in self._signature_index.items():
            similarity = self._signature_similarity(signature, sig)
            if similarity > 0.8:
                fp = self._fingerprints[fp_id]
                matches.append((similarity, fp))
        
        # Sort by similarity
        matches.sort(key=lambda x: x[0], reverse=True)
        return [fp for _, fp in matches[:top_k]]
    
    def _features_to_signature(self, features: np.ndarray) -> tuple:
        """Convert features to categorical signature."""
        signature = []
        for val in features[:10]:  # First 10 features
            if val > 0.7:
                signature.append("high")
            elif val > 0.3:
                signature.append("med")
            else:
                signature.append("low")
        return tuple(signature)
    
    def _signature_similarity(self, sig1: tuple, sig2: tuple) -> float:
        """Compute similarity between two signatures."""
        if len(sig1) != len(sig2):
            return 0.0
        
        matches = sum(1 for a, b in zip(sig1, sig2) if a == b)
        return matches / len(sig1)
    
    def get_fingerprint(self, fp_id: str) -> Optional[ThreatFingerprint]:
        """Get fingerprint by ID."""
        return self._fingerprints.get(fp_id)
    
    def list_fingerprints(
        self,
        pattern_type: Optional[str] = None,
        min_confidence: float = 0.0
    ) -> List[ThreatFingerprint]:
        """List all fingerprints with optional filtering."""
        results = list(self._fingerprints.values())
        
        if pattern_type:
            results = [fp for fp in results if fp.pattern_type == pattern_type]
        
        results = [fp for fp in results if fp.confidence >= min_confidence]
        
        return sorted(results, key=lambda fp: fp.confidence, reverse=True)
    
    def import_fingerprints(self, fingerprints: List[Dict[str, Any]]) -> int:
        """
        Import fingerprints from federation.
        
        Args:
            fingerprints: List of fingerprint dictionaries
        
        Returns:
            Number of fingerprints added/updated
        """
        count = 0
        for fp_data in fingerprints:
            self.add_fingerprint(
                pattern_type=fp_data.get("pattern_type", "unknown"),
                feature_signature=tuple(fp_data.get("feature_signature", [])),
                severity=fp_data.get("severity", "medium"),
            )
            count += 1
        return count
    
    def export_fingerprints(self) -> List[Dict[str, Any]]:
        """Export all fingerprints for sharing."""
        return [fp.to_dict() for fp in self._fingerprints.values()]
