"""
Anomaly Detection Module
========================

Detect anomalous behavior and risk deviations using statistical and ML methods.

Methods include:
    - Z-score based outlier detection
    - Isolation Forest for high-dimensional anomalies
    - Time-series anomaly detection for risk trajectories
    - Graph-based anomaly detection for unusual connectivity

Author: PDRI Team
Version: 1.0.0
"""

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple
import numpy as np


class AnomalyType(Enum):
    """Types of detectable anomalies."""
    STATISTICAL_OUTLIER = "statistical_outlier"
    BEHAVIORAL_CHANGE = "behavioral_change"
    RISK_SPIKE = "risk_spike"
    CONNECTIVITY_ANOMALY = "connectivity_anomaly"
    TEMPORAL_ANOMALY = "temporal_anomaly"
    ISOLATION_FOREST = "isolation_forest"


class AnomalyScore(Enum):
    """Anomaly severity scores."""
    NORMAL = "normal"
    MILD = "mild"
    MODERATE = "moderate"
    SEVERE = "severe"
    EXTREME = "extreme"


@dataclass
class Anomaly:
    """A detected anomaly."""
    anomaly_id: str
    anomaly_type: AnomalyType
    score: AnomalyScore
    raw_score: float  # -1 to 1, where higher is more anomalous
    node_id: str
    timestamp: datetime
    features_flagged: Dict[str, float]
    baseline_values: Dict[str, float]
    description: str
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "anomaly_id": self.anomaly_id,
            "anomaly_type": self.anomaly_type.value,
            "score": self.score.value,
            "raw_score": self.raw_score,
            "node_id": self.node_id,
            "timestamp": self.timestamp.isoformat(),
            "features_flagged": self.features_flagged,
            "baseline_values": self.baseline_values,
            "description": self.description,
        }


class AnomalyDetector:
    """
    Detect anomalies in risk data using multiple techniques.
    
    Detection methods:
    1. Z-Score: Flag values beyond N standard deviations
    2. IQR: Interquartile range method for robust outliers
    3. Isolation Forest: Unsupervised ML for complex anomalies
    4. Temporal: Detect sudden changes in time-series
    
    Example:
        detector = AnomalyDetector()
        detector.fit(historical_vectors)
        anomalies = detector.detect(current_vectors)
    """
    
    # Features to monitor for anomalies
    MONITORED_FEATURES = [
        "current_risk_score",
        "exposure_score",
        "sensitivity_score",
        "risk_score_7d_std",
        "access_frequency_24h",
        "inbound_connection_count",
        "outbound_connection_count",
        "exposure_path_count",
        "anomalous_access_count",
    ]
    
    def __init__(
        self,
        z_threshold: float = 3.0,
        contamination: float = 0.05,
        use_isolation_forest: bool = True
    ):
        """
        Initialize anomaly detector.
        
        Args:
            z_threshold: Z-score threshold for statistical outliers
            contamination: Expected proportion of outliers (for Isolation Forest)
            use_isolation_forest: Whether to use Isolation Forest
        """
        self.z_threshold = z_threshold
        self.contamination = contamination
        self.use_isolation_forest = use_isolation_forest
        
        # Baseline statistics (computed during fit)
        self._means: Dict[str, float] = {}
        self._stds: Dict[str, float] = {}
        self._medians: Dict[str, float] = {}
        self._q1: Dict[str, float] = {}
        self._q3: Dict[str, float] = {}
        
        # Isolation Forest model
        self._isolation_forest = None
        
        # Counter for anomaly IDs
        self._anomaly_counter = 0
        
        # Fitted flag
        self._is_fitted = False
    
    def fit(self, feature_vectors: List[Any]) -> "AnomalyDetector":
        """
        Fit the detector on historical data.
        
        Args:
            feature_vectors: Historical FeatureVector objects
        
        Returns:
            Self for chaining
        """
        if not feature_vectors:
            return self
        
        # Extract features into arrays
        feature_data: Dict[str, List[float]] = {name: [] for name in self.MONITORED_FEATURES}
        
        for vector in feature_vectors:
            for name in self.MONITORED_FEATURES:
                if name in vector.features:
                    feature_data[name].append(vector.features[name])
        
        # Compute statistics for each feature
        for name, values in feature_data.items():
            if values:
                arr = np.array(values)
                self._means[name] = float(np.mean(arr))
                self._stds[name] = float(np.std(arr))
                self._medians[name] = float(np.median(arr))
                self._q1[name] = float(np.percentile(arr, 25))
                self._q3[name] = float(np.percentile(arr, 75))
        
        # Fit Isolation Forest if enabled
        if self.use_isolation_forest and len(feature_vectors) >= 10:
            self._fit_isolation_forest(feature_vectors)
        
        self._is_fitted = True
        return self
    
    def _fit_isolation_forest(self, feature_vectors: List[Any]) -> None:
        """Fit Isolation Forest model."""
        try:
            from sklearn.ensemble import IsolationForest
            
            # Prepare feature matrix
            X = []
            for vector in feature_vectors:
                row = [vector.features.get(name, 0.0) for name in self.MONITORED_FEATURES]
                X.append(row)
            
            X = np.array(X)
            
            self._isolation_forest = IsolationForest(
                contamination=self.contamination,
                random_state=42,
                n_estimators=100,
            )
            self._isolation_forest.fit(X)
        except ImportError:
            # sklearn not available
            self._isolation_forest = None
    
    def detect(self, feature_vectors: List[Any]) -> List[Anomaly]:
        """
        Detect anomalies in feature vectors.
        
        Args:
            feature_vectors: Current FeatureVector objects to check
        
        Returns:
            List of detected Anomalies
        """
        if not self._is_fitted:
            # Use default detection without baseline
            return self._detect_without_baseline(feature_vectors)
        
        anomalies = []
        
        for vector in feature_vectors:
            # Z-score detection
            z_anomalies = self._detect_zscore_anomalies(vector)
            anomalies.extend(z_anomalies)
            
            # IQR detection
            iqr_anomalies = self._detect_iqr_anomalies(vector)
            anomalies.extend(iqr_anomalies)
            
            # Isolation Forest detection
            if self._isolation_forest is not None:
                if_anomalies = self._detect_isolation_forest_anomalies(vector)
                anomalies.extend(if_anomalies)
        
        # Deduplicate (keep highest severity)
        anomalies = self._deduplicate_anomalies(anomalies)
        
        return anomalies
    
    def detect_for_node(self, feature_vector: Any) -> List[Anomaly]:
        """Detect anomalies for a single node."""
        return self.detect([feature_vector])
    
    def _detect_zscore_anomalies(self, vector: Any) -> List[Anomaly]:
        """Detect anomalies using z-score method."""
        anomalies = []
        features_flagged = {}
        baseline_values = {}
        
        for name in self.MONITORED_FEATURES:
            if name not in vector.features or name not in self._means:
                continue
            
            value = vector.features[name]
            mean = self._means[name]
            std = self._stds[name]
            
            if std == 0:
                continue
            
            z_score = abs(value - mean) / std
            
            if z_score >= self.z_threshold:
                features_flagged[name] = value
                baseline_values[name] = mean
        
        if features_flagged:
            # Calculate aggregate anomaly score
            raw_score = sum(
                abs(v - baseline_values[k]) / (self._stds.get(k, 1) + 1e-8)
                for k, v in features_flagged.items()
            ) / len(features_flagged)
            
            # Normalize to 0-1
            raw_score = min(1.0, raw_score / 10)
            
            self._anomaly_counter += 1
            anomalies.append(Anomaly(
                anomaly_id=f"ano-z-{self._anomaly_counter:06d}",
                anomaly_type=AnomalyType.STATISTICAL_OUTLIER,
                score=self._score_from_raw(raw_score),
                raw_score=raw_score,
                node_id=vector.node_id,
                timestamp=vector.timestamp,
                features_flagged=features_flagged,
                baseline_values=baseline_values,
                description=f"Statistical outlier: {len(features_flagged)} features exceed {self.z_threshold}σ threshold",
            ))
        
        return anomalies
    
    def _detect_iqr_anomalies(self, vector: Any) -> List[Anomaly]:
        """Detect anomalies using IQR method."""
        anomalies = []
        features_flagged = {}
        baseline_values = {}
        
        for name in self.MONITORED_FEATURES:
            if name not in vector.features or name not in self._q1:
                continue
            
            value = vector.features[name]
            q1 = self._q1[name]
            q3 = self._q3[name]
            iqr = q3 - q1
            
            if iqr == 0:
                continue
            
            lower_bound = q1 - 1.5 * iqr
            upper_bound = q3 + 1.5 * iqr
            
            if value < lower_bound or value > upper_bound:
                # Check if extreme (3 * IQR)
                extreme_lower = q1 - 3 * iqr
                extreme_upper = q3 + 3 * iqr
                
                if value < extreme_lower or value > extreme_upper:
                    # Extreme outlier
                    features_flagged[name] = value
                    baseline_values[name] = self._medians[name]
        
        if features_flagged:
            raw_score = min(1.0, len(features_flagged) / 3)
            
            self._anomaly_counter += 1
            anomalies.append(Anomaly(
                anomaly_id=f"ano-iqr-{self._anomaly_counter:06d}",
                anomaly_type=AnomalyType.BEHAVIORAL_CHANGE,
                score=self._score_from_raw(raw_score),
                raw_score=raw_score,
                node_id=vector.node_id,
                timestamp=vector.timestamp,
                features_flagged=features_flagged,
                baseline_values=baseline_values,
                description=f"Behavioral deviation: {len(features_flagged)} features outside IQR bounds",
            ))
        
        return anomalies
    
    def _detect_isolation_forest_anomalies(self, vector: Any) -> List[Anomaly]:
        """Detect anomalies using Isolation Forest."""
        anomalies = []
        
        # Prepare feature row
        X = [[vector.features.get(name, 0.0) for name in self.MONITORED_FEATURES]]
        X = np.array(X)
        
        # Get prediction (-1 = anomaly, 1 = normal)
        prediction = self._isolation_forest.predict(X)[0]
        
        if prediction == -1:
            # Get anomaly score (more negative = more anomalous)
            score = self._isolation_forest.score_samples(X)[0]
            raw_score = -score  # Convert to positive (higher = more anomalous)
            
            # Normalize to 0-1 (typical scores range from -0.5 to 0.5)
            raw_score = min(1.0, max(0.0, (raw_score + 0.5)))
            
            self._anomaly_counter += 1
            anomalies.append(Anomaly(
                anomaly_id=f"ano-if-{self._anomaly_counter:06d}",
                anomaly_type=AnomalyType.ISOLATION_FOREST,
                score=self._score_from_raw(raw_score),
                raw_score=raw_score,
                node_id=vector.node_id,
                timestamp=vector.timestamp,
                features_flagged=vector.features,
                baseline_values={},
                description="Multi-dimensional anomaly detected by Isolation Forest",
            ))
        
        return anomalies
    
    def _detect_without_baseline(self, feature_vectors: List[Any]) -> List[Anomaly]:
        """Detect obvious anomalies without historical baseline."""
        anomalies = []
        
        # Hard-coded thresholds for obvious anomalies
        thresholds = {
            "current_risk_score": 90.0,
            "exposure_score": 0.9,
            "access_frequency_24h": 5000.0,
            "anomalous_access_count": 5.0,
        }
        
        for vector in feature_vectors:
            features_flagged = {}
            
            for name, threshold in thresholds.items():
                if name in vector.features and vector.features[name] >= threshold:
                    features_flagged[name] = vector.features[name]
            
            if features_flagged:
                raw_score = 0.7  # Default high score for threshold violations
                
                self._anomaly_counter += 1
                anomalies.append(Anomaly(
                    anomaly_id=f"ano-th-{self._anomaly_counter:06d}",
                    anomaly_type=AnomalyType.RISK_SPIKE,
                    score=AnomalyScore.SEVERE,
                    raw_score=raw_score,
                    node_id=vector.node_id,
                    timestamp=vector.timestamp,
                    features_flagged=features_flagged,
                    baseline_values=thresholds,
                    description=f"Threshold violation: {len(features_flagged)} features exceed critical thresholds",
                ))
        
        return anomalies
    
    def _score_from_raw(self, raw_score: float) -> AnomalyScore:
        """Convert raw score to categorical score."""
        if raw_score >= 0.9:
            return AnomalyScore.EXTREME
        elif raw_score >= 0.7:
            return AnomalyScore.SEVERE
        elif raw_score >= 0.5:
            return AnomalyScore.MODERATE
        elif raw_score >= 0.3:
            return AnomalyScore.MILD
        else:
            return AnomalyScore.NORMAL
    
    def _deduplicate_anomalies(self, anomalies: List[Anomaly]) -> List[Anomaly]:
        """Remove duplicate anomalies, keeping highest severity."""
        unique = {}
        
        for anomaly in anomalies:
            key = (anomaly.node_id, anomaly.anomaly_type)
            
            if key not in unique or anomaly.raw_score > unique[key].raw_score:
                unique[key] = anomaly
        
        return list(unique.values())
    
    def detect_risk_spike(
        self,
        node_id: str,
        current_score: float,
        historical_scores: List[Tuple[datetime, float]],
        spike_threshold: float = 20.0
    ) -> Optional[Anomaly]:
        """
        Detect sudden risk score spikes.
        
        Args:
            node_id: Node identifier
            current_score: Current risk score
            historical_scores: Historical (timestamp, score) pairs
            spike_threshold: Minimum score increase to flag
        
        Returns:
            Anomaly if spike detected, None otherwise
        """
        if len(historical_scores) < 2:
            return None
        
        # Get recent average
        recent_scores = [s for _, s in historical_scores[-7:]]  # Last 7 data points
        avg_score = np.mean(recent_scores)
        
        spike = current_score - avg_score
        
        if spike >= spike_threshold:
            raw_score = min(1.0, spike / 50)
            
            self._anomaly_counter += 1
            return Anomaly(
                anomaly_id=f"ano-spike-{self._anomaly_counter:06d}",
                anomaly_type=AnomalyType.RISK_SPIKE,
                score=self._score_from_raw(raw_score),
                raw_score=raw_score,
                node_id=node_id,
                timestamp=datetime.now(timezone.utc),
                features_flagged={"current_risk_score": current_score},
                baseline_values={"avg_score": float(avg_score)},
                description=f"Risk score spike: +{spike:.1f} points above 7-day average",
            )
        
        return None
