"""
Trajectory Anomaly Detection
============================

Detect anomalies in risk trajectories using time-series methods.

Features:
    - Sudden spikes/drops
    - Trend breakpoints
    - Seasonal anomalies
    - Forecast deviation alerts

Author: PDRI Team
Version: 1.0.0
"""

from dataclasses import dataclass
from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple
import numpy as np


@dataclass
class TrajectoryAnomaly:
    """An anomaly detected in a risk trajectory."""
    anomaly_id: str
    node_id: str
    timestamp: datetime
    anomaly_type: str  # "spike", "drop", "breakpoint", "deviation"
    severity: str  # "low", "medium", "high", "critical"
    expected_value: float
    actual_value: float
    deviation: float
    description: str
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "anomaly_id": self.anomaly_id,
            "node_id": self.node_id,
            "timestamp": self.timestamp.isoformat(),
            "anomaly_type": self.anomaly_type,
            "severity": self.severity,
            "expected_value": self.expected_value,
            "actual_value": self.actual_value,
            "deviation": self.deviation,
            "description": self.description,
        }


class TrajectoryAnomalyDetector:
    """
    Detect anomalies in risk trajectories.
    
    Detects:
    - Sudden spikes: Risk jumps significantly in short time
    - Sudden drops: Unexpected risk decrease (might indicate data issues)
    - Breakpoints: Trend direction changes
    - Forecast deviations: Actual differs from predicted
    
    Example:
        detector = TrajectoryAnomalyDetector()
        anomalies = detector.detect(history, forecasted)
    """
    
    def __init__(
        self,
        spike_threshold: float = 20.0,
        drop_threshold: float = -15.0,
        deviation_z_threshold: float = 2.5
    ):
        """
        Initialize detector.
        
        Args:
            spike_threshold: Minimum score increase to flag as spike
            drop_threshold: Minimum score decrease to flag as drop
            deviation_z_threshold: Z-score threshold for deviations
        """
        self.spike_threshold = spike_threshold
        self.drop_threshold = drop_threshold
        self.deviation_z_threshold = deviation_z_threshold
        self._anomaly_counter = 0
    
    def detect(
        self,
        history: List[Tuple[datetime, float]],
        node_id: str = "unknown"
    ) -> List[TrajectoryAnomaly]:
        """
        Detect anomalies in a trajectory.
        
        Args:
            history: Historical (timestamp, score) pairs
            node_id: Node identifier
        
        Returns:
            List of detected anomalies
        """
        anomalies = []
        
        if len(history) < 3:
            return anomalies
        
        timestamps = [ts for ts, _ in history]
        scores = np.array([score for _, score in history])
        
        # Detect spikes and drops
        change_anomalies = self._detect_sudden_changes(
            timestamps, scores, node_id
        )
        anomalies.extend(change_anomalies)
        
        # Detect breakpoints
        breakpoint_anomalies = self._detect_breakpoints(
            timestamps, scores, node_id
        )
        anomalies.extend(breakpoint_anomalies)
        
        # Detect statistical outliers
        outlier_anomalies = self._detect_outliers(
            timestamps, scores, node_id
        )
        anomalies.extend(outlier_anomalies)
        
        return anomalies
    
    def detect_forecast_deviation(
        self,
        node_id: str,
        timestamp: datetime,
        forecasted: float,
        actual: float,
        historical_std: float
    ) -> Optional[TrajectoryAnomaly]:
        """
        Detect if actual value deviates significantly from forecast.
        
        Args:
            node_id: Node identifier
            timestamp: Time of observation
            forecasted: Predicted value
            actual: Observed value
            historical_std: Standard deviation of historical data
        
        Returns:
            Anomaly if deviation is significant, None otherwise
        """
        deviation = actual - forecasted
        z_score = abs(deviation) / (historical_std + 1e-8)
        
        if z_score >= self.deviation_z_threshold:
            self._anomaly_counter += 1
            
            severity = self._calculate_severity(z_score)
            
            return TrajectoryAnomaly(
                anomaly_id=f"traj-dev-{self._anomaly_counter:06d}",
                node_id=node_id,
                timestamp=timestamp,
                anomaly_type="deviation",
                severity=severity,
                expected_value=forecasted,
                actual_value=actual,
                deviation=deviation,
                description=f"Risk score deviated {deviation:+.1f} points from forecast (z={z_score:.2f})",
            )
        
        return None
    
    def _detect_sudden_changes(
        self,
        timestamps: List[datetime],
        scores: np.ndarray,
        node_id: str
    ) -> List[TrajectoryAnomaly]:
        """Detect sudden spikes and drops."""
        anomalies = []
        
        # Calculate point-to-point changes
        changes = np.diff(scores)
        
        for i, change in enumerate(changes):
            timestamp = timestamps[i + 1]
            
            if change >= self.spike_threshold:
                self._anomaly_counter += 1
                severity = self._severity_from_change(change)
                
                anomalies.append(TrajectoryAnomaly(
                    anomaly_id=f"traj-spike-{self._anomaly_counter:06d}",
                    node_id=node_id,
                    timestamp=timestamp,
                    anomaly_type="spike",
                    severity=severity,
                    expected_value=float(scores[i]),
                    actual_value=float(scores[i + 1]),
                    deviation=float(change),
                    description=f"Risk score spiked {change:+.1f} points",
                ))
            
            elif change <= self.drop_threshold:
                self._anomaly_counter += 1
                severity = self._severity_from_change(abs(change))
                
                anomalies.append(TrajectoryAnomaly(
                    anomaly_id=f"traj-drop-{self._anomaly_counter:06d}",
                    node_id=node_id,
                    timestamp=timestamp,
                    anomaly_type="drop",
                    severity=severity,
                    expected_value=float(scores[i]),
                    actual_value=float(scores[i + 1]),
                    deviation=float(change),
                    description=f"Risk score dropped {change:.1f} points suddenly",
                ))
        
        return anomalies
    
    def _detect_breakpoints(
        self,
        timestamps: List[datetime],
        scores: np.ndarray,
        node_id: str
    ) -> List[TrajectoryAnomaly]:
        """Detect trend breakpoints."""
        anomalies = []
        
        if len(scores) < 7:
            return anomalies
        
        # Calculate rolling trends
        window = 3
        for i in range(window, len(scores) - window):
            # Trend before
            before = scores[i-window:i]
            slope_before, _ = np.polyfit(np.arange(window), before, 1)
            
            # Trend after
            after = scores[i:i+window]
            slope_after, _ = np.polyfit(np.arange(window), after, 1)
            
            # Check for reversal
            if slope_before > 0.5 and slope_after < -0.5:
                # Peak detected
                self._anomaly_counter += 1
                anomalies.append(TrajectoryAnomaly(
                    anomaly_id=f"traj-break-{self._anomaly_counter:06d}",
                    node_id=node_id,
                    timestamp=timestamps[i],
                    anomaly_type="breakpoint",
                    severity="medium",
                    expected_value=float(scores[i-1]),
                    actual_value=float(scores[i]),
                    deviation=float(scores[i] - scores[i-1]),
                    description="Trend reversal: upward to downward",
                ))
            
            elif slope_before < -0.5 and slope_after > 0.5:
                # Trough detected
                self._anomaly_counter += 1
                anomalies.append(TrajectoryAnomaly(
                    anomaly_id=f"traj-break-{self._anomaly_counter:06d}",
                    node_id=node_id,
                    timestamp=timestamps[i],
                    anomaly_type="breakpoint",
                    severity="medium",
                    expected_value=float(scores[i-1]),
                    actual_value=float(scores[i]),
                    deviation=float(scores[i] - scores[i-1]),
                    description="Trend reversal: downward to upward",
                ))
        
        return anomalies
    
    def _detect_outliers(
        self,
        timestamps: List[datetime],
        scores: np.ndarray,
        node_id: str
    ) -> List[TrajectoryAnomaly]:
        """Detect statistical outliers using z-score."""
        anomalies = []
        
        mean = np.mean(scores)
        std = np.std(scores)
        
        if std == 0:
            return anomalies
        
        for i, score in enumerate(scores):
            z_score = abs(score - mean) / std
            
            if z_score >= self.deviation_z_threshold:
                self._anomaly_counter += 1
                severity = self._calculate_severity(z_score)
                
                anomalies.append(TrajectoryAnomaly(
                    anomaly_id=f"traj-outlier-{self._anomaly_counter:06d}",
                    node_id=node_id,
                    timestamp=timestamps[i],
                    anomaly_type="outlier",
                    severity=severity,
                    expected_value=float(mean),
                    actual_value=float(score),
                    deviation=float(score - mean),
                    description=f"Statistical outlier detected (z={z_score:.2f})",
                ))
        
        return anomalies
    
    def _severity_from_change(self, change: float) -> str:
        """Determine severity from score change magnitude."""
        if change >= 40:
            return "critical"
        elif change >= 30:
            return "high"
        elif change >= 20:
            return "medium"
        else:
            return "low"
    
    def _calculate_severity(self, z_score: float) -> str:
        """Determine severity from z-score."""
        if z_score >= 4:
            return "critical"
        elif z_score >= 3:
            return "high"
        elif z_score >= 2.5:
            return "medium"
        else:
            return "low"
    
    def detect_pattern_change(
        self,
        recent_history: List[Tuple[datetime, float]],
        baseline_history: List[Tuple[datetime, float]],
        node_id: str
    ) -> Optional[TrajectoryAnomaly]:
        """
        Detect if recent behavior differs from baseline.
        
        Args:
            recent_history: Recent observations
            baseline_history: Historical baseline
            node_id: Node identifier
        
        Returns:
            Anomaly if pattern changed significantly
        """
        if not recent_history or not baseline_history:
            return None
        
        recent_scores = np.array([s for _, s in recent_history])
        baseline_scores = np.array([s for _, s in baseline_history])
        
        # Compare distributions
        recent_mean = np.mean(recent_scores)
        baseline_mean = np.mean(baseline_scores)
        baseline_std = np.std(baseline_scores)
        
        if baseline_std == 0:
            return None
        
        z_score = abs(recent_mean - baseline_mean) / baseline_std
        
        if z_score >= 2.0:  # Significant shift
            self._anomaly_counter += 1
            
            direction = "increased" if recent_mean > baseline_mean else "decreased"
            
            return TrajectoryAnomaly(
                anomaly_id=f"traj-pattern-{self._anomaly_counter:06d}",
                node_id=node_id,
                timestamp=recent_history[-1][0],
                anomaly_type="pattern_change",
                severity=self._calculate_severity(z_score),
                expected_value=baseline_mean,
                actual_value=recent_mean,
                deviation=recent_mean - baseline_mean,
                description=f"Risk pattern {direction} compared to baseline",
            )
        
        return None
