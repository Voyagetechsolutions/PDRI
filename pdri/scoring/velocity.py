"""
PDRI Risk Velocity Service
==========================

Temporal trend analysis for risk scores.

Provides:
    - Risk velocity calculation (rate of change)
    - Trend direction detection (increasing, decreasing, stable)
    - Projected risk levels based on historical trends
    - Threshold breach prediction

Example:
    velocity_service = RiskVelocityService(db)

    result = await velocity_service.calculate_velocity("entity-123")
    # {
    #     "current_score": 0.72,
    #     "velocity_7d": 0.15,
    #     "velocity_30d": 0.08,
    #     "trend": "increasing",
    #     "projected_score_14d": 0.87,
    #     "projected_severity_14d": "critical",
    #     "days_to_critical": 10
    # }

Author: PDRI Team
Version: 1.0.0
"""

import logging
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional, Tuple
from enum import Enum

import numpy as np
from sqlalchemy import select, func, and_
from sqlalchemy.ext.asyncio import AsyncSession

from pdri.db.models import ScoreHistoryDB
from pdri.config import settings


logger = logging.getLogger(__name__)


class TrendDirection(str, Enum):
    """Direction of risk trend."""
    INCREASING = "increasing"
    DECREASING = "decreasing"
    STABLE = "stable"
    VOLATILE = "volatile"  # Fluctuating without clear direction


class VelocityMetrics:
    """Container for velocity calculation results."""

    def __init__(
        self,
        entity_id: str,
        current_score: float,
        velocity_7d: float,
        velocity_30d: float,
        velocity_90d: float,
        trend: TrendDirection,
        volatility: float,
        projected_score_7d: float,
        projected_score_14d: float,
        projected_score_30d: float,
        days_to_critical: Optional[int],
        days_to_high: Optional[int],
        confidence: float,
        data_points: int,
        history: List[Dict[str, Any]],
    ):
        self.entity_id = entity_id
        self.current_score = current_score
        self.velocity_7d = velocity_7d
        self.velocity_30d = velocity_30d
        self.velocity_90d = velocity_90d
        self.trend = trend
        self.volatility = volatility
        self.projected_score_7d = projected_score_7d
        self.projected_score_14d = projected_score_14d
        self.projected_score_30d = projected_score_30d
        self.days_to_critical = days_to_critical
        self.days_to_high = days_to_high
        self.confidence = confidence
        self.data_points = data_points
        self.history = history

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for API response."""
        return {
            "entity_id": self.entity_id,
            "current_score": round(self.current_score, 4),
            "velocity": {
                "7_day": round(self.velocity_7d, 4),
                "30_day": round(self.velocity_30d, 4),
                "90_day": round(self.velocity_90d, 4),
            },
            "trend": self.trend.value,
            "volatility": round(self.volatility, 4),
            "projections": {
                "7_day": {
                    "score": round(self.projected_score_7d, 4),
                    "severity": self._score_to_severity(self.projected_score_7d),
                },
                "14_day": {
                    "score": round(self.projected_score_14d, 4),
                    "severity": self._score_to_severity(self.projected_score_14d),
                },
                "30_day": {
                    "score": round(self.projected_score_30d, 4),
                    "severity": self._score_to_severity(self.projected_score_30d),
                },
            },
            "threshold_predictions": {
                "days_to_critical": self.days_to_critical,
                "days_to_high": self.days_to_high,
            },
            "confidence": round(self.confidence, 2),
            "data_points": self.data_points,
            "history": self.history,
        }

    @staticmethod
    def _score_to_severity(score: float) -> str:
        """Convert score to severity label."""
        if score >= 0.85:
            return "critical"
        elif score >= 0.70:
            return "high"
        elif score >= 0.50:
            return "medium"
        else:
            return "low"


class RiskVelocityService:
    """
    Service for calculating risk velocity and trends.

    Risk velocity measures how fast risk is changing over time,
    enabling proactive risk management through predictions.
    """

    # Thresholds for severity levels
    THRESHOLD_CRITICAL = 0.85
    THRESHOLD_HIGH = 0.70
    THRESHOLD_MEDIUM = 0.50

    # Minimum data points for reliable prediction
    MIN_DATA_POINTS = 3

    # Trend detection thresholds
    VELOCITY_THRESHOLD_SIGNIFICANT = 0.05  # 5% change is significant
    VOLATILITY_THRESHOLD = 0.10  # High volatility if std > 10%

    def __init__(self, db: AsyncSession):
        """
        Initialize the velocity service.

        Args:
            db: Async database session
        """
        self.db = db

    async def calculate_velocity(
        self,
        entity_id: str,
        lookback_days: int = 90,
    ) -> Optional[VelocityMetrics]:
        """
        Calculate risk velocity for an entity.

        Args:
            entity_id: Entity to analyze
            lookback_days: How far back to look for history

        Returns:
            VelocityMetrics or None if insufficient data
        """
        # Get historical scores
        history = await self._get_score_history(entity_id, lookback_days)

        if not history:
            logger.debug(f"No score history for entity {entity_id}")
            return None

        # Convert to time series
        timestamps = np.array([h["calculated_at"].timestamp() for h in history])
        scores = np.array([h["composite_score"] for h in history])

        # Current score is the most recent
        current_score = scores[-1] if len(scores) > 0 else 0.0

        # Calculate velocities for different windows
        velocity_7d = self._calculate_window_velocity(timestamps, scores, days=7)
        velocity_30d = self._calculate_window_velocity(timestamps, scores, days=30)
        velocity_90d = self._calculate_window_velocity(timestamps, scores, days=90)

        # Calculate volatility (standard deviation)
        volatility = float(np.std(scores)) if len(scores) > 1 else 0.0

        # Determine trend direction
        trend = self._determine_trend(velocity_30d, volatility)

        # Project future scores
        slope, intercept, confidence = self._fit_linear_trend(timestamps, scores)

        now_ts = datetime.now(timezone.utc).timestamp()
        projected_7d = self._project_score(slope, intercept, now_ts, days=7)
        projected_14d = self._project_score(slope, intercept, now_ts, days=14)
        projected_30d = self._project_score(slope, intercept, now_ts, days=30)

        # Calculate days to threshold
        days_to_critical = self._days_to_threshold(
            current_score, slope, self.THRESHOLD_CRITICAL
        )
        days_to_high = self._days_to_threshold(
            current_score, slope, self.THRESHOLD_HIGH
        )

        # Build response history (last 30 entries for visualization)
        history_response = [
            {
                "timestamp": h["calculated_at"].isoformat(),
                "score": round(h["composite_score"], 4),
                "exposure": round(h.get("exposure_score", 0), 4),
                "volatility": round(h.get("volatility_score", 0), 4),
                "sensitivity": round(h.get("sensitivity_score", 0), 4),
            }
            for h in history[-30:]
        ]

        return VelocityMetrics(
            entity_id=entity_id,
            current_score=current_score,
            velocity_7d=velocity_7d,
            velocity_30d=velocity_30d,
            velocity_90d=velocity_90d,
            trend=trend,
            volatility=volatility,
            projected_score_7d=projected_7d,
            projected_score_14d=projected_14d,
            projected_score_30d=projected_30d,
            days_to_critical=days_to_critical,
            days_to_high=days_to_high,
            confidence=confidence,
            data_points=len(history),
            history=history_response,
        )

    async def get_high_velocity_entities(
        self,
        threshold: float = 0.10,
        limit: int = 50,
    ) -> List[Dict[str, Any]]:
        """
        Find entities with high risk velocity (fast increasing).

        Args:
            threshold: Minimum velocity to include (per 7 days)
            limit: Maximum results

        Returns:
            List of entities with high velocity
        """
        # Get all entities with recent scores
        cutoff = datetime.now(timezone.utc) - timedelta(days=30)

        stmt = (
            select(ScoreHistoryDB.entity_id)
            .where(ScoreHistoryDB.calculated_at >= cutoff)
            .group_by(ScoreHistoryDB.entity_id)
            .having(func.count(ScoreHistoryDB.id) >= self.MIN_DATA_POINTS)
        )

        result = await self.db.execute(stmt)
        entity_ids = [r[0] for r in result.all()]

        # Calculate velocity for each
        high_velocity = []
        for entity_id in entity_ids:
            metrics = await self.calculate_velocity(entity_id)
            if metrics and metrics.velocity_7d >= threshold:
                high_velocity.append({
                    "entity_id": entity_id,
                    "current_score": metrics.current_score,
                    "velocity_7d": metrics.velocity_7d,
                    "trend": metrics.trend.value,
                    "projected_severity_14d": metrics._score_to_severity(
                        metrics.projected_score_14d
                    ),
                    "days_to_critical": metrics.days_to_critical,
                })

        # Sort by velocity descending
        high_velocity.sort(key=lambda x: x["velocity_7d"], reverse=True)

        return high_velocity[:limit]

    async def get_entities_approaching_threshold(
        self,
        threshold: float = THRESHOLD_HIGH,
        max_days: int = 14,
        limit: int = 50,
    ) -> List[Dict[str, Any]]:
        """
        Find entities projected to breach a threshold.

        Args:
            threshold: Risk threshold (default HIGH)
            max_days: Maximum days to breach
            limit: Maximum results

        Returns:
            List of entities approaching threshold
        """
        # Get entities with increasing trends
        cutoff = datetime.now(timezone.utc) - timedelta(days=30)

        stmt = (
            select(ScoreHistoryDB.entity_id)
            .where(ScoreHistoryDB.calculated_at >= cutoff)
            .group_by(ScoreHistoryDB.entity_id)
            .having(func.count(ScoreHistoryDB.id) >= self.MIN_DATA_POINTS)
        )

        result = await self.db.execute(stmt)
        entity_ids = [r[0] for r in result.all()]

        approaching = []
        for entity_id in entity_ids:
            metrics = await self.calculate_velocity(entity_id)
            if metrics is None:
                continue

            # Check if below threshold but approaching
            if metrics.current_score < threshold:
                days_to = self._days_to_threshold(
                    metrics.current_score,
                    metrics.velocity_30d / 30,  # Daily rate
                    threshold
                )

                if days_to is not None and days_to <= max_days:
                    approaching.append({
                        "entity_id": entity_id,
                        "current_score": metrics.current_score,
                        "current_severity": metrics._score_to_severity(
                            metrics.current_score
                        ),
                        "target_threshold": threshold,
                        "target_severity": "critical" if threshold >= 0.85 else "high",
                        "days_to_breach": days_to,
                        "velocity_7d": metrics.velocity_7d,
                        "confidence": metrics.confidence,
                    })

        # Sort by days to breach ascending
        approaching.sort(key=lambda x: x["days_to_breach"])

        return approaching[:limit]

    async def _get_score_history(
        self,
        entity_id: str,
        days: int,
    ) -> List[Dict[str, Any]]:
        """Get historical scores for an entity."""
        cutoff = datetime.now(timezone.utc) - timedelta(days=days)

        stmt = (
            select(ScoreHistoryDB)
            .where(
                and_(
                    ScoreHistoryDB.entity_id == entity_id,
                    ScoreHistoryDB.calculated_at >= cutoff
                )
            )
            .order_by(ScoreHistoryDB.calculated_at.asc())
        )

        result = await self.db.execute(stmt)
        records = result.scalars().all()

        return [
            {
                "calculated_at": r.calculated_at,
                "composite_score": r.composite_score,
                "exposure_score": r.exposure_score,
                "volatility_score": r.volatility_score,
                "sensitivity_score": r.sensitivity_score,
            }
            for r in records
        ]

    def _calculate_window_velocity(
        self,
        timestamps: np.ndarray,
        scores: np.ndarray,
        days: int,
    ) -> float:
        """
        Calculate velocity over a specific time window.

        Velocity = (end_score - start_score) / window_size
        """
        if len(scores) < 2:
            return 0.0

        now = datetime.now(timezone.utc).timestamp()
        window_start = now - (days * 24 * 3600)

        # Find scores within window
        mask = timestamps >= window_start
        window_scores = scores[mask]

        if len(window_scores) < 2:
            return 0.0

        # Simple velocity: last - first
        return float(window_scores[-1] - window_scores[0])

    def _determine_trend(
        self,
        velocity: float,
        volatility: float,
    ) -> TrendDirection:
        """Determine trend direction from velocity and volatility."""
        if volatility > self.VOLATILITY_THRESHOLD:
            return TrendDirection.VOLATILE

        if velocity > self.VELOCITY_THRESHOLD_SIGNIFICANT:
            return TrendDirection.INCREASING
        elif velocity < -self.VELOCITY_THRESHOLD_SIGNIFICANT:
            return TrendDirection.DECREASING
        else:
            return TrendDirection.STABLE

    def _fit_linear_trend(
        self,
        timestamps: np.ndarray,
        scores: np.ndarray,
    ) -> Tuple[float, float, float]:
        """
        Fit a linear trend to the data.

        Returns:
            Tuple of (slope, intercept, r_squared)
        """
        if len(timestamps) < self.MIN_DATA_POINTS:
            return 0.0, float(scores[-1]) if len(scores) > 0 else 0.0, 0.0

        # Normalize timestamps for numerical stability
        t_min = timestamps.min()
        t_normalized = (timestamps - t_min) / (24 * 3600)  # Days

        try:
            # Fit linear regression
            coeffs = np.polyfit(t_normalized, scores, 1)
            slope = coeffs[0]  # Change per day
            intercept = coeffs[1]

            # Calculate R-squared
            y_pred = np.polyval(coeffs, t_normalized)
            ss_res = np.sum((scores - y_pred) ** 2)
            ss_tot = np.sum((scores - np.mean(scores)) ** 2)
            r_squared = 1 - (ss_res / ss_tot) if ss_tot > 0 else 0.0

            # Adjust intercept for current time
            now_normalized = (datetime.now(timezone.utc).timestamp() - t_min) / (24 * 3600)
            current_pred = slope * now_normalized + intercept

            return float(slope), float(current_pred), max(0.0, float(r_squared))

        except Exception as e:
            logger.warning(f"Error fitting trend: {e}")
            return 0.0, float(scores[-1]) if len(scores) > 0 else 0.0, 0.0

    def _project_score(
        self,
        slope: float,
        intercept: float,
        now_ts: float,
        days: int,
    ) -> float:
        """Project score into the future."""
        projected = intercept + (slope * days)
        # Clamp to valid range
        return max(0.0, min(1.0, projected))

    def _days_to_threshold(
        self,
        current_score: float,
        daily_slope: float,
        threshold: float,
    ) -> Optional[int]:
        """
        Calculate days until threshold is reached.

        Returns:
            Days to threshold, or None if not approaching
        """
        if current_score >= threshold:
            return 0  # Already there

        if daily_slope <= 0:
            return None  # Not increasing

        days = (threshold - current_score) / daily_slope

        if days > 365:
            return None  # Too far out to be meaningful

        return int(np.ceil(days))
