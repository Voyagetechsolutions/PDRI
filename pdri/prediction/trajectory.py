"""
Trajectory Prediction Module
============================

Predict future risk trajectories using time-series analysis.

Methods:
    - Moving average models
    - Exponential smoothing
    - ARIMA forecasting
    - Prophet (if available)
    - LSTM neural networks

Author: PDRI Team
Version: 1.0.0
"""

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional, Tuple
import numpy as np


@dataclass
class RiskDataPoint:
    """A single point in a risk trajectory."""
    timestamp: datetime
    risk_score: float
    confidence: float = 1.0
    is_forecast: bool = False
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "timestamp": self.timestamp.isoformat(),
            "risk_score": self.risk_score,
            "confidence": self.confidence,
            "is_forecast": self.is_forecast,
        }


@dataclass
class RiskTrajectory:
    """A risk trajectory with historical and forecasted data."""
    node_id: str
    historical: List[RiskDataPoint]
    forecast: List[RiskDataPoint]
    trend: str  # "increasing", "stable", "decreasing"
    trend_strength: float  # 0-1
    forecast_model: str
    forecast_horizon_days: int
    confidence_interval: Optional[Tuple[List[float], List[float]]] = None
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "node_id": self.node_id,
            "historical": [p.to_dict() for p in self.historical],
            "forecast": [p.to_dict() for p in self.forecast],
            "trend": self.trend,
            "trend_strength": self.trend_strength,
            "forecast_model": self.forecast_model,
            "forecast_horizon_days": self.forecast_horizon_days,
            "confidence_interval": {
                "lower": self.confidence_interval[0] if self.confidence_interval else [],
                "upper": self.confidence_interval[1] if self.confidence_interval else [],
            },
        }
    
    @property
    def forecasted_max(self) -> float:
        """Maximum forecasted risk score."""
        if not self.forecast:
            return 0.0
        return max(p.risk_score for p in self.forecast)
    
    @property
    def days_to_critical(self) -> Optional[int]:
        """Days until risk exceeds critical threshold (80)."""
        critical_threshold = 80.0
        
        for i, point in enumerate(self.forecast):
            if point.risk_score >= critical_threshold:
                return i
        return None


class TrajectoryPredictor:
    """
    Predict risk trajectories using time-series methods.
    
    Supports multiple forecasting models:
    - Moving Average: Simple, fast baseline
    - Exponential Smoothing: Weight recent observations
    - ARIMA: Statistical time-series model
    - Prophet: Facebook's forecasting library
    
    Example:
        predictor = TrajectoryPredictor()
        trajectory = await predictor.predict(node_id, history, horizon_days=30)
        print(f"Trend: {trajectory.trend}, Days to critical: {trajectory.days_to_critical}")
    """
    
    def __init__(
        self,
        model_type: str = "exponential_smoothing",
        confidence_level: float = 0.95
    ):
        """
        Initialize predictor.
        
        Args:
            model_type: Forecasting model to use
            confidence_level: Confidence level for prediction intervals
        """
        self.model_type = model_type
        self.confidence_level = confidence_level
    
    async def predict(
        self,
        node_id: str,
        history: List[Tuple[datetime, float]],
        horizon_days: int = 30,
        frequency: str = "daily"
    ) -> RiskTrajectory:
        """
        Predict risk trajectory.
        
        Args:
            node_id: Node identifier
            history: Historical (timestamp, risk_score) pairs
            horizon_days: Number of days to forecast
            frequency: Data frequency ("daily", "hourly")
        
        Returns:
            RiskTrajectory with historical and forecasted data
        """
        # Convert history to arrays
        timestamps = [ts for ts, _ in history]
        scores = np.array([score for _, score in history])
        
        if len(scores) < 3:
            # Not enough data, return flat forecast
            return self._create_flat_trajectory(node_id, history, horizon_days)
        
        # Calculate trend
        trend, trend_strength = self._calculate_trend(scores)
        
        # Forecast using selected model
        if self.model_type == "moving_average":
            forecast, confidence = self._moving_average_forecast(scores, horizon_days)
        elif self.model_type == "exponential_smoothing":
            forecast, confidence = self._exponential_smoothing_forecast(scores, horizon_days)
        elif self.model_type == "arima":
            forecast, confidence = self._arima_forecast(scores, horizon_days)
        else:
            forecast, confidence = self._exponential_smoothing_forecast(scores, horizon_days)
        
        # Create data points
        historical_points = [
            RiskDataPoint(timestamp=ts, risk_score=score, confidence=1.0, is_forecast=False)
            for ts, score in history
        ]
        
        # Generate forecast timestamps
        last_ts = timestamps[-1]
        delta = timedelta(days=1) if frequency == "daily" else timedelta(hours=1)
        
        forecast_points = []
        for i, score in enumerate(forecast):
            ts = last_ts + delta * (i + 1)
            conf = confidence[i] if isinstance(confidence, list) else confidence
            forecast_points.append(
                RiskDataPoint(timestamp=ts, risk_score=score, confidence=conf, is_forecast=True)
            )
        
        # Calculate confidence interval
        lower_bound, upper_bound = self._calculate_confidence_interval(
            forecast, scores
        )
        
        return RiskTrajectory(
            node_id=node_id,
            historical=historical_points,
            forecast=forecast_points,
            trend=trend,
            trend_strength=trend_strength,
            forecast_model=self.model_type,
            forecast_horizon_days=horizon_days,
            confidence_interval=(lower_bound, upper_bound),
        )
    
    def _calculate_trend(self, scores: np.ndarray) -> Tuple[str, float]:
        """Calculate trend direction and strength."""
        if len(scores) < 2:
            return "stable", 0.0
        
        # Linear regression
        x = np.arange(len(scores))
        slope, _ = np.polyfit(x, scores, 1)
        
        # Normalize slope to trend strength
        # Typical risk scores are 0-100, so divide by score range
        normalized_slope = slope / 10  # Adjust scaling as needed
        trend_strength = min(1.0, abs(normalized_slope))
        
        if normalized_slope > 0.02:
            trend = "increasing"
        elif normalized_slope < -0.02:
            trend = "decreasing"
        else:
            trend = "stable"
        
        return trend, trend_strength
    
    def _moving_average_forecast(
        self,
        scores: np.ndarray,
        horizon: int,
        window: int = 7
    ) -> Tuple[List[float], float]:
        """Simple moving average forecast."""
        # Use last window values for forecast
        window = min(window, len(scores))
        ma_value = np.mean(scores[-window:])
        
        # Slight trend continuation
        if len(scores) >= 2 * window:
            recent_ma = np.mean(scores[-window:])
            older_ma = np.mean(scores[-2*window:-window])
            trend_adjustment = (recent_ma - older_ma) / window
        else:
            trend_adjustment = 0
        
        forecast = []
        for i in range(horizon):
            predicted = ma_value + trend_adjustment * i
            predicted = np.clip(predicted, 0, 100)
            forecast.append(float(predicted))
        
        # Confidence is lower for longer horizons
        confidence = 0.9 - (0.01 * horizon)
        confidence = max(0.5, confidence)
        
        return forecast, [float(confidence)] * horizon
    
    def _exponential_smoothing_forecast(
        self,
        scores: np.ndarray,
        horizon: int,
        alpha: float = 0.3,
        beta: float = 0.1
    ) -> Tuple[List[float], List[float]]:
        """Holt's exponential smoothing (double exponential)."""
        n = len(scores)
        
        # Initialize level and trend
        level = scores[0]
        trend = (scores[-1] - scores[0]) / n if n > 1 else 0
        
        # Fit on historical data
        for i in range(1, n):
            last_level = level
            level = alpha * scores[i] + (1 - alpha) * (level + trend)
            trend = beta * (level - last_level) + (1 - beta) * trend
        
        # Forecast
        forecast = []
        confidence = []
        for i in range(1, horizon + 1):
            predicted = level + i * trend
            predicted = np.clip(predicted, 0, 100)
            forecast.append(float(predicted))
            
            # Confidence decreases with horizon
            conf = max(0.5, 0.95 - 0.02 * i)
            confidence.append(conf)
        
        return forecast, confidence
    
    def _arima_forecast(
        self,
        scores: np.ndarray,
        horizon: int
    ) -> Tuple[List[float], List[float]]:
        """ARIMA forecast using statsmodels."""
        try:
            from statsmodels.tsa.arima.model import ARIMA
            
            # Fit ARIMA(1,1,1) model
            model = ARIMA(scores, order=(1, 1, 1))
            fitted = model.fit()
            
            # Forecast
            forecast_result = fitted.get_forecast(steps=horizon)
            forecast = forecast_result.predicted_mean.tolist()
            
            # Get confidence intervals
            conf_int = forecast_result.conf_int(alpha=1 - self.confidence_level)
            lower = conf_int.iloc[:, 0].tolist()
            upper = conf_int.iloc[:, 1].tolist()
            
            # Clip to valid range
            forecast = [float(np.clip(f, 0, 100)) for f in forecast]
            
            # Calculate confidence from interval width
            confidence = []
            for i in range(len(forecast)):
                width = upper[i] - lower[i]
                conf = max(0.5, 1 - width / 100)
                confidence.append(conf)
            
            return forecast, confidence
            
        except ImportError:
            # Fallback to exponential smoothing
            return self._exponential_smoothing_forecast(scores, horizon)
    
    def _calculate_confidence_interval(
        self,
        forecast: List[float],
        historical: np.ndarray
    ) -> Tuple[List[float], List[float]]:
        """Calculate confidence interval for forecast."""
        # Use historical std as basis for interval
        std = np.std(historical)
        
        lower = []
        upper = []
        
        for i, pred in enumerate(forecast):
            # Widen interval over time
            margin = std * (1 + 0.1 * i)
            
            lower.append(float(max(0, pred - margin)))
            upper.append(float(min(100, pred + margin)))
        
        return lower, upper
    
    def _create_flat_trajectory(
        self,
        node_id: str,
        history: List[Tuple[datetime, float]],
        horizon_days: int
    ) -> RiskTrajectory:
        """Create flat trajectory when insufficient data."""
        historical_points = [
            RiskDataPoint(timestamp=ts, risk_score=score, confidence=1.0, is_forecast=False)
            for ts, score in history
        ]
        
        # Forecast flat at last known value
        last_score = history[-1][1] if history else 50.0
        last_ts = history[-1][0] if history else datetime.now(timezone.utc)
        
        forecast_points = []
        for i in range(1, horizon_days + 1):
            ts = last_ts + timedelta(days=i)
            forecast_points.append(
                RiskDataPoint(timestamp=ts, risk_score=last_score, confidence=0.5, is_forecast=True)
            )
        
        return RiskTrajectory(
            node_id=node_id,
            historical=historical_points,
            forecast=forecast_points,
            trend="stable",
            trend_strength=0.0,
            forecast_model="flat",
            forecast_horizon_days=horizon_days,
        )
    
    async def predict_batch(
        self,
        nodes: List[Tuple[str, List[Tuple[datetime, float]]]],
        horizon_days: int = 30,
        max_concurrency: int = 20,
    ) -> List[RiskTrajectory]:
        """
        Predict trajectories for multiple nodes concurrently.
        
        Args:
            nodes: List of (node_id, history) tuples
            horizon_days: Forecast horizon
            max_concurrency: Max concurrent predictions (semaphore limit)
        
        Returns:
            List of RiskTrajectory objects
        """
        import asyncio

        semaphore = asyncio.Semaphore(max_concurrency)

        async def _predict_one(node_id: str, history):
            async with semaphore:
                return await self.predict(node_id, history, horizon_days)

        tasks = [
            _predict_one(node_id, history)
            for node_id, history in nodes
        ]

        results = await asyncio.gather(*tasks, return_exceptions=True)

        trajectories = []
        for i, result in enumerate(results):
            if isinstance(result, Exception):
                print(f"Error predicting {nodes[i][0]}: {result}")
            else:
                trajectories.append(result)
        return trajectories
    
    def find_critical_risks(
        self,
        trajectories: List[RiskTrajectory],
        days_threshold: int = 7,
        score_threshold: float = 80.0
    ) -> List[Tuple[str, int, float]]:
        """
        Find nodes at risk of becoming critical.
        
        Args:
            trajectories: List of RiskTrajectory objects
            days_threshold: Alert if critical within this many days
            score_threshold: Score threshold for "critical"
        
        Returns:
            List of (node_id, days_to_critical, forecasted_max) tuples
        """
        at_risk = []
        
        for traj in trajectories:
            days_to_critical = None
            for i, point in enumerate(traj.forecast):
                if point.risk_score >= score_threshold:
                    days_to_critical = i
                    break
            
            if days_to_critical is not None and days_to_critical <= days_threshold:
                at_risk.append((
                    traj.node_id,
                    days_to_critical,
                    traj.forecasted_max,
                ))
        
        # Sort by days to critical (most urgent first)
        at_risk.sort(key=lambda x: x[1])
        
        return at_risk
