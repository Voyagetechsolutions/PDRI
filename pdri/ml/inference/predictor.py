"""
Risk Predictor
==============

Real-time risk prediction service.

Features:
    - Low-latency prediction
    - Model caching
    - Feature preprocessing
    - Prediction explanation

Author: PDRI Team
Version: 1.0.0
"""

from dataclasses import dataclass
from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple
import numpy as np


@dataclass
class RiskPrediction:
    """A risk prediction result."""
    node_id: str
    risk_probability: float  # 0-1 probability of high risk
    risk_class: int  # 0 = low, 1 = high (or multi-class)
    risk_label: str  # "low", "medium", "high", "critical"
    confidence: float  # Model confidence
    timestamp: datetime
    model_version: str
    features_used: Dict[str, float]
    explanation: Optional[Dict[str, float]] = None
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "node_id": self.node_id,
            "risk_probability": self.risk_probability,
            "risk_class": self.risk_class,
            "risk_label": self.risk_label,
            "confidence": self.confidence,
            "timestamp": self.timestamp.isoformat(),
            "model_version": self.model_version,
            "features_used": self.features_used,
            "explanation": self.explanation,
        }


class RiskPredictor:
    """
    Real-time risk prediction service.
    
    Provides low-latency predictions using trained ML models with:
    - Automatic model loading from registry
    - Feature preprocessing and validation
    - Prediction explanations (SHAP/LIME)
    - Confidence scoring
    
    Example:
        predictor = RiskPredictor(model_registry, feature_engineer)
        prediction = await predictor.predict("node-123")
        print(f"Risk: {prediction.risk_label} ({prediction.risk_probability:.2f})")
    """
    
    # Risk thresholds for classification
    RISK_THRESHOLDS = {
        "low": 0.25,
        "medium": 0.5,
        "high": 0.75,
        "critical": 1.0,
    }
    
    def __init__(
        self,
        model_registry: Any,
        feature_engineer: Any,
        model_type: str = "risk_classifier",
        enable_explanations: bool = True
    ):
        """
        Initialize predictor.
        
        Args:
            model_registry: Registry to load models from
            feature_engineer: Feature extraction engine
            model_type: Type of model to load
            enable_explanations: Whether to compute explanations
        """
        self.model_registry = model_registry
        self.feature_engineer = feature_engineer
        self.model_type = model_type
        self.enable_explanations = enable_explanations
        
        # Cached model
        self._model = None
        self._model_version = None
        self._feature_names = None
        
        # Explainer (SHAP)
        self._explainer = None
    
    async def load_model(self) -> None:
        """Load production model from registry."""
        from ..signatures.model_registry import ModelType
        
        model_type_enum = ModelType(self.model_type)
        model = self.model_registry.get_production_model(model_type_enum)
        
        if model is None:
            raise RuntimeError(f"No production model found for {self.model_type}")
        
        self._model = model
        
        # Get version info
        for registered in self.model_registry.list_models(model_type_enum):
            prod_version = registered.production_version
            if prod_version:
                self._model_version = prod_version.version_id
                self._feature_names = prod_version.feature_names
                break
        
        # Initialize explainer
        if self.enable_explanations:
            self._init_explainer()
    
    def _init_explainer(self) -> None:
        """Initialize SHAP explainer for model explanations."""
        try:
            import shap
            
            # Tree explainer for tree-based models
            if hasattr(self._model, 'feature_importances_'):
                self._explainer = shap.TreeExplainer(self._model)
            else:
                # Kernel explainer as fallback
                self._explainer = None  # Too slow for real-time
        except ImportError:
            self._explainer = None
    
    async def predict(
        self,
        node_id: str,
        features: Optional[Dict[str, float]] = None
    ) -> RiskPrediction:
        """
        Predict risk for a single node.
        
        Args:
            node_id: ID of the node to predict
            features: Optional pre-computed features (will extract if not provided)
        
        Returns:
            RiskPrediction with classification and confidence
        """
        if self._model is None:
            await self.load_model()
        
        # Get features
        if features is None:
            feature_vector = await self.feature_engineer.extract_features(node_id)
            features = feature_vector.features
            feature_names = feature_vector.feature_names
        else:
            feature_names = list(features.keys())
        
        # Prepare input
        X = self._prepare_features(features, feature_names)
        
        # Predict
        if hasattr(self._model, 'predict_proba'):
            proba = self._model.predict_proba(X)[0]
            risk_probability = float(proba[1]) if len(proba) > 1 else float(proba[0])
            risk_class = int(self._model.predict(X)[0])
            confidence = float(max(proba))
        else:
            prediction = self._model.predict(X)[0]
            risk_probability = float(prediction)
            risk_class = 1 if prediction >= 0.5 else 0
            confidence = abs(prediction - 0.5) * 2  # Distance from boundary
        
        # Determine risk label
        risk_label = self._classify_risk(risk_probability)
        
        # Get explanation
        explanation = None
        if self.enable_explanations and self._explainer is not None:
            explanation = self._explain_prediction(X)
        elif self.enable_explanations:
            # Fallback to basic feature importance
            explanation = self._basic_explanation(features)
        
        return RiskPrediction(
            node_id=node_id,
            risk_probability=risk_probability,
            risk_class=risk_class,
            risk_label=risk_label,
            confidence=confidence,
            timestamp=datetime.utcnow(),
            model_version=self._model_version or "unknown",
            features_used=features,
            explanation=explanation,
        )
    
    async def predict_batch(
        self,
        node_ids: List[str]
    ) -> List[RiskPrediction]:
        """
        Predict risk for multiple nodes.
        
        Args:
            node_ids: List of node IDs
        
        Returns:
            List of RiskPrediction objects
        """
        predictions = []
        for node_id in node_ids:
            try:
                pred = await self.predict(node_id)
                predictions.append(pred)
            except Exception as e:
                # Log error and continue
                print(f"Error predicting {node_id}: {e}")
        return predictions
    
    def _prepare_features(
        self,
        features: Dict[str, float],
        feature_names: List[str]
    ) -> np.ndarray:
        """Prepare features for model input."""
        # Ensure features are in correct order
        if self._feature_names:
            ordered = [features.get(name, 0.0) for name in self._feature_names]
        else:
            ordered = [features.get(name, 0.0) for name in feature_names]
        
        return np.array([ordered])
    
    def _classify_risk(self, probability: float) -> str:
        """Classify probability into risk label."""
        for label, threshold in sorted(self.RISK_THRESHOLDS.items(), key=lambda x: x[1]):
            if probability <= threshold:
                return label
        return "critical"
    
    def _explain_prediction(self, X: np.ndarray) -> Dict[str, float]:
        """Get SHAP-based explanation for prediction."""
        try:
            shap_values = self._explainer.shap_values(X)
            
            # Handle different SHAP output formats
            if isinstance(shap_values, list):
                values = shap_values[1][0]  # Class 1 values
            else:
                values = shap_values[0]
            
            explanation = {}
            for i, name in enumerate(self._feature_names or []):
                if i < len(values):
                    explanation[name] = float(values[i])
            
            # Sort by absolute impact
            return dict(sorted(
                explanation.items(),
                key=lambda x: abs(x[1]),
                reverse=True
            )[:10])  # Top 10 features
            
        except Exception:
            return {}
    
    def _basic_explanation(self, features: Dict[str, float]) -> Dict[str, float]:
        """Basic explanation based on feature values."""
        # Highlight high-value features as contributors
        important_features = [
            "current_risk_score",
            "exposure_score",
            "sensitivity_score",
            "ai_tool_connection_count",
            "exposure_path_count",
        ]
        
        explanation = {}
        for name in important_features:
            if name in features:
                value = features[name]
                # Normalize to -1 to 1 impact range
                if name == "current_risk_score":
                    impact = (value - 50) / 50
                else:
                    impact = value - 0.5
                explanation[name] = float(impact)
        
        return explanation
    
    def set_thresholds(self, thresholds: Dict[str, float]) -> None:
        """
        Set custom risk thresholds.
        
        Args:
            thresholds: Dict of label -> probability threshold
        """
        self.RISK_THRESHOLDS.update(thresholds)
    
    async def health_check(self) -> Dict[str, Any]:
        """Check predictor health."""
        return {
            "status": "healthy" if self._model is not None else "no_model",
            "model_loaded": self._model is not None,
            "model_version": self._model_version,
            "explanations_enabled": self.enable_explanations,
            "explainer_available": self._explainer is not None,
        }
