"""
Federation Client
=================

Client for participating in federated learning.

Features:
    - Local model training
    - Gradient computation
    - Secure model update sharing
    - Fingerprint contribution

Author: PDRI Team
Version: 1.0.0
"""

from dataclasses import dataclass
from datetime import datetime
from typing import Any, Dict, List, Optional
import numpy as np
import hashlib
import json


@dataclass
class FederationConfig:
    """Configuration for federation participation."""
    organization_id: str
    federation_endpoint: str
    api_key: str
    local_epochs: int = 5
    min_samples_for_update: int = 100
    contribution_frequency_hours: int = 24
    privacy_epsilon: float = 1.0
    privacy_delta: float = 1e-5
    enable_secure_aggregation: bool = True


@dataclass
class ModelUpdate:
    """A local model update to share with federation."""
    update_id: str
    organization_id: str
    model_version: str
    timestamp: datetime
    gradients: Dict[str, np.ndarray]
    sample_count: int
    local_metrics: Dict[str, float]
    fingerprints: List[Dict[str, Any]]
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "update_id": self.update_id,
            "organization_id": self.organization_id,
            "model_version": self.model_version,
            "timestamp": self.timestamp.isoformat(),
            "gradients": {k: v.tolist() for k, v in self.gradients.items()},
            "sample_count": self.sample_count,
            "local_metrics": self.local_metrics,
            "fingerprints": self.fingerprints,
        }


@dataclass
class GlobalUpdate:
    """A global model update received from federation."""
    update_id: str
    model_version: str
    timestamp: datetime
    aggregated_weights: Dict[str, np.ndarray]
    global_metrics: Dict[str, float]
    participating_orgs: int
    new_fingerprints: List[Dict[str, Any]]


class FederationClient:
    """
    Client for federated learning participation.
    
    Enables organizations to:
    - Train local models on private data
    - Share model updates (not raw data)
    - Receive aggregated global models
    - Contribute and receive risk fingerprints
    
    Example:
        config = FederationConfig(
            organization_id="org-123",
            federation_endpoint="https://federation.pdri.io",
            api_key="xxx"
        )
        client = FederationClient(config, local_model)
        
        # Train on local data
        update = await client.train_local(local_data)
        
        # Share with federation
        await client.submit_update(update)
        
        # Get global model
        global_update = await client.get_global_update()
        client.apply_global_update(global_update)
    """
    
    def __init__(
        self,
        config: FederationConfig,
        local_model: Any,
        privacy_engine: Optional[Any] = None
    ):
        """
        Initialize federation client.
        
        Args:
            config: Federation configuration
            local_model: Local ML model to train
            privacy_engine: Optional differential privacy engine
        """
        self.config = config
        self.local_model = local_model
        self.privacy_engine = privacy_engine
        
        self._update_counter = 0
        self._local_fingerprints: List[Dict[str, Any]] = []
        self._last_global_version = None
    
    async def train_local(
        self,
        training_data: Any,
        validation_data: Optional[Any] = None
    ) -> ModelUpdate:
        """
        Train local model and prepare update.
        
        Args:
            training_data: Local training data
            validation_data: Optional validation data
        
        Returns:
            ModelUpdate ready for submission
        """
        # Get initial model weights
        initial_weights = self._get_model_weights()
        
        # Train locally
        for epoch in range(self.config.local_epochs):
            self._train_epoch(training_data)
        
        # Compute gradients (weight differences)
        final_weights = self._get_model_weights()
        gradients = {
            key: final_weights[key] - initial_weights[key]
            for key in initial_weights
        }
        
        # Apply differential privacy if enabled
        if self.privacy_engine is not None:
            gradients = self.privacy_engine.add_noise(
                gradients,
                epsilon=self.config.privacy_epsilon,
                delta=self.config.privacy_delta,
            )
        
        # Compute local metrics
        local_metrics = {}
        if validation_data is not None:
            local_metrics = self._evaluate(validation_data)
        
        # Extract any new fingerprints
        fingerprints = self._extract_fingerprints(training_data)
        
        self._update_counter += 1
        
        return ModelUpdate(
            update_id=f"{self.config.organization_id}-{self._update_counter:06d}",
            organization_id=self.config.organization_id,
            model_version=self._last_global_version or "v1",
            timestamp=datetime.utcnow(),
            gradients=gradients,
            sample_count=len(training_data) if hasattr(training_data, '__len__') else 0,
            local_metrics=local_metrics,
            fingerprints=fingerprints,
        )
    
    def _get_model_weights(self) -> Dict[str, np.ndarray]:
        """Extract model weights."""
        weights = {}
        
        # Handle different model types
        if hasattr(self.local_model, 'coef_'):
            weights['coef'] = np.array(self.local_model.coef_)
            if hasattr(self.local_model, 'intercept_'):
                weights['intercept'] = np.array(self.local_model.intercept_)
        elif hasattr(self.local_model, 'get_weights'):
            # Keras/TensorFlow style
            for i, w in enumerate(self.local_model.get_weights()):
                weights[f'layer_{i}'] = w
        elif hasattr(self.local_model, 'state_dict'):
            # PyTorch style
            for name, param in self.local_model.state_dict().items():
                weights[name] = param.numpy()
        else:
            # Fallback: try to get from estimator
            if hasattr(self.local_model, 'feature_importances_'):
                weights['feature_importances'] = np.array(
                    self.local_model.feature_importances_
                )
        
        return weights
    
    def _train_epoch(self, data: Any) -> None:
        """Train one epoch on local data."""
        if hasattr(self.local_model, 'partial_fit'):
            # Incremental learning
            X, y = self._extract_xy(data)
            self.local_model.partial_fit(X, y)
        elif hasattr(self.local_model, 'fit'):
            # Full fit (for tree-based models)
            X, y = self._extract_xy(data)
            self.local_model.fit(X, y)
    
    def _extract_xy(self, data: Any) -> tuple:
        """Extract features and labels from data."""
        if isinstance(data, tuple):
            return data
        if hasattr(data, 'features') and hasattr(data, 'labels'):
            return data.features, data.labels
        if isinstance(data, list) and hasattr(data[0], 'features'):
            X = np.stack([d.features for d in data])
            y = np.array([d.label for d in data])
            return X, y
        return data, None
    
    def _evaluate(self, data: Any) -> Dict[str, float]:
        """Evaluate model on validation data."""
        X, y = self._extract_xy(data)
        
        if y is None:
            return {}
        
        metrics = {"accuracy": float(self.local_model.score(X, y))}
        
        if hasattr(self.local_model, 'predict_proba'):
            from sklearn.metrics import roc_auc_score
            try:
                y_proba = self.local_model.predict_proba(X)[:, 1]
                metrics["auc_roc"] = float(roc_auc_score(y, y_proba))
            except Exception:
                pass
        
        return metrics
    
    def _extract_fingerprints(self, data: Any) -> List[Dict[str, Any]]:
        """Extract risk fingerprints from training data."""
        fingerprints = []
        
        # Extract any high-risk patterns as fingerprints
        # In production, this would use pattern detection
        if hasattr(data, '__iter__'):
            for item in list(data)[:10]:  # Sample
                if hasattr(item, 'label') and item.label == 1:
                    # High risk sample - create anonymized fingerprint
                    fp = self._create_fingerprint(item)
                    if fp:
                        fingerprints.append(fp)
        
        return fingerprints
    
    def _create_fingerprint(self, sample: Any) -> Optional[Dict[str, Any]]:
        """Create an anonymized risk fingerprint."""
        if not hasattr(sample, 'features'):
            return None
        
        # Create hash of feature pattern (not actual values)
        feature_pattern = tuple(
            "high" if v > 0.7 else "med" if v > 0.3 else "low"
            for v in sample.features[:10]  # First 10 features
        )
        
        pattern_hash = hashlib.sha256(
            json.dumps(feature_pattern).encode()
        ).hexdigest()[:16]
        
        return {
            "fingerprint_id": pattern_hash,
            "pattern_type": "high_risk",
            "feature_signature": feature_pattern,
            "timestamp": datetime.utcnow().isoformat(),
            "organization": self.config.organization_id[:3] + "***",  # Anonymized
        }
    
    async def submit_update(self, update: ModelUpdate) -> bool:
        """
        Submit model update to federation server.
        
        Args:
            update: ModelUpdate to submit
        
        Returns:
            True if accepted, False otherwise
        """
        # In production, this would make HTTPS request to federation server
        # For now, simulate submission
        
        if update.sample_count < self.config.min_samples_for_update:
            return False
        
        # Apply secure aggregation if enabled
        if self.config.enable_secure_aggregation:
            update = self._encrypt_update(update)
        
        # Simulate network call
        # await self._http_post(self.config.federation_endpoint + "/submit", update.to_dict())
        
        return True
    
    def _encrypt_update(self, update: ModelUpdate) -> ModelUpdate:
        """Apply secure aggregation encryption."""
        # In production, this would use Paillier or similar encryption
        # For now, just add noise (placeholder for real encryption)
        encrypted_gradients = {}
        for key, gradient in update.gradients.items():
            noise = np.random.normal(0, 0.001, gradient.shape)
            encrypted_gradients[key] = gradient + noise
        
        return ModelUpdate(
            update_id=update.update_id,
            organization_id=update.organization_id,
            model_version=update.model_version,
            timestamp=update.timestamp,
            gradients=encrypted_gradients,
            sample_count=update.sample_count,
            local_metrics=update.local_metrics,
            fingerprints=update.fingerprints,
        )
    
    async def get_global_update(self) -> Optional[GlobalUpdate]:
        """
        Get latest global model from federation.
        
        Returns:
            GlobalUpdate if available, None otherwise
        """
        # In production, this would fetch from federation server
        # Simulate receiving global update
        
        return GlobalUpdate(
            update_id=f"global-{datetime.utcnow().strftime('%Y%m%d%H')}",
            model_version="v1.1",
            timestamp=datetime.utcnow(),
            aggregated_weights={},  # Would contain actual weights
            global_metrics={"accuracy": 0.85, "auc_roc": 0.92},
            participating_orgs=15,
            new_fingerprints=[],
        )
    
    def apply_global_update(self, update: GlobalUpdate) -> None:
        """
        Apply global model update to local model.
        
        Args:
            update: GlobalUpdate from federation
        """
        # In production, would update model weights
        self._last_global_version = update.model_version
        
        # Store new fingerprints
        self._local_fingerprints.extend(update.new_fingerprints)
    
    def get_known_fingerprints(self) -> List[Dict[str, Any]]:
        """Get all known risk fingerprints."""
        return self._local_fingerprints.copy()
    
    def check_fingerprint_match(
        self,
        sample_features: np.ndarray
    ) -> List[Dict[str, Any]]:
        """
        Check if a sample matches known risk fingerprints.
        
        Args:
            sample_features: Feature array to check
        
        Returns:
            List of matching fingerprints
        """
        matches = []
        
        # Create pattern for sample
        sample_pattern = tuple(
            "high" if v > 0.7 else "med" if v > 0.3 else "low"
            for v in sample_features[:10]
        )
        
        sample_hash = hashlib.sha256(
            json.dumps(sample_pattern).encode()
        ).hexdigest()[:16]
        
        for fp in self._local_fingerprints:
            if fp.get("fingerprint_id") == sample_hash:
                matches.append(fp)
        
        return matches
