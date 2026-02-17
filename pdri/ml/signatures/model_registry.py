"""
Model Registry Module
=====================

Manage ML model lifecycle: storage, versioning, and deployment.

Features:
    - Model version tracking
    - Performance metric storage
    - Model export/import (pickle, ONNX)
    - A/B testing support

Author: PDRI Team
Version: 1.0.0
"""

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional
import json
import pickle
import hashlib


class ModelStatus(Enum):
    """Status of a registered model."""
    DRAFT = "draft"
    STAGING = "staging"
    PRODUCTION = "production"
    DEPRECATED = "deprecated"
    ARCHIVED = "archived"


class ModelType(Enum):
    """Types of ML models."""
    RISK_CLASSIFIER = "risk_classifier"
    PATTERN_DETECTOR = "pattern_detector"
    ANOMALY_DETECTOR = "anomaly_detector"
    TRAJECTORY_PREDICTOR = "trajectory_predictor"
    EMBEDDING_MODEL = "embedding_model"


@dataclass
class ModelMetrics:
    """Performance metrics for a model."""
    accuracy: Optional[float] = None
    precision: Optional[float] = None
    recall: Optional[float] = None
    f1_score: Optional[float] = None
    auc_roc: Optional[float] = None
    mse: Optional[float] = None
    mae: Optional[float] = None
    custom_metrics: Dict[str, float] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        result = {}
        for key in ["accuracy", "precision", "recall", "f1_score", "auc_roc", "mse", "mae"]:
            value = getattr(self, key)
            if value is not None:
                result[key] = value
        result.update(self.custom_metrics)
        return result


@dataclass
class ModelVersion:
    """A specific version of a model."""
    version_id: str
    model_id: str
    version_number: str
    created_at: datetime
    model_type: ModelType
    status: ModelStatus
    metrics: ModelMetrics
    hyperparameters: Dict[str, Any]
    feature_names: List[str]
    description: str
    artifact_path: Optional[str] = None
    training_data_hash: Optional[str] = None
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "version_id": self.version_id,
            "model_id": self.model_id,
            "version_number": self.version_number,
            "created_at": self.created_at.isoformat(),
            "model_type": self.model_type.value,
            "status": self.status.value,
            "metrics": self.metrics.to_dict(),
            "hyperparameters": self.hyperparameters,
            "feature_names": self.feature_names,
            "description": self.description,
            "artifact_path": self.artifact_path,
            "training_data_hash": self.training_data_hash,
        }


@dataclass
class RegisteredModel:
    """A registered model with all its versions."""
    model_id: str
    name: str
    model_type: ModelType
    description: str
    created_at: datetime
    updated_at: datetime
    versions: List[ModelVersion] = field(default_factory=list)
    tags: Dict[str, str] = field(default_factory=dict)
    
    @property
    def latest_version(self) -> Optional[ModelVersion]:
        """Get the latest version."""
        if not self.versions:
            return None
        return max(self.versions, key=lambda v: v.created_at)
    
    @property
    def production_version(self) -> Optional[ModelVersion]:
        """Get the production version."""
        for v in self.versions:
            if v.status == ModelStatus.PRODUCTION:
                return v
        return None
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "model_id": self.model_id,
            "name": self.name,
            "model_type": self.model_type.value,
            "description": self.description,
            "created_at": self.created_at.isoformat(),
            "updated_at": self.updated_at.isoformat(),
            "versions": [v.to_dict() for v in self.versions],
            "tags": self.tags,
        }


class ModelRegistry:
    """
    Registry for managing ML models.
    
    Provides:
    - Model registration and versioning
    - Model storage and retrieval
    - Status management (staging → production)
    - Performance tracking
    
    Example:
        registry = ModelRegistry("/models")
        model_id = registry.register_model("risk_classifier", ModelType.RISK_CLASSIFIER)
        version_id = registry.log_version(model_id, trained_model, metrics)
        registry.promote_to_production(version_id)
    """
    
    def __init__(self, storage_path: str):
        """
        Initialize model registry.
        
        Args:
            storage_path: Path to store model artifacts
        """
        self.storage_path = Path(storage_path)
        self.storage_path.mkdir(parents=True, exist_ok=True)
        
        # In-memory registry (would be database in production)
        self._models: Dict[str, RegisteredModel] = {}
        self._artifacts: Dict[str, Any] = {}
        
        # Load existing registry
        self._load_registry()
    
    def _load_registry(self) -> None:
        """Load registry from disk."""
        registry_file = self.storage_path / "registry.json"
        if registry_file.exists():
            try:
                with open(registry_file, "r") as f:
                    data = json.load(f)
                    for model_data in data.get("models", []):
                        model = self._dict_to_model(model_data)
                        self._models[model.model_id] = model
            except Exception:
                pass  # Start fresh if corrupted
    
    def _save_registry(self) -> None:
        """Save registry to disk."""
        registry_file = self.storage_path / "registry.json"
        data = {
            "models": [m.to_dict() for m in self._models.values()],
            "updated_at": datetime.now(timezone.utc).isoformat(),
        }
        with open(registry_file, "w") as f:
            json.dump(data, f, indent=2)
    
    def _dict_to_model(self, data: Dict[str, Any]) -> RegisteredModel:
        """Convert dictionary to RegisteredModel."""
        versions = []
        for v_data in data.get("versions", []):
            versions.append(ModelVersion(
                version_id=v_data["version_id"],
                model_id=v_data["model_id"],
                version_number=v_data["version_number"],
                created_at=datetime.fromisoformat(v_data["created_at"]),
                model_type=ModelType(v_data["model_type"]),
                status=ModelStatus(v_data["status"]),
                metrics=ModelMetrics(**v_data.get("metrics", {})),
                hyperparameters=v_data.get("hyperparameters", {}),
                feature_names=v_data.get("feature_names", []),
                description=v_data.get("description", ""),
                artifact_path=v_data.get("artifact_path"),
                training_data_hash=v_data.get("training_data_hash"),
            ))
        
        return RegisteredModel(
            model_id=data["model_id"],
            name=data["name"],
            model_type=ModelType(data["model_type"]),
            description=data.get("description", ""),
            created_at=datetime.fromisoformat(data["created_at"]),
            updated_at=datetime.fromisoformat(data["updated_at"]),
            versions=versions,
            tags=data.get("tags", {}),
        )
    
    def register_model(
        self,
        name: str,
        model_type: ModelType,
        description: str = "",
        tags: Optional[Dict[str, str]] = None
    ) -> str:
        """
        Register a new model.
        
        Args:
            name: Human-readable model name
            model_type: Type of the model
            description: Model description
            tags: Optional metadata tags
        
        Returns:
            Model ID
        """
        model_id = self._generate_id(name)
        now = datetime.now(timezone.utc)
        
        model = RegisteredModel(
            model_id=model_id,
            name=name,
            model_type=model_type,
            description=description,
            created_at=now,
            updated_at=now,
            tags=tags or {},
        )
        
        self._models[model_id] = model
        self._save_registry()
        
        return model_id
    
    def log_version(
        self,
        model_id: str,
        model_artifact: Any,
        metrics: ModelMetrics,
        hyperparameters: Optional[Dict[str, Any]] = None,
        feature_names: Optional[List[str]] = None,
        description: str = "",
        training_data: Optional[bytes] = None
    ) -> str:
        """
        Log a new model version.
        
        Args:
            model_id: ID of the registered model
            model_artifact: The trained model object
            metrics: Performance metrics
            hyperparameters: Training hyperparameters
            feature_names: List of input feature names
            description: Version description
            training_data: Optional training data for hash computation
        
        Returns:
            Version ID
        """
        if model_id not in self._models:
            raise ValueError(f"Model {model_id} not found")
        
        model = self._models[model_id]
        version_num = len(model.versions) + 1
        version_id = f"{model_id}-v{version_num}"
        
        # Save artifact
        artifact_path = self._save_artifact(version_id, model_artifact)
        
        # Compute training data hash
        data_hash = None
        if training_data:
            data_hash = hashlib.sha256(training_data).hexdigest()[:16]
        
        version = ModelVersion(
            version_id=version_id,
            model_id=model_id,
            version_number=f"v{version_num}",
            created_at=datetime.now(timezone.utc),
            model_type=model.model_type,
            status=ModelStatus.DRAFT,
            metrics=metrics,
            hyperparameters=hyperparameters or {},
            feature_names=feature_names or [],
            description=description,
            artifact_path=str(artifact_path),
            training_data_hash=data_hash,
        )
        
        model.versions.append(version)
        model.updated_at = datetime.now(timezone.utc)
        
        self._save_registry()
        
        return version_id
    
    def _save_artifact(self, version_id: str, artifact: Any) -> Path:
        """Save model artifact to disk."""
        artifact_dir = self.storage_path / "artifacts"
        artifact_dir.mkdir(exist_ok=True)
        
        artifact_path = artifact_dir / f"{version_id}.pkl"
        
        with open(artifact_path, "wb") as f:
            pickle.dump(artifact, f)
        
        self._artifacts[version_id] = artifact
        
        return artifact_path
    
    def load_artifact(self, version_id: str) -> Any:
        """Load model artifact from disk or cache."""
        if version_id in self._artifacts:
            return self._artifacts[version_id]
        
        # Find version
        version = self._find_version(version_id)
        if not version or not version.artifact_path:
            raise ValueError(f"Artifact not found for {version_id}")
        
        with open(version.artifact_path, "rb") as f:
            artifact = pickle.load(f)
        
        self._artifacts[version_id] = artifact
        return artifact
    
    def _find_version(self, version_id: str) -> Optional[ModelVersion]:
        """Find a version by ID."""
        for model in self._models.values():
            for version in model.versions:
                if version.version_id == version_id:
                    return version
        return None
    
    def promote_to_staging(self, version_id: str) -> None:
        """Promote a version to staging."""
        version = self._find_version(version_id)
        if not version:
            raise ValueError(f"Version {version_id} not found")
        
        version.status = ModelStatus.STAGING
        self._save_registry()
    
    def promote_to_production(self, version_id: str) -> None:
        """
        Promote a version to production.
        
        This will demote the current production version to deprecated.
        """
        version = self._find_version(version_id)
        if not version:
            raise ValueError(f"Version {version_id} not found")
        
        model = self._models.get(version.model_id)
        if model:
            # Demote current production
            for v in model.versions:
                if v.status == ModelStatus.PRODUCTION:
                    v.status = ModelStatus.DEPRECATED
        
        version.status = ModelStatus.PRODUCTION
        self._save_registry()
    
    def get_model(self, model_id: str) -> Optional[RegisteredModel]:
        """Get a registered model by ID."""
        return self._models.get(model_id)
    
    def get_production_model(self, model_type: ModelType) -> Optional[Any]:
        """Get the production model artifact for a type."""
        for model in self._models.values():
            if model.model_type == model_type:
                prod_version = model.production_version
                if prod_version:
                    return self.load_artifact(prod_version.version_id)
        return None
    
    def list_models(
        self,
        model_type: Optional[ModelType] = None
    ) -> List[RegisteredModel]:
        """List all registered models."""
        models = list(self._models.values())
        if model_type:
            models = [m for m in models if m.model_type == model_type]
        return models
    
    def compare_versions(
        self,
        version_id_a: str,
        version_id_b: str
    ) -> Dict[str, Any]:
        """Compare two model versions."""
        version_a = self._find_version(version_id_a)
        version_b = self._find_version(version_id_b)
        
        if not version_a or not version_b:
            raise ValueError("One or both versions not found")
        
        metrics_a = version_a.metrics.to_dict()
        metrics_b = version_b.metrics.to_dict()
        
        comparison = {
            "version_a": version_id_a,
            "version_b": version_id_b,
            "metrics_diff": {},
        }
        
        all_metrics = set(metrics_a.keys()) | set(metrics_b.keys())
        for metric in all_metrics:
            val_a = metrics_a.get(metric)
            val_b = metrics_b.get(metric)
            if val_a is not None and val_b is not None:
                comparison["metrics_diff"][metric] = {
                    "a": val_a,
                    "b": val_b,
                    "diff": val_b - val_a,
                    "improvement": val_b > val_a,
                }
        
        return comparison
    
    def _generate_id(self, name: str) -> str:
        """Generate unique model ID."""
        slug = name.lower().replace(" ", "-")
        timestamp = datetime.now(timezone.utc).strftime("%Y%m%d%H%M%S")
        return f"{slug}-{timestamp}"
