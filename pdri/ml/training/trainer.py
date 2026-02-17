"""
Model Trainer
=============

Training infrastructure for risk prediction models.

Supports:
    - Scikit-learn classifiers
    - XGBoost/LightGBM
    - Neural networks (PyTorch)
    - Hyperparameter tuning

Author: PDRI Team
Version: 1.0.0
"""

from dataclasses import dataclass
from datetime import datetime
from typing import Any, Callable, Dict, List, Optional, Tuple
import numpy as np


@dataclass
class TrainingConfig:
    """Configuration for model training."""
    model_type: str  # "random_forest", "xgboost", "neural_net"
    hyperparameters: Dict[str, Any]
    epochs: int = 100
    batch_size: int = 32
    learning_rate: float = 0.001
    early_stopping_patience: int = 10
    validation_frequency: int = 1
    checkpoint_frequency: int = 10
    random_seed: int = 42


@dataclass
class TrainingResult:
    """Result of a training run."""
    model: Any
    train_metrics: Dict[str, float]
    val_metrics: Dict[str, float]
    training_time_seconds: float
    epochs_trained: int
    best_epoch: int
    history: Dict[str, List[float]]
    config: TrainingConfig
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "train_metrics": self.train_metrics,
            "val_metrics": self.val_metrics,
            "training_time_seconds": self.training_time_seconds,
            "epochs_trained": self.epochs_trained,
            "best_epoch": self.best_epoch,
            "config": {
                "model_type": self.config.model_type,
                "hyperparameters": self.config.hyperparameters,
            },
        }


class RiskModelTrainer:
    """
    Train machine learning models for risk prediction.
    
    Supports multiple model types:
    - Random Forest
    - XGBoost
    - LightGBM
    - Neural Network
    
    Example:
        trainer = RiskModelTrainer()
        config = TrainingConfig(
            model_type="xgboost",
            hyperparameters={"max_depth": 6, "n_estimators": 100}
        )
        result = trainer.train(train_data, val_data, config)
    """
    
    def __init__(
        self,
        model_registry: Optional[Any] = None,
        callbacks: Optional[List[Callable]] = None
    ):
        """
        Initialize trainer.
        
        Args:
            model_registry: Optional registry for saving models
            callbacks: Optional training callbacks
        """
        self.model_registry = model_registry
        self.callbacks = callbacks or []
    
    def train(
        self,
        train_data: Any,  # List[TrainingExample] or TrainingBatch iterator
        val_data: Any,
        config: TrainingConfig,
        feature_names: Optional[List[str]] = None
    ) -> TrainingResult:
        """
        Train a model.
        
        Args:
            train_data: Training examples
            val_data: Validation examples
            config: Training configuration
            feature_names: Optional feature names for interpretability
        
        Returns:
            TrainingResult with trained model and metrics
        """
        import time
        start_time = time.time()
        
        # Prepare data
        X_train, y_train = self._prepare_data(train_data)
        X_val, y_val = self._prepare_data(val_data)
        
        # Set random seed
        np.random.seed(config.random_seed)
        
        # Train based on model type
        if config.model_type == "random_forest":
            model, history = self._train_random_forest(
                X_train, y_train, X_val, y_val, config
            )
        elif config.model_type == "xgboost":
            model, history = self._train_xgboost(
                X_train, y_train, X_val, y_val, config
            )
        elif config.model_type == "neural_net":
            model, history = self._train_neural_net(
                X_train, y_train, X_val, y_val, config
            )
        else:
            raise ValueError(f"Unknown model type: {config.model_type}")
        
        # Compute final metrics
        train_metrics = self._compute_metrics(model, X_train, y_train)
        val_metrics = self._compute_metrics(model, X_val, y_val)
        
        training_time = time.time() - start_time
        
        # Find best epoch
        best_epoch = 0
        if "val_accuracy" in history:
            best_epoch = int(np.argmax(history["val_accuracy"]))
        
        result = TrainingResult(
            model=model,
            train_metrics=train_metrics,
            val_metrics=val_metrics,
            training_time_seconds=training_time,
            epochs_trained=len(history.get("train_loss", [1])),
            best_epoch=best_epoch,
            history=history,
            config=config,
        )
        
        # Run callbacks
        for callback in self.callbacks:
            callback(result)
        
        return result
    
    def _prepare_data(self, data: Any) -> Tuple[np.ndarray, np.ndarray]:
        """Prepare data for training."""
        if isinstance(data, list):
            # List of TrainingExample
            X = np.stack([ex.features for ex in data])
            y = np.array([ex.label for ex in data])
            return X, y
        else:
            # Assume already numpy arrays
            return data.features, data.labels
    
    def _train_random_forest(
        self,
        X_train: np.ndarray,
        y_train: np.ndarray,
        X_val: np.ndarray,
        y_val: np.ndarray,
        config: TrainingConfig
    ) -> Tuple[Any, Dict[str, List[float]]]:
        """Train Random Forest model."""
        try:
            from sklearn.ensemble import RandomForestClassifier
        except ImportError:
            raise ImportError("scikit-learn required for Random Forest")
        
        params = config.hyperparameters.copy()
        params.setdefault("n_estimators", 100)
        params.setdefault("max_depth", 10)
        params.setdefault("random_state", config.random_seed)
        
        model = RandomForestClassifier(**params)
        model.fit(X_train, y_train)
        
        # Compute metrics for history
        train_acc = model.score(X_train, y_train)
        val_acc = model.score(X_val, y_val)
        
        history = {
            "train_accuracy": [train_acc],
            "val_accuracy": [val_acc],
        }
        
        return model, history
    
    def _train_xgboost(
        self,
        X_train: np.ndarray,
        y_train: np.ndarray,
        X_val: np.ndarray,
        y_val: np.ndarray,
        config: TrainingConfig
    ) -> Tuple[Any, Dict[str, List[float]]]:
        """Train XGBoost model."""
        try:
            import xgboost as xgb
        except ImportError:
            # Fallback to sklearn gradient boosting
            from sklearn.ensemble import GradientBoostingClassifier
            
            params = config.hyperparameters.copy()
            params.setdefault("n_estimators", 100)
            params.setdefault("max_depth", 6)
            params.setdefault("random_state", config.random_seed)
            
            model = GradientBoostingClassifier(**params)
            model.fit(X_train, y_train)
            
            return model, {
                "train_accuracy": [model.score(X_train, y_train)],
                "val_accuracy": [model.score(X_val, y_val)],
            }
        
        params = {
            "objective": "binary:logistic",
            "eval_metric": "auc",
            "max_depth": config.hyperparameters.get("max_depth", 6),
            "learning_rate": config.learning_rate,
            "n_estimators": config.hyperparameters.get("n_estimators", 100),
            "random_state": config.random_seed,
            "early_stopping_rounds": config.early_stopping_patience,
        }
        
        model = xgb.XGBClassifier(**params)
        model.fit(
            X_train, y_train,
            eval_set=[(X_val, y_val)],
            verbose=False,
        )
        
        history = {
            "train_accuracy": [model.score(X_train, y_train)],
            "val_accuracy": [model.score(X_val, y_val)],
        }
        
        return model, history
    
    def _train_neural_net(
        self,
        X_train: np.ndarray,
        y_train: np.ndarray,
        X_val: np.ndarray,
        y_val: np.ndarray,
        config: TrainingConfig
    ) -> Tuple[Any, Dict[str, List[float]]]:
        """Train neural network model."""
        try:
            from sklearn.neural_network import MLPClassifier
        except ImportError:
            raise ImportError("scikit-learn required for neural network")
        
        hidden_layers = config.hyperparameters.get("hidden_layers", (100, 50))
        
        model = MLPClassifier(
            hidden_layer_sizes=hidden_layers,
            learning_rate_init=config.learning_rate,
            max_iter=config.epochs,
            early_stopping=True,
            validation_fraction=0.1,
            n_iter_no_change=config.early_stopping_patience,
            random_state=config.random_seed,
        )
        
        model.fit(X_train, y_train)
        
        history = {
            "train_loss": model.loss_curve_ if hasattr(model, 'loss_curve_') else [],
            "train_accuracy": [model.score(X_train, y_train)],
            "val_accuracy": [model.score(X_val, y_val)],
        }
        
        return model, history
    
    def _compute_metrics(
        self,
        model: Any,
        X: np.ndarray,
        y: np.ndarray
    ) -> Dict[str, float]:
        """Compute evaluation metrics."""
        try:
            from sklearn.metrics import (
                accuracy_score, precision_score, recall_score,
                f1_score, roc_auc_score
            )
            
            y_pred = model.predict(X)
            y_proba = None
            if hasattr(model, 'predict_proba'):
                y_proba = model.predict_proba(X)[:, 1]
            
            metrics = {
                "accuracy": float(accuracy_score(y, y_pred)),
                "precision": float(precision_score(y, y_pred, zero_division=0)),
                "recall": float(recall_score(y, y_pred, zero_division=0)),
                "f1_score": float(f1_score(y, y_pred, zero_division=0)),
            }
            
            if y_proba is not None:
                try:
                    metrics["auc_roc"] = float(roc_auc_score(y, y_proba))
                except ValueError:
                    pass  # Only one class in y
            
            return metrics
            
        except ImportError:
            return {"accuracy": float(model.score(X, y))}
    
    def hyperparameter_search(
        self,
        train_data: Any,
        val_data: Any,
        model_type: str,
        param_grid: Dict[str, List[Any]],
        scoring: str = "accuracy",
        n_trials: int = 20
    ) -> Tuple[Dict[str, Any], TrainingResult]:
        """
        Search for optimal hyperparameters.
        
        Args:
            train_data: Training data
            val_data: Validation data
            model_type: Type of model to train
            param_grid: Dictionary of parameter -> list of values
            scoring: Metric to optimize
            n_trials: Number of random search trials
        
        Returns:
            Tuple of (best_params, best_result)
        """
        best_score = -np.inf
        best_params = None
        best_result = None
        
        # Random search
        for _ in range(n_trials):
            # Sample random params
            params = {
                key: np.random.choice(values)
                for key, values in param_grid.items()
            }
            
            config = TrainingConfig(
                model_type=model_type,
                hyperparameters=params,
            )
            
            try:
                result = self.train(train_data, val_data, config)
                score = result.val_metrics.get(scoring, 0)
                
                if score > best_score:
                    best_score = score
                    best_params = params
                    best_result = result
            except Exception as e:
                print(f"Trial failed with params {params}: {e}")
        
        return best_params, best_result
    
    def cross_validate(
        self,
        data: List[Any],
        config: TrainingConfig,
        n_folds: int = 5
    ) -> Dict[str, List[float]]:
        """
        Perform k-fold cross-validation.
        
        Args:
            data: All training examples
            config: Training configuration
            n_folds: Number of folds
        
        Returns:
            Dictionary of metric -> list of scores per fold
        """
        np.random.seed(config.random_seed)
        indices = np.arange(len(data))
        np.random.shuffle(indices)
        
        fold_size = len(data) // n_folds
        all_metrics = {}
        
        for fold in range(n_folds):
            # Define fold indices
            val_start = fold * fold_size
            val_end = val_start + fold_size
            
            val_indices = indices[val_start:val_end]
            train_indices = np.concatenate([indices[:val_start], indices[val_end:]])
            
            train_fold = [data[i] for i in train_indices]
            val_fold = [data[i] for i in val_indices]
            
            result = self.train(train_fold, val_fold, config)
            
            for metric, value in result.val_metrics.items():
                if metric not in all_metrics:
                    all_metrics[metric] = []
                all_metrics[metric].append(value)
        
        return all_metrics
