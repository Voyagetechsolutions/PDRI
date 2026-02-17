"""
Model Evaluation Module
=======================

Comprehensive evaluation of trained models.

Features:
    - Standard classification metrics
    - Confusion matrix analysis
    - Feature importance
    - Calibration curves
    - Error analysis

Author: PDRI Team
Version: 1.0.0
"""

from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple
import numpy as np


@dataclass
class EvaluationReport:
    """Complete evaluation report for a model."""
    model_name: str
    dataset_name: str
    sample_count: int
    metrics: Dict[str, float]
    confusion_matrix: Optional[np.ndarray] = None
    class_report: Optional[Dict[str, Dict[str, float]]] = None
    feature_importance: Optional[Dict[str, float]] = None
    calibration_curve: Optional[Dict[str, List[float]]] = None
    error_analysis: Optional[Dict[str, Any]] = None
    
    def to_dict(self) -> Dict[str, Any]:
        result = {
            "model_name": self.model_name,
            "dataset_name": self.dataset_name,
            "sample_count": self.sample_count,
            "metrics": self.metrics,
        }
        
        if self.confusion_matrix is not None:
            result["confusion_matrix"] = self.confusion_matrix.tolist()
        if self.class_report:
            result["class_report"] = self.class_report
        if self.feature_importance:
            result["feature_importance"] = self.feature_importance
        if self.error_analysis:
            result["error_analysis"] = self.error_analysis
        
        return result
    
    def summary(self) -> str:
        """Generate text summary."""
        lines = [
            f"Model: {self.model_name}",
            f"Dataset: {self.dataset_name} ({self.sample_count} samples)",
            "",
            "Metrics:",
        ]
        
        for name, value in self.metrics.items():
            lines.append(f"  {name}: {value:.4f}")
        
        if self.feature_importance:
            lines.append("")
            lines.append("Top 5 Features:")
            sorted_features = sorted(
                self.feature_importance.items(),
                key=lambda x: x[1],
                reverse=True
            )[:5]
            for name, importance in sorted_features:
                lines.append(f"  {name}: {importance:.4f}")
        
        return "\n".join(lines)


class ModelEvaluator:
    """
    Evaluate ML models comprehensively.
    
    Provides:
    - Classification metrics (accuracy, precision, recall, F1, AUC)
    - Confusion matrix
    - Per-class performance
    - Feature importance analysis
    - Calibration assessment
    - Error analysis for debugging
    
    Example:
        evaluator = ModelEvaluator()
        report = evaluator.evaluate(model, X_test, y_test, feature_names)
        print(report.summary())
    """
    
    def __init__(self, threshold: float = 0.5):
        """
        Initialize evaluator.
        
        Args:
            threshold: Classification threshold for binary classification
        """
        self.threshold = threshold
    
    def evaluate(
        self,
        model: Any,
        X: np.ndarray,
        y: np.ndarray,
        feature_names: Optional[List[str]] = None,
        model_name: str = "model",
        dataset_name: str = "test"
    ) -> EvaluationReport:
        """
        Evaluate a model on a dataset.
        
        Args:
            model: Trained model
            X: Feature matrix
            y: True labels
            feature_names: Optional feature names
            model_name: Name for the model
            dataset_name: Name for the dataset
        
        Returns:
            EvaluationReport with all metrics
        """
        # Get predictions
        y_pred = model.predict(X)
        y_proba = None
        if hasattr(model, 'predict_proba'):
            y_proba = model.predict_proba(X)
        
        # Compute metrics
        metrics = self._compute_classification_metrics(y, y_pred, y_proba)
        
        # Confusion matrix
        cm = self._compute_confusion_matrix(y, y_pred)
        
        # Per-class report
        class_report = self._compute_class_report(y, y_pred)
        
        # Feature importance
        feature_importance = None
        if feature_names:
            feature_importance = self._compute_feature_importance(
                model, X, y, feature_names
            )
        
        # Calibration curve
        calibration = None
        if y_proba is not None:
            calibration = self._compute_calibration_curve(y, y_proba)
        
        # Error analysis
        error_analysis = self._analyze_errors(X, y, y_pred, feature_names)
        
        return EvaluationReport(
            model_name=model_name,
            dataset_name=dataset_name,
            sample_count=len(y),
            metrics=metrics,
            confusion_matrix=cm,
            class_report=class_report,
            feature_importance=feature_importance,
            calibration_curve=calibration,
            error_analysis=error_analysis,
        )
    
    def _compute_classification_metrics(
        self,
        y_true: np.ndarray,
        y_pred: np.ndarray,
        y_proba: Optional[np.ndarray]
    ) -> Dict[str, float]:
        """Compute standard classification metrics."""
        try:
            from sklearn.metrics import (
                accuracy_score, precision_score, recall_score,
                f1_score, roc_auc_score, log_loss, matthews_corrcoef
            )
            
            metrics = {
                "accuracy": float(accuracy_score(y_true, y_pred)),
                "precision": float(precision_score(y_true, y_pred, zero_division=0)),
                "recall": float(recall_score(y_true, y_pred, zero_division=0)),
                "f1_score": float(f1_score(y_true, y_pred, zero_division=0)),
            }
            
            # Matthews correlation coefficient
            try:
                metrics["mcc"] = float(matthews_corrcoef(y_true, y_pred))
            except Exception:
                pass
            
            # Probability-based metrics
            if y_proba is not None:
                proba = y_proba[:, 1] if y_proba.ndim > 1 else y_proba
                
                try:
                    metrics["auc_roc"] = float(roc_auc_score(y_true, proba))
                except ValueError:
                    pass
                
                try:
                    metrics["log_loss"] = float(log_loss(y_true, proba))
                except Exception:
                    pass
            
            return metrics
            
        except ImportError:
            # Fallback manual accuracy
            return {"accuracy": float(np.mean(y_true == y_pred))}
    
    def _compute_confusion_matrix(
        self,
        y_true: np.ndarray,
        y_pred: np.ndarray
    ) -> np.ndarray:
        """Compute confusion matrix."""
        try:
            from sklearn.metrics import confusion_matrix
            return confusion_matrix(y_true, y_pred)
        except ImportError:
            # Manual calculation for binary
            tp = np.sum((y_true == 1) & (y_pred == 1))
            tn = np.sum((y_true == 0) & (y_pred == 0))
            fp = np.sum((y_true == 0) & (y_pred == 1))
            fn = np.sum((y_true == 1) & (y_pred == 0))
            return np.array([[tn, fp], [fn, tp]])
    
    def _compute_class_report(
        self,
        y_true: np.ndarray,
        y_pred: np.ndarray
    ) -> Dict[str, Dict[str, float]]:
        """Compute per-class metrics."""
        try:
            from sklearn.metrics import classification_report
            report = classification_report(y_true, y_pred, output_dict=True)
            return report
        except ImportError:
            return {}
    
    def _compute_feature_importance(
        self,
        model: Any,
        X: np.ndarray,
        y: np.ndarray,
        feature_names: List[str]
    ) -> Dict[str, float]:
        """Compute feature importance."""
        importance = {}
        
        # Tree-based models have feature_importances_
        if hasattr(model, 'feature_importances_'):
            for i, name in enumerate(feature_names):
                importance[name] = float(model.feature_importances_[i])
            return importance
        
        # Coefficient-based models
        if hasattr(model, 'coef_'):
            coefs = model.coef_.flatten()
            for i, name in enumerate(feature_names):
                if i < len(coefs):
                    importance[name] = float(abs(coefs[i]))
            return importance
        
        # Permutation importance as fallback
        try:
            importance = self._permutation_importance(model, X, y, feature_names)
            return importance
        except Exception:
            return {}
    
    def _permutation_importance(
        self,
        model: Any,
        X: np.ndarray,
        y: np.ndarray,
        feature_names: List[str],
        n_repeats: int = 10
    ) -> Dict[str, float]:
        """Compute permutation importance."""
        baseline_score = model.score(X, y)
        importance = {}
        
        for i, name in enumerate(feature_names):
            scores = []
            for _ in range(n_repeats):
                X_permuted = X.copy()
                np.random.shuffle(X_permuted[:, i])
                score = model.score(X_permuted, y)
                scores.append(baseline_score - score)
            
            importance[name] = float(np.mean(scores))
        
        return importance
    
    def _compute_calibration_curve(
        self,
        y_true: np.ndarray,
        y_proba: np.ndarray,
        n_bins: int = 10
    ) -> Dict[str, List[float]]:
        """Compute calibration curve."""
        proba = y_proba[:, 1] if y_proba.ndim > 1 else y_proba
        
        bin_edges = np.linspace(0, 1, n_bins + 1)
        mean_predicted = []
        fraction_positive = []
        
        for i in range(n_bins):
            mask = (proba >= bin_edges[i]) & (proba < bin_edges[i + 1])
            if np.sum(mask) > 0:
                mean_predicted.append(float(np.mean(proba[mask])))
                fraction_positive.append(float(np.mean(y_true[mask])))
        
        return {
            "mean_predicted": mean_predicted,
            "fraction_positive": fraction_positive,
        }
    
    def _analyze_errors(
        self,
        X: np.ndarray,
        y_true: np.ndarray,
        y_pred: np.ndarray,
        feature_names: Optional[List[str]] = None
    ) -> Dict[str, Any]:
        """Analyze prediction errors."""
        errors = y_true != y_pred
        n_errors = int(np.sum(errors))
        
        analysis = {
            "total_errors": n_errors,
            "error_rate": float(n_errors / len(y_true)),
        }
        
        if n_errors == 0:
            return analysis
        
        # False positives and negatives
        fp = (y_true == 0) & (y_pred == 1)
        fn = (y_true == 1) & (y_pred == 0)
        
        analysis["false_positives"] = int(np.sum(fp))
        analysis["false_negatives"] = int(np.sum(fn))
        
        # Feature statistics for errors
        if feature_names and len(feature_names) <= X.shape[1]:
            error_features = X[errors]
            correct_features = X[~errors]
            
            feature_diffs = {}
            for i, name in enumerate(feature_names[:X.shape[1]]):
                error_mean = float(np.mean(error_features[:, i]))
                correct_mean = float(np.mean(correct_features[:, i]))
                feature_diffs[name] = {
                    "error_mean": error_mean,
                    "correct_mean": correct_mean,
                    "difference": error_mean - correct_mean,
                }
            
            # Sort by absolute difference
            sorted_diffs = sorted(
                feature_diffs.items(),
                key=lambda x: abs(x[1]["difference"]),
                reverse=True
            )
            analysis["top_error_features"] = dict(sorted_diffs[:5])
        
        return analysis
    
    def compare_models(
        self,
        models: List[Tuple[str, Any]],
        X: np.ndarray,
        y: np.ndarray,
        feature_names: Optional[List[str]] = None
    ) -> Dict[str, EvaluationReport]:
        """
        Compare multiple models.
        
        Args:
            models: List of (name, model) tuples
            X: Test features
            y: Test labels
            feature_names: Optional feature names
        
        Returns:
            Dictionary of model_name -> EvaluationReport
        """
        reports = {}
        for name, model in models:
            reports[name] = self.evaluate(
                model, X, y, feature_names,
                model_name=name
            )
        return reports
    
    def find_threshold(
        self,
        model: Any,
        X: np.ndarray,
        y: np.ndarray,
        metric: str = "f1_score",
        thresholds: Optional[List[float]] = None
    ) -> Tuple[float, Dict[str, float]]:
        """
        Find optimal classification threshold.
        
        Args:
            model: Trained model
            X: Features
            y: Labels
            metric: Metric to optimize
            thresholds: Optional list of thresholds to try
        
        Returns:
            Tuple of (best_threshold, best_metrics)
        """
        if not hasattr(model, 'predict_proba'):
            return 0.5, {}
        
        if thresholds is None:
            thresholds = np.arange(0.1, 0.91, 0.05).tolist()
        
        y_proba = model.predict_proba(X)[:, 1]
        
        best_threshold = 0.5
        best_score = -np.inf
        best_metrics = {}
        
        for threshold in thresholds:
            y_pred = (y_proba >= threshold).astype(int)
            metrics = self._compute_classification_metrics(y, y_pred, None)
            
            score = metrics.get(metric, 0)
            if score > best_score:
                best_score = score
                best_threshold = threshold
                best_metrics = metrics
        
        return best_threshold, best_metrics
