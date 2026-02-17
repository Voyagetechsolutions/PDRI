"""
Federated Aggregator
====================

Server-side aggregation of federated model updates.

Methods:
    - FedAvg: Weighted averaging of gradients
    - FedProx: Proximal term for heterogeneous data
    - FedSGD: Synchronized stochastic gradient descent

Author: PDRI Team
Version: 1.0.0
"""

from dataclasses import dataclass
from datetime import datetime
from typing import Any, Dict, List, Optional
import numpy as np


@dataclass
class AggregationRound:
    """A single round of federated aggregation."""
    round_id: str
    started_at: datetime
    completed_at: Optional[datetime] = None
    participating_orgs: int = 0
    total_samples: int = 0
    aggregated_metrics: Dict[str, float] = None
    status: str = "pending"  # pending, in_progress, completed
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "round_id": self.round_id,
            "started_at": self.started_at.isoformat(),
            "completed_at": self.completed_at.isoformat() if self.completed_at else None,
            "participating_orgs": self.participating_orgs,
            "total_samples": self.total_samples,
            "aggregated_metrics": self.aggregated_metrics or {},
            "status": self.status,
        }


class FederatedAggregator:
    """
    Server-side federated model aggregation.
    
    Aggregates model updates from multiple organizations:
    - Weighted by sample count
    - Privacy-preserved (no raw data)
    - Secure aggregation support
    
    Example:
        aggregator = FederatedAggregator()
        
        # Collect updates from organizations
        for update in org_updates:
            aggregator.add_update(update)
        
        # Aggregate
        global_weights = aggregator.aggregate()
    """
    
    def __init__(
        self,
        method: str = "fedavg",
        min_participants: int = 3,
        staleness_threshold_hours: int = 24
    ):
        """
        Initialize aggregator.
        
        Args:
            method: Aggregation method (fedavg, fedprox)
            min_participants: Minimum orgs required to aggregate
            staleness_threshold_hours: Max age of updates to include
        """
        self.method = method
        self.min_participants = min_participants
        self.staleness_threshold_hours = staleness_threshold_hours
        
        # Current round state
        self._current_round: Optional[AggregationRound] = None
        self._pending_updates: List[Dict[str, Any]] = []
        self._global_weights: Dict[str, np.ndarray] = {}
        self._round_counter = 0
        
        # Fingerprint aggregation
        self._global_fingerprints: List[Dict[str, Any]] = []
    
    def start_round(self) -> AggregationRound:
        """
        Start a new aggregation round.
        
        Returns:
            New AggregationRound object
        """
        self._round_counter += 1
        self._pending_updates = []
        
        self._current_round = AggregationRound(
            round_id=f"round-{self._round_counter:06d}",
            started_at=datetime.utcnow(),
            status="in_progress",
        )
        
        return self._current_round
    
    def add_update(self, update: Dict[str, Any]) -> bool:
        """
        Add a model update to current round.
        
        Args:
            update: Model update dictionary
        
        Returns:
            True if accepted, False otherwise
        """
        if self._current_round is None:
            self.start_round()
        
        # Validate update
        if not self._validate_update(update):
            return False
        
        # Check staleness
        update_time = datetime.fromisoformat(update.get("timestamp", datetime.utcnow().isoformat()))
        age_hours = (datetime.utcnow() - update_time).total_seconds() / 3600
        if age_hours > self.staleness_threshold_hours:
            return False
        
        self._pending_updates.append(update)
        
        # Update round stats
        self._current_round.participating_orgs = len(set(
            u.get("organization_id") for u in self._pending_updates
        ))
        self._current_round.total_samples += update.get("sample_count", 0)
        
        # Collect fingerprints
        fingerprints = update.get("fingerprints", [])
        self._global_fingerprints.extend(fingerprints)
        
        return True
    
    def _validate_update(self, update: Dict[str, Any]) -> bool:
        """Validate update structure."""
        required = ["organization_id", "gradients", "sample_count"]
        return all(key in update for key in required)
    
    def aggregate(self) -> Dict[str, np.ndarray]:
        """
        Aggregate all pending updates.
        
        Returns:
            Aggregated model weights
        """
        if len(self._pending_updates) < self.min_participants:
            raise ValueError(
                f"Insufficient participants: {len(self._pending_updates)} < {self.min_participants}"
            )
        
        if self.method == "fedavg":
            aggregated = self._fedavg()
        elif self.method == "fedprox":
            aggregated = self._fedprox()
        else:
            aggregated = self._fedavg()
        
        # Update global weights
        for key, value in aggregated.items():
            if key in self._global_weights:
                self._global_weights[key] = self._global_weights[key] + value
            else:
                self._global_weights[key] = value
        
        # Complete round
        if self._current_round:
            self._current_round.status = "completed"
            self._current_round.completed_at = datetime.utcnow()
            self._current_round.aggregated_metrics = self._compute_aggregated_metrics()
        
        # Deduplicate fingerprints
        self._deduplicate_fingerprints()
        
        return self._global_weights.copy()
    
    def _fedavg(self) -> Dict[str, np.ndarray]:
        """
        Federated Averaging aggregation.
        
        Weight updates by sample count.
        """
        aggregated = {}
        total_samples = sum(u.get("sample_count", 1) for u in self._pending_updates)
        
        for update in self._pending_updates:
            weight = update.get("sample_count", 1) / total_samples
            gradients = update.get("gradients", {})
            
            for key, gradient in gradients.items():
                gradient_array = np.array(gradient)
                weighted = gradient_array * weight
                
                if key in aggregated:
                    aggregated[key] = aggregated[key] + weighted
                else:
                    aggregated[key] = weighted
        
        return aggregated
    
    def _fedprox(self, mu: float = 0.01) -> Dict[str, np.ndarray]:
        """
        FedProx aggregation with proximal term.
        
        Better for heterogeneous data distributions.
        """
        # Start with fedavg
        aggregated = self._fedavg()
        
        # Add proximal regularization toward global model
        for key, value in aggregated.items():
            if key in self._global_weights:
                # Proximal term: pull toward global model
                proximal = mu * (self._global_weights[key] - value)
                aggregated[key] = value + proximal
        
        return aggregated
    
    def _compute_aggregated_metrics(self) -> Dict[str, float]:
        """Compute aggregated metrics from all updates."""
        all_metrics = [u.get("local_metrics", {}) for u in self._pending_updates]
        
        if not all_metrics or not all_metrics[0]:
            return {}
        
        metric_names = set()
        for m in all_metrics:
            metric_names.update(m.keys())
        
        aggregated = {}
        for name in metric_names:
            values = [m.get(name, 0) for m in all_metrics if name in m]
            if values:
                aggregated[name] = float(np.mean(values))
        
        return aggregated
    
    def _deduplicate_fingerprints(self) -> None:
        """Remove duplicate fingerprints."""
        seen = set()
        unique = []
        
        for fp in self._global_fingerprints:
            fp_id = fp.get("fingerprint_id")
            if fp_id not in seen:
                seen.add(fp_id)
                unique.append(fp)
        
        self._global_fingerprints = unique
    
    def get_global_weights(self) -> Dict[str, np.ndarray]:
        """Get current global model weights."""
        return self._global_weights.copy()
    
    def get_global_fingerprints(self) -> List[Dict[str, Any]]:
        """Get all aggregated fingerprints."""
        return self._global_fingerprints.copy()
    
    def get_round_status(self) -> Optional[AggregationRound]:
        """Get current round status."""
        return self._current_round
    
    def create_global_update(self) -> Dict[str, Any]:
        """
        Create a global update for distribution.
        
        Returns:
            Dictionary suitable for client consumption
        """
        return {
            "update_id": f"global-{datetime.utcnow().strftime('%Y%m%d%H%M%S')}",
            "model_version": f"v{self._round_counter}.0",
            "timestamp": datetime.utcnow().isoformat(),
            "aggregated_weights": {
                k: v.tolist() for k, v in self._global_weights.items()
            },
            "global_metrics": self._current_round.aggregated_metrics if self._current_round else {},
            "participating_orgs": self._current_round.participating_orgs if self._current_round else 0,
            "new_fingerprints": self._global_fingerprints[-100:],  # Last 100
        }
    
    def set_initial_weights(self, weights: Dict[str, np.ndarray]) -> None:
        """Set initial global model weights."""
        self._global_weights = {k: np.array(v) for k, v in weights.items()}
