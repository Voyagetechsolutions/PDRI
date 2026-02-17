"""
Privacy-Preserving Techniques
============================

Differential privacy and secure aggregation for federated learning.

Features:
    - Differential Privacy noise addition
    - Gradient clipping
    - Secure multi-party aggregation
    - Privacy budget tracking

Author: PDRI Team
Version: 1.0.0
"""

from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple
import numpy as np


@dataclass
class PrivacyBudget:
    """Track privacy budget consumption."""
    total_epsilon: float
    total_delta: float
    consumed_epsilon: float = 0.0
    consumed_delta: float = 0.0
    query_count: int = 0
    
    @property
    def remaining_epsilon(self) -> float:
        return max(0, self.total_epsilon - self.consumed_epsilon)
    
    @property
    def remaining_delta(self) -> float:
        return max(0, self.total_delta - self.consumed_delta)
    
    @property
    def is_exhausted(self) -> bool:
        return self.remaining_epsilon <= 0 or self.remaining_delta <= 0
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "total_epsilon": self.total_epsilon,
            "total_delta": self.total_delta,
            "consumed_epsilon": self.consumed_epsilon,
            "consumed_delta": self.consumed_delta,
            "remaining_epsilon": self.remaining_epsilon,
            "remaining_delta": self.remaining_delta,
            "query_count": self.query_count,
            "is_exhausted": self.is_exhausted,
        }


class DifferentialPrivacy:
    """
    Apply differential privacy to gradients and queries.
    
    Differential privacy provides mathematically provable guarantees
    that individual data points cannot be identified from model outputs.
    
    Methods:
    - Gaussian mechanism: Add calibrated Gaussian noise
    - Laplacian mechanism: Add calibrated Laplacian noise
    - Gradient clipping: Bound sensitivity before noise
    
    Example:
        dp = DifferentialPrivacy(epsilon=1.0, delta=1e-5)
        private_gradients = dp.add_noise(gradients)
    """
    
    def __init__(
        self,
        epsilon: float = 1.0,
        delta: float = 1e-5,
        max_grad_norm: float = 1.0,
        mechanism: str = "gaussian"
    ):
        """
        Initialize differential privacy engine.
        
        Args:
            epsilon: Privacy budget (lower = more private)
            delta: Probability of privacy breach
            max_grad_norm: Maximum gradient L2 norm (for clipping)
            mechanism: Noise mechanism ("gaussian" or "laplacian")
        """
        self.epsilon = epsilon
        self.delta = delta
        self.max_grad_norm = max_grad_norm
        self.mechanism = mechanism
        
        self.budget = PrivacyBudget(
            total_epsilon=epsilon * 100,  # Allow 100 queries
            total_delta=delta * 100,
        )
    
    def add_noise(
        self,
        gradients: Dict[str, np.ndarray],
        epsilon: Optional[float] = None,
        delta: Optional[float] = None
    ) -> Dict[str, np.ndarray]:
        """
        Add differential privacy noise to gradients.
        
        Args:
            gradients: Dictionary of gradient arrays
            epsilon: Optional per-query epsilon
            delta: Optional per-query delta
        
        Returns:
            Noisy gradients
        """
        eps = epsilon or self.epsilon
        dlt = delta or self.delta
        
        # Check budget
        if self.budget.is_exhausted:
            raise RuntimeError("Privacy budget exhausted")
        
        # Clip gradients
        clipped = self._clip_gradients(gradients)
        
        # Add noise based on mechanism
        if self.mechanism == "gaussian":
            noisy = self._gaussian_mechanism(clipped, eps, dlt)
        else:
            noisy = self._laplacian_mechanism(clipped, eps)
        
        # Update budget
        self.budget.consumed_epsilon += eps
        self.budget.consumed_delta += dlt
        self.budget.query_count += 1
        
        return noisy
    
    def _clip_gradients(
        self,
        gradients: Dict[str, np.ndarray]
    ) -> Dict[str, np.ndarray]:
        """Clip gradient norms to bound sensitivity."""
        clipped = {}
        
        for key, grad in gradients.items():
            norm = np.linalg.norm(grad)
            if norm > self.max_grad_norm:
                # Scale down to max norm
                clipped[key] = grad * (self.max_grad_norm / norm)
            else:
                clipped[key] = grad.copy()
        
        return clipped
    
    def _gaussian_mechanism(
        self,
        gradients: Dict[str, np.ndarray],
        epsilon: float,
        delta: float
    ) -> Dict[str, np.ndarray]:
        """
        Add calibrated Gaussian noise.
        
        Noise calibrated for (epsilon, delta)-DP.
        """
        # Compute noise scale (sigma)
        sensitivity = self.max_grad_norm
        c = np.sqrt(2 * np.log(1.25 / delta))
        sigma = c * sensitivity / epsilon
        
        noisy = {}
        for key, grad in gradients.items():
            noise = np.random.normal(0, sigma, grad.shape)
            noisy[key] = grad + noise
        
        return noisy
    
    def _laplacian_mechanism(
        self,
        gradients: Dict[str, np.ndarray],
        epsilon: float
    ) -> Dict[str, np.ndarray]:
        """
        Add calibrated Laplacian noise.
        
        Noise calibrated for epsilon-DP.
        """
        sensitivity = self.max_grad_norm
        scale = sensitivity / epsilon
        
        noisy = {}
        for key, grad in gradients.items():
            noise = np.random.laplace(0, scale, grad.shape)
            noisy[key] = grad + noise
        
        return noisy
    
    def privatize_query(
        self,
        value: float,
        sensitivity: float,
        epsilon: Optional[float] = None
    ) -> float:
        """
        Add noise to a numeric query result.
        
        Args:
            value: True query result
            sensitivity: Query sensitivity
            epsilon: Privacy budget for this query
        
        Returns:
            Noisy result
        """
        eps = epsilon or self.epsilon
        
        if self.mechanism == "gaussian":
            sigma = sensitivity * np.sqrt(2 * np.log(1.25 / self.delta)) / eps
            noise = np.random.normal(0, sigma)
        else:
            scale = sensitivity / eps
            noise = np.random.laplace(0, scale)
        
        self.budget.consumed_epsilon += eps
        self.budget.query_count += 1
        
        return value + noise
    
    def get_budget_status(self) -> PrivacyBudget:
        """Get current privacy budget status."""
        return self.budget
    
    def reset_budget(self) -> None:
        """Reset privacy budget for new training period."""
        self.budget = PrivacyBudget(
            total_epsilon=self.epsilon * 100,
            total_delta=self.delta * 100,
        )


class SecureAggregation:
    """
    Secure multi-party aggregation.
    
    Enables aggregation of values without revealing individual inputs.
    Uses secret sharing and masking techniques.
    
    This is a simplified implementation for demonstration.
    Production would use Paillier encryption or MPC libraries.
    
    Example:
        sa = SecureAggregation(num_parties=10)
        shares = sa.create_shares(my_gradient, party_id=0)
        # ... exchange shares ...
        aggregated = sa.aggregate_shares(all_shares)
    """
    
    def __init__(
        self,
        num_parties: int,
        threshold: int = None,
        prime: int = 2**31 - 1
    ):
        """
        Initialize secure aggregation.
        
        Args:
            num_parties: Number of participating parties
            threshold: Minimum parties needed for reconstruction
            prime: Prime for modular arithmetic
        """
        self.num_parties = num_parties
        self.threshold = threshold or (num_parties // 2 + 1)
        self.prime = prime
        
        # Per-party random masks
        self._masks: Dict[int, Dict[str, np.ndarray]] = {}
    
    def create_shares(
        self,
        gradients: Dict[str, np.ndarray],
        party_id: int
    ) -> Dict[str, Dict[str, np.ndarray]]:
        """
        Create secret shares of gradients.
        
        Args:
            gradients: Gradient arrays to share
            party_id: ID of this party
        
        Returns:
            Dictionary of party_id -> shares
        """
        shares = {i: {} for i in range(self.num_parties)}
        
        for key, grad in gradients.items():
            # Create random shares that sum to gradient
            random_shares = [
                np.random.randint(-1000, 1000, grad.shape, dtype=np.int64)
                for _ in range(self.num_parties - 1)
            ]
            
            # Last share makes sum equal gradient
            last_share = (grad * 1000).astype(np.int64) - sum(random_shares)
            random_shares.append(last_share)
            
            # Distribute shares
            for i, share in enumerate(random_shares):
                shares[i][key] = share
        
        return shares
    
    def aggregate_shares(
        self,
        all_shares: List[Dict[int, Dict[str, np.ndarray]]]
    ) -> Dict[str, np.ndarray]:
        """
        Aggregate shares from all parties.
        
        Args:
            all_shares: List of share dictionaries from each party
        
        Returns:
            Aggregated gradients
        """
        if len(all_shares) < self.threshold:
            raise ValueError(f"Insufficient shares: {len(all_shares)} < {self.threshold}")
        
        # Sum shares from all parties
        aggregated = {}
        
        # For each party's shares
        for party_shares in all_shares:
            for party_id, shares in party_shares.items():
                for key, share in shares.items():
                    if key not in aggregated:
                        aggregated[key] = share.astype(np.float64)
                    else:
                        aggregated[key] = aggregated[key] + share.astype(np.float64)
        
        # Rescale back
        for key in aggregated:
            aggregated[key] = aggregated[key] / (1000 * len(all_shares))
        
        return aggregated
    
    def generate_mask(
        self,
        shape: Tuple[int, ...],
        party_i: int,
        party_j: int,
        seed: int
    ) -> np.ndarray:
        """
        Generate pairwise mask between two parties.
        
        Masks cancel out during aggregation.
        """
        np.random.seed(seed)
        mask = np.random.normal(0, 1, shape)
        
        # Party with lower ID adds, higher ID subtracts
        if party_i < party_j:
            return mask
        else:
            return -mask
    
    def masked_aggregation(
        self,
        gradients: Dict[str, np.ndarray],
        party_id: int,
        seeds: Dict[int, int]
    ) -> Dict[str, np.ndarray]:
        """
        Add pairwise masks to gradients for secure aggregation.
        
        Args:
            gradients: Gradient arrays
            party_id: This party's ID
            seeds: Dictionary of other_party_id -> shared seed
        
        Returns:
            Masked gradients
        """
        masked = {}
        
        for key, grad in gradients.items():
            masked_grad = grad.copy()
            
            for other_id, seed in seeds.items():
                mask = self.generate_mask(grad.shape, party_id, other_id, seed)
                masked_grad = masked_grad + mask
            
            masked[key] = masked_grad
        
        return masked
