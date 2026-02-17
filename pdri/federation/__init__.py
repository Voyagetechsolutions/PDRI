"""
PDRI Federation Package
=======================

Federated learning and privacy-preserving model sharing.

Author: PDRI Team
Version: 1.0.0
"""

from .client import FederationClient
from .aggregator import FederatedAggregator
from .privacy import DifferentialPrivacy, SecureAggregation

__all__ = [
    "FederationClient",
    "FederatedAggregator",
    "DifferentialPrivacy",
    "SecureAggregation",
]
