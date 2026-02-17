"""
Federation Models Package
=========================

Threat fingerprinting and shared signature models.

Author: PDRI Team
Version: 1.0.0
"""

from .threat_fingerprints import ThreatFingerprint, ThreatFingerprintDatabase

__all__ = [
    "ThreatFingerprint",
    "ThreatFingerprintDatabase",
]
