"""
PDRI Findings Module
====================

Risk findings generation, persistence, and lifecycle management.

This module connects scoring events to actionable findings that
the Platform layer can consume.

Author: PDRI Team
Version: 1.0.0
"""

from pdri.findings.service import FindingsService
from pdri.findings.generator import FindingGenerator

__all__ = ["FindingsService", "FindingGenerator"]
