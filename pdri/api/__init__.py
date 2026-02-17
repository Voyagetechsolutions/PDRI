"""
PDRI API Package
================

FastAPI REST API layer for the PDRI platform.

This package provides:
    - main: FastAPI application and route configuration
    - routes/: Endpoint implementations
    - dependencies: Shared dependency injection

Author: PDRI Team
Version: 1.0.0
"""

from pdri.api.main import app, create_app

__all__ = [
    "app",
    "create_app",
]
