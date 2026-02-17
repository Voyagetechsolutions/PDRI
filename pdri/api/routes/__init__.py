"""
PDRI API Routes Package
=======================

FastAPI route modules.

Author: PDRI Team
Version: 1.0.0
"""

from pdri.api.routes.nodes import router as nodes_router
from pdri.api.routes.scoring import router as scoring_router
from pdri.api.routes.analytics import router as analytics_router
from pdri.api.routes.health import router as health_router
from pdri.api.routes.aegis_webhooks import router as aegis_webhooks_router

__all__ = [
    "nodes_router",
    "scoring_router",
    "analytics_router",
    "health_router",
    "aegis_webhooks_router",
]
