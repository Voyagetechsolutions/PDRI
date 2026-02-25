"""
PDRI API Routes Package
=======================

FastAPI route modules.

Author: PDRI Team
Version: 2.0.0
"""

from pdri.api.routes.nodes import router as nodes_router
from pdri.api.routes.scoring import router as scoring_router
from pdri.api.routes.analytics import router as analytics_router
from pdri.api.routes.health import router as health_router
from pdri.api.routes.findings import router as findings_router
from pdri.api.routes.identity import router as identity_router
from pdri.api.routes.velocity import router as velocity_router
from pdri.api.routes.lineage import router as lineage_router

__all__ = [
    "nodes_router",
    "scoring_router",
    "analytics_router",
    "health_router",
    "findings_router",
    "identity_router",
    "velocity_router",
    "lineage_router",
]
