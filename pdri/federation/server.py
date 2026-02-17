"""
Federation Server
=================

FastAPI-based server for federated model aggregation.

Exposes REST endpoints for participating organizations to:
    - Submit model updates
    - Start/complete aggregation rounds
    - Retrieve global model weights
    - Check round status

Uses the existing FederatedAggregator for aggregation logic.

Author: PDRI Team
Version: 1.0.0
"""

import logging
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, FastAPI, HTTPException
from pydantic import BaseModel, Field

from pdri.federation.aggregator import FederatedAggregator

logger = logging.getLogger(__name__)


# ── Request/Response Models ──────────────────────────────────

class StartRoundRequest(BaseModel):
    """Request to start a new aggregation round."""
    method: str = Field(default="fedavg", description="Aggregation method")
    min_participants: int = Field(default=3, ge=1)


class SubmitUpdateRequest(BaseModel):
    """Model update submission from a participating org."""
    org_id: str = Field(..., description="Organization identifier")
    sample_count: int = Field(..., ge=1, description="Number of training samples")
    model_weights: Dict[str, List[float]] = Field(
        ..., description="Model weight arrays per layer"
    )
    metrics: Dict[str, float] = Field(
        default_factory=dict, description="Training metrics"
    )
    fingerprints: List[Dict[str, Any]] = Field(
        default_factory=list, description="Risk pattern fingerprints"
    )


class RoundStatusResponse(BaseModel):
    """Aggregation round status."""
    round_id: str
    status: str
    participating_orgs: int
    total_samples: int
    started_at: str
    completed_at: Optional[str] = None


class GlobalModelResponse(BaseModel):
    """Global aggregated model."""
    round_id: str
    weights: Dict[str, List[float]]
    metrics: Dict[str, float]
    fingerprints: List[Dict[str, Any]]
    timestamp: str


# ── Server ───────────────────────────────────────────────────

class FederationServer:
    """
    Federation server managing model aggregation rounds.

    Lifecycle:
        1. Server starts a round → participants get notified
        2. Participants train locally, submit updates
        3. When min_participants reached, aggregation executes
        4. Global model available for download
    """

    def __init__(
        self,
        method: str = "fedavg",
        min_participants: int = 3,
        staleness_hours: int = 24,
    ):
        self.aggregator = FederatedAggregator(
            method=method,
            min_participants=min_participants,
            staleness_threshold_hours=staleness_hours,
        )
        self.router = self._create_router()
        self._history: List[Dict[str, Any]] = []

    def _create_router(self) -> APIRouter:
        """Create API router with federation endpoints."""
        router = APIRouter(prefix="/federation", tags=["Federation"])

        @router.post("/rounds/start", response_model=RoundStatusResponse)
        async def start_round(request: StartRoundRequest):
            """Start a new aggregation round."""
            # Reconfigure if needed
            if request.method != self.aggregator.method:
                self.aggregator.method = request.method
            if request.min_participants != self.aggregator.min_participants:
                self.aggregator.min_participants = request.min_participants

            round_obj = self.aggregator.start_round()
            logger.info(
                "Aggregation round started: %s (method=%s, min=%d)",
                round_obj.round_id,
                request.method,
                request.min_participants,
            )
            return RoundStatusResponse(
                round_id=round_obj.round_id,
                status=round_obj.status,
                participating_orgs=round_obj.participating_orgs,
                total_samples=round_obj.total_samples,
                started_at=round_obj.started_at.isoformat(),
            )

        @router.post("/updates/submit")
        async def submit_update(request: SubmitUpdateRequest):
            """Submit a model update from a participating organization."""
            if self.aggregator.current_round is None:
                raise HTTPException(
                    status_code=409,
                    detail="No active aggregation round. Start a round first.",
                )

            import numpy as np

            update = {
                "org_id": request.org_id,
                "sample_count": request.sample_count,
                "weights": {
                    k: np.array(v) for k, v in request.model_weights.items()
                },
                "metrics": request.metrics,
                "fingerprints": request.fingerprints,
                "timestamp": datetime.now(timezone.utc),
            }

            accepted = self.aggregator.add_update(update)
            if not accepted:
                raise HTTPException(
                    status_code=400,
                    detail="Update rejected — check format or round status",
                )

            logger.info(
                "Update accepted from %s (%d samples)",
                request.org_id,
                request.sample_count,
            )

            return {
                "accepted": True,
                "org_id": request.org_id,
                "current_participants": self.aggregator.current_round.participating_orgs,
                "min_required": self.aggregator.min_participants,
            }

        @router.post("/rounds/aggregate")
        async def aggregate():
            """Trigger aggregation of submitted updates."""
            if self.aggregator.current_round is None:
                raise HTTPException(
                    status_code=409,
                    detail="No active round to aggregate",
                )

            try:
                result = self.aggregator.aggregate()
            except ValueError as e:
                raise HTTPException(status_code=400, detail=str(e))

            # Store in history
            round_info = self.aggregator.current_round.to_dict()
            self._history.append(round_info)

            logger.info(
                "Round %s aggregated: %d orgs, %d samples",
                self.aggregator.current_round.round_id,
                self.aggregator.current_round.participating_orgs,
                self.aggregator.current_round.total_samples,
            )

            return {
                "status": "aggregated",
                "round": round_info,
                "weight_keys": list(result.keys()) if result else [],
            }

        @router.get("/models/global", response_model=GlobalModelResponse)
        async def get_global_model():
            """Retrieve the current global aggregated model."""
            update = self.aggregator.create_global_update()

            # Convert numpy arrays to lists for JSON
            weights = {}
            for k, v in update.get("weights", {}).items():
                import numpy as np
                if isinstance(v, np.ndarray):
                    weights[k] = v.tolist()
                else:
                    weights[k] = list(v) if hasattr(v, "__iter__") else [v]

            return GlobalModelResponse(
                round_id=update.get("round_id", "none"),
                weights=weights,
                metrics=update.get("metrics", {}),
                fingerprints=update.get("fingerprints", []),
                timestamp=update.get("timestamp", datetime.now(timezone.utc).isoformat()),
            )

        @router.get("/rounds/status", response_model=Optional[RoundStatusResponse])
        async def get_round_status():
            """Get status of the current aggregation round."""
            status = self.aggregator.get_round_status()
            if status is None:
                return None

            return RoundStatusResponse(
                round_id=status.get("round_id", ""),
                status=status.get("status", "unknown"),
                participating_orgs=status.get("participating_orgs", 0),
                total_samples=status.get("total_samples", 0),
                started_at=status.get("started_at", ""),
                completed_at=status.get("completed_at"),
            )

        @router.get("/rounds/history")
        async def get_round_history():
            """Get history of completed aggregation rounds."""
            return {
                "rounds": self._history,
                "total": len(self._history),
            }

        @router.get("/health")
        async def federation_health():
            """Health check for the federation server."""
            return {
                "status": "healthy",
                "aggregation_method": self.aggregator.method,
                "min_participants": self.aggregator.min_participants,
                "active_round": self.aggregator.current_round is not None,
                "completed_rounds": len(self._history),
            }

        return router


def create_federation_app(
    method: str = "fedavg",
    min_participants: int = 3,
) -> FastAPI:
    """
    Create a standalone Federation server application.

    Can be run separately: uvicorn pdri.federation.server:app

    Args:
        method: Aggregation method
        min_participants: Minimum orgs before aggregation

    Returns:
        Configured FastAPI application
    """
    app = FastAPI(
        title="PDRI Federation Server",
        description="Federated model aggregation for privacy-preserving risk intelligence",
        version="1.0.0",
    )

    server = FederationServer(
        method=method,
        min_participants=min_participants,
    )
    app.include_router(server.router)

    return app


# Standalone app instance
app = create_federation_app()
