"""
Ingest API Routes
=================

REST endpoints for ingesting security events into PDRI.

Author: PDRI Team
Version: 1.0.0
"""

import logging
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy.ext.asyncio import AsyncSession

from pdri.db.session import get_db
from pdri.ingestion.pipeline import IngestionPipeline

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/ingest", tags=["Event Ingestion"])


# =============================================================================
# Request / Response Models
# =============================================================================


class IngestEventRequest(BaseModel):
    """Single security event ingestion request."""

    event_id: str = Field(..., description="Unique event identifier")
    event_type: str = Field(..., description="Type of security event")
    source_system_id: str = Field(..., description="Source system that generated the event")
    timestamp: Optional[str] = Field(None, description="ISO 8601 timestamp")
    tenant_id: str = Field(..., description="Tenant identifier")

    # Entity references
    entity_id: Optional[str] = Field(None, alias="target_entity_id")
    entity_type: Optional[str] = Field("data_store")
    entity_name: Optional[str] = None
    identity_id: Optional[str] = None
    identity_name: Optional[str] = None

    # Risk indicators
    severity: Optional[str] = Field("medium")
    exposure_direction: Optional[str] = None
    sensitivity_tags: list[str] = Field(default_factory=list)
    privilege_level: Optional[str] = None

    # AI context (optional)
    ai_context: Optional[dict] = None

    class Config:
        populate_by_name = True


class IngestEventResponse(BaseModel):
    status: str
    event_id: str
    event_db_id: Optional[str] = None
    entities_upserted: int = 0
    entity_ids: list[str] = Field(default_factory=list)


class IngestBatchRequest(BaseModel):
    tenant_id: str
    events: list[dict] = Field(..., max_length=100)


class IngestBatchResponse(BaseModel):
    processed: int
    duplicates: int
    errors: int


# =============================================================================
# Endpoints
# =============================================================================


@router.post("/events", response_model=IngestEventResponse)
async def ingest_event(
    request: IngestEventRequest,
    db: AsyncSession = Depends(get_db),
):
    """
    Ingest a single security event.

    Pipeline: validate → dedupe → upsert entities → upsert edges → store event
    """
    try:
        pipeline = IngestionPipeline(db)
        event_data = request.model_dump(exclude_none=True)
        tenant_id = event_data.pop("tenant_id")

        result = await pipeline.process_event(event_data, tenant_id)

        return IngestEventResponse(
            status=result["status"],
            event_id=result["event_id"],
            event_db_id=result.get("event_db_id"),
            entities_upserted=result.get("entities_upserted", 0),
            entity_ids=result.get("entity_ids", []),
        )
    except Exception as e:
        logger.error("Event ingestion failed: %s", e, exc_info=True)
        raise HTTPException(status_code=500, detail=f"Ingestion failed: {str(e)}")


@router.post("/events/batch", response_model=IngestBatchResponse)
async def ingest_events_batch(
    request: IngestBatchRequest,
    db: AsyncSession = Depends(get_db),
):
    """
    Ingest a batch of security events (max 100).

    Each event is processed independently; failures don't affect other events.
    """
    try:
        pipeline = IngestionPipeline(db)
        result = await pipeline.process_batch(request.events, request.tenant_id)

        return IngestBatchResponse(
            processed=result["processed"],
            duplicates=result["duplicates"],
            errors=result["errors"],
        )
    except Exception as e:
        logger.error("Batch ingestion failed: %s", e, exc_info=True)
        raise HTTPException(status_code=500, detail=f"Batch ingestion failed: {str(e)}")
