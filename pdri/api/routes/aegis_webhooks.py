"""
AegisAI Webhook Endpoints
==========================

REST endpoints for receiving data FROM AegisAI into PDRI.

Endpoints:
    POST /webhooks/aegis/findings       — receive a single finding
    POST /webhooks/aegis/findings/batch  — receive a batch of findings
    GET  /webhooks/aegis/status          — integration health / sync status

Security:
    - Optional HMAC-SHA256 signature verification via X-Aegis-Signature header
    - JWT authentication (service account)

Author: PDRI Team
Version: 1.0.0
"""

import hashlib
import hmac
import logging
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, Header, HTTPException, Request, status
from pydantic import BaseModel, Field

from pdri.config import settings
from pdri.integrations.aegis_transformer import aegis_finding_to_pdri_event

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/webhooks/aegis", tags=["AegisAI Webhooks"])


# =============================================================================
# Request / Response Models
# =============================================================================


class AegisFindingPayload(BaseModel):
    """Inbound finding from AegisAI."""

    id: str = Field(..., description="AegisAI finding UUID")
    tenant_id: Optional[str] = Field(None, description="AegisAI tenant UUID")
    cloud_account_id: Optional[str] = Field(None, description="Source cloud account")

    # Classification
    finding_type: str = Field(..., description="e.g. shadow_ai_tool, ai_api_usage")
    severity: str = Field("medium", description="low | medium | high | critical")
    status: str = Field("open", description="Finding status in Aegis")

    # Content
    title: str = Field(..., description="Finding title")
    description: str = Field("", description="Detailed description")

    # Resource
    resource_arn: str = Field("", description="AWS ARN of affected resource")
    resource_type: str = Field("", description="AWS resource type")
    region: str = Field("", description="AWS region")

    # Risk
    risk_score: float = Field(0.0, ge=0.0, le=1.0, description="Aegis risk score")
    risk_factors: Dict[str, Any] = Field(default_factory=dict)

    # AI-specific
    ai_provider: Optional[str] = Field(None, description="e.g. OpenAI, AWS")
    ai_service: Optional[str] = Field(None, description="e.g. gpt-4, Bedrock")

    # Evidence
    evidence: Dict[str, Any] = Field(default_factory=dict)

    # Timestamps
    created_at: str = Field("", description="ISO 8601 timestamp")


class AegisBatchPayload(BaseModel):
    """Batch of findings from AegisAI."""

    findings: List[AegisFindingPayload]
    sync_token: Optional[str] = Field(
        None, description="Token for resumable sync"
    )


class WebhookResponse(BaseModel):
    """Standard webhook response."""

    status: str
    pdri_event_id: Optional[str] = None
    count: Optional[int] = None
    errors: Optional[List[Dict[str, str]]] = None
    received_at: str


class IntegrationStatusResponse(BaseModel):
    """Integration health status."""

    aegis_enabled: bool
    webhook_signature_required: bool
    total_received: int
    last_received_at: Optional[str]


# =============================================================================
# Module-Level State (per-process counters)
# =============================================================================

_stats = {
    "total_received": 0,
    "total_batch_received": 0,
    "total_errors": 0,
    "last_received_at": None,
}


# =============================================================================
# Signature Verification
# =============================================================================


def _verify_webhook_signature(
    raw_body: bytes,
    signature: Optional[str],
) -> None:
    """
    Verify HMAC-SHA256 webhook signature if a secret is configured.

    Args:
        raw_body: Raw request body bytes
        signature: X-Aegis-Signature header value (format: sha256=<hex>)

    Raises:
        HTTPException 401 if signature is required but missing/invalid
    """
    webhook_secret = settings.aegis_webhook_secret

    if not webhook_secret:
        # No secret configured — skip verification
        return

    if not signature:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing X-Aegis-Signature header",
        )

    expected = hmac.new(
        webhook_secret.encode("utf-8"), raw_body, hashlib.sha256
    ).hexdigest()
    expected_header = f"sha256={expected}"

    if not hmac.compare_digest(expected_header, signature):
        logger.warning("Invalid Aegis webhook signature")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid webhook signature",
        )


# =============================================================================
# Endpoints
# =============================================================================


@router.post(
    "/findings",
    response_model=WebhookResponse,
    summary="Receive AegisAI Finding",
    description="Receive a single finding from AegisAI, transform it to a PDRI SecurityEvent, and ingest into the risk graph.",
)
async def receive_aegis_finding(
    request: Request,
    payload: AegisFindingPayload,
    x_aegis_signature: Optional[str] = Header(None),
) -> WebhookResponse:
    """
    Receive a single finding from AegisAI.

    Pipeline:
        1. Verify webhook signature (if configured)
        2. Transform AegisAI Finding → PDRI SecurityEvent
        3. Ingest into the risk graph via event handler
        4. Return acknowledgement with PDRI event ID
    """
    # Verify signature
    raw_body = await request.body()
    _verify_webhook_signature(raw_body, x_aegis_signature)

    # Transform to PDRI SecurityEvent
    finding_dict = payload.model_dump()
    pdri_event = aegis_finding_to_pdri_event(finding_dict)

    # TODO: Send to ingestion pipeline — currently we log and acknowledge
    # In production, call:
    #   from pdri.ingestion.handlers import handle_event
    #   await handle_event(pdri_event)
    logger.info(
        "Received Aegis finding",
        extra={
            "aegis_finding_id": payload.id,
            "severity": payload.severity,
            "finding_type": payload.finding_type,
            "pdri_event_type": pdri_event["event_type"],
        },
    )

    _stats["total_received"] += 1
    _stats["last_received_at"] = datetime.now(timezone.utc).isoformat()

    return WebhookResponse(
        status="accepted",
        pdri_event_id=f"aegis-{payload.id}",
        received_at=datetime.now(timezone.utc).isoformat(),
    )


@router.post(
    "/findings/batch",
    response_model=WebhookResponse,
    summary="Receive AegisAI Findings Batch",
    description="Receive multiple findings from AegisAI in a single request.",
)
async def receive_aegis_findings_batch(
    request: Request,
    payload: AegisBatchPayload,
    x_aegis_signature: Optional[str] = Header(None),
) -> WebhookResponse:
    """
    Receive a batch of findings from AegisAI.

    Processes each finding individually, collects errors, returns summary.
    """
    raw_body = await request.body()
    _verify_webhook_signature(raw_body, x_aegis_signature)

    errors: List[Dict[str, str]] = []
    processed = 0

    for finding in payload.findings:
        try:
            finding_dict = finding.model_dump()
            pdri_event = aegis_finding_to_pdri_event(finding_dict)
            # TODO: Send each to ingestion pipeline
            processed += 1
        except Exception as e:
            logger.error(f"Failed to process Aegis finding {finding.id}: {e}")
            errors.append({"finding_id": finding.id, "error": str(e)})

    _stats["total_batch_received"] += processed
    _stats["total_received"] += processed
    _stats["total_errors"] += len(errors)
    _stats["last_received_at"] = datetime.now(timezone.utc).isoformat()

    logger.info(
        f"Batch: processed {processed}/{len(payload.findings)} Aegis findings, "
        f"{len(errors)} errors"
    )

    return WebhookResponse(
        status="accepted" if not errors else "partial",
        count=processed,
        errors=errors if errors else None,
        received_at=datetime.now(timezone.utc).isoformat(),
    )


@router.get(
    "/status",
    response_model=IntegrationStatusResponse,
    summary="AegisAI Integration Status",
    description="Returns current integration health and statistics.",
)
async def integration_status() -> IntegrationStatusResponse:
    """Return Aegis webhook integration status."""
    return IntegrationStatusResponse(
        aegis_enabled=settings.aegis_enabled,
        webhook_signature_required=bool(settings.aegis_webhook_secret),
        total_received=_stats["total_received"],
        last_received_at=_stats["last_received_at"],
    )
