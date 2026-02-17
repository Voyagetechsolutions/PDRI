# AegisAI ↔ PDRI — Integration Engineering Brief

**For: AegisAI Engineers + PDRI Engineers**
**Date:** 17 February 2026
**Status:** Ready to implement — both sides analyzed, all questions answered

---

## TL;DR — What Each Team Does

| Team | Creates These Files | Implements These Capabilities |
|------|--------------------|-----------------------------|
| **AegisAI** | 5 new endpoints, 1 client module, 1 transformer, 1 Celery worker | Receive PDRI risk summaries, expose threat intel, sync entities |
| **PDRI** | 1 webhook router, config additions, AegisClient wiring | Receive Aegis findings, expose risk data via existing API |

**Integration pattern:** Bidirectional REST + optional webhooks. No shared database.

---

## Part 1: Answers to All AegisAI Team Questions

> These directly answer every question in Part 7 of the AegisAI spec.

### Q1: Authentication

**PDRI uses JWT Bearer tokens (HS256).**

```
Header:   Authorization: Bearer <token>
Algorithm: HS256
Secret:   Shared secret (set via JWT_SECRET env var)
Expiry:   60 minutes (configurable via JWT_EXPIRE_MINUTES)

Token claims:
{
  "sub": "aegis-service-account",    // user_id
  "role": "analyst",                  // admin | analyst | viewer
  "iat": 1740000000,
  "exp": 1740003600,
  "email": "aegis@internal"           // optional
}
```

**For service-to-service auth, AegisAI should:**
1. Call PDRI's token creation once (or use a pre-generated long-lived service token)
2. Include `Authorization: Bearer <token>` on every PDRI API call
3. Role `analyst` gives: read, score, simulate, predict
4. Role `admin` gives: all of the above + write, delete, configure, compliance, audit

**PDRI file:** [`pdri/api/auth.py`](file:///c:/Users/bathini%20bona/Documents/PDRI/pdri/api/auth.py) — `create_access_token()` at line 104.

**For AegisAI's side:** PDRI's `AegisClient` sends `Authorization: Bearer {api_key}` in every request. AegisAI should validate this via its existing JWT middleware. Create a PDRI service account in AegisAI with tenant-level permissions.

---

### Q2: PDRI API Endpoints Available to AegisAI

**Base URL:** `http://<pdri-host>:8000` (configurable via `API_HOST`, `API_PORT`)

| Endpoint | Method | Auth | What It Returns |
|----------|--------|------|-----------------|
| `/health` | GET | No | `{"status":"healthy","service":"PDRI","version":"1.0.0"}` |
| `/health/ready` | GET | No | `{"status":"ready","dependencies":{"neo4j":{...}}}` |
| `/health/live` | GET | No | `{"status":"alive"}` |
| `/nodes/data-stores` | GET | JWT | Paginated data store nodes |
| `/nodes/services` | GET | JWT | Paginated service nodes |
| `/nodes/ai-tools` | GET | JWT | Paginated AI tool nodes |
| `/nodes/{node_id}` | GET | JWT | Single node with optional relationships |
| `/scoring/{entity_id}` | POST | JWT | Calculate risk score for entity |
| `/scoring/{entity_id}/explain` | GET | JWT | Score explanation with factors + recommendations |
| `/scoring/batch` | POST | JWT | Batch scoring by node type |
| `/scoring/all` | POST | JWT | Score all entities |
| `/scoring/weights` | GET | JWT | Current scoring weights |
| `/analytics/risk-distribution` | GET | JWT | Risk counts by level |
| `/analytics/high-risk` | GET | JWT | High-risk entities (threshold configurable) |
| `/analytics/risk-summary` | GET | JWT | Full risk summary |
| `/analytics/exposure-paths/{id}` | GET | JWT | Paths to external exposure |
| `/analytics/ai-exposure` | GET | JWT | Paths from sensitive data to AI tools |
| `/analytics/external-exposures` | GET | JWT | All external resource exposures |
| `/analytics/graph-metrics` | GET | JWT | Node counts, connectivity stats |
| `/ws/risk-events` | WS | JWT (query param `token`) | Real-time risk events stream |

**Rate limit:** 100 requests/minute per IP (configurable via slowapi).

**Pagination format (all list endpoints):**
```
?skip=0&limit=100
```
Response includes items array. No cursor pagination yet.

---

### Q3: PDRI Data Schemas

#### Risk Score Response (what AegisAI receives when calling `/scoring/{id}`)
```json
{
  "entity_id": "ds-001",
  "exposure_score": 0.72,
  "volatility_score": 0.45,
  "sensitivity_likelihood": 0.88,
  "composite_score": 0.68,
  "risk_level": "high",
  "scoring_version": "1.0.0",
  "calculated_at": "2026-02-17T12:00:00Z"
}
```

#### Score Explanation Response (`/scoring/{id}/explain`)
```json
{
  "entity_id": "ds-001",
  "risk_level": "high",
  "composite_score": 0.68,
  "summary": "This entity has high risk due to...",
  "top_risk_factors": ["external_connections", "ai_integrations", "privilege_level"],
  "factor_breakdown": {
    "external_connection_factor": 0.8,
    "ai_integration_factor": 0.7,
    "data_volume_factor": 0.5,
    "privilege_level_factor": 0.6,
    "sensitivity_tag_factor": 0.9
  },
  "score_breakdown": {
    "exposure_score": 0.72,
    "volatility_score": 0.45,
    "sensitivity_likelihood": 0.88
  },
  "recommendations": [
    "Review and reduce external connections",
    "Audit AI tool integrations",
    "Implement data classification"
  ]
}
```

#### Risk Summary Response (`/analytics/risk-summary`)
```json
{
  "total_entities": 150,
  "high_risk_count": 12,
  "medium_risk_count": 45,
  "low_risk_count": 93,
  "top_risks": [
    {
      "id": "ds-001",
      "name": "Customer PII Database",
      "type": "data_store",
      "exposure_score": 0.85,
      "volatility_score": 0.6,
      "sensitivity_likelihood": 0.95
    }
  ],
  "calculated_at": "2026-02-17T12:00:00Z"
}
```

#### PDRI Security Event Schema (Kafka / shared)
```json
{
  "event_id": "evt-uuid",
  "event_type": "AI_DATA_ACCESS",
  "source_system_id": "aegis-scanner-01",
  "timestamp": "2026-02-17T10:00:00Z",
  "entity_id": "internal-db-01",
  "entity_type": "data_store",
  "exposure_direction": "internal_to_ai",
  "sensitivity_tags": ["financial_related", "identity_related"],
  "severity": "high",
  "ai_context": {
    "ai_tool_id": "openai-gpt4",
    "model_name": "gpt-4",
    "data_volume_bytes": 50000
  },
  "metadata": {}
}
```

**Valid `event_type` values:**
```
AI_DATA_ACCESS, AI_PROMPT_SENSITIVITY, AI_TOOL_DISCOVERY,
AI_MODEL_TRAINING, SYSTEM_ACCESS, SYSTEM_AUTH_FAILURE,
PRIVILEGE_ESCALATION, DATA_MOVEMENT, DATA_EXPORT, DATA_AGGREGATION
```

#### Error Response Format (all endpoints)
```json
{
  "detail": "Entity not found: ds-999"
}
```
HTTP status codes: 400 (bad request), 401 (unauthorized), 403 (forbidden), 404 (not found), 422 (validation), 429 (rate limited), 500 (server error).

---

### Q4: Webhooks

PDRI **does not currently have** a webhook receiver for Aegis. This needs to be built (see Part 3 below for exact implementation).

PDRI **can send** via `AegisClient` using HTTP POST to these AegisAI endpoints (which the Aegis team needs to create):

| PDRI Calls This Aegis Endpoint | What PDRI Sends |
|-------------------------------|-----------------|
| `POST /api/v1/integrations/risk-summary` | Full risk summary payload |
| `POST /api/v1/incidents` | Incident report |
| `POST /api/v1/integrations/entity-sync` | Entity catalog batch |
| `GET /api/v1/threat-intel` | (pulls threat intelligence) |
| `GET /api/v1/policies/latest` | (pulls policy updates) |
| `GET /health` | Health check |

**Signature algorithm:** Not yet implemented. Recommendation: HMAC-SHA256 with shared secret.

---

### Q5: Sync Strategy

**Bidirectional, hybrid (real-time + batch):**

| Direction | Method | Frequency |
|-----------|--------|-----------|
| PDRI → Aegis: risk summaries | HTTP POST | Every 15 min (Celery task) |
| PDRI → Aegis: incidents | HTTP POST | Real-time (on detection) |
| PDRI → Aegis: entity catalog | HTTP POST | Every 1 hour |
| Aegis → PDRI: findings | Webhook POST to PDRI | Real-time (on new finding) |
| Aegis → PDRI: threat intel | PDRI pulls via GET | Every 15 min |
| Aegis → PDRI: policy updates | PDRI pulls via GET | Every 1 hour |

**Conflict resolution:** Last-write-wins with `pidr_synced_at` timestamp. PDRI is source of truth for risk scores; Aegis is source of truth for findings.

---

### Q6: Testing

PDRI can run locally: `uvicorn pdri.api.main:app --reload` (port 8000).
Health check: `GET http://localhost:8000/health`.
No shared sandbox yet — recommendation: use Docker Compose to spin up both services locally.

### Q7: Monitoring

- Health: `GET /health` (basic), `/health/ready` (with dependencies), `/health/live` (K8s liveness)
- Metrics: `GET /metrics` (Prometheus format)
- Tracing: OpenTelemetry → OTLP exporter (Jaeger compatible)

---

## Part 2: Exact Field Mappings

### AegisAI `Finding` → PDRI `SecurityEvent`

This is the core transformation. When Aegis sends a finding to PDRI, it must be converted to PDRI's `SecurityEvent` schema.

```python
# AegisAI engineers: implement in app/integrations/pidr/transformers.py

def aegis_finding_to_pdri_event(finding: dict) -> dict:
    """Convert AegisAI Finding → PDRI SecurityEvent."""
    
    # Map finding_type → PDRI event_type
    TYPE_MAP = {
        "ai_api_usage":           "AI_DATA_ACCESS",
        "shadow_ai_tool":         "AI_TOOL_DISCOVERY",
        "sensitive_data_exposure": "DATA_EXPORT",
        "privilege_risk":         "PRIVILEGE_ESCALATION",
        "shadow_ai_deployment":   "AI_TOOL_DISCOVERY",
        "policy_violation":       "SYSTEM_ACCESS",
    }
    
    # Map severity → PDRI severity
    SEVERITY_MAP = {
        "low": "low",
        "medium": "medium",
        "high": "high",
        "critical": "critical",
    }
    
    return {
        "event_id": str(finding["id"]),
        "event_type": TYPE_MAP.get(finding["finding_type"], "SYSTEM_ACCESS"),
        "source_system_id": f"aegis-{finding.get('cloud_account_id', 'unknown')}",
        "timestamp": finding["created_at"],
        "entity_id": finding.get("resource_arn", finding["id"]),
        "entity_type": _infer_entity_type(finding.get("resource_type", "")),
        "severity": SEVERITY_MAP.get(finding["severity"], "medium"),
        "exposure_direction": _infer_exposure_direction(finding["finding_type"]),
        "sensitivity_tags": _extract_sensitivity_tags(finding),
        "ai_context": {
            "ai_tool_id": finding.get("ai_service", ""),
            "model_name": finding.get("ai_service", ""),
            "data_volume_bytes": 0,
        } if finding.get("ai_provider") else None,
        "metadata": {
            "aegis_finding_id": str(finding["id"]),
            "aegis_tenant_id": str(finding.get("tenant_id", "")),
            "aegis_risk_score": finding.get("risk_score", 0),
            "aegis_evidence": finding.get("evidence", {}),
            "resource_arn": finding.get("resource_arn", ""),
            "region": finding.get("region", ""),
        },
    }

def _infer_entity_type(resource_type: str) -> str:
    """Map AWS resource type → PDRI entity type."""
    if resource_type in ("lambda", "ecs", "ec2", "sagemaker"):
        return "service"
    elif resource_type in ("s3", "rds", "dynamodb", "redshift"):
        return "data_store"
    elif resource_type in ("bedrock", "openai"):
        return "ai_tool"
    else:
        return "service"

def _infer_exposure_direction(finding_type: str) -> str:
    if finding_type in ("ai_api_usage", "shadow_ai_tool"):
        return "internal_to_ai"
    elif finding_type == "sensitive_data_exposure":
        return "internal_to_external"
    else:
        return "internal_to_internal"

def _extract_sensitivity_tags(finding: dict) -> list:
    """Extract sensitivity tags from finding evidence."""
    tags = []
    evidence = finding.get("evidence", {})
    risk_factors = finding.get("risk_factors", {})
    
    if evidence.get("has_pii"):
        tags.append("identity_related")
    if evidence.get("has_financial"):
        tags.append("financial_related")
    if evidence.get("has_credentials"):
        tags.append("credentials_related")
    if risk_factors.get("data_sensitivity", 0) > 0.7:
        tags.append("regulated_data")
    
    return tags or ["unknown"]
```

### PDRI `SecurityEvent` → AegisAI `Finding`

When PDRI sends data back to Aegis (via risk summaries or incident reports), Aegis needs this reverse mapping:

```python
# AegisAI engineers: implement in app/integrations/pidr/transformers.py

def pdri_event_to_aegis_finding(pdri_data: dict) -> dict:
    """Convert PDRI risk data → AegisAI Finding format."""
    
    TYPE_MAP = {
        "AI_DATA_ACCESS":       "ai_api_usage",
        "AI_TOOL_DISCOVERY":    "shadow_ai_tool",
        "AI_PROMPT_SENSITIVITY":"ai_api_usage",
        "DATA_EXPORT":          "sensitive_data_exposure",
        "PRIVILEGE_ESCALATION": "privilege_risk",
        "SYSTEM_ACCESS":        "ai_api_usage",
        "DATA_MOVEMENT":        "sensitive_data_exposure",
    }
    
    return {
        "pidr_id": pdri_data.get("entity_id", ""),
        "finding_type": TYPE_MAP.get(pdri_data.get("event_type"), "ai_api_usage"),
        "severity": pdri_data.get("risk_level", "medium"),
        "title": f"PDRI Risk Alert: {pdri_data.get('entity_id', 'Unknown')}",
        "description": pdri_data.get("summary", "Risk detected by PDRI"),
        "risk_score": pdri_data.get("composite_score", 0.0),
        "risk_factors": pdri_data.get("factor_breakdown", {}),
        "status": "open",
        "pidr_sync_status": "synced",
        "pidr_synced_at": pdri_data.get("calculated_at"),
        "pidr_metadata": {
            "exposure_score": pdri_data.get("exposure_score"),
            "volatility_score": pdri_data.get("volatility_score"),
            "sensitivity_likelihood": pdri_data.get("sensitivity_likelihood"),
            "recommendations": pdri_data.get("recommendations", []),
        },
    }
```

### AegisAI `Policy` → PDRI Compliance Mapping

```python
# AegisAI policy enforcement_mode → PDRI autonomous response
ENFORCEMENT_MAP = {
    "detect_only":  "monitor",      # PDRI: just score and alert
    "alert":        "alert",        # PDRI: WebSocket + notification
    "ticket":       "escalate",     # PDRI: route to response engine
    "remediate":    "auto_respond", # PDRI: autonomous remediation
}
```

---

## Part 3: What Each Team Must Build

### PDRI Team — 3 Items

#### Item 1: Add Aegis Config to `pdri/config.py`

```python
# Add these fields to the Settings class in pdri/config.py

    # AegisAI Integration
    aegis_api_url: str = "http://localhost:8000"
    aegis_api_key: str = ""
    aegis_enabled: bool = False
    aegis_sync_interval_minutes: int = 15
    aegis_webhook_secret: str = ""
```

And update `.env.example`:
```bash
# AegisAI Integration
AEGIS_ENABLED=false
AEGIS_API_URL=http://localhost:8000/api/v1
AEGIS_API_KEY=<aegis-service-token>
AEGIS_WEBHOOK_SECRET=<shared-hmac-secret>
AEGIS_SYNC_INTERVAL_MINUTES=15
```

#### Item 2: Create Webhook Receiver (`pdri/api/routes/aegis_webhooks.py`)

```python
"""
Webhook endpoints for receiving data FROM AegisAI.
"""
import hashlib
import hmac
import logging
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Header, HTTPException, status
from pydantic import BaseModel, Field

from pdri.config import settings

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/webhooks/aegis", tags=["AegisAI Webhooks"])


class AegisFindingPayload(BaseModel):
    """Inbound finding from AegisAI."""
    id: str
    tenant_id: Optional[str] = None
    finding_type: str
    severity: str
    title: str
    description: str = ""
    resource_arn: str = ""
    resource_type: str = ""
    region: str = ""
    risk_score: float = Field(0.0, ge=0.0, le=1.0)
    risk_factors: Dict[str, Any] = Field(default_factory=dict)
    ai_provider: Optional[str] = None
    ai_service: Optional[str] = None
    evidence: Dict[str, Any] = Field(default_factory=dict)
    status: str = "open"
    created_at: str = ""


class AegisBatchPayload(BaseModel):
    """Batch of findings from AegisAI."""
    findings: List[AegisFindingPayload]
    sync_token: Optional[str] = None


def _verify_signature(payload: bytes, signature: str, secret: str) -> bool:
    """Verify HMAC-SHA256 webhook signature."""
    expected = hmac.new(
        secret.encode(), payload, hashlib.sha256
    ).hexdigest()
    return hmac.compare_digest(f"sha256={expected}", signature)


@router.post("/findings")
async def receive_aegis_finding(
    payload: AegisFindingPayload,
    x_aegis_signature: Optional[str] = Header(None),
):
    """
    Receive a single finding from AegisAI.
    
    PDRI will:
    1. Convert to SecurityEvent format
    2. Ingest into the risk graph
    3. Trigger rescoring
    """
    # TODO: verify signature if configured
    # TODO: transform to SecurityEvent using mapping from Part 2
    # TODO: send to ingestion pipeline or directly update graph
    logger.info(f"Received Aegis finding: {payload.id} ({payload.severity})")
    return {"status": "accepted", "pdri_event_id": f"aegis-{payload.id}"}


@router.post("/findings/batch")
async def receive_aegis_findings_batch(
    payload: AegisBatchPayload,
    x_aegis_signature: Optional[str] = Header(None),
):
    """Receive a batch of findings from AegisAI."""
    count = len(payload.findings)
    logger.info(f"Received {count} Aegis findings in batch")
    return {"status": "accepted", "count": count}
```

Then register in `pdri/api/main.py`:
```python
# In create_app(), after WebSocket router:
from pdri.api.routes.aegis_webhooks import router as aegis_webhook_router
app.include_router(aegis_webhook_router)
```

#### Item 3: Wire `AegisClient` Into Autonomous Response

In `pdri/autonomous/response_engine.py`, when an incident is detected, call `AegisClient.report_incident()` so Aegis receives real-time alerts.

---

### AegisAI Team — 5 Items

#### Item 1: Create Integration Router (`app/api/v1/pdri_integration.py`)

These are the endpoints that PDRI's `AegisClient` calls. They must exist at these exact paths:

```python
from fastapi import APIRouter, Depends, Header, HTTPException, Query
from pydantic import BaseModel
from typing import Any, Dict, List, Optional
from datetime import datetime

router = APIRouter(prefix="/api/v1", tags=["PDRI Integration"])


# ─── Endpoint 1: Receive Risk Summary ─────────────────────────────
# Called by: PDRI AegisClient.push_risk_summary()
# Path PDRI expects: POST /api/v1/integrations/risk-summary
# Frequency: Every 15 minutes

class RiskSummaryPayload(BaseModel):
    source: str                         # Always "pdri"
    timestamp: str                      # ISO 8601
    summary: Dict[str, Any]             # Contains:
    # summary.total_entities: int
    # summary.high_risk_count: int
    # summary.medium_risk_count: int
    # summary.low_risk_count: int
    # summary.top_risks: list[{id, name, type, exposure_score, ...}]

@router.post("/integrations/risk-summary")
async def receive_risk_summary(payload: RiskSummaryPayload):
    """Receive PDRI risk summary for Aegis dashboard display."""
    # Store in DB or cache for frontend dashboard
    return {"status": "accepted", "received_at": datetime.utcnow().isoformat()}


# ─── Endpoint 2: Receive Incident ─────────────────────────────────
# Called by: PDRI AegisClient.report_incident()
# Path PDRI expects: POST /api/v1/incidents
# Frequency: On-demand (when PDRI detects high-risk incident)

class IncidentPayload(BaseModel):
    source: str                         # Always "pdri"
    reported_at: str                    # ISO 8601
    entity_id: str                      # Affected entity
    incident_type: str                  # breach, escalation, anomaly
    severity: str                       # low, medium, high, critical
    description: str
    risk_score: Optional[float] = None
    recommendations: Optional[List[str]] = None

@router.post("/incidents")
async def receive_incident(payload: IncidentPayload):
    """Receive PDRI incident for Aegis response pipeline."""
    # Create incident ticket, alert on-call
    ticket_id = f"INC-{datetime.utcnow().strftime('%Y%m%d%H%M%S')}"
    return {"status": "accepted", "ticket_id": ticket_id}


# ─── Endpoint 3: Entity Catalog Sync ──────────────────────────────
# Called by: PDRI AegisClient.sync_entity_catalog()
# Path PDRI expects: POST /api/v1/integrations/entity-sync
# Frequency: Every 1 hour

class EntitySyncPayload(BaseModel):
    source: str
    synced_at: str
    entities: List[Dict[str, Any]]      # Each has: id, name, type, risk_level

@router.post("/integrations/entity-sync")
async def receive_entity_sync(payload: EntitySyncPayload):
    """Sync PDRI entities with Aegis for cross-platform correlation."""
    matched = 0
    new = 0
    for entity in payload.entities:
        # Try to match with existing Aegis resources by ARN or name
        # If matched: update risk data. If new: create reference.
        new += 1  # placeholder
    return {"status": "synced", "matched": matched, "new": new}


# ─── Endpoint 4: Threat Intelligence Feed ─────────────────────────
# Called by: PDRI AegisClient.pull_threat_intel()
# Path PDRI expects: GET /api/v1/threat-intel
# Frequency: Every 15 minutes (PDRI polls)

@router.get("/threat-intel")
async def get_threat_intel(
    since: Optional[str] = Query(None),
    limit: int = Query(100, ge=1, le=500),
):
    """
    Return threat intelligence for PDRI consumption.
    
    Each item should include:
    - threat_id: str
    - threat_type: str (e.g., "shadow_ai", "data_exfil", "credential_abuse")
    - indicators: list[str] (IPs, domains, tool names)
    - severity: str
    - description: str
    - first_seen: str (ISO 8601)
    """
    # Query Aegis findings/events that qualify as threat intel
    return []  # List of threat intel items


# ─── Endpoint 5: Policy Updates ────────────────────────────────────
# Called by: PDRI AegisClient.pull_policy_updates()
# Path PDRI expects: GET /api/v1/policies/latest
# Frequency: Every 1 hour (PDRI polls)

@router.get("/policies/latest")
async def get_latest_policies():
    """
    Return latest policy updates for PDRI scoring alignment.
    
    PDRI uses this to:
    - Update scoring weights
    - Add/remove sanctioned AI tools
    - Adjust risk thresholds
    """
    # Query active policies and format for PDRI
    return {
        "updated_at": datetime.utcnow().isoformat(),
        "scoring_adjustments": {},
        "sanctioned_ai_tools": [],
        "blocked_ai_providers": [],
        "risk_thresholds": {
            "critical": 0.8,
            "high": 0.6,
            "medium": 0.4,
        },
    }
```

**Register in Aegis `app/main.py`:**
```python
from app.api.v1.pdri_integration import router as pdri_router
app.include_router(pdri_router)
```

#### Item 2: Create PDRI Client (`app/integrations/pidr/client.py`)

```python
import httpx
from app.config import settings

class PDRIClient:
    """Client for calling PDRI API endpoints."""
    
    def __init__(self):
        self.base_url = settings.pidr_api_url.rstrip("/")
        self.api_key = settings.pidr_api_key
        self._client = None
    
    async def _get_client(self) -> httpx.AsyncClient:
        if self._client is None or self._client.is_closed:
            self._client = httpx.AsyncClient(
                base_url=self.base_url,
                timeout=settings.pidr_timeout_seconds,
                headers={
                    "Authorization": f"Bearer {self.api_key}",
                    "Content-Type": "application/json",
                    "X-Source": "aegis",
                },
            )
        return self._client
    
    async def get_risk_summary(self) -> dict:
        """GET /analytics/risk-summary"""
        client = await self._get_client()
        r = await client.get("/analytics/risk-summary")
        r.raise_for_status()
        return r.json()
    
    async def get_entity_score(self, entity_id: str) -> dict:
        """POST /scoring/{entity_id}"""
        client = await self._get_client()
        r = await client.post(f"/scoring/{entity_id}")
        r.raise_for_status()
        return r.json()
    
    async def get_score_explanation(self, entity_id: str) -> dict:
        """GET /scoring/{entity_id}/explain"""
        client = await self._get_client()
        r = await client.get(f"/scoring/{entity_id}/explain")
        r.raise_for_status()
        return r.json()
    
    async def get_high_risk_entities(self, threshold: float = 0.6) -> list:
        """GET /analytics/high-risk?threshold=X"""
        client = await self._get_client()
        r = await client.get("/analytics/high-risk", params={"threshold": threshold})
        r.raise_for_status()
        return r.json()
    
    async def send_finding_webhook(self, finding: dict) -> dict:
        """POST /webhooks/aegis/findings — push finding to PDRI."""
        client = await self._get_client()
        r = await client.post("/webhooks/aegis/findings", json=finding)
        r.raise_for_status()
        return r.json()
    
    async def check_health(self) -> dict:
        """GET /health"""
        client = await self._get_client()
        try:
            r = await client.get("/health")
            return r.json()
        except Exception as e:
            return {"status": "unreachable", "error": str(e)}
    
    async def close(self):
        if self._client:
            await self._client.aclose()
```

#### Item 3: Implement Transformer (`app/integrations/pidr/transformers.py`)

Use the exact field mapping code from Part 2 above.

#### Item 4: Create Celery Sync Worker (`app/workers/pidr_sync_tasks.py`)

```python
from celery import shared_task

@shared_task
def sync_findings_to_pdri():
    """
    Push new/updated findings to PDRI every 15 minutes.
    
    Query: Finding.pidr_sync_status IN ('pending', 'failed')
    Transform each with aegis_finding_to_pdri_event()
    POST to PDRI /webhooks/aegis/findings/batch
    Update pidr_sync_status = 'synced' on success
    """
    pass

@shared_task
def pull_risk_scores_from_pdri():
    """
    Pull latest risk scores from PDRI.
    
    Call PDRIClient.get_high_risk_entities()
    Update Aegis findings with PDRI risk scores
    """
    pass
```

Add to Celery beat schedule:
```python
CELERY_BEAT_SCHEDULE = {
    'sync-findings-to-pdri': {
        'task': 'app.workers.pidr_sync_tasks.sync_findings_to_pdri',
        'schedule': crontab(minute='*/15'),
    },
    'pull-risk-from-pdri': {
        'task': 'app.workers.pidr_sync_tasks.pull_risk_scores_from_pdri',
        'schedule': crontab(minute='*/15'),
    },
}
```

#### Item 5: Add Config (`app/config.py` additions)

```python
# PDRI Integration
pidr_enabled: bool = False
pidr_api_url: str = "http://localhost:8000"
pidr_api_key: str = ""           # JWT token for PDRI auth
pidr_webhook_secret: str = ""    # HMAC secret for signature
pidr_sync_interval_minutes: int = 15
pidr_timeout_seconds: int = 30
pidr_batch_size: int = 100
```

---

## Part 4: Implementation Sequence

### Week 1: Foundation (Both teams in parallel)

| Day | PDRI Team | AegisAI Team |
|-----|-----------|-------------|
| 1 | Add Aegis config to `config.py` + `.env` | Add PDRI config to `config.py` + `.env` |
| 2 | Create `aegis_webhooks.py` router | Create `pdri_integration.py` router |
| 3 | Register webhook in `main.py` | Register integration router |
| 4 | Create PDRI service account JWT for Aegis | Create Aegis service account JWT for PDRI |
| 5 | Test: both health checks pass cross-system | Test: both health checks pass cross-system |

### Week 2: Data Exchange

| Day | PDRI Team | AegisAI Team |
|-----|-----------|-------------|
| 1-2 | Implement webhook payload processing → graph ingestion | Create `PDRIClient` with all methods |
| 3-4 | Wire `AegisClient` into autonomous response | Implement `transformers.py` (both directions) |
| 5 | Integration test: Aegis finding → PDRI score update | Integration test: PDRI risk summary → Aegis dashboard |

### Week 3: Sync & Production

| Day | PDRI Team | AegisAI Team |
|-----|-----------|-------------|
| 1-2 | Add circuit breaker to AegisClient | Create Celery sync workers |
| 3-4 | Add Prometheus metrics for integration | Add sync monitoring + metrics |
| 5 | End-to-end test in Docker Compose | End-to-end test in Docker Compose |

---

## Part 5: Docker Compose for Local Development

```yaml
# docker-compose.integration.yml
# Spins up both systems for local integration testing

version: "3.9"

services:
  pdri-api:
    build: ./PDRI
    ports:
      - "8000:8000"
    environment:
      AEGIS_ENABLED: "true"
      AEGIS_API_URL: "http://aegis-api:8001/api/v1"
      AEGIS_API_KEY: "${AEGIS_SERVICE_TOKEN}"
      JWT_SECRET: "shared-dev-secret"
    depends_on:
      - neo4j
    
  aegis-api:
    build: ./AegisAI
    ports:
      - "8001:8001"
    environment:
      PIDR_ENABLED: "true"
      PIDR_API_URL: "http://pdri-api:8000"
      PIDR_API_KEY: "${PDRI_SERVICE_TOKEN}"
    depends_on:
      - postgres
      - redis
    
  neo4j:
    image: neo4j:5
    ports:
      - "7474:7474"
      - "7687:7687"
    environment:
      NEO4J_AUTH: neo4j/testpassword
    
  postgres:
    image: postgres:15
    environment:
      POSTGRES_DB: aegis
      POSTGRES_USER: aegis
      POSTGRES_PASSWORD: testpassword
    
  redis:
    image: redis:7-alpine
```

---

## Part 6: Verification Checklist

Both teams should verify these pass before declaring integration complete:

```
[ ] AegisAI → PDRI health check returns 200
[ ] PDRI → AegisAI health check returns 200
[ ] Aegis finding POST → PDRI webhook → graph node created
[ ] PDRI risk summary GET → Aegis dashboard displays data
[ ] PDRI incident POST → Aegis incident ticket created
[ ] Entity catalog sync → matched count > 0
[ ] Threat intel pull → PDRI receives threat items
[ ] Policy pull → PDRI updates scoring thresholds
[ ] WebSocket: Aegis connects to PDRI ws://host/ws/risk-events
[ ] Error handling: PDRI down → Aegis retries gracefully
[ ] Error handling: Aegis down → PDRI continues operating
[ ] Rate limiting: 100 req/min respected
[ ] Auth: invalid token → 401 on both sides
```

---

*This brief answers every question from the AegisAI team's specification. Both teams can begin implementation immediately.*
