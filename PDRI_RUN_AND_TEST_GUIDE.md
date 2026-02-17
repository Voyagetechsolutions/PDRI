# PDRI — Run & Test Guide

## Prerequisites

| Tool | Minimum Version | Check |
|------|----------------|-------|
| **Python** | 3.12+ | `python --version` |
| **Docker** | 24+ | `docker --version` |
| **Docker Compose** | 2.0+ | `docker compose version` |
| **Git** | any | `git --version` |

---

## Step 1: Environment Setup

```bash
# Clone and enter project
cd PDRI

# Copy env template and edit
cp .env.example .env

# Install Python dependencies
pip install -r requirements.txt
```

### Key `.env` settings to configure:

```env
# ── Required for local dev ──
DEBUG=true
LOG_LEVEL=DEBUG

# ── Integrations (set to true when ready) ──
AEGIS_ENABLED=false
DMITRY_ENABLED=false

# ── Security (CHANGE for production) ──
JWT_SECRET=pdri-dev-secret-CHANGE-IN-PRODUCTION
```

---

## Step 2: Start Infrastructure

```bash
# Start all backing services
docker compose up -d

# Watch startup (wait for all health checks to pass)
docker compose ps
```

### Service Map

| Service | Port | URL | What to check |
|---------|------|-----|--------------|
| **PostgreSQL** | 5432 | — | `docker compose exec postgres pg_isready` |
| **Neo4j** | 7474 / 7687 | http://localhost:7474 | Browser opens, login with `neo4j / neo4j_secure_password_change_me` |
| **Kafka** | 9092 | — | `docker compose logs kafka-setup` shows "Topics created" |
| **Redis** | 6379 | — | `docker compose exec redis redis-cli ping` → PONG |
| **Prometheus** | 9090 | http://localhost:9090 | Targets page shows PDRI target |
| **Grafana** | 3000 | http://localhost:3000 | Login: `admin / pdri_grafana_change_me` |

**Expected**: After ~60 seconds, `docker compose ps` shows all services as `healthy`:

```
pdri-postgres    running (healthy)
pdri-neo4j       running (healthy)
pdri-zookeeper   running (healthy)
pdri-kafka       running (healthy)
pdri-kafka-setup exited (0)        ← normal, it's a one-shot
pdri-redis       running (healthy)
pdri-prometheus  running (healthy)
pdri-grafana     running (healthy)
```

---

## Step 3: Start PDRI API

```bash
# Run the API server
python -m uvicorn pdri.api.main:app --host 0.0.0.0 --port 8000 --reload
```

### Verify API is up:

```bash
# Health check (should return {"status": "ready"})
curl http://localhost:8000/health

# Readiness (checks all dependencies)
curl http://localhost:8000/health/ready

# Liveness
curl http://localhost:8000/health/live

# OpenAPI docs in browser
# → http://localhost:8000/docs
```

**What to look for in the terminal:**
```
INFO:     Uvicorn running on http://0.0.0.0:8000
INFO:     Started reloader process
```

If you see errors about `neo4j` or `kafka` connections — make sure Docker services are running first.

---

## Step 4: Run Tests

### Run all tests
```bash
pytest tests/ -v
```

### Run specific test suites

```bash
# API layer tests
pytest tests/test_api.py -v

# Scoring engine tests
pytest tests/test_scoring.py -v

# Graph engine tests
pytest tests/test_graph.py -v

# Autonomous response engine
pytest tests/test_autonomous.py -v

# AegisAI client integration
pytest tests/test_aegis_client.py -v

# WebSocket real-time events
pytest tests/test_websocket.py -v

# Compliance framework
pytest tests/test_compliance.py -v

# Prediction/ML engine
pytest tests/test_prediction.py -v

# Simulation engine
pytest tests/test_simulation.py -v

# Integration tests (end-to-end)
pytest tests/test_integration.py -v

# Redis score cache
pytest tests/test_score_cache.py -v

# Performance tests
pytest tests/test_performance.py -v

# Ingestion pipeline
pytest tests/test_ingestion.py -v
```

### With coverage report
```bash
pytest tests/ -v --cov=pdri --cov-report=term-missing
```

**What to look for:**
- All tests should show **PASSED** (green)
- Coverage should be reported per module
- Tests use `sys.modules` mocking — they can run without live services

---

## Step 5: Test API Endpoints Manually

### 5a. Scoring Endpoints

```bash
# Get risk score for an entity
curl http://localhost:8000/scoring/customer-db

# Get score explanation (human-readable)
curl http://localhost:8000/scoring/customer-db/explain

# Get score history
curl http://localhost:8000/scoring/customer-db/history?days=30
```

### 5b. Analytics Endpoints

```bash
# Overall risk summary
curl http://localhost:8000/analytics/risk-summary

# High-risk entities
curl http://localhost:8000/analytics/high-risk?threshold=0.6&limit=10

# AI exposure paths
curl http://localhost:8000/analytics/ai-exposure?min_sensitivity=0.5

# Exposure paths for specific entity
curl http://localhost:8000/analytics/exposure-paths/customer-db
```

### 5c. Node Endpoints

```bash
# Get node details
curl http://localhost:8000/nodes/customer-db

# Get all AI tools
curl http://localhost:8000/nodes/ai-tools

# Get all data stores
curl http://localhost:8000/nodes/data-stores
```

### 5d. Metrics & Monitoring

```bash
# Prometheus metrics
curl http://localhost:8000/metrics
```

---

## Step 6: Test AegisAI Integration

> **Requires**: `AEGIS_ENABLED=true` in `.env`

### 6a. Webhook receiver test

```bash
# Single finding
curl -X POST http://localhost:8000/webhooks/aegis/findings \
  -H "Content-Type: application/json" \
  -d '{
    "id": "f-001",
    "tenant_id": "t-001",
    "finding_type": "shadow_ai_tool",
    "severity": "high",
    "title": "Shadow AI Detected",
    "description": "Unauthorized AI tool",
    "resource_arn": "arn:aws:lambda:us-east-1:123:function:fn",
    "resource_type": "lambda",
    "region": "us-east-1",
    "risk_score": 0.82,
    "risk_factors": {"data_sensitivity": 0.9},
    "ai_provider": "OpenAI",
    "ai_service": "gpt-4",
    "evidence": {"has_pii": true},
    "status": "open",
    "created_at": "2026-02-17T10:00:00Z"
  }'

# Expected: {"status": "accepted", "event_id": "...", ...}
```

```bash
# Batch findings
curl -X POST http://localhost:8000/webhooks/aegis/findings/batch \
  -H "Content-Type: application/json" \
  -d '{
    "findings": [
      {"id": "f-001", "finding_type": "shadow_ai_tool", "severity": "high", "title": "Test 1", "status": "open", "created_at": "2026-02-17T10:00:00Z"},
      {"id": "f-002", "finding_type": "sensitive_data_exposure", "severity": "critical", "title": "Test 2", "status": "open", "created_at": "2026-02-17T10:00:00Z"}
    ]
  }'

# Expected: {"accepted": 2, "rejected": 0, ...}
```

```bash
# Integration status
curl http://localhost:8000/webhooks/aegis/status

# Expected: {"status": "active", "findings_received": ..., ...}
```

### 6b. Run Aegis-specific tests

```bash
pytest tests/test_aegis_client.py -v
```

**What to look for:**
- Webhook returns 200 with `"status": "accepted"`
- Batch endpoint reports accepted/rejected counts
- No HMAC signature errors (unless you set `AEGIS_WEBHOOK_SECRET`)

---

## Step 7: Test Dmitry Integration

> **Requires**: Dmitry server running on port 8765 + `DMITRY_ENABLED=true`

### 7a. Start Dmitry (if available)

```bash
# In the Dmitry/MarkX project:
cd MarkX
python run_dmitry.py --mode server
# Expected: "Agent API server started on http://127.0.0.1:8765"
```

### 7b. Test from Python

```python
import asyncio
from pdri.integrations.dmitry_client import DmitryBackendClient

async def test_dmitry():
    client = DmitryBackendClient()

    # Health check
    health = await client.health_check()
    print(f"Connected: {health['healthy']}, Latency: {health['latency_ms']}ms")

    # Get status
    status = await client.get_status()
    print(f"Mode: {status.get('mode')}")

    # Send a message
    response = await client.send_message("What's the current risk level?")
    print(f"Response: {response.get('text', '')[:200]}")

    # Switch to security mode
    result = await client.switch_mode("security")
    print(f"Mode switch: {result.get('success')}")

    # Analyze a threat
    analysis = await client.analyze_threat(
        "Multiple failed login attempts from 192.168.1.100"
    )
    print(f"Threat analysis: {analysis.get('text', '')[:200]}")

    await client.close()

asyncio.run(test_dmitry())
```

**What to look for:**
- `Connected: True` with latency < 500ms
- Mode switches return `"success": true`
- Threat analysis returns meaningful text (not error)

---

## Step 8: WebSocket Real-Time Events

```python
import asyncio
import websockets
import json

async def listen():
    uri = "ws://localhost:8000/ws/risk-events?rooms=all"
    async with websockets.connect(uri) as ws:
        print("Connected to PDRI WebSocket")
        async for message in ws:
            data = json.loads(message)
            if data.get("type") == "ping":
                await ws.send(json.dumps({"type": "pong"}))
            else:
                print(f"Event: {data}")

asyncio.run(listen())
```

**What to look for:**
- Connection establishes without error
- Ping/pong keeps connection alive
- Risk events appear when data changes

---

## Step 9: Neo4j Graph Browser

Open http://localhost:7474 and run these Cypher queries:

```cypher
-- See all node types
CALL db.labels()

-- Count all nodes
MATCH (n) RETURN labels(n) AS type, count(n) AS count

-- Find high-risk entities
MATCH (n) WHERE n.risk_score > 0.7
RETURN n.id, n.name, n.risk_score
ORDER BY n.risk_score DESC
LIMIT 10

-- Find AI exposure paths
MATCH path = (ds:DataStore)-[*1..5]->(ai:AITool)
RETURN path LIMIT 10
```

---

## Step 10: Grafana Dashboards

1. Open http://localhost:3000
2. Login: `admin` / `pdri_grafana_change_me`
3. Navigate to **Dashboards → PDRI Overview**
4. Check for:
   - API request rates
   - Scoring latency
   - Error rates
   - Integration health

---

## Troubleshooting

| Symptom | Cause | Fix |
|---------|-------|-----|
| `ModuleNotFoundError: aiokafka` | Missing dependency | `pip install aiokafka` |
| `ConnectionRefusedError` on 7687 | Neo4j not ready | Wait 30s, check `docker compose ps` |
| `ConnectionRefusedError` on 9092 | Kafka not ready | Wait 60s, check `docker compose logs kafka` |
| API starts but 500s on scoring | No graph data loaded | Ingest test data first |
| `AEGIS_ENABLED` but 404 on webhooks | Settings not loaded | Restart API after changing `.env` |
| Dmitry `circuit_open` error | Dmitry server not running | Start Dmitry: `python run_dmitry.py --mode server` |
| `pydantic_settings` import error | Wrong pydantic version | `pip install pydantic-settings>=2.1.0` |

---

## Quick Reference Commands

```bash
# Start everything
docker compose up -d && python -m uvicorn pdri.api.main:app --reload

# Run all tests
pytest tests/ -v --cov=pdri

# Check service health
curl -s http://localhost:8000/health | python -m json.tool

# View API docs
start http://localhost:8000/docs    # Windows
open http://localhost:8000/docs     # macOS

# Stop everything
docker compose down

# Reset all data (destructive!)
docker compose down -v
```
