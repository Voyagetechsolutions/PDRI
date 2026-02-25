# PDRI Data Ownership

## The Golden Rule

> **Never duplicate truth across Neo4j and PostgreSQL.**

Each system owns specific data. The other system references it but doesn't copy it.

---

## Neo4j Owns

### Entity Graph (Source of Truth for Relationships)
- DataStore nodes
- Service nodes
- AITool nodes
- Identity nodes
- API nodes
- All edges (ACCESSES, INTEGRATES_WITH, MOVES_DATA_TO, EXPOSES, etc.)

### Risk Computation (Source of Truth for Scores)
- Exposure score calculation
- Volatility score calculation
- Sensitivity likelihood calculation
- Composite score calculation
- Factor weights and rules
- Exposure path traversal
- Graph-based analytics

### What Neo4j Does NOT Own
- Finding lifecycle (status, assignment, SLA)
- Event history
- Audit trail
- Compliance assessment results
- User/tenant data

---

## PostgreSQL Owns

### Event Processing (Source of Truth for Ingestion)
- Processed events (idempotency)
- Event fingerprints
- Event correlations
- Duplicate detection

### Finding Lifecycle (Source of Truth for Remediation)
- Finding status (open → acknowledged → resolved)
- Assignment (who's working on it)
- SLA tracking (due dates, breaches)
- Resolution notes
- False positive tracking
- Occurrence counting
- First/last seen timestamps

### Audit & Compliance (Source of Truth for Evidence)
- Audit logs
- Compliance assessments
- Evidence collection
- Report generation

### What PostgreSQL Does NOT Own
- Entity relationships (those are in Neo4j)
- Live risk scores (computed by Neo4j)
- Exposure paths (traversed in Neo4j)

---

## The Data Flow

```
┌─────────────────────────────────────────────────────────────────────┐
│                         INGESTION LAYER                              │
│                                                                      │
│  SecurityEvent (from Kafka)                                          │
│       │                                                              │
│       ▼                                                              │
│  ┌─────────────────┐                                                 │
│  │ Deduplication   │◄── Postgres: processed_events                   │
│  │ (event_id)      │                                                 │
│  └────────┬────────┘                                                 │
│           │                                                          │
│           ▼                                                          │
│  ┌─────────────────┐                                                 │
│  │ Correlation     │◄── Postgres: event_correlations                 │
│  │ (fingerprint)   │                                                 │
│  └────────┬────────┘                                                 │
│           │                                                          │
└───────────┼──────────────────────────────────────────────────────────┘
            │
            ▼
┌───────────────────────────────────────────────────────────────────────┐
│                         GRAPH LAYER (Neo4j)                           │
│                                                                       │
│  ┌─────────────────┐     ┌─────────────────┐     ┌─────────────────┐ │
│  │ Create/Update   │────▶│ Score Entity    │────▶│ Find Exposure   │ │
│  │ Nodes/Edges     │     │ (11 factors)    │     │ Paths           │ │
│  └─────────────────┘     └────────┬────────┘     └─────────────────┘ │
│                                   │                                   │
└───────────────────────────────────┼───────────────────────────────────┘
                                    │
                                    ▼
┌───────────────────────────────────────────────────────────────────────┐
│                         FINDING LAYER (Postgres)                      │
│                                                                       │
│  ┌─────────────────┐                                                  │
│  │ Generate/Update │◄── Score + Correlation + Threshold               │
│  │ Finding         │                                                  │
│  └────────┬────────┘                                                  │
│           │                                                           │
│           ▼                                                           │
│  ┌─────────────────────────────────────────────────────────────────┐ │
│  │                     Finding Lifecycle                            │ │
│  │  open → acknowledged → in_progress → resolved                    │ │
│  │         │                                                        │ │
│  │         └──────────────▶ false_positive                          │ │
│  └─────────────────────────────────────────────────────────────────┘ │
│                                                                       │
└───────────────────────────────────────────────────────────────────────┘
```

---

## Reference Pattern

### Finding → Graph Entity Reference

```python
# Finding stores ID only
class FindingDB:
    primary_entity_id: str      # "datastore:customer-db"
    primary_entity_type: str    # "data_store"
    entities_involved: List     # [{"entity_id": "...", "role": "..."}]

# When API needs entity details, query Neo4j
async def get_finding_with_context(finding_id: str):
    finding = await postgres.get_finding(finding_id)
    entity = await neo4j.get_node(finding.primary_entity_id)
    return {**finding, "entity_details": entity}
```

### Finding → Score (Point-in-Time Copy)

```python
# Finding stores score AT TIME OF CREATION
# This is intentional - shows what score triggered the finding
class FindingDB:
    risk_score: float          # Score when finding was created
    exposure_score: float      # Component scores at creation
    volatility_score: float
    sensitivity_score: float

# For CURRENT score, query Neo4j or scoring engine
async def get_finding_with_current_score(finding_id: str):
    finding = await postgres.get_finding(finding_id)
    current_score = await scoring_engine.score_entity(finding.primary_entity_id)
    return {
        **finding,
        "score_at_creation": finding.risk_score,
        "current_score": current_score.composite_score,
        "score_change": current_score.composite_score - finding.risk_score,
    }
```

---

## Anti-Patterns (Don't Do This)

### ❌ Duplicating Graph Data in Postgres

```python
# BAD: Storing full entity data in finding
class FindingDB:
    entity_name: str           # NO - query Neo4j
    entity_technology: str     # NO - query Neo4j
    entity_connections: List   # NO - query Neo4j
```

### ❌ Duplicating Lifecycle in Neo4j

```python
# BAD: Storing finding status on graph node
await neo4j.update_node(entity_id, {
    "finding_status": "open",    # NO - this belongs in Postgres
    "assigned_to": "analyst-1",  # NO - this belongs in Postgres
})
```

### ❌ Computing Scores in Postgres

```python
# BAD: Trying to calculate risk in SQL
SELECT
    f.*,
    (exposure * 0.5 + volatility * 0.3) as risk_score  # NO
FROM findings f;
```

---

## Summary Table

| Data | Owner | Other System |
|------|-------|--------------|
| Entity nodes | Neo4j | Postgres references by ID |
| Entity relationships | Neo4j | Postgres stores path as ID list |
| Risk scores | Neo4j computes | Postgres stores point-in-time copy |
| Exposure paths | Neo4j traverses | Postgres stores as ID list |
| Event deduplication | Postgres | Neo4j doesn't know about events |
| Event correlation | Postgres | Neo4j doesn't know about correlations |
| Finding lifecycle | Postgres | Neo4j doesn't know about findings |
| SLA tracking | Postgres | Neo4j doesn't track time |
| Audit trail | Postgres | Neo4j doesn't audit |
| Compliance results | Postgres | Neo4j provides evidence data |

---

## When to Query Which

| Need | Query |
|------|-------|
| "What entities are connected to X?" | Neo4j |
| "What's the current risk score?" | Neo4j (via ScoringEngine) |
| "What's the exposure path?" | Neo4j |
| "What findings are open?" | Postgres |
| "Who's assigned to this finding?" | Postgres |
| "Is the SLA breached?" | Postgres |
| "What events triggered this finding?" | Postgres |
| "Show audit trail" | Postgres |
