"""
Test Fixtures for MVP Graph-Lite Tables
=========================================

Provides a realistic fixture dataset for integration testing:
    - 10 entities (3 data_stores, 3 ai_tools, 2 identities, 1 saas_app, 1 service)
    - 15 edges connecting them
    - 20 security events
    - Expected scoring and finding outcomes

Author: PDRI Team
Version: 1.0.0
"""

from datetime import datetime, timedelta, timezone

TENANT_ID = "t-test-acme"
NOW = datetime.now(timezone.utc)
WEEK_AGO = NOW - timedelta(days=7)


# =============================================================================
# Entities
# =============================================================================

ENTITIES = [
    # Data stores
    {
        "external_id": "ds-customer-db",
        "entity_type": "data_store",
        "name": "Customer PII Database",
        "attributes": {
            "technology": "PostgreSQL",
            "data_classification": "confidential",
            "is_public": False,
            "sensitivity_tags": ["identity_related", "financial_related"],
        },
    },
    {
        "external_id": "ds-analytics-dw",
        "entity_type": "data_store",
        "name": "Analytics Data Warehouse",
        "attributes": {
            "technology": "BigQuery",
            "data_classification": "internal",
            "is_public": False,
        },
    },
    {
        "external_id": "ds-logs-bucket",
        "entity_type": "data_store",
        "name": "Application Logs Bucket",
        "attributes": {
            "technology": "S3",
            "data_classification": "public",
            "is_public": True,
        },
    },
    # AI tools
    {
        "external_id": "ai-chatgpt-plugin",
        "entity_type": "ai_tool",
        "name": "ChatGPT Plugin (Unsanctioned)",
        "attributes": {
            "vendor": "OpenAI",
            "model_name": "gpt-4",
            "is_sanctioned": False,
            "sends_data_external": True,
        },
    },
    {
        "external_id": "ai-copilot",
        "entity_type": "ai_tool",
        "name": "GitHub Copilot",
        "attributes": {
            "vendor": "GitHub",
            "model_name": "copilot",
            "is_sanctioned": True,
            "sends_data_external": True,
        },
    },
    {
        "external_id": "ai-internal-ml",
        "entity_type": "ai_tool",
        "name": "Internal ML Pipeline",
        "attributes": {
            "vendor": "internal",
            "model_name": "fraud-detector-v2",
            "is_sanctioned": True,
            "sends_data_external": False,
        },
    },
    # Identities
    {
        "external_id": "id-admin-alice",
        "entity_type": "identity",
        "name": "alice@acme.com",
        "attributes": {"privilege_level": "admin", "department": "engineering"},
    },
    {
        "external_id": "id-viewer-bob",
        "entity_type": "identity",
        "name": "bob@acme.com",
        "attributes": {"privilege_level": "read", "department": "marketing"},
    },
    # SaaS app
    {
        "external_id": "saas-salesforce",
        "entity_type": "saas_app",
        "name": "Salesforce CRM",
        "attributes": {"vendor": "Salesforce", "has_api_access": True, "is_public": False},
    },
    # Service
    {
        "external_id": "svc-api-gateway",
        "entity_type": "service",
        "name": "API Gateway",
        "attributes": {"technology": "Kong", "is_public": True},
    },
]


# =============================================================================
# Edges
# =============================================================================

EDGES = [
    # Unsanctioned ChatGPT → Customer DB
    {"src": "ai-chatgpt-plugin", "dst": "ds-customer-db", "rel": "ACCESSES", "weight": 0.9},
    # Copilot → Analytics DW
    {"src": "ai-copilot", "dst": "ds-analytics-dw", "rel": "INTEGRATES_WITH", "weight": 0.7},
    # Internal ML → Customer DB
    {"src": "ai-internal-ml", "dst": "ds-customer-db", "rel": "ACCESSES", "weight": 0.8},
    # Admin Alice → ChatGPT
    {"src": "id-admin-alice", "dst": "ai-chatgpt-plugin", "rel": "ACCESSES", "weight": 0.9},
    # Admin Alice → Customer DB
    {"src": "id-admin-alice", "dst": "ds-customer-db", "rel": "ACCESSES", "weight": 0.9},
    # Admin Alice → API Gateway
    {"src": "id-admin-alice", "dst": "svc-api-gateway", "rel": "AUTHENTICATES_VIA", "weight": 0.5},
    # Viewer Bob → Analytics DW
    {"src": "id-viewer-bob", "dst": "ds-analytics-dw", "rel": "ACCESSES", "weight": 0.5},
    # Viewer Bob → Salesforce
    {"src": "id-viewer-bob", "dst": "saas-salesforce", "rel": "ACCESSES", "weight": 0.6},
    # Customer DB → Salesforce (data movement)
    {"src": "ds-customer-db", "dst": "saas-salesforce", "rel": "MOVES_DATA_TO", "weight": 0.7},
    # Customer DB → Analytics DW
    {"src": "ds-customer-db", "dst": "ds-analytics-dw", "rel": "MOVES_DATA_TO", "weight": 0.8},
    # API Gateway → Customer DB
    {"src": "svc-api-gateway", "dst": "ds-customer-db", "rel": "ACCESSES", "weight": 0.6},
    # Internal ML → Analytics DW
    {"src": "ai-internal-ml", "dst": "ds-analytics-dw", "rel": "ACCESSES", "weight": 0.7},
    # ChatGPT → Analytics DW (another exfiltration path)
    {"src": "ai-chatgpt-plugin", "dst": "ds-analytics-dw", "rel": "ACCESSES", "weight": 0.6},
    # Salesforce → Logs Bucket (export)
    {"src": "saas-salesforce", "dst": "ds-logs-bucket", "rel": "EXPORTS_TO", "weight": 0.4},
    # Customer DB → ChatGPT (reverse - data export)
    {"src": "ds-customer-db", "dst": "ai-chatgpt-plugin", "rel": "EXPORTS_TO", "weight": 0.9},
]


# =============================================================================
# Security Events
# =============================================================================

EVENTS = [
    # Shadow AI accessing customer data (triggers Rule 1)
    {
        "event_id": "evt-001",
        "event_type": "AI_DATA_ACCESS",
        "source_system_id": "aegis-scanner-01",
        "timestamp": (NOW - timedelta(hours=2)).isoformat(),
        "entity_id": "ds-customer-db",
        "entity_type": "data_store",
        "identity_id": "ai-chatgpt-plugin",
        "severity": "high",
        "exposure_direction": "internal_to_ai",
        "sensitivity_tags": ["identity_related", "financial_related"],
        "ai_context": {
            "ai_tool_id": "ai-chatgpt-plugin",
            "model_name": "gpt-4",
            "data_volume_bytes": 52_000_000,
            "is_sanctioned": False,
        },
    },
    # Admin Alice using ChatGPT (triggers Rule 2)
    {
        "event_id": "evt-002",
        "event_type": "AI_DATA_ACCESS",
        "source_system_id": "aegis-scanner-01",
        "timestamp": (NOW - timedelta(hours=1)).isoformat(),
        "entity_id": "ai-chatgpt-plugin",
        "entity_type": "ai_tool",
        "identity_id": "id-admin-alice",
        "severity": "high",
        "exposure_direction": "internal_to_ai",
        "sensitivity_tags": [],
        "privilege_level": "admin",
        "ai_context": {
            "ai_tool_id": "ai-chatgpt-plugin",
            "model_name": "gpt-4",
            "data_volume_bytes": 5_000_000,
            "is_sanctioned": False,
        },
    },
    # Large data export from customer DB (contributes to Rule 3)
    {
        "event_id": "evt-003",
        "event_type": "DATA_EXPORT",
        "source_system_id": "dlp-sensor-01",
        "timestamp": (NOW - timedelta(days=1)).isoformat(),
        "entity_id": "ds-customer-db",
        "entity_type": "data_store",
        "identity_id": "svc-api-gateway",
        "severity": "medium",
        "exposure_direction": "internal_to_external",
        "sensitivity_tags": ["financial_related"],
        "ai_context": {"data_volume_bytes": 75_000_000},
    },
    {
        "event_id": "evt-004",
        "event_type": "DATA_EXPORT",
        "source_system_id": "dlp-sensor-01",
        "timestamp": (NOW - timedelta(days=2)).isoformat(),
        "entity_id": "ds-customer-db",
        "entity_type": "data_store",
        "identity_id": "svc-api-gateway",
        "severity": "medium",
        "exposure_direction": "internal_to_external",
        "sensitivity_tags": ["financial_related"],
        "ai_context": {"data_volume_bytes": 60_000_000},
    },
    # Normal data movement (should not trigger findings)
    {
        "event_id": "evt-005",
        "event_type": "DATA_MOVEMENT",
        "source_system_id": "etl-pipeline",
        "timestamp": (NOW - timedelta(hours=6)).isoformat(),
        "entity_id": "ds-analytics-dw",
        "entity_type": "data_store",
        "identity_id": "ai-internal-ml",
        "severity": "low",
        "exposure_direction": "internal_to_internal",
        "sensitivity_tags": [],
        "ai_context": {"data_volume_bytes": 10_000_000},
    },
    {
        "event_id": "evt-006",
        "event_type": "SYSTEM_ACCESS",
        "source_system_id": "iam-system",
        "timestamp": (NOW - timedelta(hours=3)).isoformat(),
        "entity_id": "ds-customer-db",
        "entity_type": "data_store",
        "identity_id": "id-viewer-bob",
        "severity": "low",
        "privilege_level": "read",
    },
    {
        "event_id": "evt-007",
        "event_type": "SYSTEM_ACCESS",
        "source_system_id": "iam-system",
        "timestamp": (NOW - timedelta(hours=4)).isoformat(),
        "entity_id": "saas-salesforce",
        "entity_type": "saas_app",
        "identity_id": "id-viewer-bob",
        "severity": "low",
        "privilege_level": "read",
    },
    {
        "event_id": "evt-008",
        "event_type": "PRIVILEGE_ESCALATION",
        "source_system_id": "iam-system",
        "timestamp": (NOW - timedelta(days=3)).isoformat(),
        "entity_id": "ds-customer-db",
        "entity_type": "data_store",
        "identity_id": "id-admin-alice",
        "severity": "high",
        "privilege_level": "admin",
    },
    {
        "event_id": "evt-009",
        "event_type": "AI_TOOL_DISCOVERY",
        "source_system_id": "aegis-scanner-01",
        "timestamp": (NOW - timedelta(days=5)).isoformat(),
        "entity_id": "ai-chatgpt-plugin",
        "entity_type": "ai_tool",
        "identity_id": "id-admin-alice",
        "severity": "medium",
        "ai_context": {
            "ai_tool_id": "ai-chatgpt-plugin",
            "model_name": "gpt-4",
            "is_sanctioned": False,
        },
    },
    {
        "event_id": "evt-010",
        "event_type": "DATA_MOVEMENT",
        "source_system_id": "etl-pipeline",
        "timestamp": (NOW - timedelta(days=1)).isoformat(),
        "entity_id": "ds-customer-db",
        "entity_type": "data_store",
        "identity_id": "ai-chatgpt-plugin",
        "severity": "high",
        "exposure_direction": "internal_to_ai",
        "sensitivity_tags": ["identity_related"],
        "ai_context": {"data_volume_bytes": 30_000_000, "is_sanctioned": False},
    },
]

# Add more events for volume testing
for i in range(11, 21):
    EVENTS.append({
        "event_id": f"evt-{i:03d}",
        "event_type": "SYSTEM_ACCESS",
        "source_system_id": "iam-system",
        "timestamp": (NOW - timedelta(hours=i)).isoformat(),
        "entity_id": "ds-analytics-dw",
        "entity_type": "data_store",
        "identity_id": "id-viewer-bob",
        "severity": "low",
        "privilege_level": "read",
    })


# =============================================================================
# Expected Outcomes (for test assertions)
# =============================================================================

EXPECTED = {
    # Customer DB should score high due to shadow AI + sensitive data
    "ds-customer-db_risk_level": "high",  # or critical
    # ChatGPT accessing customer DB should trigger shadow_ai finding
    "shadow_ai_finding_expected": True,
    # Alice (admin) → ChatGPT should trigger privileged_identity finding
    "privileged_identity_finding_expected": True,
    # Customer DB export (75MB + 60MB = 135MB > 100MB) should trigger excessive_export
    "excessive_export_finding_expected": True,
    # Analytics DW should be medium risk (internal classification, no external AI)
    "ds-analytics-dw_risk_level": "medium",
    # Logs bucket should be low risk (public but no sensitive data)
    "ds-logs-bucket_risk_level": "low",
}
