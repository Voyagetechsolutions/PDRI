"""
AegisAI ↔ PDRI Data Transformer
=================================

Bidirectional data transformation between AegisAI and PDRI formats.

Transforms:
    - AegisAI Finding → PDRI SecurityEvent
    - PDRI SecurityEvent/Risk Data → AegisAI Finding
    - AegisAI Policy enforcement_mode → PDRI autonomous response type

Author: PDRI Team
Version: 1.0.0
"""

import logging
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)


# =============================================================================
# Type Mappings
# =============================================================================

# AegisAI finding_type → PDRI event_type
FINDING_TYPE_TO_EVENT_TYPE = {
    "ai_api_usage": "AI_DATA_ACCESS",
    "shadow_ai_tool": "AI_TOOL_DISCOVERY",
    "sensitive_data_exposure": "DATA_EXPORT",
    "privilege_risk": "PRIVILEGE_ESCALATION",
    "shadow_ai_deployment": "AI_TOOL_DISCOVERY",
    "policy_violation": "SYSTEM_ACCESS",
}

# PDRI event_type → AegisAI finding_type (reverse)
EVENT_TYPE_TO_FINDING_TYPE = {
    "AI_DATA_ACCESS": "ai_api_usage",
    "AI_TOOL_DISCOVERY": "shadow_ai_tool",
    "AI_PROMPT_SENSITIVITY": "ai_api_usage",
    "AI_MODEL_TRAINING": "ai_api_usage",
    "DATA_EXPORT": "sensitive_data_exposure",
    "DATA_MOVEMENT": "sensitive_data_exposure",
    "DATA_AGGREGATION": "sensitive_data_exposure",
    "PRIVILEGE_ESCALATION": "privilege_risk",
    "SYSTEM_ACCESS": "ai_api_usage",
    "SYSTEM_AUTH_FAILURE": "privilege_risk",
}

# Severity mapping (identical between platforms)
SEVERITY_MAP = {
    "low": "low",
    "medium": "medium",
    "high": "high",
    "critical": "critical",
}

# AegisAI enforcement mode → PDRI autonomous response type
ENFORCEMENT_TO_RESPONSE = {
    "detect_only": "monitor",
    "alert": "alert",
    "ticket": "escalate",
    "remediate": "auto_respond",
}

# AWS resource type → PDRI entity type
RESOURCE_TYPE_TO_ENTITY_TYPE = {
    "lambda": "service",
    "ecs": "service",
    "ec2": "service",
    "sagemaker": "service",
    "s3": "data_store",
    "rds": "data_store",
    "dynamodb": "data_store",
    "redshift": "data_store",
    "aurora": "data_store",
    "elasticache": "data_store",
    "bedrock": "ai_tool",
    "openai": "ai_tool",
    "anthropic": "ai_tool",
    "comprehend": "ai_tool",
    "rekognition": "ai_tool",
    "iam": "identity",
    "cognito": "identity",
    "apigateway": "api",
    "elb": "api",
    "cloudfront": "api",
}


# =============================================================================
# AegisAI Finding → PDRI SecurityEvent
# =============================================================================


def aegis_finding_to_pdri_event(finding: Dict[str, Any]) -> Dict[str, Any]:
    """
    Convert an AegisAI Finding into a PDRI SecurityEvent.

    This is used when PDRI receives findings from AegisAI via webhook
    and needs to ingest them into the risk graph.

    Args:
        finding: AegisAI finding dict with fields:
            id, tenant_id, finding_type, severity, title, description,
            resource_arn, resource_type, region, risk_score, risk_factors,
            ai_provider, ai_service, evidence, status, created_at

    Returns:
        PDRI SecurityEvent dict ready for ingestion pipeline
    """
    finding_type = finding.get("finding_type", "")
    ai_provider = finding.get("ai_provider")

    event = {
        "event_id": str(finding.get("id", "")),
        "event_type": FINDING_TYPE_TO_EVENT_TYPE.get(finding_type, "SYSTEM_ACCESS"),
        "source_system_id": f"aegis-{finding.get('cloud_account_id', finding.get('tenant_id', 'unknown'))}",
        "timestamp": finding.get("created_at", datetime.now(timezone.utc).isoformat()),
        "entity_id": finding.get("resource_arn") or str(finding.get("id", "")),
        "entity_type": _infer_entity_type(finding.get("resource_type", "")),
        "severity": SEVERITY_MAP.get(finding.get("severity", "medium"), "medium"),
        "exposure_direction": _infer_exposure_direction(finding_type),
        "sensitivity_tags": _extract_sensitivity_tags(finding),
        "metadata": {
            "aegis_finding_id": str(finding.get("id", "")),
            "aegis_tenant_id": str(finding.get("tenant_id", "")),
            "aegis_risk_score": finding.get("risk_score", 0),
            "aegis_evidence": finding.get("evidence", {}),
            "aegis_status": finding.get("status", "open"),
            "resource_arn": finding.get("resource_arn", ""),
            "region": finding.get("region", ""),
            "title": finding.get("title", ""),
            "description": finding.get("description", ""),
        },
    }

    # Add AI context if an AI provider is involved
    if ai_provider:
        event["ai_context"] = {
            "ai_tool_id": finding.get("ai_service", ai_provider),
            "model_name": finding.get("ai_service", ""),
            "data_volume_bytes": 0,
        }

    return event


# =============================================================================
# PDRI Risk Data → AegisAI Finding
# =============================================================================


def pdri_risk_to_aegis_finding(pdri_data: Dict[str, Any]) -> Dict[str, Any]:
    """
    Convert PDRI risk/score data into an AegisAI Finding-compatible dict.

    Used when PDRI pushes incidents or risk summaries to AegisAI.

    Args:
        pdri_data: PDRI risk data dict, typically from score explanation
            or autonomous risk event, with fields like entity_id,
            risk_level, composite_score, event_type, summary, etc.

    Returns:
        Dict compatible with AegisAI's Finding inbound schema
    """
    return {
        "pidr_id": pdri_data.get("entity_id", ""),
        "finding_type": EVENT_TYPE_TO_FINDING_TYPE.get(
            pdri_data.get("event_type", ""), "ai_api_usage"
        ),
        "severity": pdri_data.get("risk_level", "medium"),
        "title": f"PDRI Risk Alert: {pdri_data.get('entity_id', 'Unknown')}",
        "description": pdri_data.get("summary", "Risk detected by PDRI"),
        "risk_score": pdri_data.get("composite_score", 0.0),
        "risk_factors": pdri_data.get("factor_breakdown", {}),
        "status": "open",
        "pidr_sync_status": "synced",
        "pidr_synced_at": pdri_data.get(
            "calculated_at", datetime.now(timezone.utc).isoformat()
        ),
        "pidr_metadata": {
            "exposure_score": pdri_data.get("exposure_score"),
            "volatility_score": pdri_data.get("volatility_score"),
            "sensitivity_likelihood": pdri_data.get("sensitivity_likelihood"),
            "recommendations": pdri_data.get("recommendations", []),
        },
    }


# =============================================================================
# Incident Payload Builder
# =============================================================================


def build_aegis_incident_payload(
    entity_id: str,
    action_type: str,
    severity: str,
    description: str,
    risk_score: Optional[float] = None,
    recommendations: Optional[List[str]] = None,
    metadata: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """
    Build an incident payload for reporting to AegisAI.

    Called by ResponseEngine when a response action is triggered.

    Args:
        entity_id: Affected entity ID
        action_type: Response action type (alert, restrict, isolate, etc.)
        severity: Risk severity level
        description: Human-readable incident description
        risk_score: Optional composite risk score
        recommendations: Optional list of recommendations
        metadata: Optional additional metadata

    Returns:
        Incident payload dict ready for AegisClient.report_incident()
    """
    return {
        "entity_id": entity_id,
        "incident_type": _action_to_incident_type(action_type),
        "severity": severity,
        "description": description,
        "risk_score": risk_score,
        "recommendations": recommendations or [],
        "pdri_metadata": metadata or {},
    }


# =============================================================================
# Private Helpers
# =============================================================================


def _infer_entity_type(resource_type: str) -> str:
    """Map AWS resource type string to PDRI entity type."""
    resource_type_lower = resource_type.lower().strip()
    return RESOURCE_TYPE_TO_ENTITY_TYPE.get(resource_type_lower, "service")


def _infer_exposure_direction(finding_type: str) -> str:
    """Infer data exposure direction from finding type."""
    if finding_type in ("ai_api_usage", "shadow_ai_tool", "shadow_ai_deployment"):
        return "internal_to_ai"
    elif finding_type == "sensitive_data_exposure":
        return "internal_to_external"
    else:
        return "internal_to_internal"


def _extract_sensitivity_tags(finding: Dict[str, Any]) -> List[str]:
    """Extract sensitivity tags from finding evidence and risk factors."""
    tags: List[str] = []
    evidence = finding.get("evidence", {})
    risk_factors = finding.get("risk_factors", {})

    if evidence.get("has_pii") or evidence.get("pii_detected"):
        tags.append("identity_related")
    if evidence.get("has_financial") or evidence.get("financial_data"):
        tags.append("financial_related")
    if evidence.get("has_credentials") or evidence.get("credentials_detected"):
        tags.append("credentials_related")
    if evidence.get("has_phi") or evidence.get("health_data"):
        tags.append("health_related")
    if risk_factors.get("data_sensitivity", 0) > 0.7:
        tags.append("regulated_data")

    return tags or ["unknown"]


def _action_to_incident_type(action_type: str) -> str:
    """Map PDRI response action type to an Aegis incident type string."""
    mapping = {
        "alert": "anomaly",
        "restrict": "policy_enforcement",
        "isolate": "breach",
        "escalate": "escalation",
        "remediate": "remediation",
        "audit": "audit_trigger",
        "report": "report",
    }
    return mapping.get(action_type, "anomaly")
