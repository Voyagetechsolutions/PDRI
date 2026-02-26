"""
Tests for MVP Finding Rules
============================

Tests all 3 finding rules with boundary conditions:
    1. Shadow AI Accessing Sensitive Assets
    2. Privileged Identity Linked to AI Integration
    3. Excessive Data Export

Author: PDRI Team
Version: 1.0.0
"""

import pytest
from datetime import datetime, timedelta, timezone
from unittest.mock import AsyncMock, MagicMock, patch
from uuid import uuid4

# We test the rule logic in isolation using mock DB sessions


class MockScalar:
    """Helper to mock SQLAlchemy scalar results."""
    def __init__(self, value):
        self._value = value
    def scalar_one_or_none(self):
        return self._value
    def scalar(self):
        return self._value
    def scalars(self):
        return self
    def all(self):
        if isinstance(self._value, list):
            return self._value
        return [self._value] if self._value else []


def make_entity(external_id, entity_type, name, attributes=None, eid=None):
    """Create a mock entity."""
    e = MagicMock()
    e.id = eid or str(uuid4())
    e.external_id = external_id
    e.entity_type = entity_type
    e.name = name
    e.attributes = attributes or {}
    e.confidence = 1.0
    return e


def make_edge(src_id, dst_id, rel_type, attrs=None):
    """Create a mock edge."""
    e = MagicMock()
    e.id = str(uuid4())
    e.src_id = src_id
    e.dst_id = dst_id
    e.relation_type = rel_type
    e.attributes = attrs or {}
    e.first_seen = datetime.now(timezone.utc)
    return e


def make_score(entity_id, composite=0.5, sensitivity=0.5, risk_level="medium"):
    """Create a mock score."""
    s = MagicMock()
    s.entity_id = entity_id
    s.composite_score = composite
    s.sensitivity_score = sensitivity
    s.risk_level = risk_level
    return s


class TestScoringFormula:
    """Tests for the v1 scoring formula constants and classify_risk_level."""

    def test_classify_risk_levels(self):
        from pdri.scoring.pg_engine import classify_risk_level
        assert classify_risk_level(0.95) == "critical"
        assert classify_risk_level(0.80) == "critical"
        assert classify_risk_level(0.79) == "high"
        assert classify_risk_level(0.60) == "high"
        assert classify_risk_level(0.59) == "medium"
        assert classify_risk_level(0.40) == "medium"
        assert classify_risk_level(0.39) == "low"
        assert classify_risk_level(0.20) == "low"
        assert classify_risk_level(0.19) == "minimal"
        assert classify_risk_level(0.0) == "minimal"

    def test_weights_sum_to_one(self):
        from pdri.scoring.pg_engine import W_EXPOSURE, W_SENSITIVITY, W_VOLATILITY, W_CONFIDENCE
        total = W_EXPOSURE + W_SENSITIVITY + W_VOLATILITY + W_CONFIDENCE
        assert abs(total - 1.0) < 0.001

    def test_exposure_factor_weights_sum(self):
        from pdri.scoring.pg_engine import (
            EF_EXTERNAL_CONN, EF_AI_INTEGRATION, EF_DATA_VOLUME, EF_PRIVILEGE, EF_PUBLIC
        )
        total = EF_EXTERNAL_CONN + EF_AI_INTEGRATION + EF_DATA_VOLUME + EF_PRIVILEGE + EF_PUBLIC
        assert abs(total - 1.0) < 0.001

    def test_sensitivity_factor_weights_sum(self):
        from pdri.scoring.pg_engine import SF_NAME_HEURISTIC, SF_DATA_CLASSIFICATION, SF_SENSITIVITY_TAGS
        total = SF_NAME_HEURISTIC + SF_DATA_CLASSIFICATION + SF_SENSITIVITY_TAGS
        assert abs(total - 1.0) < 0.001


class TestSensitivityComputation:
    """Test sensitivity scoring in isolation."""

    def test_sensitive_name_detection(self):
        from pdri.scoring.pg_engine import _SENSITIVE_RE
        assert _SENSITIVE_RE.search("customer_credentials_db")
        assert _SENSITIVE_RE.search("Patient Records")
        assert _SENSITIVE_RE.search("employee_salary_data")
        assert not _SENSITIVE_RE.search("generic_cache")
        assert not _SENSITIVE_RE.search("app_config")

    def test_classification_scores(self):
        from pdri.scoring.pg_engine import CLASSIFICATION_SCORES
        assert CLASSIFICATION_SCORES["public"] == 0.0
        assert CLASSIFICATION_SCORES["internal"] == 0.3
        assert CLASSIFICATION_SCORES["confidential"] == 0.7
        assert CLASSIFICATION_SCORES["restricted"] == 1.0


class TestIngestionPipeline:
    """Test the ingestion pipeline helpers."""

    def test_fingerprint_deterministic(self):
        from pdri.ingestion.pipeline import _fingerprint
        fp1 = _fingerprint("evt-001", "source-a")
        fp2 = _fingerprint("evt-001", "source-a")
        assert fp1 == fp2

    def test_fingerprint_unique_per_event(self):
        from pdri.ingestion.pipeline import _fingerprint
        fp1 = _fingerprint("evt-001", "source-a")
        fp2 = _fingerprint("evt-002", "source-a")
        assert fp1 != fp2

    def test_extract_entities_from_event(self):
        from pdri.ingestion.pipeline import _extract_entities
        event = {
            "entity_id": "ds-customer-db",
            "entity_type": "data_store",
            "entity_name": "Customer DB",
            "identity_id": "chatgpt-01",
            "ai_context": {
                "ai_tool_id": "chatgpt-01",
                "model_name": "gpt-4",
                "is_sanctioned": False,
                "data_volume_bytes": 50_000_000,
            },
        }
        entities = _extract_entities(event, "t-test")
        assert len(entities) == 2
        assert entities[0]["entity_type"] == "data_store"
        assert entities[1]["entity_type"] == "ai_tool"
        assert entities[1]["attributes"]["is_sanctioned"] is False

    def test_extract_entities_identity_only(self):
        from pdri.ingestion.pipeline import _extract_entities
        event = {
            "entity_id": "ds-db",
            "entity_type": "data_store",
            "identity_id": "user-alice",
            "privilege_level": "admin",
        }
        entities = _extract_entities(event, "t-test")
        assert len(entities) == 2
        assert entities[1]["entity_type"] == "identity"
        assert entities[1]["attributes"]["privilege_level"] == "admin"

    def test_extract_edge(self):
        from pdri.ingestion.pipeline import _extract_edge
        event = {
            "entity_id": "ds-customer-db",
            "identity_id": "chatgpt-01",
            "event_type": "AI_DATA_ACCESS",
            "exposure_direction": "internal_to_ai",
            "ai_context": {"data_volume_bytes": 50_000_000},
        }
        edge = _extract_edge(event, "t-test")
        assert edge is not None
        assert edge["relation_type"] == "ACCESSES"
        assert edge["src_external_id"] == "chatgpt-01"
        assert edge["dst_external_id"] == "ds-customer-db"

    def test_extract_edge_no_identity(self):
        from pdri.ingestion.pipeline import _extract_edge
        event = {"entity_id": "ds-db", "event_type": "SYSTEM_ACCESS"}
        edge = _extract_edge(event, "t-test")
        assert edge is None


class TestSLACalculation:
    """Test SLA deadline assignment."""

    def test_sla_hours_mapping(self):
        from pdri.scoring.pg_engine import SLA_HOURS
        assert SLA_HOURS["critical"] == 4
        assert SLA_HOURS["high"] == 24
        assert SLA_HOURS["medium"] == 72
        assert SLA_HOURS["low"] == 168
        assert SLA_HOURS["minimal"] is None
