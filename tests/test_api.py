"""
Tests for API endpoints.

Uses sys.modules mocking to avoid neo4j dependency in import chain.

Author: PDRI Team
Version: 1.0.0
"""

import sys
from unittest.mock import MagicMock

# Mock neo4j before any pdri imports can chain to it
sys.modules.setdefault("neo4j", MagicMock())

import pytest
from unittest.mock import AsyncMock, patch
from datetime import datetime, timezone


class TestAuditMiddleware:
    """Test audit middleware (standalone, no pdri.api import chain)."""

    def test_audit_store_operations(self):
        """AuditStore should store and retrieve entries."""
        # Import directly from the module file to avoid __init__.py chain
        import importlib.util
        spec = importlib.util.spec_from_file_location(
            "audit_middleware",
            r"c:\Users\bathini bona\Documents\PDRI\pdri\api\audit_middleware.py",
        )
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)

        store = mod.AuditStore(max_entries=100)
        entry = mod.AuditEntry(
            method="POST",
            path="/scoring/batch",
            client_ip="10.0.0.1",
            user_id="admin-1",
            user_role="admin",
            status_code=200,
            duration_ms=150.5,
        )
        store.add(entry)
        assert store.count == 1

        recent = store.get_recent(limit=10)
        assert len(recent) == 1
        assert recent[0]["method"] == "POST"
        assert recent[0]["user_id"] == "admin-1"

    def test_audit_entry_serialization(self):
        """AuditEntry should serialize to dict."""
        import importlib.util
        spec = importlib.util.spec_from_file_location(
            "audit_middleware",
            r"c:\Users\bathini bona\Documents\PDRI\pdri\api\audit_middleware.py",
        )
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)

        entry = mod.AuditEntry(
            method="DELETE",
            path="/nodes/node-1",
            client_ip="192.168.1.1",
        )
        data = entry.to_dict()
        assert "timestamp" in data
        assert data["method"] == "DELETE"
        assert data["path"] == "/nodes/node-1"

    def test_audit_store_rotation(self):
        """AuditStore should rotate when exceeding max entries."""
        import importlib.util
        spec = importlib.util.spec_from_file_location(
            "audit_middleware",
            r"c:\Users\bathini bona\Documents\PDRI\pdri\api\audit_middleware.py",
        )
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)

        store = mod.AuditStore(max_entries=5)
        for i in range(10):
            store.add(mod.AuditEntry(
                method="POST", path=f"/test/{i}", client_ip="10.0.0.1",
            ))
        assert store.count == 5
        recent = store.get_recent()
        assert recent[-1]["path"] == "/test/9"

    def test_audit_user_filter(self):
        """Should filter audit entries by user."""
        import importlib.util
        spec = importlib.util.spec_from_file_location(
            "audit_middleware",
            r"c:\Users\bathini bona\Documents\PDRI\pdri\api\audit_middleware.py",
        )
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)

        store = mod.AuditStore()
        store.add(mod.AuditEntry(method="POST", path="/a", client_ip="1", user_id="alice"))
        store.add(mod.AuditEntry(method="POST", path="/b", client_ip="1", user_id="bob"))
        store.add(mod.AuditEntry(method="POST", path="/c", client_ip="1", user_id="alice"))

        alice_entries = store.get_by_user("alice")
        assert len(alice_entries) == 2
        assert all(e["user_id"] == "alice" for e in alice_entries)

    def test_excluded_paths(self):
        """Health and docs paths should be excluded from audit."""
        import importlib.util
        spec = importlib.util.spec_from_file_location(
            "audit_middleware",
            r"c:\Users\bathini bona\Documents\PDRI\pdri\api\audit_middleware.py",
        )
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)

        assert "/health" in mod.EXCLUDED_PATHS
        assert "/docs" in mod.EXCLUDED_PATHS
        assert "/metrics" in mod.EXCLUDED_PATHS


class TestSecretsManager:
    """Test secrets manager functionality."""

    def test_env_provider(self):
        """EnvSecretProvider should read from environment."""
        from pdri.secrets import SecretManager

        manager = SecretManager(provider="env")
        # PATH should always exist
        assert manager.has("PATH") is True
        assert manager.get("PATH") is not None

    def test_mask_function(self):
        """mask() should hide most of the secret."""
        from pdri.secrets import SecretManager

        assert SecretManager.mask("my-secret-key") == "my-s*********"
        assert SecretManager.mask("ab") == "****"
        assert SecretManager.mask("") == "****"

    def test_validate_required(self):
        """validate_required should check existence of keys."""
        from pdri.secrets import SecretManager

        manager = SecretManager(provider="env")
        results = manager.validate_required(["PATH", "NONEXISTENT_PDRI_KEY_XYZ"])
        assert results["PATH"] is True
        assert results["NONEXISTENT_PDRI_KEY_XYZ"] is False

    def test_get_required_raises(self):
        """get_required should raise for missing secrets."""
        from pdri.secrets import SecretManager

        manager = SecretManager(provider="env")
        with pytest.raises(ValueError, match="not found"):
            manager.get_required("NONEXISTENT_PDRI_KEY_XYZ")


class TestScoringWeightsModel:
    """Test scoring weights request model."""

    def test_scoring_weights_validation(self):
        """ScoringWeightsRequest should validate weight ranges."""
        from pdri.api.routes.scoring import ScoringWeightsRequest

        req = ScoringWeightsRequest(
            external_connections=0.5,
            ai_integrations=0.8,
        )
        assert req.external_connections == 0.5
        assert req.ai_integrations == 0.8

    def test_scoring_weights_reject_out_of_range(self):
        """Weights outside [0, 1] should be rejected."""
        from pdri.api.routes.scoring import ScoringWeightsRequest
        from pydantic import ValidationError

        with pytest.raises(ValidationError):
            ScoringWeightsRequest(external_connections=1.5)

        with pytest.raises(ValidationError):
            ScoringWeightsRequest(sensitivity=-0.1)


class TestAuthModule:
    """Test auth module."""

    def test_auth_module_importable(self):
        """Auth module should be importable."""
        from pdri.api.auth import get_current_user, require_role
        assert callable(get_current_user)
        assert callable(require_role)

    def test_role_definitions(self):
        """Expected roles should be defined."""
        from pdri.api.auth import require_role

        for role in ["admin", "analyst", "viewer"]:
            dep = require_role(role)
            assert dep is not None


class TestRateLimiting:
    """Test rate limiting configuration."""

    def test_slowapi_integration(self):
        """Rate limiter flag should be importable."""
        from pdri.api.main import HAS_SLOWAPI
        assert isinstance(HAS_SLOWAPI, bool)
