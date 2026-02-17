"""
Secrets Manager
===============

Centralized secrets management with multiple provider backends.

Providers:
    - env: Environment variables (default)
    - file: File-based secrets (e.g., Docker secrets at /run/secrets/)
    - vault: HashiCorp Vault (requires hvac package)

Author: PDRI Team
Version: 1.0.0
"""

import logging
import os
from abc import ABC, abstractmethod
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)


class SecretProvider(ABC):
    """Abstract base class for secret providers."""

    @abstractmethod
    def get(self, key: str, default: Optional[str] = None) -> Optional[str]:
        """Retrieve a secret value by key."""
        ...

    @abstractmethod
    def has(self, key: str) -> bool:
        """Check if a secret exists."""
        ...


class EnvSecretProvider(SecretProvider):
    """Load secrets from environment variables."""

    def get(self, key: str, default: Optional[str] = None) -> Optional[str]:
        return os.environ.get(key, default)

    def has(self, key: str) -> bool:
        return key in os.environ


class FileSecretProvider(SecretProvider):
    """Load secrets from files (e.g., Docker/K8s mounted secrets)."""

    def __init__(self, secrets_dir: str = "/run/secrets"):
        self._dir = secrets_dir

    def get(self, key: str, default: Optional[str] = None) -> Optional[str]:
        path = os.path.join(self._dir, key)
        try:
            with open(path, "r") as f:
                return f.read().strip()
        except FileNotFoundError:
            return default

    def has(self, key: str) -> bool:
        return os.path.isfile(os.path.join(self._dir, key))


class VaultSecretProvider(SecretProvider):
    """Load secrets from HashiCorp Vault."""

    def __init__(self, vault_url: str, token: Optional[str] = None, mount: str = "secret"):
        self._url = vault_url
        self._mount = mount
        self._client = None
        self._cache: Dict[str, str] = {}

        try:
            import hvac
            self._client = hvac.Client(
                url=vault_url,
                token=token or os.environ.get("VAULT_TOKEN", ""),
            )
            if self._client.is_authenticated():
                logger.info("Connected to HashiCorp Vault")
            else:
                logger.warning("Vault authentication failed, falling back to cache-only")
                self._client = None
        except ImportError:
            logger.warning("hvac package not installed, Vault provider unavailable")

    def get(self, key: str, default: Optional[str] = None) -> Optional[str]:
        if key in self._cache:
            return self._cache[key]

        if not self._client:
            return default

        try:
            response = self._client.secrets.kv.v2.read_secret_version(
                path=key, mount_point=self._mount
            )
            value = response["data"]["data"].get("value", default)
            self._cache[key] = value
            return value
        except Exception as e:
            logger.warning(f"Vault read failed for {key}: {e}")
            return default

    def has(self, key: str) -> bool:
        return self.get(key) is not None


class SecretManager:
    """
    Centralized secrets manager.

    Usage:
        manager = SecretManager(provider="env")
        db_password = manager.get("POSTGRES_PASSWORD")
        manager.validate_required(["JWT_SECRET_KEY", "POSTGRES_PASSWORD"])
    """

    REQUIRED_SECRETS: List[str] = [
        "POSTGRES_PASSWORD",
        "NEO4J_PASSWORD",
        "JWT_SECRET_KEY",
    ]

    def __init__(self, provider: str = "env", **kwargs: Any):
        self._provider_name = provider
        if provider == "file":
            self._provider = FileSecretProvider(
                secrets_dir=kwargs.get("secrets_dir", "/run/secrets")
            )
        elif provider == "vault":
            self._provider = VaultSecretProvider(
                vault_url=kwargs.get("vault_url", ""),
                token=kwargs.get("vault_token"),
                mount=kwargs.get("vault_mount", "secret"),
            )
        else:
            self._provider = EnvSecretProvider()

    def get(self, key: str, default: Optional[str] = None) -> Optional[str]:
        """Get a secret, returning default if not found."""
        return self._provider.get(key, default)

    def get_required(self, key: str) -> str:
        """Get a secret, raising ValueError if not found."""
        value = self._provider.get(key)
        if value is None:
            raise ValueError(f"Required secret '{key}' not found in {self._provider_name} provider")
        return value

    def has(self, key: str) -> bool:
        """Check if a secret exists."""
        return self._provider.has(key)

    def validate_required(self, keys: Optional[List[str]] = None) -> Dict[str, bool]:
        """
        Validate that all required secrets exist.

        Returns dict of key -> found status.
        Logs warnings for missing secrets.
        """
        check_keys = keys or self.REQUIRED_SECRETS
        results = {}
        for key in check_keys:
            found = self.has(key)
            results[key] = found
            if not found:
                logger.warning(f"Required secret '{key}' not found")
        return results

    @staticmethod
    def mask(value: str, show_chars: int = 4) -> str:
        """Mask a secret value for safe logging."""
        if not value or len(value) <= show_chars:
            return "****"
        return value[:show_chars] + "*" * (len(value) - show_chars)

    def __repr__(self) -> str:
        return f"SecretManager(provider={self._provider_name!r})"
