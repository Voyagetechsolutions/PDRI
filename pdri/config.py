"""
PDRI Configuration Module
=========================

Centralized configuration management using Pydantic Settings.

Loads configuration from:
    1. Environment variables
    2. .env file (if present)
    3. Default values

Usage:
    from pdri.config import settings
    
    print(settings.neo4j_uri)
    print(settings.kafka_bootstrap_servers)

Author: PDRI Team
Version: 1.0.0
"""

from functools import lru_cache
from typing import List
from pydantic_settings import BaseSettings, SettingsConfigDict
from pydantic import Field


class Settings(BaseSettings):
    """
    Application settings loaded from environment variables.
    
    All settings can be overridden via environment variables.
    Naming convention: UPPER_SNAKE_CASE in env, lower_snake_case in code.
    """
    
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
    )
    
    # =========================================================================
    # Application Settings
    # =========================================================================
    
    app_name: str = Field(default="PDRI", description="Application name")
    app_version: str = Field(default="1.0.0", description="Application version")
    debug: bool = Field(default=False, description="Debug mode")
    log_level: str = Field(default="INFO", description="Logging level")
    
    # =========================================================================
    # API Server
    # =========================================================================
    
    api_host: str = Field(default="0.0.0.0", description="API server host")
    api_port: int = Field(default=8000, description="API server port")
    
    # =========================================================================
    # PostgreSQL
    # =========================================================================
    
    postgres_host: str = Field(default="localhost", description="PostgreSQL host")
    postgres_port: int = Field(default=5432, description="PostgreSQL port")
    postgres_db: str = Field(default="pdri", description="PostgreSQL database")
    postgres_user: str = Field(default="pdri_user", description="PostgreSQL user")
    postgres_password: str = Field(
        default="pdri_secure_password_change_me",
        description="PostgreSQL password"
    )
    
    @property
    def postgres_dsn(self) -> str:
        """Get PostgreSQL connection string."""
        return (
            f"postgresql://{self.postgres_user}:{self.postgres_password}"
            f"@{self.postgres_host}:{self.postgres_port}/{self.postgres_db}"
        )
    
    @property
    def postgres_async_dsn(self) -> str:
        """Get async PostgreSQL connection string for asyncpg."""
        return (
            f"postgresql+asyncpg://{self.postgres_user}:{self.postgres_password}"
            f"@{self.postgres_host}:{self.postgres_port}/{self.postgres_db}"
        )
    
    # =========================================================================
    # Neo4j
    # =========================================================================
    
    neo4j_uri: str = Field(
        default="bolt://localhost:7687",
        description="Neo4j Bolt URI"
    )
    neo4j_user: str = Field(default="neo4j", description="Neo4j username")
    neo4j_password: str = Field(
        default="neo4j_secure_password_change_me",
        description="Neo4j password"
    )
    
    # =========================================================================
    # Kafka
    # =========================================================================
    
    kafka_bootstrap_servers: str = Field(
        default="localhost:9092",
        description="Kafka bootstrap servers (comma-separated)"
    )
    kafka_security_events_topic: str = Field(
        default="security-events",
        description="Kafka topic for security events"
    )
    kafka_consumer_group: str = Field(
        default="pdri-consumers",
        description="Kafka consumer group ID"
    )
    
    @property
    def kafka_servers_list(self) -> List[str]:
        """Get Kafka servers as a list."""
        return [s.strip() for s in self.kafka_bootstrap_servers.split(",")]
    
    # =========================================================================
    # Integration Services
    # =========================================================================
    
    shadow_ai_enabled: bool = Field(
        default=False,
        description="Whether Shadow AI integration is enabled"
    )
    shadow_ai_api_url: str = Field(
        default="http://localhost:8001",
        description="Shadow AI API URL"
    )
    
    dmitry_enabled: bool = Field(
        default=False,
        description="Whether Dmitry integration is enabled"
    )
    dmitry_api_url: str = Field(
        default="http://localhost:8002",
        description="Dmitry API URL"
    )
    
    # =========================================================================
    # Risk Scoring Weights
    # =========================================================================
    
    score_weight_external_connections: float = Field(
        default=0.25,
        ge=0.0,
        le=1.0,
        description="Weight for external connection factor"
    )
    score_weight_ai_integrations: float = Field(
        default=0.30,
        ge=0.0,
        le=1.0,
        description="Weight for AI integration factor"
    )
    score_weight_data_volume: float = Field(
        default=0.20,
        ge=0.0,
        le=1.0,
        description="Weight for data volume factor"
    )
    score_weight_privilege_level: float = Field(
        default=0.15,
        ge=0.0,
        le=1.0,
        description="Weight for privilege level factor"
    )
    score_weight_sensitivity: float = Field(
        default=0.10,
        ge=0.0,
        le=1.0,
        description="Weight for sensitivity factor"
    )
    
    # =========================================================================
    # Trajectory Settings
    # =========================================================================
    
    trajectory_window_short: int = Field(
        default=7,
        description="Short trajectory window (days)"
    )
    trajectory_window_medium: int = Field(
        default=30,
        description="Medium trajectory window (days)"
    )
    trajectory_window_long: int = Field(
        default=90,
        description="Long trajectory window (days)"
    )


@lru_cache()
def get_settings() -> Settings:
    """
    Get cached application settings.
    
    Uses LRU cache to ensure settings are loaded only once.
    
    Returns:
        Settings instance
    """
    return Settings()


# Convenience alias
settings = get_settings()
