"""
SQLAlchemy Base Model
=====================

Declarative base for all PDRI database models.

Author: PDRI Team
Version: 1.0.0
"""

from datetime import datetime, timezone
from typing import Any
from uuid import uuid4

from sqlalchemy import DateTime, String, func
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


def generate_uuid() -> str:
    """Generate a UUID string."""
    return str(uuid4())


def utc_now() -> datetime:
    """Get current UTC datetime."""
    return datetime.now(timezone.utc)


class Base(DeclarativeBase):
    """
    Base class for all PDRI database models.

    Provides:
        - Automatic table name generation from class name
        - Common timestamp fields (created_at, updated_at)
        - JSON serialization support
    """

    # Type annotation mapping for Pydantic compatibility
    type_annotation_map = {
        datetime: DateTime(timezone=True),
    }

    def to_dict(self) -> dict[str, Any]:
        """Convert model to dictionary."""
        return {
            column.name: getattr(self, column.name)
            for column in self.__table__.columns
        }


class TimestampMixin:
    """Mixin providing created_at and updated_at timestamps."""

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=utc_now,
        server_default=func.now(),
        nullable=False,
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=utc_now,
        onupdate=utc_now,
        server_default=func.now(),
        nullable=False,
    )
