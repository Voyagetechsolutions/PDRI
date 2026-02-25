"""
PDRI Database Layer
====================

PostgreSQL database layer using SQLAlchemy 2.0 async.

This module provides:
    - Async database session management
    - Base model class for all database entities
    - Connection pooling and lifecycle management

Usage:
    from pdri.db import get_db, AsyncSession

    async def my_endpoint(db: AsyncSession = Depends(get_db)):
        result = await db.execute(select(Finding))
        ...

Author: PDRI Team
Version: 1.0.0
"""

from pdri.db.session import (
    engine,
    async_session_factory,
    get_db,
    init_db,
    close_db,
    AsyncSession,
)
from pdri.db.base import Base

__all__ = [
    "engine",
    "async_session_factory",
    "get_db",
    "init_db",
    "close_db",
    "AsyncSession",
    "Base",
]
