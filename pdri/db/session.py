"""
Database Session Management
===========================

Async SQLAlchemy session factory and dependency injection.

Author: PDRI Team
Version: 1.0.0
"""

import logging
from typing import AsyncGenerator

from sqlalchemy.ext.asyncio import (
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)
from sqlalchemy.pool import NullPool

from pdri.config import settings

logger = logging.getLogger(__name__)

# Create async engine with connection pooling
engine = create_async_engine(
    settings.postgres_async_dsn,
    echo=settings.debug,
    pool_pre_ping=True,
    # Use NullPool for serverless/container environments
    # poolclass=NullPool,
)

# Session factory
async_session_factory = async_sessionmaker(
    engine,
    class_=AsyncSession,
    expire_on_commit=False,
    autocommit=False,
    autoflush=False,
)


async def get_db() -> AsyncGenerator[AsyncSession, None]:
    """
    Dependency that provides a database session.

    Usage:
        @app.get("/items")
        async def get_items(db: AsyncSession = Depends(get_db)):
            ...

    Yields:
        AsyncSession: Database session that auto-closes
    """
    async with async_session_factory() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise
        finally:
            await session.close()


async def init_db() -> None:
    """
    Initialize database connection.

    Called during application startup.
    """
    logger.info("Initializing PostgreSQL connection...")

    # Test connection
    async with engine.begin() as conn:
        await conn.run_sync(lambda _: None)

    logger.info("PostgreSQL connection established")


async def close_db() -> None:
    """
    Close database connections.

    Called during application shutdown.
    """
    logger.info("Closing PostgreSQL connections...")
    await engine.dispose()
    logger.info("PostgreSQL connections closed")


# Re-export for convenience
__all__ = [
    "engine",
    "async_session_factory",
    "get_db",
    "init_db",
    "close_db",
    "AsyncSession",
]
