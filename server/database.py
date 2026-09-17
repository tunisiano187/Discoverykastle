"""
Database engine, session factory, and schema initialisation.

Schema management uses Alembic incremental migrations instead of
``Base.metadata.create_all``.  On every server startup ``init_db()`` runs
``alembic upgrade head`` so that any pending migration is applied before
the application begins serving requests.

Upgrading an existing installation that was created with ``create_all()``
(i.e. before Alembic was wired into the startup path):

    alembic stamp 0001   # mark DB as already at the initial revision
    alembic upgrade head # apply migrations 0002…

After that the server's ``init_db()`` takes over automatically.
"""

import asyncio
from pathlib import Path

from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession, async_sessionmaker
from sqlalchemy.orm import DeclarativeBase
from server.config import settings


engine = create_async_engine(settings.database_url, echo=False)
AsyncSessionLocal = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)


class Base(DeclarativeBase):
    pass


async def get_db() -> AsyncSession:
    async with AsyncSessionLocal() as session:
        try:
            yield session
        finally:
            await session.close()


def _run_alembic_upgrade() -> None:
    """
    Synchronous helper that runs ``alembic upgrade head``.

    Called inside ``asyncio.to_thread()`` so that Alembic's internal
    ``asyncio.run()`` (in ``env.py``) works correctly — it must not be
    invoked from within a running event loop.
    """
    from alembic import command as alembic_command
    from alembic.config import Config as AlembicConfig

    # alembic.ini lives one level above the server/ package
    ini_path = Path(__file__).parent.parent / "alembic.ini"
    cfg = AlembicConfig(str(ini_path))
    # Override the URL from alembic.ini with the live settings value so
    # Docker / test overrides (DKASTLE_DATABASE_URL) are respected.
    cfg.set_main_option("sqlalchemy.url", settings.database_url)
    alembic_command.upgrade(cfg, "head")


async def init_db() -> None:
    """Apply all pending Alembic migrations at server startup."""
    await asyncio.to_thread(_run_alembic_upgrade)
