"""
Alembic environment — async SQLAlchemy setup.

The database URL is read from DKASTLE_DATABASE_URL (or server.config.settings)
so migrations work both locally and inside Docker without editing alembic.ini.
"""

from __future__ import annotations

import asyncio
import os
from logging.config import fileConfig

from sqlalchemy import pool
from sqlalchemy.engine import Connection
from sqlalchemy.ext.asyncio import async_engine_from_config

from alembic import context

# ---------------------------------------------------------------------------
# Load all models so their metadata is registered on Base
# ---------------------------------------------------------------------------
# These imports must happen before target_metadata is referenced.
import server.models  # noqa: F401 — registers all ORM models

from server.database import Base

# ---------------------------------------------------------------------------
# Alembic config / logging
# ---------------------------------------------------------------------------

config = context.config

if config.config_file_name is not None:
    fileConfig(config.config_file_name)

target_metadata = Base.metadata

# Override the URL from the environment so alembic.ini values are ignored
# when DKASTLE_DATABASE_URL is set (e.g. inside Docker).
_db_url = os.environ.get("DKASTLE_DATABASE_URL") or config.get_main_option("sqlalchemy.url")
config.set_main_option("sqlalchemy.url", _db_url)


# ---------------------------------------------------------------------------
# Run migrations
# ---------------------------------------------------------------------------

def run_migrations_offline() -> None:
    """
    Run migrations without a live DB connection — outputs SQL to stdout.
    Useful for auditing or applying migrations via a DBA.
    """
    url = config.get_main_option("sqlalchemy.url")
    context.configure(
        url=url,
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
    )
    with context.begin_transaction():
        context.run_migrations()


def do_run_migrations(connection: Connection) -> None:
    context.configure(connection=connection, target_metadata=target_metadata)
    with context.begin_transaction():
        context.run_migrations()


async def run_async_migrations() -> None:
    connectable = async_engine_from_config(
        config.get_section(config.config_ini_section, {}),
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,
    )
    async with connectable.connect() as connection:
        await connection.run_sync(do_run_migrations)
    await connectable.dispose()


def run_migrations_online() -> None:
    asyncio.run(run_async_migrations())


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
