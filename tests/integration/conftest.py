"""
Integration test fixtures — require a live PostgreSQL instance.

Run integration tests with:
    INTEGRATION_TEST_DB_URL=postgresql+asyncpg://... pytest tests/integration/ -v

All tests are skipped when INTEGRATION_TEST_DB_URL is not set so that
the normal unit-test run (no PostgreSQL) is unaffected.
"""
from __future__ import annotations

import base64
import os
import subprocess
import sys

import pytest
import pytest_asyncio

# ---------------------------------------------------------------------------
# Skip the whole module if no integration DB is configured.
# ---------------------------------------------------------------------------
_INTEGRATION_DB = os.environ.get("INTEGRATION_TEST_DB_URL")
if not _INTEGRATION_DB:
    pytest.skip(
        "INTEGRATION_TEST_DB_URL not set — skipping integration tests",
        allow_module_level=True,
    )

# ---------------------------------------------------------------------------
# Undo the asyncpg stub injected by tests/conftest.py so the real driver
# is used.  Server modules must also be cleared so they re-import cleanly.
# ---------------------------------------------------------------------------
for _mod in [k for k in sys.modules if "asyncpg" in k or "server.database" in k]:
    del sys.modules[_mod]

# ---------------------------------------------------------------------------
# Configure the server BEFORE any server module is imported.
# ---------------------------------------------------------------------------
os.environ["DKASTLE_DATABASE_URL"] = _INTEGRATION_DB
os.environ.setdefault("DKASTLE_SECRET_KEY", "it-secret-key-integration-tests-32ch!")
# 32 random bytes encoded as base64 (safe dummy value for tests)
os.environ.setdefault(
    "DKASTLE_VAULT_KEY",
    base64.b64encode(b"\xde\xad\xbe\xef" * 8).decode(),
)
os.environ.setdefault("DKASTLE_ADMIN_USERNAME", "admin")
os.environ.setdefault("DKASTLE_ADMIN_PASSWORD", "it-admin-pass!")

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture(scope="session", autouse=True)
def apply_migrations():
    """Run alembic upgrade head against the integration test database."""
    result = subprocess.run(
        ["alembic", "upgrade", "head"],
        env=os.environ,
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        pytest.fail(
            f"alembic upgrade failed:\nSTDOUT:\n{result.stdout}\nSTDERR:\n{result.stderr}"
        )


@pytest_asyncio.fixture(scope="session", autouse=True)
async def seed_fixture_users(engine, apply_migrations):
    """Seed the synthetic JWT users into the DB so /me returns correct roles."""
    from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

    from server.models.user import User
    from server.services.auth import hash_password

    Session = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
    async with Session() as session:
        for username, role in [
            ("it-operator", "operator"),
            ("it-admin", "admin"),
            ("it-viewer", "viewer"),
        ]:
            user = User(
                username=username,
                email=f"{username}@test.local",
                password_hash=hash_password("it-fixture-user-sentinel"),
                role=role,
                is_active=True,
            )
            session.add(user)
        await session.commit()


@pytest_asyncio.fixture(scope="session")
async def engine():
    from sqlalchemy.ext.asyncio import create_async_engine

    eng = create_async_engine(_INTEGRATION_DB, echo=False, future=True)
    yield eng
    await eng.dispose()


@pytest_asyncio.fixture
async def db(engine):
    """Per-test async session that rolls back after each test."""
    from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

    Session = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
    async with Session() as session:
        yield session
        await session.rollback()


@pytest.fixture(scope="session")
def secret_key() -> str:
    return os.environ["DKASTLE_SECRET_KEY"]


@pytest.fixture(scope="session")
def operator_token(secret_key: str) -> str:
    from server.services.auth import create_access_token

    return create_access_token("it-operator", "operator", secret_key, expire_minutes=120)


@pytest.fixture(scope="session")
def admin_token(secret_key: str) -> str:
    from server.services.auth import create_access_token

    return create_access_token("it-admin", "admin", secret_key, expire_minutes=120)


@pytest.fixture(scope="session")
def viewer_token(secret_key: str) -> str:
    from server.services.auth import create_access_token

    return create_access_token("it-viewer", "viewer", secret_key, expire_minutes=120)


def _build_test_app():
    """Minimal FastAPI app with real DB wiring (no lifespan side-effects)."""
    from fastapi import FastAPI
    from server.api.auth_api import router as auth_router
    from server.api.inventory import router as inventory_router
    from server.api.vault import router as vault_router

    app = FastAPI()
    app.include_router(auth_router)
    app.include_router(inventory_router)
    app.include_router(vault_router)
    return app


_APP = None


@pytest.fixture(scope="session")
def test_app():
    global _APP
    if _APP is None:
        _APP = _build_test_app()
    return _APP


@pytest_asyncio.fixture
async def client(test_app):
    import httpx

    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=test_app),
        base_url="http://testserver",
    ) as c:
        yield c


@pytest.fixture
def auth_headers(operator_token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {operator_token}"}


@pytest.fixture
def admin_headers(admin_token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {admin_token}"}
