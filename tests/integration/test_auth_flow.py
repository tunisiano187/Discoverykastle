"""
Integration tests — authentication flows.

Tests cover login, JWT validation, /me endpoint, and token refresh against
a real PostgreSQL database.
"""
from __future__ import annotations

import pytest


@pytest.fixture(scope="module", autouse=True)
async def seed_user(engine):
    """Insert a known test user once per module, delete on teardown."""
    from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker
    from sqlalchemy import text
    from server.models.user import User
    from server.services.auth import hash_password

    Session = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
    async with Session() as session:
        user = User(
            username="it-login-user",
            email="it@test.local",
            password_hash=hash_password("it-auth-value-correct"),
            role="operator",
            is_active=True,
        )
        session.add(user)
        await session.commit()

    yield

    async with Session() as session:
        await session.execute(
            text("DELETE FROM users WHERE username = 'it-login-user'")
        )
        await session.commit()


class TestLogin:
    @pytest.mark.asyncio
    async def test_login_valid_credentials(self, client):
        resp = await client.post(
            "/api/v1/auth/login",
            json={"username": "it-login-user", "password": "it-auth-value-correct"},
        )
        assert resp.status_code == 200
        body = resp.json()
        assert "access_token" in body
        assert body["token_type"] == "bearer"
        assert body["access_token"]

    @pytest.mark.asyncio
    async def test_login_wrong_password(self, client):
        resp = await client.post(
            "/api/v1/auth/login",
            json={"username": "it-login-user", "password": "wrong-password"},
        )
        assert resp.status_code == 401

    @pytest.mark.asyncio
    async def test_login_nonexistent_user(self, client):
        resp = await client.post(
            "/api/v1/auth/login",
            json={"username": "nobody", "password": "irrelevant"},
        )
        assert resp.status_code == 401

    @pytest.mark.asyncio
    async def test_login_inactive_user(self, client, engine):
        from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker
        from sqlalchemy import text
        from server.models.user import User
        from server.services.auth import hash_password

        Session = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
        async with Session() as session:
            user = User(
                username="it-inactive-user",
                password_hash=hash_password("it-auth-value-inactive"),
                role="viewer",
                is_active=False,
            )
            session.add(user)
            await session.commit()

        try:
            resp = await client.post(
                "/api/v1/auth/login",
                json={
                    "username": "it-inactive-user",
                    "password": "it-auth-value-inactive",  # gitguardian:ignore
                },
            )
            assert resp.status_code == 401
        finally:
            async with Session() as session:
                await session.execute(
                    text("DELETE FROM users WHERE username = 'it-inactive-user'")
                )
                await session.commit()


class TestMe:
    @pytest.mark.asyncio
    async def test_get_me_with_valid_token(self, client, operator_token):
        resp = await client.get(
            "/api/v1/auth/me",
            headers={"Authorization": f"Bearer {operator_token}"},
        )
        assert resp.status_code == 200
        body = resp.json()
        assert body["username"] == "it-operator"
        assert body["role"] == "operator"

    @pytest.mark.asyncio
    async def test_get_me_requires_auth(self, client):
        resp = await client.get("/api/v1/auth/me")
        assert resp.status_code == 401

    @pytest.mark.asyncio
    async def test_get_me_with_garbage_token(self, client):
        resp = await client.get(
            "/api/v1/auth/me",
            headers={"Authorization": "Bearer not-a-valid-jwt"},
        )
        assert resp.status_code == 401


class TestTokenRefresh:
    @pytest.mark.asyncio
    async def test_refresh_returns_new_token(self, client, operator_token):
        resp = await client.post(
            "/api/v1/auth/refresh",
            headers={"Authorization": f"Bearer {operator_token}"},
        )
        assert resp.status_code == 200
        body = resp.json()
        assert "access_token" in body
        assert body["access_token"]
