"""
Unit tests for RBAC: role hierarchy, dependency enforcement, user CRUD API.
No database required — DB calls are mocked.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any
from unittest.mock import MagicMock, patch

import pytest
from fastapi import HTTPException

from server.models.user import ROLES, User
from server.services.auth import (
    _ROLE_RANK,
    hash_password,
    require_min_role,
    verify_password,
)

_SECRET = "rbac-test-secret-key-only"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_token(username: str, role: str, expire_minutes: int = 60) -> str:
    from server.services.auth import create_access_token
    return create_access_token(username, role, _SECRET, expire_minutes=expire_minutes)


def _make_credentials(token: str):
    cred = MagicMock()
    cred.credentials = token
    return cred


# ---------------------------------------------------------------------------
# Role hierarchy — pure logic, no HTTP or JWT needed
# ---------------------------------------------------------------------------


class TestRoleHierarchy:
    def test_roles_list_complete(self) -> None:
        assert set(ROLES) == {"viewer", "analyst", "operator", "admin"}

    def test_rank_ordering(self) -> None:
        assert _ROLE_RANK["viewer"] < _ROLE_RANK["analyst"]
        assert _ROLE_RANK["analyst"] < _ROLE_RANK["operator"]
        assert _ROLE_RANK["operator"] < _ROLE_RANK["admin"]

    def test_decode_returns_correct_role(self) -> None:
        from server.services.auth import create_access_token, decode_token

        for role in ROLES:
            token = create_access_token("u", role, _SECRET, expire_minutes=60)
            _, decoded_role = decode_token(token, _SECRET)
            assert decoded_role == role

    def test_all_roles_in_rank_table(self) -> None:
        for role in ROLES:
            assert role in _ROLE_RANK

    def test_unknown_role_not_in_table(self) -> None:
        assert "superuser" not in _ROLE_RANK


# ---------------------------------------------------------------------------
# require_min_role dependency — patch decode_token so we control (user, role)
# without needing a real JWT secret in settings
# ---------------------------------------------------------------------------


class TestRequireMinRole:
    """Tests the require_min_role factory without a live HTTP stack."""

    @pytest.mark.asyncio
    async def test_admin_passes_all_roles(self) -> None:
        for min_role in ROLES:
            dep = require_min_role(min_role)
            with patch("server.services.auth.decode_token", return_value=("alice", "admin")):
                result = await dep(_make_credentials("fake-token"))
            assert result == "alice"

    @pytest.mark.asyncio
    async def test_viewer_fails_analyst_gate(self) -> None:
        dep = require_min_role("analyst")
        with patch("server.services.auth.decode_token", return_value=("bob", "viewer")):
            with pytest.raises(HTTPException) as exc:
                await dep(_make_credentials("fake-token"))
        assert exc.value.status_code == 403

    @pytest.mark.asyncio
    async def test_operator_passes_operator_gate(self) -> None:
        dep = require_min_role("operator")
        with patch("server.services.auth.decode_token", return_value=("carol", "operator")):
            result = await dep(_make_credentials("fake-token"))
        assert result == "carol"

    @pytest.mark.asyncio
    async def test_operator_fails_admin_gate(self) -> None:
        dep = require_min_role("admin")
        with patch("server.services.auth.decode_token", return_value=("dave", "operator")):
            with pytest.raises(HTTPException) as exc:
                await dep(_make_credentials("fake-token"))
        assert exc.value.status_code == 403

    @pytest.mark.asyncio
    async def test_missing_credentials_raises_401(self) -> None:
        dep = require_min_role("viewer")
        with pytest.raises(HTTPException) as exc:
            await dep(None)
        assert exc.value.status_code == 401

    @pytest.mark.asyncio
    async def test_analyst_passes_viewer_gate(self) -> None:
        dep = require_min_role("viewer")
        with patch("server.services.auth.decode_token", return_value=("eve", "analyst")):
            result = await dep(_make_credentials("fake-token"))
        assert result == "eve"

    @pytest.mark.asyncio
    async def test_viewer_passes_viewer_gate(self) -> None:
        dep = require_min_role("viewer")
        with patch("server.services.auth.decode_token", return_value=("frank", "viewer")):
            result = await dep(_make_credentials("fake-token"))
        assert result == "frank"


# ---------------------------------------------------------------------------
# User CRUD API (mocked DB)
# ---------------------------------------------------------------------------


def _make_db_user(
    username: str = "alice",
    role: str = "viewer",
    user_id: uuid.UUID | None = None,
) -> User:
    u = MagicMock(spec=User)
    u.id = user_id or uuid.uuid4()
    u.username = username
    u.email = None
    u.password_hash = hash_password("secret")
    u.role = role
    u.is_active = True
    u.last_login = None
    u.created_at = datetime(2026, 1, 1)
    u.updated_at = datetime(2026, 1, 1)
    return u


class TestUsersAPI:
    """Tests for the /api/v1/users endpoints using mocked DB sessions."""

    @pytest.mark.asyncio
    async def test_create_user_hashes_password(self) -> None:
        """Password stored in DB is hashed, not plain text."""
        created_users: list[Any] = []

        class _FakeSession:
            def add(self, obj: Any) -> None:
                created_users.append(obj)

            async def execute(self, stmt: Any) -> Any:
                mock = MagicMock()
                mock.scalar_one_or_none.return_value = None
                return mock

            async def commit(self) -> None:
                pass

            async def refresh(self, obj: Any) -> None:
                pass

        from server.api.users import UserCreate, create_user

        body = UserCreate(username="newuser", password="plaintext-test-value", role="analyst")
        await create_user(body, "superadmin", _FakeSession())  # type: ignore[arg-type]
        assert len(created_users) == 1
        stored_user = created_users[0]
        assert stored_user.password_hash != "plaintext-test-value"
        assert verify_password("plaintext-test-value", stored_user.password_hash)

    @pytest.mark.asyncio
    async def test_create_user_duplicate_raises_409(self) -> None:
        from server.api.users import UserCreate, create_user

        class _FakeSession:
            async def execute(self, stmt: Any) -> Any:
                existing = _make_db_user("alice")
                mock = MagicMock()
                mock.scalar_one_or_none.return_value = existing
                return mock

        body = UserCreate(username="alice", password="pw", role="viewer")
        with pytest.raises(HTTPException) as exc:
            await create_user(body, "superadmin", _FakeSession())  # type: ignore[arg-type]
        assert exc.value.status_code == 409

    @pytest.mark.asyncio
    async def test_delete_own_account_raises_400(self) -> None:
        from server.api.users import delete_user

        uid = uuid.uuid4()
        existing = _make_db_user("superadmin", "admin", uid)

        class _FakeSession:
            async def execute(self, stmt: Any) -> Any:
                mock = MagicMock()
                mock.scalar_one_or_none.return_value = existing
                return mock

        with pytest.raises(HTTPException) as exc:
            await delete_user(uid, "superadmin", _FakeSession())  # type: ignore[arg-type]
        assert exc.value.status_code == 400

    @pytest.mark.asyncio
    async def test_delete_nonexistent_user_raises_404(self) -> None:
        from server.api.users import delete_user

        class _FakeSession:
            async def execute(self, stmt: Any) -> Any:
                mock = MagicMock()
                mock.scalar_one_or_none.return_value = None
                return mock

        with pytest.raises(HTTPException) as exc:
            await delete_user(uuid.uuid4(), "superadmin", _FakeSession())  # type: ignore[arg-type]
        assert exc.value.status_code == 404


# ---------------------------------------------------------------------------
# UserCreate role validation
# ---------------------------------------------------------------------------


class TestUserCreateValidation:
    def test_valid_roles_accepted(self) -> None:
        from server.api.users import UserCreate

        for role in ROLES:
            u = UserCreate(username="x", password="p", role=role)
            assert u.role == role

    def test_invalid_role_rejected(self) -> None:
        from server.api.users import UserCreate

        with pytest.raises(Exception):
            UserCreate(username="x", password="p", role="superuser")

    def test_default_role_is_viewer(self) -> None:
        from server.api.users import UserCreate

        u = UserCreate(username="x", password="p")
        assert u.role == "viewer"
