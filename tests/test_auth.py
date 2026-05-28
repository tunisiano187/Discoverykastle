"""Tests for the JWT authentication helpers."""

from __future__ import annotations

import pytest
from fastapi import HTTPException

from server.services.auth import (
    create_access_token,
    decode_token,
    hash_password,
    verify_password,
)

_SECRET = "test-secret-key-for-unit-tests-only"


class TestPasswordHashing:
    def test_hash_and_verify(self) -> None:
        hashed = hash_password("mysecret")
        assert verify_password("mysecret", hashed)

    def test_wrong_password_fails(self) -> None:
        hashed = hash_password("correct")
        assert not verify_password("wrong", hashed)

    def test_hash_is_not_plaintext(self) -> None:
        hashed = hash_password("plaintext")
        assert hashed != "plaintext"
        assert hashed.startswith("$")


class TestJWTTokens:
    def test_create_and_decode(self) -> None:
        token = create_access_token("alice", "admin", _SECRET, expire_minutes=60)
        sub, role = decode_token(token, _SECRET)
        assert sub == "alice"
        assert role == "admin"

    def test_role_preserved(self) -> None:
        token = create_access_token("bob", "viewer", _SECRET, expire_minutes=60)
        _, role = decode_token(token, _SECRET)
        assert role == "viewer"

    def test_legacy_token_defaults_to_admin(self) -> None:
        """Tokens without a role claim (pre-RBAC) are treated as admin."""
        from jose import jwt
        from datetime import datetime, timedelta, timezone

        payload = {
            "sub": "legacy-user",
            "iat": datetime.now(tz=timezone.utc),
            "exp": datetime.now(tz=timezone.utc) + timedelta(hours=1),
        }
        token = jwt.encode(payload, _SECRET, algorithm="HS256")
        sub, role = decode_token(token, _SECRET)
        assert sub == "legacy-user"
        assert role == "admin"

    def test_expired_token_raises(self) -> None:
        from unittest.mock import patch
        from datetime import datetime, timezone

        past = datetime(2000, 1, 1, tzinfo=timezone.utc)
        with patch("server.services.auth.datetime") as mock_dt:
            mock_dt.now.return_value = past
            token = create_access_token("carol", "viewer", _SECRET, expire_minutes=60)

        with pytest.raises(HTTPException) as exc_info:
            decode_token(token, _SECRET)
        assert exc_info.value.status_code == 401

    def test_wrong_secret_raises(self) -> None:
        token = create_access_token("dave", "operator", _SECRET, expire_minutes=60)
        with pytest.raises(HTTPException) as exc_info:
            decode_token(token, "wrong-secret")
        assert exc_info.value.status_code == 401

    def test_tampered_token_raises(self) -> None:
        token = create_access_token("eve", "analyst", _SECRET, expire_minutes=60)
        tampered = token[:-5] + "XXXXX"
        with pytest.raises(HTTPException):
            decode_token(tampered, _SECRET)
