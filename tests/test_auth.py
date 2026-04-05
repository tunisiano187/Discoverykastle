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
        assert hashed.startswith("$")  # passlib prefixes all hashes with $


class TestJWTTokens:
    def test_create_and_decode(self) -> None:
        token = create_access_token("alice", _SECRET, expire_minutes=60)
        sub = decode_token(token, _SECRET)
        assert sub == "alice"

    def test_expired_token_raises(self) -> None:
        # Build a token with an expiry in the past by patching the datetime
        from unittest.mock import patch
        from datetime import datetime, timezone, timedelta

        past = datetime(2000, 1, 1, tzinfo=timezone.utc)
        with patch("server.services.auth.datetime") as mock_dt:
            mock_dt.now.return_value = past
            token = create_access_token("bob", _SECRET, expire_minutes=60)

        with pytest.raises(HTTPException) as exc_info:
            decode_token(token, _SECRET)
        assert exc_info.value.status_code == 401

    def test_wrong_secret_raises(self) -> None:
        token = create_access_token("carol", _SECRET, expire_minutes=60)
        with pytest.raises(HTTPException) as exc_info:
            decode_token(token, "wrong-secret")
        assert exc_info.value.status_code == 401

    def test_tampered_token_raises(self) -> None:
        token = create_access_token("dave", _SECRET, expire_minutes=60)
        tampered = token[:-5] + "XXXXX"
        with pytest.raises(HTTPException):
            decode_token(tampered, _SECRET)
