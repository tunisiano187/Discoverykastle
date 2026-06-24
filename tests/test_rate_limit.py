"""
Tests for server/services/rate_limit.py.

Strategy: mock Redis client so no real Redis is needed.
Tests verify the sliding-window logic, 429 enforcement, and failure recording.
"""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fastapi import HTTPException


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_request(ip: str = "127.0.0.1") -> MagicMock:
    req = MagicMock()
    req.client = MagicMock()
    req.client.host = ip
    return req


def _make_redis(user_count: int = 0, ip_count: int = 0, ttl: int = 250) -> AsyncMock:
    """Return a mocked Redis client with configurable GET and TTL responses."""
    redis = AsyncMock()
    redis.ping = AsyncMock(return_value=True)
    # GET alternates: first call → user key, second call → IP key
    redis.get = AsyncMock(side_effect=[
        str(user_count) if user_count else None,
        str(ip_count) if ip_count else None,
    ])
    redis.ttl = AsyncMock(return_value=ttl)
    pipe = AsyncMock()
    pipe.incr = MagicMock(return_value=pipe)
    pipe.expire = MagicMock(return_value=pipe)
    pipe.execute = AsyncMock(return_value=[1, True])
    redis.pipeline = MagicMock(return_value=pipe)
    redis.delete = AsyncMock(return_value=1)
    redis.aclose = AsyncMock()
    return redis


# ---------------------------------------------------------------------------
# check_login_rate_limit
# ---------------------------------------------------------------------------

class TestCheckLoginRateLimit:
    @pytest.mark.asyncio
    async def test_no_block_when_under_threshold(self) -> None:
        from server.services.rate_limit import check_login_rate_limit
        redis = _make_redis(user_count=3, ip_count=2)
        with patch("server.services.rate_limit._get_redis", return_value=redis):
            # Should not raise — 3 < 5 (default threshold)
            await check_login_rate_limit(_make_request(), "alice")

    @pytest.mark.asyncio
    async def test_blocks_when_user_count_at_threshold(self) -> None:
        from server.services.rate_limit import check_login_rate_limit
        redis = _make_redis(user_count=5, ip_count=0, ttl=120)
        with patch("server.services.rate_limit._get_redis", return_value=redis), \
             patch("server.config.settings") as mock_settings:
            mock_settings.login_rate_limit_attempts = 5
            mock_settings.login_rate_limit_window = 300
            with pytest.raises(HTTPException) as exc_info:
                await check_login_rate_limit(_make_request(), "alice")
        assert exc_info.value.status_code == 429

    @pytest.mark.asyncio
    async def test_blocks_when_ip_count_at_threshold(self) -> None:
        from server.services.rate_limit import check_login_rate_limit
        # user_count=0 (passes), ip_count=5 (blocks)
        redis = _make_redis(user_count=0, ip_count=5, ttl=60)
        with patch("server.services.rate_limit._get_redis", return_value=redis), \
             patch("server.config.settings") as mock_settings:
            mock_settings.login_rate_limit_attempts = 5
            mock_settings.login_rate_limit_window = 300
            with pytest.raises(HTTPException) as exc_info:
                await check_login_rate_limit(_make_request(), "bob")
        assert exc_info.value.status_code == 429

    @pytest.mark.asyncio
    async def test_retry_after_header_set(self) -> None:
        from server.services.rate_limit import check_login_rate_limit
        redis = _make_redis(user_count=5, ip_count=0, ttl=180)
        with patch("server.services.rate_limit._get_redis", return_value=redis), \
             patch("server.config.settings") as mock_settings:
            mock_settings.login_rate_limit_attempts = 5
            mock_settings.login_rate_limit_window = 300
            with pytest.raises(HTTPException) as exc_info:
                await check_login_rate_limit(_make_request(), "eve")
        assert "Retry-After" in exc_info.value.headers
        assert exc_info.value.headers["Retry-After"] == "180"

    @pytest.mark.asyncio
    async def test_no_block_when_redis_unavailable(self) -> None:
        from server.services.rate_limit import check_login_rate_limit
        with patch("server.services.rate_limit._get_redis", return_value=None):
            # Fail open — don't block if Redis is down
            await check_login_rate_limit(_make_request(), "alice")

    @pytest.mark.asyncio
    async def test_zero_count_not_blocked(self) -> None:
        from server.services.rate_limit import check_login_rate_limit
        redis = _make_redis(user_count=0, ip_count=0)
        with patch("server.services.rate_limit._get_redis", return_value=redis), \
             patch("server.config.settings") as mock_settings:
            mock_settings.login_rate_limit_attempts = 5
            mock_settings.login_rate_limit_window = 300
            await check_login_rate_limit(_make_request(), "new_user")


# ---------------------------------------------------------------------------
# record_failed_login
# ---------------------------------------------------------------------------

class TestRecordFailedLogin:
    @pytest.mark.asyncio
    async def test_increments_both_keys(self) -> None:
        from server.services.rate_limit import record_failed_login
        redis = _make_redis()
        with patch("server.services.rate_limit._get_redis", return_value=redis), \
             patch("server.config.settings") as mock_settings:
            mock_settings.login_rate_limit_window = 300
            await record_failed_login(_make_request("1.2.3.4"), "alice")
        # pipeline() should have been called twice (once per key)
        assert redis.pipeline.call_count == 2

    @pytest.mark.asyncio
    async def test_no_error_when_redis_unavailable(self) -> None:
        from server.services.rate_limit import record_failed_login
        with patch("server.services.rate_limit._get_redis", return_value=None):
            # Must not raise
            await record_failed_login(_make_request(), "alice")

    @pytest.mark.asyncio
    async def test_uses_correct_key_prefix(self) -> None:
        from server.services.rate_limit import record_failed_login
        redis = _make_redis()
        calls = []

        def _capture_pipeline():
            pipe = AsyncMock()
            pipe.incr = MagicMock(side_effect=lambda k: calls.append(k) or pipe)
            pipe.expire = MagicMock(return_value=pipe)
            pipe.execute = AsyncMock(return_value=[1, True])
            return pipe

        redis.pipeline = _capture_pipeline
        with patch("server.services.rate_limit._get_redis", return_value=redis), \
             patch("server.config.settings") as mock_settings:
            mock_settings.login_rate_limit_window = 300
            await record_failed_login(_make_request("10.0.0.1"), "bob")
        user_key = next((k for k in calls if "user:" in k), None)
        ip_key = next((k for k in calls if "ip:" in k), None)
        assert user_key is not None and "bob" in user_key
        assert ip_key is not None and "10.0.0.1" in ip_key


# ---------------------------------------------------------------------------
# clear_login_failures
# ---------------------------------------------------------------------------

class TestClearLoginFailures:
    @pytest.mark.asyncio
    async def test_deletes_user_key(self) -> None:
        from server.services.rate_limit import clear_login_failures
        redis = _make_redis()
        with patch("server.services.rate_limit._get_redis", return_value=redis):
            await clear_login_failures("alice")
        redis.delete.assert_awaited_once()
        key = redis.delete.call_args[0][0]
        assert "user:alice" in key

    @pytest.mark.asyncio
    async def test_no_error_when_redis_unavailable(self) -> None:
        from server.services.rate_limit import clear_login_failures
        with patch("server.services.rate_limit._get_redis", return_value=None):
            await clear_login_failures("alice")
