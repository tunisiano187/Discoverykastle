"""
Login rate limiter — Redis-backed sliding-window counter.

Limits failed login attempts per username and per source IP to prevent
brute-force attacks.  Both windows are independent; tripping either one
blocks the request.

Thresholds (configurable via Settings):
  login_rate_limit_attempts : max failed attempts before lock (default 5)
  login_rate_limit_window   : window in seconds (default 300 = 5 min)
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING

from fastapi import HTTPException, Request, status

if TYPE_CHECKING:
    pass

logger = logging.getLogger(__name__)

# Redis key prefix
_PREFIX = "dkastle:login:fail:"


async def _get_redis():
    """Return the shared Redis client, or None if Redis is unavailable."""
    try:
        import redis.asyncio as aioredis
        from server.config import settings
        client = aioredis.from_url(settings.redis_url, decode_responses=True, socket_connect_timeout=1)
        await client.ping()
        return client
    except Exception:
        return None


async def check_login_rate_limit(request: Request, username: str) -> None:
    """
    Raise HTTP 429 if the username or source IP has exceeded the failed-login
    threshold within the configured window.

    Call this BEFORE verifying the password so lockouts cannot be bypassed
    by guessing the correct password while still within a locked window.
    """
    from server.config import settings

    max_attempts: int = settings.login_rate_limit_attempts

    redis = await _get_redis()
    if redis is None:
        return  # Redis unavailable — fail open (don't block legitimate users)

    try:
        ip = request.client.host if request.client else "unknown"
        for key in (f"{_PREFIX}user:{username}", f"{_PREFIX}ip:{ip}"):
            count_str = await redis.get(key)
            count = int(count_str) if count_str else 0
            if count >= max_attempts:
                ttl = await redis.ttl(key)
                logger.warning(
                    "Login rate limit exceeded: key=%s attempts=%d ttl=%ds",
                    key, count, ttl,
                )
                raise HTTPException(
                    status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                    detail=(
                        f"Too many failed login attempts. "
                        f"Try again in {max(ttl, 1)} seconds."
                    ),
                    headers={"Retry-After": str(max(ttl, 1))},
                )
    finally:
        await redis.aclose()


async def record_failed_login(request: Request, username: str) -> None:
    """Increment the failure counters for this username and source IP."""
    from server.config import settings

    window: int = settings.login_rate_limit_window

    redis = await _get_redis()
    if redis is None:
        return

    try:
        ip = request.client.host if request.client else "unknown"
        for key in (f"{_PREFIX}user:{username}", f"{_PREFIX}ip:{ip}"):
            pipe = redis.pipeline()
            pipe.incr(key)
            pipe.expire(key, window, nx=True)  # nx=True: only set TTL on first write
            await pipe.execute()
    except Exception:
        logger.debug("Failed to record login failure in Redis", exc_info=True)
    finally:
        await redis.aclose()


async def clear_login_failures(username: str) -> None:
    """Clear failure counters on successful login."""
    redis = await _get_redis()
    if redis is None:
        return
    try:
        await redis.delete(f"{_PREFIX}user:{username}")
    except Exception:
        pass
    finally:
        await redis.aclose()
