"""
JWT-based authentication with RBAC.

Roles (ascending privilege): viewer → analyst → operator → admin

Usage::

    from server.services.auth import require_operator, require_min_role

    # Any authenticated user:
    @router.get("/data")
    async def handler(user: str = Depends(require_operator)):
        ...

    # Admin-only:
    @router.delete("/users/{id}")
    async def delete_user(user: str = Depends(require_min_role("admin"))):
        ...

JWT payload::

    {"sub": "<username>", "role": "<role>", "exp": <unix ts>}

Tokens without a "role" claim (issued before RBAC was introduced) are treated
as "admin" to avoid breaking existing deployments during upgrade.
"""

from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone
from typing import Annotated

from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from jose import JWTError, jwt
from passlib.context import CryptContext

logger = logging.getLogger(__name__)

_bearer = HTTPBearer(auto_error=False)

_ROLE_RANK: dict[str, int] = {
    "viewer": 0,
    "analyst": 1,
    "operator": 2,
    "admin": 3,
}


def _make_pwd_ctx() -> CryptContext:
    try:
        ctx = CryptContext(schemes=["bcrypt"], deprecated="auto")
        ctx.hash("probe")
        return ctx
    except Exception:
        return CryptContext(schemes=["pbkdf2_sha256"], deprecated="auto")


_pwd_ctx = _make_pwd_ctx()


# ------------------------------------------------------------------
# Password helpers
# ------------------------------------------------------------------


def hash_password(plain: str) -> str:
    """Return a bcrypt hash of ``plain``."""
    return _pwd_ctx.hash(plain)


def verify_password(plain: str, hashed: str) -> bool:
    """Return True if ``plain`` matches the ``hashed`` bcrypt digest."""
    return _pwd_ctx.verify(plain, hashed)


# ------------------------------------------------------------------
# JWT helpers
# ------------------------------------------------------------------


def create_access_token(
    username: str, role: str, secret_key: str, expire_minutes: int
) -> str:
    """
    Create a signed JWT access token carrying ``username`` and ``role``.

    Args:
        username: Subject claim value.
        role: RBAC role (viewer | analyst | operator | admin).
        secret_key: HMAC-SHA-256 signing key.
        expire_minutes: Token lifetime in minutes.

    Returns:
        Encoded JWT string.
    """
    now = datetime.now(tz=timezone.utc)
    payload = {
        "sub": username,
        "role": role,
        "iat": now,
        "exp": now + timedelta(minutes=expire_minutes),
    }
    return jwt.encode(payload, secret_key, algorithm="HS256")


def decode_token(token: str, secret_key: str) -> tuple[str, str]:
    """
    Decode and validate a JWT, returning ``(username, role)``.

    Tokens without a ``role`` claim (pre-RBAC) are treated as ``"admin"``
    for backward compatibility.

    Raises:
        HTTPException 401 if the token is invalid or expired.
    """
    try:
        payload = jwt.decode(token, secret_key, algorithms=["HS256"])
        sub: str | None = payload.get("sub")
        if not sub:
            raise JWTError("missing sub claim")
        role: str = payload.get("role", "admin")
        return sub, role
    except JWTError as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"Invalid or expired token: {exc}",
            headers={"WWW-Authenticate": "Bearer"},
        ) from exc


# ------------------------------------------------------------------
# FastAPI dependencies
# ------------------------------------------------------------------


async def require_operator(
    credentials: Annotated[HTTPAuthorizationCredentials | None, Depends(_bearer)],
) -> str:
    """
    Validate the Bearer JWT and return the username.

    Accepts any authenticated user regardless of role (viewer and above).
    Raises HTTP 401 if no token or an invalid token is provided.
    """
    from server.config import settings  # late import avoids circular deps

    if credentials is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Not authenticated",
            headers={"WWW-Authenticate": "Bearer"},
        )
    username, _role = decode_token(credentials.credentials, settings.secret_key)
    return username


def require_min_role(min_role: str):
    """
    Return a FastAPI dependency that enforces a minimum RBAC role.

    The dependency resolves to the authenticated username on success.

    Args:
        min_role: Minimum required role (viewer | analyst | operator | admin).

    Returns:
        An async callable suitable for use with ``Depends()``.

    Example::

        @router.delete("/users/{id}")
        async def delete_user(user: str = Depends(require_min_role("admin"))):
            ...
    """
    min_rank = _ROLE_RANK.get(min_role, 99)

    async def _dep(
        credentials: Annotated[HTTPAuthorizationCredentials | None, Depends(_bearer)],
    ) -> str:
        from server.config import settings

        if credentials is None:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Not authenticated",
                headers={"WWW-Authenticate": "Bearer"},
            )
        username, role = decode_token(credentials.credentials, settings.secret_key)
        if _ROLE_RANK.get(role, -1) < min_rank:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Insufficient permissions (requires {min_role}, got {role})",
            )
        return username

    return _dep


# Named shortcuts
require_admin = require_min_role("admin")
require_operator_role = require_min_role("operator")
require_analyst = require_min_role("analyst")
