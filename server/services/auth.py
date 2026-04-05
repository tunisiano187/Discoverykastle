"""
JWT-based operator authentication helpers.

Usage in FastAPI endpoints::

    from server.services.auth import require_operator

    @router.get("/protected")
    async def handler(user: str = Depends(require_operator)):
        ...

Token payload::

    {"sub": "<username>", "exp": <unix timestamp>}
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

# Use bcrypt when available; fall back to pbkdf2_sha256 in environments
# where the bcrypt C extension is broken or version-incompatible (e.g. bcrypt 4.x + passlib 1.7.x).
def _make_pwd_ctx() -> CryptContext:
    try:
        ctx = CryptContext(schemes=["bcrypt"], deprecated="auto")
        ctx.hash("probe")  # will raise if bcrypt backend is broken
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

def create_access_token(username: str, secret_key: str, expire_minutes: int) -> str:
    """
    Create a signed JWT access token.

    Args:
        username: Subject claim value.
        secret_key: HMAC-SHA-256 signing key.
        expire_minutes: Token lifetime in minutes.

    Returns:
        Encoded JWT string.
    """
    now = datetime.now(tz=timezone.utc)
    payload = {
        "sub": username,
        "iat": now,
        "exp": now + timedelta(minutes=expire_minutes),
    }
    return jwt.encode(payload, secret_key, algorithm="HS256")


def decode_token(token: str, secret_key: str) -> str:
    """
    Decode and validate a JWT, returning the ``sub`` claim.

    Args:
        token: Encoded JWT string.
        secret_key: HMAC-SHA-256 signing key.

    Returns:
        Username extracted from the ``sub`` claim.

    Raises:
        HTTPException 401 if the token is invalid or expired.
    """
    try:
        payload = jwt.decode(token, secret_key, algorithms=["HS256"])
        sub: str | None = payload.get("sub")
        if not sub:
            raise JWTError("missing sub claim")
        return sub
    except JWTError as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"Invalid or expired token: {exc}",
            headers={"WWW-Authenticate": "Bearer"},
        ) from exc


# ------------------------------------------------------------------
# FastAPI dependency
# ------------------------------------------------------------------

async def require_operator(
    credentials: Annotated[HTTPAuthorizationCredentials | None, Depends(_bearer)],
) -> str:
    """
    FastAPI dependency that validates the Bearer JWT and returns the username.

    Raises HTTP 401 if no token or an invalid token is provided.
    """
    from server.config import settings  # late import avoids circular deps

    if credentials is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Not authenticated",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return decode_token(credentials.credentials, settings.secret_key)
