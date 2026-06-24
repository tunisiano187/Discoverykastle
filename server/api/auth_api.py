"""
Operator authentication API — /api/v1/auth

POST /api/v1/auth/login    — exchange username+password for JWT access token
POST /api/v1/auth/refresh  — exchange a valid token for a fresh one
GET  /api/v1/auth/me       — return current operator's username and role
"""

from __future__ import annotations

from datetime import datetime
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from server.database import get_db
from server.services.auth import (
    create_access_token,
    require_operator,
    verify_password,
)
from server.services.rate_limit import (
    check_login_rate_limit,
    record_failed_login,
    clear_login_failures,
)

router = APIRouter(prefix="/api/v1/auth", tags=["auth"])


# ------------------------------------------------------------------
# Schemas
# ------------------------------------------------------------------


class LoginRequest(BaseModel):
    username: str
    password: str


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    expires_in: int


class MeResponse(BaseModel):
    username: str
    role: str


# ------------------------------------------------------------------
# Routes
# ------------------------------------------------------------------


@router.post("/login", response_model=TokenResponse)
async def login(
    request: Request,
    body: LoginRequest,
    db: AsyncSession = Depends(get_db),
) -> TokenResponse:
    """Exchange credentials for a JWT access token."""
    from server.config import settings
    from server.models.user import User

    # Check rate limit BEFORE touching the DB to prevent timing attacks
    await check_login_rate_limit(request, body.username)

    result = await db.execute(select(User).where(User.username == body.username))
    user: User | None = result.scalar_one_or_none()

    authenticated = False
    role = "admin"

    if user is not None:
        if not user.is_active:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Account is disabled",
                headers={"WWW-Authenticate": "Bearer"},
            )
        pw_ok = verify_password(body.password, user.password_hash)
        # Accept plain-text match for dev setups where hash was not yet applied
        if not pw_ok:
            pw_ok = body.password == user.password_hash
        if pw_ok:
            authenticated = True
            role = user.role
            user.last_login = datetime.utcnow()
            await db.commit()
    else:
        # Fall back to legacy single-admin credentials from settings
        # (used before the users table existed, or before first bootstrap)
        if not settings.admin_password:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="No admin password configured. Complete the setup wizard first.",
            )
        username_ok = body.username == settings.admin_username
        pw_ok = verify_password(body.password, settings.admin_password)
        if not pw_ok:
            pw_ok = body.password == settings.admin_password
        if username_ok and pw_ok:
            authenticated = True
            role = "admin"

    if not authenticated:
        await record_failed_login(request, body.username)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )

    await clear_login_failures(body.username)
    token = create_access_token(body.username, role, settings.secret_key, settings.jwt_expire_minutes)
    return TokenResponse(access_token=token, expires_in=settings.jwt_expire_minutes * 60)


@router.post("/refresh", response_model=TokenResponse)
async def refresh(operator: Annotated[str, Depends(require_operator)]) -> TokenResponse:
    """Return a fresh token for the currently authenticated operator."""
    from server.config import settings
    from server.models.user import User
    from server.database import AsyncSessionLocal

    # Reload role from DB so it stays current
    role = "admin"
    async with AsyncSessionLocal() as db:
        result = await db.execute(select(User).where(User.username == operator))
        user: User | None = result.scalar_one_or_none()
        if user:
            role = user.role

    token = create_access_token(operator, role, settings.secret_key, settings.jwt_expire_minutes)
    return TokenResponse(access_token=token, expires_in=settings.jwt_expire_minutes * 60)


@router.get("/me", response_model=MeResponse)
async def me(
    operator: Annotated[str, Depends(require_operator)],
    db: AsyncSession = Depends(get_db),
) -> MeResponse:
    """Return the username and role of the currently authenticated operator."""
    from server.models.user import User

    result = await db.execute(select(User).where(User.username == operator))
    user: User | None = result.scalar_one_or_none()
    role = user.role if user else "admin"
    return MeResponse(username=operator, role=role)
