"""
Operator authentication API — /api/v1/auth

POST /api/v1/auth/login    — exchange username+password for JWT access token
POST /api/v1/auth/refresh  — exchange a valid token for a fresh one
GET  /api/v1/auth/me       — return the current operator's username
"""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel

from server.services.auth import (
    create_access_token,
    require_operator,
    verify_password,
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
    expires_in: int  # seconds


class MeResponse(BaseModel):
    username: str


# ------------------------------------------------------------------
# Routes
# ------------------------------------------------------------------

@router.post("/login", response_model=TokenResponse)
async def login(body: LoginRequest) -> TokenResponse:
    """
    Exchange operator credentials for a JWT access token.

    Credentials are validated against ``DKASTLE_ADMIN_USERNAME`` /
    ``DKASTLE_ADMIN_PASSWORD`` from the server config (set during
    first-run setup).
    """
    from server.config import settings

    if not settings.admin_password:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=(
                "No admin password configured. "
                "Complete the first-run setup wizard before logging in."
            ),
        )

    username_ok = body.username == settings.admin_username
    password_ok = verify_password(body.password, settings.admin_password)

    # Also accept a plain-text password match for the initial dev setup
    # where the password was not yet hashed (e.g. set via raw .env).
    if not password_ok:
        password_ok = (body.password == settings.admin_password)

    if not username_ok or not password_ok:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )

    token = create_access_token(
        body.username,
        settings.secret_key,
        settings.jwt_expire_minutes,
    )
    return TokenResponse(
        access_token=token,
        expires_in=settings.jwt_expire_minutes * 60,
    )


@router.post("/refresh", response_model=TokenResponse)
async def refresh(operator: Annotated[str, Depends(require_operator)]) -> TokenResponse:
    """
    Return a fresh access token for the currently authenticated operator.
    The existing token must still be valid.
    """
    from server.config import settings

    token = create_access_token(
        operator,
        settings.secret_key,
        settings.jwt_expire_minutes,
    )
    return TokenResponse(
        access_token=token,
        expires_in=settings.jwt_expire_minutes * 60,
    )


@router.get("/me", response_model=MeResponse)
async def me(operator: Annotated[str, Depends(require_operator)]) -> MeResponse:
    """Return the username of the currently authenticated operator."""
    return MeResponse(username=operator)
