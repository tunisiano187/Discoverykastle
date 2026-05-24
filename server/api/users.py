"""
User management API — /api/v1/users (admin only)

GET    /api/v1/users           — list all users
POST   /api/v1/users           — create a new user
GET    /api/v1/users/{id}      — get a specific user
PUT    /api/v1/users/{id}      — update a user (role, email, password, active)
DELETE /api/v1/users/{id}      — delete a user (cannot delete yourself)
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, field_validator
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from server.database import get_db
from server.models.user import ROLES, User
from server.services.auth import hash_password, require_admin

router = APIRouter(prefix="/api/v1/users", tags=["users"])


# ------------------------------------------------------------------
# Schemas
# ------------------------------------------------------------------


class UserCreate(BaseModel):
    username: str
    password: str
    email: str | None = None
    role: str = "viewer"

    @field_validator("role")
    @classmethod
    def _validate_role(cls, v: str) -> str:
        if v not in ROLES:
            raise ValueError(f"role must be one of {ROLES}")
        return v


class UserUpdate(BaseModel):
    email: str | None = None
    role: str | None = None
    password: str | None = None
    is_active: bool | None = None

    @field_validator("role")
    @classmethod
    def _validate_role(cls, v: str | None) -> str | None:
        if v is not None and v not in ROLES:
            raise ValueError(f"role must be one of {ROLES}")
        return v


class UserOut(BaseModel):
    id: uuid.UUID
    username: str
    email: str | None
    role: str
    is_active: bool
    last_login: datetime | None
    created_at: datetime
    updated_at: datetime

    model_config = {"from_attributes": True}


# ------------------------------------------------------------------
# Routes
# ------------------------------------------------------------------


@router.get("", response_model=list[UserOut])
async def list_users(
    _admin: Annotated[str, Depends(require_admin)],
    db: AsyncSession = Depends(get_db),
) -> list[UserOut]:
    """List all users. Requires admin role."""
    result = await db.execute(select(User).order_by(User.created_at))
    return list(result.scalars())


@router.post("", response_model=UserOut, status_code=status.HTTP_201_CREATED)
async def create_user(
    body: UserCreate,
    _admin: Annotated[str, Depends(require_admin)],
    db: AsyncSession = Depends(get_db),
) -> UserOut:
    """Create a new user. Requires admin role."""
    existing = await db.execute(select(User).where(User.username == body.username))
    if existing.scalar_one_or_none():
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"Username '{body.username}' already exists",
        )
    user = User(
        username=body.username,
        email=body.email,
        password_hash=hash_password(body.password),
        role=body.role,
    )
    db.add(user)
    await db.commit()
    await db.refresh(user)
    return user  # type: ignore[return-value]


@router.get("/{user_id}", response_model=UserOut)
async def get_user(
    user_id: uuid.UUID,
    _admin: Annotated[str, Depends(require_admin)],
    db: AsyncSession = Depends(get_db),
) -> UserOut:
    """Get a specific user by ID. Requires admin role."""
    result = await db.execute(select(User).where(User.id == user_id))
    user = result.scalar_one_or_none()
    if user is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")
    return user  # type: ignore[return-value]


@router.put("/{user_id}", response_model=UserOut)
async def update_user(
    user_id: uuid.UUID,
    body: UserUpdate,
    _admin: Annotated[str, Depends(require_admin)],
    db: AsyncSession = Depends(get_db),
) -> UserOut:
    """Update a user's role, email, password, or active status. Requires admin role."""
    result = await db.execute(select(User).where(User.id == user_id))
    user: User | None = result.scalar_one_or_none()
    if user is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")
    if body.email is not None:
        user.email = body.email
    if body.role is not None:
        user.role = body.role
    if body.password is not None:
        user.password_hash = hash_password(body.password)
    if body.is_active is not None:
        user.is_active = body.is_active
    user.updated_at = datetime.utcnow()
    await db.commit()
    await db.refresh(user)
    return user  # type: ignore[return-value]


@router.delete("/{user_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_user(
    user_id: uuid.UUID,
    admin: Annotated[str, Depends(require_admin)],
    db: AsyncSession = Depends(get_db),
) -> None:
    """Delete a user. Cannot delete your own account. Requires admin role."""
    result = await db.execute(select(User).where(User.id == user_id))
    user: User | None = result.scalar_one_or_none()
    if user is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")
    if user.username == admin:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Cannot delete your own account",
        )
    await db.delete(user)
    await db.commit()
