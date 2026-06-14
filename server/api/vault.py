"""
Credential vault API — /api/v1/vault/credentials

Manages encrypted device credentials (SSH, SNMP, WinRM, HTTP API keys).

Access control:
  - operator role required for all write operations (POST / PATCH / DELETE)
  - operator role required for read operations (GET)

IMPORTANT: The secret value is NEVER returned by any endpoint.
           Plaintext credentials are only delivered to agents via the mTLS
           WebSocket as task-scoped ephemeral tokens.

Routes:
  GET    /api/v1/vault/credentials           — list all (metadata only)
  POST   /api/v1/vault/credentials           — create a credential
  GET    /api/v1/vault/credentials/{id}      — get one (metadata only)
  PATCH  /api/v1/vault/credentials/{id}      — update label / secret / notes
  DELETE /api/v1/vault/credentials/{id}      — delete
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
from server.models.credential import CREDENTIAL_TYPES, Credential
from server.services.auth import require_operator_role
from server.services.vault import get_vault

router = APIRouter(prefix="/api/v1/vault", tags=["vault"])

_require_operator = require_operator_role


# ------------------------------------------------------------------
# Schemas
# ------------------------------------------------------------------


class CredentialCreate(BaseModel):
    device_id: str
    credential_type: str
    label: str | None = None
    username: str | None = None
    secret: str
    notes: str | None = None

    @field_validator("credential_type")
    @classmethod
    def _validate_type(cls, v: str) -> str:
        if v not in CREDENTIAL_TYPES:
            raise ValueError(f"credential_type must be one of {CREDENTIAL_TYPES}")
        return v

    @field_validator("secret")
    @classmethod
    def _secret_not_empty(cls, v: str) -> str:
        if not v.strip():
            raise ValueError("secret must not be empty")
        return v


class CredentialUpdate(BaseModel):
    label: str | None = None
    username: str | None = None
    secret: str | None = None
    notes: str | None = None

    @field_validator("secret")
    @classmethod
    def _secret_not_empty(cls, v: str | None) -> str | None:
        if v is not None and not v.strip():
            raise ValueError("secret must not be empty")
        return v


class CredentialOut(BaseModel):
    """Public representation — secret fields are intentionally excluded."""

    id: uuid.UUID
    device_id: str
    credential_type: str
    label: str | None
    has_username: bool
    has_notes: bool
    created_by: str
    created_at: datetime
    updated_at: datetime

    model_config = {"from_attributes": False}

    @classmethod
    def from_orm(cls, c: Credential) -> "CredentialOut":
        return cls(
            id=c.id,
            device_id=c.device_id,
            credential_type=c.credential_type,
            label=c.label,
            has_username=c.username_enc is not None,
            has_notes=c.notes_enc is not None,
            created_by=c.created_by,
            created_at=c.created_at,
            updated_at=c.updated_at,
        )


# ------------------------------------------------------------------
# Routes
# ------------------------------------------------------------------


@router.get("/credentials", response_model=list[CredentialOut])
async def list_credentials(
    operator: Annotated[str, Depends(_require_operator)],
    device_id: str | None = None,
    db: AsyncSession = Depends(get_db),
) -> list[CredentialOut]:
    """List all stored credentials (metadata only — no secret values)."""
    q = select(Credential).order_by(Credential.device_id, Credential.credential_type)
    if device_id:
        q = q.where(Credential.device_id == device_id)
    result = await db.execute(q)
    return [CredentialOut.from_orm(c) for c in result.scalars()]


@router.post("/credentials", response_model=CredentialOut, status_code=status.HTTP_201_CREATED)
async def create_credential(
    body: CredentialCreate,
    operator: Annotated[str, Depends(_require_operator)],
    db: AsyncSession = Depends(get_db),
) -> CredentialOut:
    """Store a new encrypted credential. The secret is encrypted before persistence."""
    vault = get_vault()
    cred = Credential(
        device_id=body.device_id,
        credential_type=body.credential_type,
        label=body.label,
        username_enc=vault.encrypt(body.username) if body.username else None,
        secret_enc=vault.encrypt(body.secret),
        notes_enc=vault.encrypt(body.notes) if body.notes else None,
        created_by=operator,
    )
    db.add(cred)
    await db.commit()
    await db.refresh(cred)
    return CredentialOut.from_orm(cred)


@router.get("/credentials/{credential_id}", response_model=CredentialOut)
async def get_credential(
    credential_id: uuid.UUID,
    operator: Annotated[str, Depends(_require_operator)],
    db: AsyncSession = Depends(get_db),
) -> CredentialOut:
    """Get credential metadata by ID (no secret returned)."""
    result = await db.execute(select(Credential).where(Credential.id == credential_id))
    cred = result.scalar_one_or_none()
    if cred is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Credential not found")
    return CredentialOut.from_orm(cred)


@router.patch("/credentials/{credential_id}", response_model=CredentialOut)
async def update_credential(
    credential_id: uuid.UUID,
    body: CredentialUpdate,
    operator: Annotated[str, Depends(_require_operator)],
    db: AsyncSession = Depends(get_db),
) -> CredentialOut:
    """Update label, username, secret, or notes. Only provided fields are changed."""
    result = await db.execute(select(Credential).where(Credential.id == credential_id))
    cred: Credential | None = result.scalar_one_or_none()
    if cred is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Credential not found")

    vault = get_vault()
    if body.label is not None:
        cred.label = body.label
    if body.username is not None:
        cred.username_enc = vault.encrypt(body.username)
    if body.secret is not None:
        cred.secret_enc = vault.encrypt(body.secret)
    if body.notes is not None:
        cred.notes_enc = vault.encrypt(body.notes)
    cred.updated_at = datetime.utcnow()

    await db.commit()
    await db.refresh(cred)
    return CredentialOut.from_orm(cred)


@router.delete("/credentials/{credential_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_credential(
    credential_id: uuid.UUID,
    operator: Annotated[str, Depends(_require_operator)],
    db: AsyncSession = Depends(get_db),
) -> None:
    """Permanently delete a stored credential."""
    result = await db.execute(select(Credential).where(Credential.id == credential_id))
    cred: Credential | None = result.scalar_one_or_none()
    if cred is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Credential not found")
    await db.delete(cred)
    await db.commit()
