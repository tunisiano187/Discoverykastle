"""
Credential Vault API — /api/v1/vault/credentials

POST   /api/v1/vault/credentials        — store encrypted credential (operator+)
GET    /api/v1/vault/credentials        — list credential metadata (operator+)
GET    /api/v1/vault/credentials/{id}   — get credential metadata (operator+)
PATCH  /api/v1/vault/credentials/{id}   — update label/device_id/data (operator+)
DELETE /api/v1/vault/credentials/{id}   — delete credential (admin only)
POST   /api/v1/vault/credentials/{id}/decrypt — decrypt for task use (operator+)

Plaintext credentials are never stored; only the AES-256-GCM ciphertext blob.
The master key lives in the DKASTLE_VAULT_KEY environment variable.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from server.database import get_db
from server.models.credential import Credential
from server.services.vault import VaultError, decrypt, encrypt

router = APIRouter(prefix="/api/v1/vault/credentials", tags=["vault"])

_bearer = HTTPBearer(auto_error=False)


def _lazy_role(min_role: str):
    """Auth dependency with lazy jose import — avoids importing jose at module load time."""

    async def _dep(
        credentials: Annotated[HTTPAuthorizationCredentials | None, Depends(_bearer)],
    ) -> str:
        from server.services.auth import require_min_role  # noqa: PLC0415

        return await require_min_role(min_role)(credentials)

    _dep.__name__ = f"require_{min_role}"
    return _dep


_require_operator = _lazy_role("operator")
_require_admin = _lazy_role("admin")


# ------------------------------------------------------------------
# Schemas
# ------------------------------------------------------------------


class CredentialCreate(BaseModel):
    label: str
    credential_type: str
    device_id: uuid.UUID | None = None
    data: dict


class CredentialUpdate(BaseModel):
    label: str | None = None
    device_id: uuid.UUID | None = None
    data: dict | None = None  # if provided, re-encrypts with a fresh nonce


class CredentialOut(BaseModel):
    id: uuid.UUID
    label: str
    credential_type: str
    device_id: uuid.UUID | None
    created_by: str
    updated_by: str | None
    created_at: datetime
    updated_at: datetime

    model_config = {"from_attributes": True}


class CredentialDecryptOut(BaseModel):
    id: uuid.UUID
    label: str
    credential_type: str
    data: dict


# ------------------------------------------------------------------
# Routes
# ------------------------------------------------------------------


@router.post("", response_model=CredentialOut, status_code=status.HTTP_201_CREATED)
async def create_credential(
    body: CredentialCreate,
    username: Annotated[str, Depends(_require_operator)],
    db: AsyncSession = Depends(get_db),
) -> CredentialOut:
    """Store a new encrypted credential. Requires operator role."""
    try:
        ciphertext = encrypt(body.data)
    except VaultError as exc:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=str(exc),
        ) from exc

    cred = Credential(
        label=body.label,
        credential_type=body.credential_type,
        device_id=body.device_id,
        ciphertext=ciphertext,
        created_by=username,
    )
    db.add(cred)
    await db.commit()
    await db.refresh(cred)
    return cred  # type: ignore[return-value]


@router.get("", response_model=list[CredentialOut])
async def list_credentials(
    username: Annotated[str, Depends(_require_operator)],
    db: AsyncSession = Depends(get_db),
    credential_type: str | None = Query(None, description="Filter by credential type"),
    label: str | None = Query(None, description="Filter by label substring (case-insensitive)"),
    skip: int = Query(0, ge=0, description="Pagination offset"),
    limit: int = Query(50, ge=1, le=500, description="Max results"),
) -> list[CredentialOut]:
    """List credential metadata (no plaintext). Supports type/label filtering and pagination."""
    stmt = select(Credential).order_by(Credential.created_at)
    if credential_type:
        stmt = stmt.where(Credential.credential_type == credential_type)
    if label:
        stmt = stmt.where(Credential.label.ilike(f"%{label}%"))
    stmt = stmt.offset(skip).limit(limit)
    result = await db.execute(stmt)
    return list(result.scalars())  # type: ignore[return-value]


@router.get("/{credential_id}", response_model=CredentialOut)
async def get_credential(
    credential_id: uuid.UUID,
    username: Annotated[str, Depends(_require_operator)],
    db: AsyncSession = Depends(get_db),
) -> CredentialOut:
    """Get credential metadata by ID. Requires operator role."""
    cred = await db.get(Credential, credential_id)
    if cred is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Credential not found")
    return cred  # type: ignore[return-value]


@router.patch("/{credential_id}", response_model=CredentialOut)
async def update_credential(
    credential_id: uuid.UUID,
    body: CredentialUpdate,
    username: Annotated[str, Depends(_require_operator)],
    db: AsyncSession = Depends(get_db),
) -> CredentialOut:
    """
    Update a credential's label, device_id, or plaintext data.

    If ``data`` is provided the secret is re-encrypted with a fresh nonce.
    Requires operator role.
    """
    cred = await db.get(Credential, credential_id)
    if cred is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Credential not found")

    if body.label is not None:
        cred.label = body.label
    if body.device_id is not None:
        cred.device_id = body.device_id
    if body.data is not None:
        try:
            cred.ciphertext = encrypt(body.data)
        except VaultError as exc:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=str(exc),
            ) from exc

    cred.updated_by = username
    cred.updated_at = datetime.utcnow()
    await db.commit()
    await db.refresh(cred)
    return cred  # type: ignore[return-value]


@router.delete("/{credential_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_credential(
    credential_id: uuid.UUID,
    username: Annotated[str, Depends(_require_admin)],
    db: AsyncSession = Depends(get_db),
) -> None:
    """Delete a credential. Requires admin role."""
    cred = await db.get(Credential, credential_id)
    if cred is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Credential not found")
    await db.delete(cred)
    await db.commit()


@router.post("/{credential_id}/decrypt", response_model=CredentialDecryptOut)
async def decrypt_credential(
    credential_id: uuid.UUID,
    username: Annotated[str, Depends(_require_operator)],
    db: AsyncSession = Depends(get_db),
) -> CredentialDecryptOut:
    """
    Decrypt and return a credential's plaintext data.

    Intended for ephemeral task-scoped use. The response is never cached.
    Requires operator role.
    """
    cred = await db.get(Credential, credential_id)
    if cred is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Credential not found")

    try:
        data = decrypt(cred.ciphertext)
    except VaultError as exc:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=str(exc),
        ) from exc

    return CredentialDecryptOut(
        id=cred.id,
        label=cred.label,
        credential_type=cred.credential_type,
        data=data,
    )
