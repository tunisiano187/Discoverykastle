"""
Agent deployment API — /api/v1/deploy

POST /api/v1/deploy/{host_id}   — trigger SSH agent deployment (operator+)

The caller must provide a credential_id (UUID of a vault credential with type
``ssh`` or ``ssh_key``) and optionally a server_url the installed agent should
use to phone home.
"""

from __future__ import annotations

import uuid
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession

from server.database import get_db
from server.services.deploy import DeployError, DeployResult, deploy_agent

router = APIRouter(prefix="/api/v1/deploy", tags=["deploy"])

_bearer = HTTPBearer(auto_error=False)


async def _require_operator(
    credentials: Annotated[HTTPAuthorizationCredentials | None, Depends(_bearer)],
) -> str:
    from server.services.auth import require_min_role

    return await require_min_role("operator")(credentials)


# ------------------------------------------------------------------
# Schemas
# ------------------------------------------------------------------


class DeployRequest(BaseModel):
    credential_id: uuid.UUID
    server_url: str = ""
    installer_url: str = ""
    port: int = 22
    timeout: int = 60


class DeployResponse(BaseModel):
    host_id: uuid.UUID
    success: bool
    message: str
    exit_code: int
    stdout: str
    stderr: str


# ------------------------------------------------------------------
# Routes
# ------------------------------------------------------------------


@router.post("/{host_id}", response_model=DeployResponse)
async def trigger_deploy(
    host_id: uuid.UUID,
    body: DeployRequest,
    username: Annotated[str, Depends(_require_operator)],
    db: AsyncSession = Depends(get_db),
) -> DeployResponse:
    """
    Deploy the Discoverykastle agent on a discovered host via SSH.

    Requires operator role. The referenced credential must have type ``ssh``
    or ``ssh_key`` and be stored in the credential vault.
    """
    try:
        kwargs = {
            "server_url": body.server_url,
            "port": body.port,
            "timeout": body.timeout,
        }
        if body.installer_url:
            kwargs["installer_url"] = body.installer_url

        result: DeployResult = await deploy_agent(
            db, host_id, body.credential_id, **kwargs
        )
    except DeployError as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail=str(exc),
        ) from exc

    return DeployResponse(
        host_id=result.host_id,
        success=result.success,
        message=result.message,
        exit_code=result.exit_code,
        stdout=result.stdout,
        stderr=result.stderr,
    )
