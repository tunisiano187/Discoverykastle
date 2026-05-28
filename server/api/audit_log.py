"""
Audit log read API — /api/v1/audit-log (admin only)

GET /api/v1/audit-log   — list audit log entries (paginated)
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Annotated

from fastapi import APIRouter, Depends, Query
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from server.database import get_db
from server.models.agent import AuditLog
from server.services.auth import require_admin

router = APIRouter(prefix="/api/v1/audit-log", tags=["audit-log"])


class AuditLogOut(BaseModel):
    id: uuid.UUID
    agent_id: uuid.UUID | None
    user_id: str | None
    action: str
    target: str | None
    params: dict
    result: str | None
    timestamp: datetime

    model_config = {"from_attributes": True}


@router.get("", response_model=list[AuditLogOut])
async def list_audit_log(
    _admin: Annotated[str, Depends(require_admin)],
    db: AsyncSession = Depends(get_db),
    limit: int = Query(100, ge=1, le=1000),
    offset: int = Query(0, ge=0),
    action: str | None = Query(None),
) -> list[AuditLogOut]:
    """
    List audit log entries, newest first. Requires admin role.

    - **limit**: max entries to return (1–1000, default 100)
    - **offset**: skip this many entries (for pagination)
    - **action**: filter by action name (exact match)
    """
    stmt = select(AuditLog).order_by(AuditLog.timestamp.desc())
    if action:
        stmt = stmt.where(AuditLog.action == action)
    stmt = stmt.offset(offset).limit(limit)
    result = await db.execute(stmt)
    return list(result.scalars())
