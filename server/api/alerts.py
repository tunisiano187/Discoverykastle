"""
Alerts API — /api/v1/alerts
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel
from sqlalchemy import select, and_
from sqlalchemy.ext.asyncio import AsyncSession

from server.database import get_db
from server.models.alert import Alert

router = APIRouter(prefix="/api/v1/alerts", tags=["alerts"])


class AlertOut(BaseModel):
    id: uuid.UUID
    severity: str
    alert_type: str
    message: str
    source: str
    details: dict
    acknowledged: bool
    acknowledged_at: datetime | None
    acknowledged_by: str | None
    created_at: datetime

    class Config:
        from_attributes = True


class AcknowledgeRequest(BaseModel):
    acknowledged_by: str


@router.get("/", response_model=list[AlertOut])
async def list_alerts(
    severity: str | None = Query(None, description="Filter by severity"),
    alert_type: str | None = Query(None, description="Filter by alert_type"),
    acknowledged: bool | None = Query(None, description="Filter by acknowledgement status"),
    limit: int = Query(100, ge=1, le=1000),
    offset: int = Query(0, ge=0),
    db: AsyncSession = Depends(get_db),
) -> list[Alert]:
    filters = []
    if severity:
        filters.append(Alert.severity == severity)
    if alert_type:
        filters.append(Alert.alert_type == alert_type)
    if acknowledged is not None:
        filters.append(Alert.acknowledged == acknowledged)

    stmt = (
        select(Alert)
        .where(and_(*filters) if filters else True)
        .order_by(Alert.created_at.desc())
        .limit(limit)
        .offset(offset)
    )
    result = await db.execute(stmt)
    return list(result.scalars())


@router.get("/{alert_id}", response_model=AlertOut)
async def get_alert(alert_id: uuid.UUID, db: AsyncSession = Depends(get_db)) -> Alert:
    alert = await db.get(Alert, alert_id)
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")
    return alert


@router.post("/{alert_id}/acknowledge", response_model=AlertOut)
async def acknowledge_alert(
    alert_id: uuid.UUID,
    body: AcknowledgeRequest,
    db: AsyncSession = Depends(get_db),
) -> Alert:
    alert = await db.get(Alert, alert_id)
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")
    alert.acknowledged = True
    alert.acknowledged_at = datetime.utcnow()
    alert.acknowledged_by = body.acknowledged_by
    await db.commit()
    await db.refresh(alert)
    return alert


@router.delete("/{alert_id}", status_code=204)
async def delete_alert(alert_id: uuid.UUID, db: AsyncSession = Depends(get_db)) -> None:
    alert = await db.get(Alert, alert_id)
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")
    await db.delete(alert)
    await db.commit()
