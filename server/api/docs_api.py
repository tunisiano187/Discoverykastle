"""
Documentation generator API — /api/v1/docs

GET /api/v1/docs/summary            — executive summary (Markdown)
GET /api/v1/docs/network/{id}       — single network report (Markdown)
GET /api/v1/docs/device/{id}        — single device report (Markdown)
GET /api/v1/docs/export             — export all reports as a single Markdown doc

All endpoints require at least analyst role.
"""

from __future__ import annotations

import uuid
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.responses import PlainTextResponse
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from server.database import get_db
from server.models.alert import Alert
from server.models.device import NetworkDevice
from server.models.host import Host
from server.models.network import Network
from server.services.docgen import (
    render_device_report,
    render_executive_summary,
    render_network_report,
)

router = APIRouter(prefix="/api/v1/docs", tags=["docs"])

_MARKDOWN = "text/markdown; charset=utf-8"
_bearer = HTTPBearer(auto_error=False)


async def _require_analyst(
    credentials: Annotated[HTTPAuthorizationCredentials | None, Depends(_bearer)],
) -> str:
    from server.services.auth import require_min_role

    return await require_min_role("analyst")(credentials)


# ------------------------------------------------------------------
# Routes
# ------------------------------------------------------------------


@router.get("/summary", response_class=PlainTextResponse)
async def get_executive_summary(
    username: Annotated[str, Depends(_require_analyst)],
    db: AsyncSession = Depends(get_db),
) -> str:
    """Generate an executive summary Markdown report."""
    networks_result = await db.execute(select(Network).order_by(Network.cidr))
    networks = list(networks_result.scalars())

    hosts_result = await db.execute(select(Host).order_by(Host.first_seen.desc()))
    hosts = list(hosts_result.scalars())

    devices_result = await db.execute(select(NetworkDevice).order_by(NetworkDevice.ip_address))
    devices = list(devices_result.scalars())

    open_alerts_result = await db.execute(
        select(func.count()).select_from(Alert).where(Alert.acknowledged == False)  # noqa: E712
    )
    open_alerts: int = open_alerts_result.scalar_one() or 0

    critical_result = await db.execute(
        select(func.count())
        .select_from(Alert)
        .where(Alert.acknowledged == False, Alert.severity == "critical")  # noqa: E712
    )
    critical_alerts: int = critical_result.scalar_one() or 0

    md = render_executive_summary(networks, hosts, devices, open_alerts, critical_alerts)
    return PlainTextResponse(md, media_type=_MARKDOWN)


@router.get("/network/{network_id}", response_class=PlainTextResponse)
async def get_network_report(
    network_id: uuid.UUID,
    username: Annotated[str, Depends(_require_analyst)],
    db: AsyncSession = Depends(get_db),
) -> str:
    """Generate a Markdown report for a single network."""
    network = await db.get(Network, network_id)
    if network is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Network not found")

    hosts_result = await db.execute(select(Host).order_by(Host.fqdn))
    hosts = list(hosts_result.scalars())

    md = render_network_report(network, hosts)
    return PlainTextResponse(md, media_type=_MARKDOWN)


@router.get("/device/{device_id}", response_class=PlainTextResponse)
async def get_device_report(
    device_id: uuid.UUID,
    username: Annotated[str, Depends(_require_analyst)],
    db: AsyncSession = Depends(get_db),
) -> str:
    """Generate a Markdown report for a single network device."""
    device = await db.get(NetworkDevice, device_id)
    if device is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Device not found")

    md = render_device_report(device)
    return PlainTextResponse(md, media_type=_MARKDOWN)


@router.get("/export", response_class=PlainTextResponse)
async def export_all_docs(
    username: Annotated[str, Depends(_require_analyst)],
    db: AsyncSession = Depends(get_db),
) -> str:
    """Export all reports concatenated into a single Markdown document."""
    networks_result = await db.execute(select(Network).order_by(Network.cidr))
    networks = list(networks_result.scalars())

    hosts_result = await db.execute(select(Host).order_by(Host.first_seen.desc()))
    hosts = list(hosts_result.scalars())

    devices_result = await db.execute(select(NetworkDevice).order_by(NetworkDevice.ip_address))
    devices = list(devices_result.scalars())

    open_alerts_result = await db.execute(
        select(func.count()).select_from(Alert).where(Alert.acknowledged == False)  # noqa: E712
    )
    open_alerts: int = open_alerts_result.scalar_one() or 0

    critical_result = await db.execute(
        select(func.count())
        .select_from(Alert)
        .where(Alert.acknowledged == False, Alert.severity == "critical")  # noqa: E712
    )
    critical_alerts: int = critical_result.scalar_one() or 0

    sections: list[str] = [
        render_executive_summary(networks, hosts, devices, open_alerts, critical_alerts),
    ]

    for network in networks:
        sections.append(render_network_report(network, hosts))

    for device in devices:
        sections.append(render_device_report(device))

    md = "\n\n---\n\n".join(sections)
    return PlainTextResponse(md, media_type=_MARKDOWN)
