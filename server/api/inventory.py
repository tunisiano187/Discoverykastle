"""
Inventory API — /api/v1/inventory
"""

from __future__ import annotations

import uuid
from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel
from sqlalchemy import select, func
from sqlalchemy.ext.asyncio import AsyncSession

from server.database import get_db
from server.models.host import Host, Service
from server.models.network import Network
from server.models.device import NetworkDevice
from server.models.vulnerability import Vulnerability
from server.modules.registry import registry

router = APIRouter(prefix="/api/v1/inventory", tags=["inventory"])


# ------------------------------------------------------------------
# Pydantic schemas
# ------------------------------------------------------------------

class ServiceOut(BaseModel):
    id: uuid.UUID
    port: int
    protocol: str
    service_name: str | None
    version: str | None

    class Config:
        from_attributes = True


class HostSummary(BaseModel):
    id: uuid.UUID
    fqdn: str | None
    ip_addresses: list[str]
    os: str | None
    os_version: str | None
    first_seen: datetime
    last_seen: datetime

    class Config:
        from_attributes = True


class HostDetail(HostSummary):
    services: list[ServiceOut] = []
    # Enriched fields from modules
    service_count: int = 0
    package_count: int = 0
    vuln_counts: dict[str, int] = {}
    extra: dict = {}


class NetworkOut(BaseModel):
    id: uuid.UUID
    cidr: str
    description: str | None
    scan_authorized: bool
    scan_depth: int
    created_at: datetime

    class Config:
        from_attributes = True


class DeviceOut(BaseModel):
    id: uuid.UUID
    ip_address: str
    hostname: str | None
    vendor: str | None
    model: str | None
    firmware_version: str | None
    device_type: str | None
    last_seen: datetime

    class Config:
        from_attributes = True


class DeviceDetail(DeviceOut):
    config_snapshot: str | None
    structured_data: str | None


class InventoryStats(BaseModel):
    total_hosts: int
    total_networks: int
    total_devices: int
    total_vulnerabilities: int
    vuln_by_severity: dict[str, int]
    os_distribution: dict[str, int]


# ------------------------------------------------------------------
# Hosts
# ------------------------------------------------------------------

@router.get("/hosts", response_model=list[HostSummary])
async def list_hosts(
    os: str | None = Query(None, description="Filter by OS (partial match)"),
    ip: str | None = Query(None, description="Filter by IP address"),
    limit: int = Query(200, ge=1, le=2000),
    offset: int = Query(0, ge=0),
    db: AsyncSession = Depends(get_db),
) -> list[Host]:
    stmt = select(Host).order_by(Host.last_seen.desc()).limit(limit).offset(offset)
    if os:
        stmt = stmt.where(Host.os.ilike(f"%{os}%"))
    if ip:
        stmt = stmt.where(Host.ip_addresses.contains([ip]))
    result = await db.execute(stmt)
    return list(result.scalars())


@router.get("/hosts/{host_id}", response_model=HostDetail)
async def get_host(host_id: uuid.UUID, db: AsyncSession = Depends(get_db)) -> HostDetail:
    host = await db.get(Host, host_id)
    if not host:
        raise HTTPException(status_code=404, detail="Host not found")

    # Load services
    svc_result = await db.execute(select(Service).where(Service.host_id == host_id))
    services = list(svc_result.scalars())

    # Module enrichment
    extra = await registry.collect_inventory_extra(str(host_id), db)

    return HostDetail(
        id=host.id,
        fqdn=host.fqdn,
        ip_addresses=host.ip_addresses,
        os=host.os,
        os_version=host.os_version,
        first_seen=host.first_seen,
        last_seen=host.last_seen,
        services=[ServiceOut.model_validate(s) for s in services],
        service_count=extra.pop("service_count", len(services)),
        package_count=extra.pop("package_count", 0),
        vuln_counts=extra.pop("vuln_counts", {}),
        extra=extra,
    )


# ------------------------------------------------------------------
# Networks
# ------------------------------------------------------------------

@router.get("/networks", response_model=list[NetworkOut])
async def list_networks(
    authorized_only: bool = Query(False),
    db: AsyncSession = Depends(get_db),
) -> list[Network]:
    stmt = select(Network).order_by(Network.cidr)
    if authorized_only:
        stmt = stmt.where(Network.scan_authorized == True)  # noqa: E712
    result = await db.execute(stmt)
    return list(result.scalars())


# ------------------------------------------------------------------
# Devices
# ------------------------------------------------------------------

@router.get("/devices", response_model=list[DeviceOut])
async def list_devices(
    vendor: str | None = Query(None),
    device_type: str | None = Query(None),
    db: AsyncSession = Depends(get_db),
) -> list[NetworkDevice]:
    stmt = select(NetworkDevice).order_by(NetworkDevice.last_seen.desc())
    if vendor:
        stmt = stmt.where(NetworkDevice.vendor.ilike(f"%{vendor}%"))
    if device_type:
        stmt = stmt.where(NetworkDevice.device_type == device_type)
    result = await db.execute(stmt)
    return list(result.scalars())


@router.get("/devices/{device_id}", response_model=DeviceDetail)
async def get_device(device_id: uuid.UUID, db: AsyncSession = Depends(get_db)) -> NetworkDevice:
    device = await db.get(NetworkDevice, device_id)
    if not device:
        raise HTTPException(status_code=404, detail="Device not found")
    return device


# ------------------------------------------------------------------
# Stats
# ------------------------------------------------------------------

@router.get("/stats", response_model=InventoryStats)
async def inventory_stats(db: AsyncSession = Depends(get_db)) -> InventoryStats:
    total_hosts = await db.scalar(select(func.count()).select_from(Host)) or 0
    total_networks = await db.scalar(select(func.count()).select_from(Network)) or 0
    total_devices = await db.scalar(select(func.count()).select_from(NetworkDevice)) or 0
    total_vulns = await db.scalar(select(func.count()).select_from(Vulnerability)) or 0

    vuln_rows = await db.execute(
        select(Vulnerability.severity, func.count()).group_by(Vulnerability.severity)
    )
    vuln_by_severity = {row[0]: row[1] for row in vuln_rows}

    os_rows = await db.execute(
        select(Host.os, func.count()).where(Host.os.isnot(None)).group_by(Host.os)
    )
    os_distribution = {row[0]: row[1] for row in os_rows}

    return InventoryStats(
        total_hosts=total_hosts,
        total_networks=total_networks,
        total_devices=total_devices,
        total_vulnerabilities=total_vulns,
        vuln_by_severity=vuln_by_severity,
        os_distribution=os_distribution,
    )
