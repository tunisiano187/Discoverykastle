"""
Inventory API — /api/v1/inventory
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, ConfigDict
from sqlalchemy import select, func
from sqlalchemy.ext.asyncio import AsyncSession

from server.database import get_db
from server.models.host import Host, Service
from server.models.network import Network, ScanResult
from server.models.device import NetworkDevice
from server.models.vulnerability import Vulnerability
from server.models.agent import AuthorizationRequest
from server.models.team import Team
from server.modules.registry import registry
from server.services.auth import require_operator
from server.services.ip_utils import classify_cidr, cidr_contains_public_ips

router = APIRouter(prefix="/api/v1/inventory", tags=["inventory"])


# ------------------------------------------------------------------
# Pydantic schemas
# ------------------------------------------------------------------

class ServiceOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    port: int
    protocol: str
    service_name: str | None
    version: str | None


class TeamAssignment(BaseModel):
    team_id: uuid.UUID | None = None


class HostSummary(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    fqdn: str | None
    ip_addresses: list[str]
    os: str | None
    os_version: str | None
    team_id: uuid.UUID | None = None
    first_seen: datetime
    last_seen: datetime


class HostDetail(HostSummary):
    services: list[ServiceOut] = []
    # Enriched fields from modules
    service_count: int = 0
    package_count: int = 0
    vuln_counts: dict[str, int] = {}
    extra: dict = {}


class NetworkOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    cidr: str
    description: str | None
    domain_name: str | None = None
    scan_authorized: bool
    scan_depth: int
    # "private" | "public" | "mixed" | "unknown" — derived from the CIDR
    ip_class: str = "unknown"
    team_id: uuid.UUID | None = None
    created_at: datetime


class AuthorizationRequestOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    agent_id: uuid.UUID
    request_type: str
    details: dict
    status: str
    requested_at: datetime
    resolved_at: datetime | None = None
    resolved_by: str | None = None
    expires_at: datetime | None = None


class ScanResultOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    network_id: uuid.UUID | None
    agent_id: uuid.UUID
    started_at: datetime
    completed_at: datetime | None
    hosts_found: list[str]
    created_at: datetime


class DeviceOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    ip_address: str
    hostname: str | None
    vendor: str | None
    model: str | None
    firmware_version: str | None
    device_type: str | None
    last_seen: datetime


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
    team_id: uuid.UUID | None = Query(None, description="Filter by team UUID"),
    limit: int = Query(200, ge=1, le=2000),
    offset: int = Query(0, ge=0),
    db: AsyncSession = Depends(get_db),
) -> list[Host]:
    stmt = select(Host).order_by(Host.last_seen.desc()).limit(limit).offset(offset)
    if os:
        stmt = stmt.where(Host.os.ilike(f"%{os}%"))
    if ip:
        stmt = stmt.where(Host.ip_addresses.contains([ip]))
    if team_id:
        stmt = stmt.where(Host.team_id == team_id)
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


@router.patch("/hosts/{host_id}/team", response_model=HostSummary)
async def assign_host_team(
    host_id: uuid.UUID,
    body: TeamAssignment,
    _: Annotated[str, Depends(require_operator)],
    db: AsyncSession = Depends(get_db),
) -> Host:
    """
    Assign or unassign a host to/from a team.

    Pass ``{"team_id": "<uuid>"}`` to assign, or ``{"team_id": null}`` to unassign.
    Requires operator role.
    """
    host = await db.get(Host, host_id)
    if not host:
        raise HTTPException(status_code=404, detail="Host not found")

    if body.team_id is not None:
        team = await db.get(Team, body.team_id)
        if not team:
            raise HTTPException(status_code=404, detail="Team not found")

    host.team_id = body.team_id
    await db.commit()
    await db.refresh(host)
    return host


# ------------------------------------------------------------------
# Networks
# ------------------------------------------------------------------

@router.get("/networks", response_model=list[NetworkOut])
async def list_networks(
    authorized_only: bool = Query(False),
    team_id: uuid.UUID | None = Query(None, description="Filter by team UUID"),
    db: AsyncSession = Depends(get_db),
) -> list[NetworkOut]:
    stmt = select(Network).order_by(Network.cidr)
    if authorized_only:
        stmt = stmt.where(Network.scan_authorized == True)  # noqa: E712
    if team_id:
        stmt = stmt.where(Network.team_id == team_id)
    result = await db.execute(stmt)
    networks = list(result.scalars())
    return [
        NetworkOut(
            id=n.id,
            cidr=n.cidr,
            description=n.description,
            domain_name=n.domain_name,
            scan_authorized=n.scan_authorized,
            scan_depth=n.scan_depth,
            ip_class=classify_cidr(n.cidr),
            team_id=n.team_id,
            created_at=n.created_at,
        )
        for n in networks
    ]


@router.patch("/networks/{network_id}/team", response_model=NetworkOut)
async def assign_network_team(
    network_id: uuid.UUID,
    body: TeamAssignment,
    _: Annotated[str, Depends(require_operator)],
    db: AsyncSession = Depends(get_db),
) -> NetworkOut:
    """
    Assign or unassign a network to/from a team.

    Pass ``{"team_id": "<uuid>"}`` to assign, or ``{"team_id": null}`` to unassign.
    Requires operator role.
    """
    network = await db.get(Network, network_id)
    if not network:
        raise HTTPException(status_code=404, detail="Network not found")

    if body.team_id is not None:
        team = await db.get(Team, body.team_id)
        if not team:
            raise HTTPException(status_code=404, detail="Team not found")

    network.team_id = body.team_id
    await db.commit()
    await db.refresh(network)
    return NetworkOut(
        id=network.id,
        cidr=network.cidr,
        description=network.description,
        domain_name=network.domain_name,
        scan_authorized=network.scan_authorized,
        scan_depth=network.scan_depth,
        ip_class=classify_cidr(network.cidr),
        team_id=network.team_id,
        created_at=network.created_at,
    )


@router.post("/networks/{network_id}/request-public-scan", response_model=AuthorizationRequestOut)
async def request_public_scan(
    network_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
) -> AuthorizationRequest:
    """
    Create an authorization request to scan a public (non-RFC-1918) network.

    For private networks the endpoint returns 400 — no explicit approval needed.
    For public CIDRs a pending AuthorizationRequest is created and must be
    approved by an administrator before scanning can proceed.
    """
    from server.config import settings

    network = await db.get(Network, network_id)
    if not network:
        raise HTTPException(status_code=404, detail="Network not found")

    if not cidr_contains_public_ips(network.cidr):
        raise HTTPException(
            status_code=400,
            detail=(
                f"{network.cidr} is a private address range — "
                "no authorization request needed."
            ),
        )

    if not settings.require_public_scan_authorization:
        # Authorization requirement disabled globally — auto-approve
        network.scan_authorized = True
        await db.commit()
        raise HTTPException(
            status_code=400,
            detail=(
                "Public scan authorization is disabled "
                "(DKASTLE_REQUIRE_PUBLIC_SCAN_AUTHORIZATION=false). "
                "Network has been automatically authorized."
            ),
        )

    # Check for an existing pending request to avoid duplicates
    existing = await db.execute(
        select(AuthorizationRequest).where(
            AuthorizationRequest.request_type == "public_scan",
            AuthorizationRequest.status == "pending",
            AuthorizationRequest.details["network_id"].as_string() == str(network_id),
        )
    )
    pending = existing.scalar_one_or_none()
    if pending:
        raise HTTPException(
            status_code=409,
            detail="A pending authorization request already exists for this network.",
        )

    # Create a dummy agent_id using a nil UUID when no agent is involved
    # (request comes from a human / UI)
    _nil_uuid = uuid.UUID("00000000-0000-0000-0000-000000000000")

    req = AuthorizationRequest(
        agent_id=_nil_uuid,
        request_type="public_scan",
        status="pending",
        details={
            "network_id": str(network_id),
            "cidr": network.cidr,
            "ip_class": classify_cidr(network.cidr),
            "reason": "Manual request via API",
        },
    )
    db.add(req)
    await db.commit()
    await db.refresh(req)
    return req


# ------------------------------------------------------------------
# Authorization requests (human approval workflow)
# ------------------------------------------------------------------

@router.get("/authorization-requests", response_model=list[AuthorizationRequestOut])
async def list_authorization_requests(
    status: str | None = Query(None, description="Filter by status: pending|approved|denied"),
    db: AsyncSession = Depends(get_db),
) -> list[AuthorizationRequest]:
    """List all authorization requests (public scan approvals, agent deploy approvals, …)."""
    stmt = select(AuthorizationRequest).order_by(AuthorizationRequest.requested_at.desc())
    if status:
        stmt = stmt.where(AuthorizationRequest.status == status)
    result = await db.execute(stmt)
    return list(result.scalars())


@router.post(
    "/authorization-requests/{request_id}/approve",
    response_model=AuthorizationRequestOut,
)
async def approve_authorization_request(
    request_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
) -> AuthorizationRequest:
    """
    Approve a pending authorization request.

    For public_scan requests this also sets Network.scan_authorized = True.
    """
    req = await db.get(AuthorizationRequest, request_id)
    if not req:
        raise HTTPException(status_code=404, detail="Authorization request not found")
    if req.status != "pending":
        raise HTTPException(
            status_code=400,
            detail=f"Request is already {req.status}.",
        )

    req.status = "approved"
    req.resolved_at = datetime.utcnow()

    # If this is a public scan request, authorize the network
    if req.request_type == "public_scan":
        network_id_str = req.details.get("network_id")
        if network_id_str:
            network = await db.get(Network, uuid.UUID(network_id_str))
            if network:
                network.scan_authorized = True

    await db.commit()
    await db.refresh(req)
    return req


@router.post(
    "/authorization-requests/{request_id}/deny",
    response_model=AuthorizationRequestOut,
)
async def deny_authorization_request(
    request_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
) -> AuthorizationRequest:
    """Deny a pending authorization request."""
    req = await db.get(AuthorizationRequest, request_id)
    if not req:
        raise HTTPException(status_code=404, detail="Authorization request not found")
    if req.status != "pending":
        raise HTTPException(
            status_code=400,
            detail=f"Request is already {req.status}.",
        )

    req.status = "denied"
    req.resolved_at = datetime.utcnow()
    await db.commit()
    await db.refresh(req)
    return req


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
async def inventory_stats(
    team_id: uuid.UUID | None = Query(None, description="Scope stats to a specific team"),
    db: AsyncSession = Depends(get_db),
) -> InventoryStats:
    host_q = select(func.count()).select_from(Host)
    net_q = select(func.count()).select_from(Network)
    vuln_q = select(Vulnerability.severity, func.count()).group_by(Vulnerability.severity)
    os_q = select(Host.os, func.count()).where(Host.os.isnot(None)).group_by(Host.os)

    if team_id:
        host_q = host_q.where(Host.team_id == team_id)
        net_q = net_q.where(Network.team_id == team_id)
        vuln_q = vuln_q.join(Host, Vulnerability.host_id == Host.id).where(Host.team_id == team_id)
        os_q = os_q.where(Host.team_id == team_id)

    total_hosts = await db.scalar(host_q) or 0
    total_networks = await db.scalar(net_q) or 0
    total_devices = await db.scalar(select(func.count()).select_from(NetworkDevice)) or 0
    total_vulns = await db.scalar(select(func.count()).select_from(Vulnerability)) or 0

    vuln_rows = await db.execute(vuln_q)
    vuln_by_severity = {row[0]: row[1] for row in vuln_rows}

    os_rows = await db.execute(os_q)
    os_distribution = {row[0]: row[1] for row in os_rows}

    return InventoryStats(
        total_hosts=total_hosts,
        total_networks=total_networks,
        total_devices=total_devices,
        total_vulnerabilities=total_vulns,
        vuln_by_severity=vuln_by_severity,
        os_distribution=os_distribution,
    )


# ------------------------------------------------------------------
# Scan results
# ------------------------------------------------------------------

@router.get("/scan-results", response_model=list[ScanResultOut])
async def list_scan_results(
    network_id: uuid.UUID | None = Query(None, description="Filter by network UUID"),
    limit: int = Query(50, ge=1, le=500, description="Max results to return (newest first)"),
    db: AsyncSession = Depends(get_db),
) -> list[ScanResult]:
    """
    List scan results, ordered newest-first.

    Optional filter: ``network_id`` restricts to a single network.
    """
    from sqlalchemy import desc

    q = select(ScanResult).order_by(desc(ScanResult.created_at)).limit(limit)
    if network_id is not None:
        q = q.where(ScanResult.network_id == network_id)
    rows = await db.execute(q)
    return list(rows.scalars())


@router.get("/networks/{network_id}/scan-results", response_model=list[ScanResultOut])
async def list_network_scan_results(
    network_id: uuid.UUID,
    limit: int = Query(20, ge=1, le=200, description="Max results to return (newest first)"),
    db: AsyncSession = Depends(get_db),
) -> list[ScanResult]:
    """
    List scan results for a specific network, ordered newest-first.

    Returns 404 when the network does not exist.
    """
    from sqlalchemy import desc

    network = await db.get(Network, network_id)
    if not network:
        raise HTTPException(status_code=404, detail="Network not found")

    q = (
        select(ScanResult)
        .where(ScanResult.network_id == network_id)
        .order_by(desc(ScanResult.created_at))
        .limit(limit)
    )
    rows = await db.execute(q)
    return list(rows.scalars())
