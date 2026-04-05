"""
Data ingestion API — /api/v1/data

Endpoints used by agents to push collected data to the server.
All routes require mTLS authentication (certificate fingerprint in header
set by the TLS termination layer or Nginx upstream).

Puppet-specific endpoint:
  POST /api/v1/data/puppet
    Accepts a batch of Puppet node facts and last-run reports collected by
    the DK agent running on the Puppet server host.

    Data flow:
      Puppet agents → Puppet server (writes fact cache + reports to vardir)
      DK agent (on Puppet server) → reads those files → submits here

    The DK agent (agent/collectors/puppet.py) is NOT a Puppet agent.
    It reads the YAML files already written by Puppet agents to the Puppet
    server's vardir, converts them to JSON, and submits them here.
    The server-side Puppet module then upserts each node into the inventory.

Generic ingestion endpoints (any DK agent):
  POST /api/v1/data/hosts             — host discovery results
  POST /api/v1/data/services          — discovered services (port/banner)
  POST /api/v1/data/packages          — installed packages
  POST /api/v1/data/vulnerabilities   — CVE findings
  POST /api/v1/data/interfaces        — network interface data
  POST /api/v1/data/scan-results      — raw nmap / network scan output
  POST /api/v1/data/device-configs    — network device configuration snapshots
  POST /api/v1/data/topology-edges    — discovered topology links (ARP/LLDP/CDP)
"""

from __future__ import annotations

import uuid
import logging
from datetime import datetime
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Header
from pydantic import BaseModel, Field
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, and_

from server.database import get_db
from server.models.agent import Agent
from server.models.host import Host, Service, Package
from server.models.network import Network, NetworkInterface, TopologyEdge, ScanResult
from server.models.device import NetworkDevice
from server.models.vulnerability import Vulnerability

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/data", tags=["data-ingestion"])


# ---------------------------------------------------------------------------
# Auth helper — resolve agent from certificate fingerprint header
# ---------------------------------------------------------------------------

async def _get_agent(
    db: AsyncSession,
    x_agent_fingerprint: str | None,
    x_agent_id: str | None,
) -> Agent:
    """
    Resolve the calling agent.

    The TLS termination layer (Nginx / Uvicorn with mTLS) forwards either:
      X-Agent-Fingerprint: <sha256 of client cert>
      X-Agent-ID:          <agent UUID>

    We accept either header for flexibility during the initial rollout.
    """
    if x_agent_fingerprint:
        result = await db.execute(
            select(Agent).where(Agent.certificate_fingerprint == x_agent_fingerprint)
        )
        agent = result.scalar_one_or_none()
        if agent:
            return agent

    if x_agent_id:
        try:
            agent_uuid = uuid.UUID(x_agent_id)
            agent = await db.get(Agent, agent_uuid)
            if agent:
                return agent
        except ValueError:
            pass

    raise HTTPException(status_code=401, detail="Agent not authenticated")


# ---------------------------------------------------------------------------
# Puppet data ingestion
# ---------------------------------------------------------------------------

class PuppetReport(BaseModel):
    """Last-run report data for a single Puppet node."""
    last_run: str | None = None          # ISO-8601 timestamp
    status: str | None = None            # "changed" | "unchanged" | "failed"
    environment: str | None = None
    puppet_version: str | None = None
    config_version: str | None = None


class PuppetNode(BaseModel):
    """
    Facts + report for a single Puppet-managed node.

    `facts` is a flat or nested dict of Facter values — same structure as
    the YAML files in the Puppet master's fact cache, converted to JSON.
    `report` is optional (present when the agent also collected run reports).
    """
    certname: str
    facts: dict[str, Any] = {}
    report: PuppetReport | None = None


class PuppetBatch(BaseModel):
    """
    Batch of Puppet node data submitted by an agent.
    An agent typically sends one batch per sync cycle.
    """
    nodes: list[PuppetNode]


class PuppetBatchResult(BaseModel):
    received: int
    imported: int
    errors: int


@router.post("/puppet", response_model=PuppetBatchResult)
async def ingest_puppet_data(
    batch: PuppetBatch,
    db: AsyncSession = Depends(get_db),
    x_agent_fingerprint: str | None = Header(None, alias="X-Agent-Fingerprint"),
    x_agent_id: str | None = Header(None, alias="X-Agent-ID"),
) -> PuppetBatchResult:
    """
    Receive a batch of Puppet node facts and reports from a DK agent.

    The DK agent is deployed on the Puppet server host.  After Puppet agents
    have finished their runs and written facts + reports to the Puppet server's
    vardir, the DK agent reads those YAML files, converts them to JSON, and
    POSTs them here.

    Authentication: mTLS — the DK agent certificate fingerprint or UUID must
    match a registered agent in the database.
    """
    agent = await _get_agent(db, x_agent_fingerprint, x_agent_id)

    from server.modules.registry import registry
    puppet_module = registry.get_module("builtin-puppet")

    if puppet_module is None:
        raise HTTPException(
            status_code=503,
            detail="Puppet module is not loaded on this server.",
        )

    imported = 0
    errors = 0
    for node in batch.nodes:
        try:
            facts: dict[str, Any] = dict(node.facts)
            # Merge report metadata into facts under private keys
            if node.report:
                if node.report.last_run:
                    facts["_puppet_last_run"] = node.report.last_run
                if node.report.status:
                    facts["_puppet_status"] = node.report.status
                if node.report.environment:
                    facts["_puppet_environment"] = node.report.environment
                if node.report.puppet_version:
                    facts["_puppet_puppet_version"] = node.report.puppet_version
                if node.report.config_version:
                    facts["_puppet_config_version"] = node.report.config_version

            await puppet_module._upsert_host(node.certname, facts, db)  # type: ignore[attr-defined]
            imported += 1
        except Exception:
            logger.exception(
                "Failed to import Puppet node %s submitted by agent %s",
                node.certname, agent.id,
            )
            errors += 1

    await db.commit()

    logger.info(
        "Puppet batch from agent %s: %d received, %d imported, %d errors",
        agent.id, len(batch.nodes), imported, errors,
    )
    return PuppetBatchResult(
        received=len(batch.nodes),
        imported=imported,
        errors=errors,
    )


# ---------------------------------------------------------------------------
# Shared result schema
# ---------------------------------------------------------------------------

class IngestionResult(BaseModel):
    received: int
    upserted: int
    errors: int


# ---------------------------------------------------------------------------
# Hosts
# ---------------------------------------------------------------------------

class HostRecord(BaseModel):
    """A single discovered host submitted by an agent."""
    fqdn: str | None = None
    ip_addresses: list[str] = Field(default_factory=list)
    os: str | None = None
    os_version: str | None = None


class HostBatch(BaseModel):
    hosts: list[HostRecord]


@router.post("/hosts", response_model=IngestionResult)
async def ingest_hosts(
    batch: HostBatch,
    db: AsyncSession = Depends(get_db),
    x_agent_fingerprint: str | None = Header(None, alias="X-Agent-Fingerprint"),
    x_agent_id: str | None = Header(None, alias="X-Agent-ID"),
) -> IngestionResult:
    """
    Receive a batch of discovered hosts from a DK agent.

    Upsert logic: match by FQDN (if present) or first IP address.
    The agent_id on the host is updated to the submitting agent.
    """
    agent = await _get_agent(db, x_agent_fingerprint, x_agent_id)
    upserted = 0
    errors = 0

    for rec in batch.hosts:
        try:
            # Resolve existing host by FQDN or any submitted IP address.
            primary_ip = rec.ip_addresses[0] if rec.ip_addresses else None
            host = await _resolve_host(db, rec.fqdn, primary_ip)

            now = datetime.utcnow()
            if host is None:
                host = Host(
                    fqdn=rec.fqdn,
                    ip_addresses=rec.ip_addresses,
                    os=rec.os,
                    os_version=rec.os_version,
                    agent_id=agent.id,
                    last_seen=now,
                )
                db.add(host)
            else:
                if rec.fqdn:
                    host.fqdn = rec.fqdn
                if rec.ip_addresses:
                    # Merge IP list (union, keep existing + new)
                    merged = list(set(host.ip_addresses) | set(rec.ip_addresses))
                    host.ip_addresses = merged
                if rec.os:
                    host.os = rec.os
                if rec.os_version:
                    host.os_version = rec.os_version
                host.agent_id = agent.id
                host.last_seen = now

            upserted += 1
        except Exception:
            logger.exception("Failed to upsert host from agent %s", agent.id)
            errors += 1

    await db.commit()
    logger.info("Host batch from agent %s: %d received, %d upserted, %d errors",
                agent.id, len(batch.hosts), upserted, errors)
    return IngestionResult(received=len(batch.hosts), upserted=upserted, errors=errors)


# ---------------------------------------------------------------------------
# Services
# ---------------------------------------------------------------------------

class ServiceRecord(BaseModel):
    """A service discovered on a host."""
    host_fqdn: str | None = None
    host_ip: str | None = None
    port: int
    protocol: str = "tcp"
    service_name: str | None = None
    version: str | None = None
    banner: str | None = None


class ServiceBatch(BaseModel):
    services: list[ServiceRecord]


@router.post("/services", response_model=IngestionResult)
async def ingest_services(
    batch: ServiceBatch,
    db: AsyncSession = Depends(get_db),
    x_agent_fingerprint: str | None = Header(None, alias="X-Agent-Fingerprint"),
    x_agent_id: str | None = Header(None, alias="X-Agent-ID"),
) -> IngestionResult:
    """
    Receive a batch of discovered services (open ports + banners).

    The service is matched to a host via FQDN or IP.  If the host is unknown,
    the service record is skipped and counted as an error.  Upsert is by
    (host_id, port, protocol).
    """
    agent = await _get_agent(db, x_agent_fingerprint, x_agent_id)
    upserted = 0
    errors = 0

    for rec in batch.services:
        try:
            host = await _resolve_host(db, rec.host_fqdn, rec.host_ip)
            if host is None:
                logger.warning(
                    "Service submission from agent %s references unknown host fqdn=%s ip=%s — skipped",
                    agent.id, rec.host_fqdn, rec.host_ip,
                )
                errors += 1
                continue

            result = await db.execute(
                select(Service).where(
                    and_(
                        Service.host_id == host.id,
                        Service.port == rec.port,
                        Service.protocol == rec.protocol,
                    )
                )
            )
            svc = result.scalar_one_or_none()

            if svc is None:
                svc = Service(
                    host_id=host.id,
                    port=rec.port,
                    protocol=rec.protocol,
                    service_name=rec.service_name,
                    version=rec.version,
                    banner=rec.banner,
                )
                db.add(svc)
            else:
                if rec.service_name:
                    svc.service_name = rec.service_name
                if rec.version:
                    svc.version = rec.version
                if rec.banner:
                    svc.banner = rec.banner

            upserted += 1
        except Exception:
            logger.exception("Failed to upsert service from agent %s", agent.id)
            errors += 1

    await db.commit()
    logger.info("Service batch from agent %s: %d received, %d upserted, %d errors",
                agent.id, len(batch.services), upserted, errors)
    return IngestionResult(received=len(batch.services), upserted=upserted, errors=errors)


# ---------------------------------------------------------------------------
# Packages
# ---------------------------------------------------------------------------

class PackageRecord(BaseModel):
    """An installed software package on a host."""
    host_fqdn: str | None = None
    host_ip: str | None = None
    name: str
    version: str | None = None
    package_manager: str | None = None   # apt, yum, pip, npm, …


class PackageBatch(BaseModel):
    packages: list[PackageRecord]


@router.post("/packages", response_model=IngestionResult)
async def ingest_packages(
    batch: PackageBatch,
    db: AsyncSession = Depends(get_db),
    x_agent_fingerprint: str | None = Header(None, alias="X-Agent-Fingerprint"),
    x_agent_id: str | None = Header(None, alias="X-Agent-ID"),
) -> IngestionResult:
    """
    Receive the installed package list for one or more hosts.

    Upsert is by (host_id, name, package_manager).
    """
    agent = await _get_agent(db, x_agent_fingerprint, x_agent_id)
    upserted = 0
    errors = 0

    for rec in batch.packages:
        try:
            host = await _resolve_host(db, rec.host_fqdn, rec.host_ip)
            if host is None:
                logger.warning(
                    "Package submission from agent %s references unknown host — skipped",
                    agent.id,
                )
                errors += 1
                continue

            result = await db.execute(
                select(Package).where(
                    and_(
                        Package.host_id == host.id,
                        Package.name == rec.name,
                        Package.package_manager == rec.package_manager,
                    )
                )
            )
            pkg = result.scalar_one_or_none()

            if pkg is None:
                pkg = Package(
                    host_id=host.id,
                    name=rec.name,
                    version=rec.version,
                    package_manager=rec.package_manager,
                )
                db.add(pkg)
            else:
                if rec.version:
                    pkg.version = rec.version

            upserted += 1
        except Exception:
            logger.exception("Failed to upsert package from agent %s", agent.id)
            errors += 1

    await db.commit()
    logger.info("Package batch from agent %s: %d received, %d upserted, %d errors",
                agent.id, len(batch.packages), upserted, errors)
    return IngestionResult(received=len(batch.packages), upserted=upserted, errors=errors)


# ---------------------------------------------------------------------------
# Vulnerabilities
# ---------------------------------------------------------------------------

class VulnerabilityRecord(BaseModel):
    """A CVE finding linked to a host (and optionally a package)."""
    host_fqdn: str | None = None
    host_ip: str | None = None
    package_name: str | None = None        # to link to specific package
    package_manager: str | None = None
    cve_id: str
    severity: str                          # critical | high | medium | low | none
    cvss_score: float | None = None
    description: str | None = None
    remediation: str | None = None


class VulnerabilityBatch(BaseModel):
    vulnerabilities: list[VulnerabilityRecord]


@router.post("/vulnerabilities", response_model=IngestionResult)
async def ingest_vulnerabilities(
    batch: VulnerabilityBatch,
    db: AsyncSession = Depends(get_db),
    x_agent_fingerprint: str | None = Header(None, alias="X-Agent-Fingerprint"),
    x_agent_id: str | None = Header(None, alias="X-Agent-ID"),
) -> IngestionResult:
    """
    Receive CVE findings from a DK agent.

    Upsert is by (host_id, cve_id).  If a package name is given, the record is
    also linked to the first matching package on that host.
    """
    agent = await _get_agent(db, x_agent_fingerprint, x_agent_id)
    upserted = 0
    errors = 0

    for rec in batch.vulnerabilities:
        try:
            host = await _resolve_host(db, rec.host_fqdn, rec.host_ip)
            if host is None:
                logger.warning(
                    "Vuln submission from agent %s references unknown host — skipped",
                    agent.id,
                )
                errors += 1
                continue

            # Optionally resolve package
            package_id: uuid.UUID | None = None
            if rec.package_name:
                pkg_q = select(Package).where(
                    and_(
                        Package.host_id == host.id,
                        Package.name == rec.package_name,
                    )
                )
                if rec.package_manager:
                    pkg_q = pkg_q.where(Package.package_manager == rec.package_manager)
                pkg_result = await db.execute(pkg_q)
                pkg = pkg_result.scalars().first()
                if pkg:
                    package_id = pkg.id

            result = await db.execute(
                select(Vulnerability).where(
                    and_(
                        Vulnerability.host_id == host.id,
                        Vulnerability.cve_id == rec.cve_id,
                    )
                )
            )
            vuln = result.scalar_one_or_none()

            if vuln is None:
                vuln = Vulnerability(
                    host_id=host.id,
                    package_id=package_id,
                    cve_id=rec.cve_id,
                    severity=rec.severity,
                    cvss_score=rec.cvss_score,
                    description=rec.description,
                    remediation=rec.remediation,
                )
                db.add(vuln)
            else:
                vuln.severity = rec.severity
                if rec.cvss_score is not None:
                    vuln.cvss_score = rec.cvss_score
                if rec.description:
                    vuln.description = rec.description
                if rec.remediation:
                    vuln.remediation = rec.remediation
                if package_id:
                    vuln.package_id = package_id

            upserted += 1
        except Exception:
            logger.exception("Failed to upsert vuln from agent %s", agent.id)
            errors += 1

    await db.commit()
    logger.info("Vuln batch from agent %s: %d received, %d upserted, %d errors",
                agent.id, len(batch.vulnerabilities), upserted, errors)
    return IngestionResult(received=len(batch.vulnerabilities), upserted=upserted, errors=errors)


# ---------------------------------------------------------------------------
# Network interfaces
# ---------------------------------------------------------------------------

class InterfaceRecord(BaseModel):
    """A network interface on a host."""
    host_fqdn: str | None = None
    host_ip: str | None = None
    name: str
    ip_address: str | None = None
    netmask: str | None = None
    mac_address: str | None = None
    interface_type: str | None = None    # ethernet, loopback, bridge, …
    is_up: bool = True


class InterfaceBatch(BaseModel):
    interfaces: list[InterfaceRecord]


@router.post("/interfaces", response_model=IngestionResult)
async def ingest_interfaces(
    batch: InterfaceBatch,
    db: AsyncSession = Depends(get_db),
    x_agent_fingerprint: str | None = Header(None, alias="X-Agent-Fingerprint"),
    x_agent_id: str | None = Header(None, alias="X-Agent-ID"),
) -> IngestionResult:
    """
    Receive network interface data for one or more hosts.

    Upsert is by (host_id, interface name).
    """
    agent = await _get_agent(db, x_agent_fingerprint, x_agent_id)
    upserted = 0
    errors = 0

    for rec in batch.interfaces:
        try:
            host = await _resolve_host(db, rec.host_fqdn, rec.host_ip)
            if host is None:
                logger.warning(
                    "Interface submission from agent %s references unknown host — skipped",
                    agent.id,
                )
                errors += 1
                continue

            result = await db.execute(
                select(NetworkInterface).where(
                    and_(
                        NetworkInterface.host_id == host.id,
                        NetworkInterface.name == rec.name,
                    )
                )
            )
            iface = result.scalar_one_or_none()

            if iface is None:
                iface = NetworkInterface(
                    host_id=host.id,
                    name=rec.name,
                    ip_address=rec.ip_address,
                    netmask=rec.netmask,
                    mac_address=rec.mac_address,
                    interface_type=rec.interface_type,
                    is_up=rec.is_up,
                )
                db.add(iface)
            else:
                if rec.ip_address:
                    iface.ip_address = rec.ip_address
                if rec.netmask:
                    iface.netmask = rec.netmask
                if rec.mac_address:
                    iface.mac_address = rec.mac_address
                if rec.interface_type:
                    iface.interface_type = rec.interface_type
                iface.is_up = rec.is_up

            upserted += 1
        except Exception:
            logger.exception("Failed to upsert interface from agent %s", agent.id)
            errors += 1

    await db.commit()
    logger.info("Interface batch from agent %s: %d received, %d upserted, %d errors",
                agent.id, len(batch.interfaces), upserted, errors)
    return IngestionResult(received=len(batch.interfaces), upserted=upserted, errors=errors)


# ---------------------------------------------------------------------------
# Scan results
# ---------------------------------------------------------------------------

class ScanResultRecord(BaseModel):
    """Result of a network scan (e.g. nmap)."""
    network_cidr: str | None = None        # if known
    started_at: datetime
    completed_at: datetime | None = None
    hosts_found: list[str] = Field(default_factory=list)
    raw_output: str | None = None


class ScanResultBatch(BaseModel):
    scan_results: list[ScanResultRecord]


@router.post("/scan-results", response_model=IngestionResult)
async def ingest_scan_results(
    batch: ScanResultBatch,
    db: AsyncSession = Depends(get_db),
    x_agent_fingerprint: str | None = Header(None, alias="X-Agent-Fingerprint"),
    x_agent_id: str | None = Header(None, alias="X-Agent-ID"),
) -> IngestionResult:
    """
    Receive raw network scan results from a DK agent.

    Each record is always inserted (not upserted) since a scan is a point-in-time
    snapshot.  If the CIDR is known, it is linked to an existing or newly created
    Network record.
    """
    agent = await _get_agent(db, x_agent_fingerprint, x_agent_id)
    upserted = 0
    errors = 0

    for rec in batch.scan_results:
        try:
            network_id: uuid.UUID | None = None
            if rec.network_cidr:
                net_result = await db.execute(
                    select(Network).where(Network.cidr == rec.network_cidr)
                )
                network = net_result.scalar_one_or_none()
                if network is None:
                    network = Network(cidr=rec.network_cidr)
                    db.add(network)
                    await db.flush()  # get id before referencing
                network_id = network.id

            scan = ScanResult(
                network_id=network_id,
                agent_id=agent.id,
                started_at=rec.started_at,
                completed_at=rec.completed_at,
                hosts_found=rec.hosts_found,
                raw_output=rec.raw_output,
            )
            db.add(scan)
            upserted += 1
        except Exception:
            logger.exception("Failed to insert scan result from agent %s", agent.id)
            errors += 1

    await db.commit()
    logger.info("Scan-result batch from agent %s: %d received, %d inserted, %d errors",
                agent.id, len(batch.scan_results), upserted, errors)
    return IngestionResult(received=len(batch.scan_results), upserted=upserted, errors=errors)


# ---------------------------------------------------------------------------
# Device configs
# ---------------------------------------------------------------------------

class DeviceConfigRecord(BaseModel):
    """Configuration snapshot for a network device (router/switch/firewall)."""
    ip_address: str
    hostname: str | None = None
    device_type: str | None = None         # router | switch | firewall | ap
    vendor: str | None = None
    model: str | None = None
    firmware_version: str | None = None
    config_snapshot: str | None = None     # sanitized running config
    structured_data: str | None = None     # JSON: interfaces, vlans, routes, neighbors


class DeviceConfigBatch(BaseModel):
    device_configs: list[DeviceConfigRecord]


@router.post("/device-configs", response_model=IngestionResult)
async def ingest_device_configs(
    batch: DeviceConfigBatch,
    db: AsyncSession = Depends(get_db),
    x_agent_fingerprint: str | None = Header(None, alias="X-Agent-Fingerprint"),
    x_agent_id: str | None = Header(None, alias="X-Agent-ID"),
) -> IngestionResult:
    """
    Receive network device configuration snapshots from a DK agent.

    Upsert is by ip_address.
    """
    agent = await _get_agent(db, x_agent_fingerprint, x_agent_id)
    upserted = 0
    errors = 0

    for rec in batch.device_configs:
        try:
            result = await db.execute(
                select(NetworkDevice).where(NetworkDevice.ip_address == rec.ip_address)
            )
            device = result.scalar_one_or_none()

            now = datetime.utcnow()
            if device is None:
                device = NetworkDevice(
                    ip_address=rec.ip_address,
                    hostname=rec.hostname,
                    device_type=rec.device_type,
                    vendor=rec.vendor,
                    model=rec.model,
                    firmware_version=rec.firmware_version,
                    config_snapshot=rec.config_snapshot,
                    structured_data=rec.structured_data,
                    last_seen=now,
                )
                db.add(device)
            else:
                if rec.hostname:
                    device.hostname = rec.hostname
                if rec.device_type:
                    device.device_type = rec.device_type
                if rec.vendor:
                    device.vendor = rec.vendor
                if rec.model:
                    device.model = rec.model
                if rec.firmware_version:
                    device.firmware_version = rec.firmware_version
                if rec.config_snapshot:
                    device.config_snapshot = rec.config_snapshot
                if rec.structured_data:
                    device.structured_data = rec.structured_data
                device.last_seen = now

            upserted += 1
        except Exception:
            logger.exception("Failed to upsert device config from agent %s", agent.id)
            errors += 1

    await db.commit()
    logger.info("Device-config batch from agent %s: %d received, %d upserted, %d errors",
                agent.id, len(batch.device_configs), upserted, errors)
    return IngestionResult(received=len(batch.device_configs), upserted=upserted, errors=errors)


# ---------------------------------------------------------------------------
# Topology edges
# ---------------------------------------------------------------------------

class TopologyEdgeRecord(BaseModel):
    """A link discovered between two hosts (ARP, LLDP, CDP, routing)."""
    source_fqdn: str | None = None
    source_ip: str | None = None
    target_fqdn: str | None = None
    target_ip: str | None = None
    edge_type: str                         # arp | lldp | cdp | routing


class TopologyEdgeBatch(BaseModel):
    topology_edges: list[TopologyEdgeRecord]


@router.post("/topology-edges", response_model=IngestionResult)
async def ingest_topology_edges(
    batch: TopologyEdgeBatch,
    db: AsyncSession = Depends(get_db),
    x_agent_fingerprint: str | None = Header(None, alias="X-Agent-Fingerprint"),
    x_agent_id: str | None = Header(None, alias="X-Agent-ID"),
) -> IngestionResult:
    """
    Receive discovered topology links from a DK agent.

    Both source and target hosts must already exist.  Upsert is by
    (source_host_id, target_host_id, edge_type).
    """
    agent = await _get_agent(db, x_agent_fingerprint, x_agent_id)
    upserted = 0
    errors = 0

    for rec in batch.topology_edges:
        try:
            source = await _resolve_host(db, rec.source_fqdn, rec.source_ip)
            target = await _resolve_host(db, rec.target_fqdn, rec.target_ip)

            if source is None or target is None:
                logger.warning(
                    "Topology edge from agent %s references unknown host(s) "
                    "source=%s/%s target=%s/%s — skipped",
                    agent.id, rec.source_fqdn, rec.source_ip, rec.target_fqdn, rec.target_ip,
                )
                errors += 1
                continue

            result = await db.execute(
                select(TopologyEdge).where(
                    and_(
                        TopologyEdge.source_host_id == source.id,
                        TopologyEdge.target_host_id == target.id,
                        TopologyEdge.edge_type == rec.edge_type,
                    )
                )
            )
            edge = result.scalar_one_or_none()

            if edge is None:
                edge = TopologyEdge(
                    source_host_id=source.id,
                    target_host_id=target.id,
                    edge_type=rec.edge_type,
                )
                db.add(edge)

            upserted += 1
        except Exception:
            logger.exception("Failed to upsert topology edge from agent %s", agent.id)
            errors += 1

    await db.commit()
    logger.info("Topology-edge batch from agent %s: %d received, %d upserted, %d errors",
                agent.id, len(batch.topology_edges), upserted, errors)
    return IngestionResult(received=len(batch.topology_edges), upserted=upserted, errors=errors)


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

async def _resolve_host(
    db: AsyncSession,
    fqdn: str | None,
    ip: str | None,
) -> Host | None:
    """
    Look up a Host by FQDN or IP address.

    Returns None when the host is not found — callers decide whether to skip
    or auto-create.
    """
    if fqdn:
        result = await db.execute(select(Host).where(Host.fqdn == fqdn))
        host = result.scalar_one_or_none()
        if host:
            return host

    if ip:
        from sqlalchemy import cast
        from sqlalchemy.dialects.postgresql import ARRAY as PG_ARRAY
        from sqlalchemy import String
        result = await db.execute(
            select(Host).where(
                Host.ip_addresses.overlap(  # type: ignore[attr-defined]
                    cast([ip], PG_ARRAY(String))
                )
            )
        )
        return result.scalars().first()

    return None
