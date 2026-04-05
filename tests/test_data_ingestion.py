"""
Tests for the data ingestion API — /api/v1/data/*

These are unit/integration tests that exercise the ingestion endpoints
using an in-memory SQLite database (via SQLAlchemy's async engine) and
a TestClient that bypasses the agent-auth header check.

Because SQLite does not support PostgreSQL ARRAY operators we mock the
_resolve_host helper and the ARRAY overlap call so the core upsert logic
can still be tested portably.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from unittest.mock import AsyncMock, patch, MagicMock

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy.ext.asyncio import AsyncSession

from server.api.data import (
    IngestionResult,
    HostBatch,
    HostRecord,
    ServiceBatch,
    ServiceRecord,
    PackageBatch,
    PackageRecord,
    VulnerabilityBatch,
    VulnerabilityRecord,
    InterfaceBatch,
    InterfaceRecord,
    ScanResultBatch,
    ScanResultRecord,
    DeviceConfigBatch,
    DeviceConfigRecord,
    TopologyEdgeBatch,
    TopologyEdgeRecord,
)
from server.models.agent import Agent
from server.models.host import Host, Service, Package
from server.models.network import NetworkInterface, TopologyEdge, ScanResult, Network
from server.models.device import NetworkDevice
from server.models.vulnerability import Vulnerability


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_agent() -> Agent:
    agent = Agent(
        id=uuid.uuid4(),
        certificate_fingerprint="deadbeef" * 8,
        hostname="test-agent",
        ip_address="10.0.0.1",
        status="online",
    )
    return agent


def _make_host(fqdn: str = "host.example.com", ips: list[str] | None = None) -> Host:
    host = Host(
        id=uuid.uuid4(),
        fqdn=fqdn,
        ip_addresses=ips or ["10.1.1.1"],
        os="Linux",
        os_version="22.04",
    )
    return host


# ---------------------------------------------------------------------------
# _get_agent helper
# ---------------------------------------------------------------------------

class TestGetAgentHelper:
    """Unit tests for the _get_agent auth helper."""

    @pytest.mark.asyncio
    async def test_resolves_by_fingerprint(self) -> None:
        from server.api.data import _get_agent

        agent = _make_agent()
        mock_db = AsyncMock(spec=AsyncSession)
        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = agent
        mock_db.execute = AsyncMock(return_value=mock_result)

        result = await _get_agent(mock_db, agent.certificate_fingerprint, None)
        assert result is agent

    @pytest.mark.asyncio
    async def test_resolves_by_agent_id(self) -> None:
        from server.api.data import _get_agent

        agent = _make_agent()
        mock_db = AsyncMock(spec=AsyncSession)
        # First execute (fingerprint lookup) returns None
        mock_result_none = MagicMock()
        mock_result_none.scalar_one_or_none.return_value = None
        mock_db.execute = AsyncMock(return_value=mock_result_none)
        mock_db.get = AsyncMock(return_value=agent)

        result = await _get_agent(mock_db, None, str(agent.id))
        assert result is agent

    @pytest.mark.asyncio
    async def test_raises_401_when_no_match(self) -> None:
        from server.api.data import _get_agent
        from fastapi import HTTPException

        mock_db = AsyncMock(spec=AsyncSession)
        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = None
        mock_db.execute = AsyncMock(return_value=mock_result)
        mock_db.get = AsyncMock(return_value=None)

        with pytest.raises(HTTPException) as exc_info:
            await _get_agent(mock_db, None, None)
        assert exc_info.value.status_code == 401


# ---------------------------------------------------------------------------
# _resolve_host helper
# ---------------------------------------------------------------------------

class TestResolveHostHelper:
    @pytest.mark.asyncio
    async def test_resolves_by_fqdn(self) -> None:
        from server.api.data import _resolve_host

        host = _make_host()
        mock_db = AsyncMock(spec=AsyncSession)
        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = host
        mock_db.execute = AsyncMock(return_value=mock_result)

        result = await _resolve_host(mock_db, "host.example.com", None)
        assert result is host

    @pytest.mark.asyncio
    async def test_returns_none_when_not_found(self) -> None:
        from server.api.data import _resolve_host

        mock_db = AsyncMock(spec=AsyncSession)
        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = None
        mock_result.scalars.return_value.first.return_value = None
        mock_db.execute = AsyncMock(return_value=mock_result)

        result = await _resolve_host(mock_db, None, None)
        assert result is None


# ---------------------------------------------------------------------------
# Host ingestion
# ---------------------------------------------------------------------------

class TestIngestHosts:
    @pytest.mark.asyncio
    async def test_upsert_new_host(self) -> None:
        from server.api import data as data_module

        agent = _make_agent()
        mock_db = AsyncMock(spec=AsyncSession)

        agent_result = MagicMock()
        agent_result.scalar_one_or_none.return_value = agent
        mock_db.execute = AsyncMock(return_value=agent_result)
        mock_db.add = MagicMock()
        mock_db.commit = AsyncMock()

        # _resolve_host returns None → new host should be created
        with patch.object(data_module, "_resolve_host", new=AsyncMock(return_value=None)):
            batch = HostBatch(hosts=[
                HostRecord(fqdn="new.host.com", ip_addresses=["192.168.1.50"], os="Linux", os_version="20.04")
            ])
            result = await data_module.ingest_hosts(
                batch,
                db=mock_db,
                x_agent_fingerprint=agent.certificate_fingerprint,
                x_agent_id=None,
            )

        assert result.received == 1
        assert result.upserted == 1
        assert result.errors == 0
        mock_db.add.assert_called_once()

    @pytest.mark.asyncio
    async def test_upsert_existing_host(self) -> None:
        from server.api import data as data_module

        agent = _make_agent()
        existing_host = _make_host(fqdn="existing.host.com", ips=["10.0.0.5"])
        mock_db = AsyncMock(spec=AsyncSession)

        agent_result = MagicMock()
        agent_result.scalar_one_or_none.return_value = agent
        mock_db.execute = AsyncMock(return_value=agent_result)
        mock_db.add = MagicMock()
        mock_db.commit = AsyncMock()

        # _resolve_host returns existing host
        with patch.object(data_module, "_resolve_host", new=AsyncMock(return_value=existing_host)):
            batch = HostBatch(hosts=[
                HostRecord(fqdn="existing.host.com", ip_addresses=["10.0.0.5", "10.0.0.6"], os="Windows")
            ])
            result = await data_module.ingest_hosts(
                batch,
                db=mock_db,
                x_agent_fingerprint=agent.certificate_fingerprint,
                x_agent_id=None,
            )

        assert result.received == 1
        assert result.upserted == 1
        assert result.errors == 0
        # Existing host OS should be updated
        assert existing_host.os == "Windows"
        # IP list should be merged
        assert "10.0.0.6" in existing_host.ip_addresses


# ---------------------------------------------------------------------------
# Service ingestion
# ---------------------------------------------------------------------------

class TestIngestServices:
    @pytest.mark.asyncio
    async def test_skips_unknown_host(self) -> None:
        from server.api.data import ingest_services

        agent = _make_agent()
        mock_db = AsyncMock(spec=AsyncSession)

        agent_result = MagicMock()
        agent_result.scalar_one_or_none.return_value = agent

        # _resolve_host returns None
        no_host = MagicMock()
        no_host.scalar_one_or_none.return_value = None
        no_host.scalars.return_value.first.return_value = None

        mock_db.execute = AsyncMock(side_effect=[agent_result, no_host, no_host])
        mock_db.add = MagicMock()
        mock_db.commit = AsyncMock()

        batch = ServiceBatch(services=[
            ServiceRecord(host_ip="99.99.99.99", port=22, protocol="tcp", service_name="ssh")
        ])
        result = await ingest_services(
            batch,
            db=mock_db,
            x_agent_fingerprint=agent.certificate_fingerprint,
            x_agent_id=None,
        )

        assert result.received == 1
        assert result.upserted == 0
        assert result.errors == 1

    @pytest.mark.asyncio
    async def test_inserts_new_service(self) -> None:
        from server.api.data import ingest_services

        agent = _make_agent()
        host = _make_host()
        mock_db = AsyncMock(spec=AsyncSession)

        agent_result = MagicMock()
        agent_result.scalar_one_or_none.return_value = agent

        host_result = MagicMock()
        host_result.scalar_one_or_none.return_value = host

        no_svc = MagicMock()
        no_svc.scalar_one_or_none.return_value = None

        mock_db.execute = AsyncMock(side_effect=[agent_result, host_result, no_svc])
        mock_db.add = MagicMock()
        mock_db.commit = AsyncMock()

        batch = ServiceBatch(services=[
            ServiceRecord(host_fqdn=host.fqdn, port=443, protocol="tcp", service_name="https")
        ])
        result = await ingest_services(
            batch,
            db=mock_db,
            x_agent_fingerprint=agent.certificate_fingerprint,
            x_agent_id=None,
        )

        assert result.received == 1
        assert result.upserted == 1
        mock_db.add.assert_called_once()


# ---------------------------------------------------------------------------
# Vulnerability ingestion
# ---------------------------------------------------------------------------

class TestIngestVulnerabilities:
    @pytest.mark.asyncio
    async def test_inserts_new_cve(self) -> None:
        from server.api.data import ingest_vulnerabilities

        agent = _make_agent()
        host = _make_host()
        mock_db = AsyncMock(spec=AsyncSession)

        agent_result = MagicMock()
        agent_result.scalar_one_or_none.return_value = agent

        host_result = MagicMock()
        host_result.scalar_one_or_none.return_value = host

        no_vuln = MagicMock()
        no_vuln.scalar_one_or_none.return_value = None

        mock_db.execute = AsyncMock(side_effect=[agent_result, host_result, no_vuln])
        mock_db.add = MagicMock()
        mock_db.commit = AsyncMock()

        batch = VulnerabilityBatch(vulnerabilities=[
            VulnerabilityRecord(
                host_fqdn=host.fqdn,
                cve_id="CVE-2024-12345",
                severity="critical",
                cvss_score=9.8,
                description="Remote code execution",
            )
        ])
        result = await ingest_vulnerabilities(
            batch,
            db=mock_db,
            x_agent_fingerprint=agent.certificate_fingerprint,
            x_agent_id=None,
        )

        assert result.received == 1
        assert result.upserted == 1
        mock_db.add.assert_called_once()


# ---------------------------------------------------------------------------
# Scan results
# ---------------------------------------------------------------------------

class TestIngestScanResults:
    @pytest.mark.asyncio
    async def test_inserts_scan_result_without_network(self) -> None:
        from server.api.data import ingest_scan_results

        agent = _make_agent()
        mock_db = AsyncMock(spec=AsyncSession)

        agent_result = MagicMock()
        agent_result.scalar_one_or_none.return_value = agent

        mock_db.execute = AsyncMock(return_value=agent_result)
        mock_db.add = MagicMock()
        mock_db.commit = AsyncMock()

        batch = ScanResultBatch(scan_results=[
            ScanResultRecord(
                started_at=datetime(2026, 1, 1, 12, 0, 0),
                completed_at=datetime(2026, 1, 1, 12, 5, 0),
                hosts_found=["10.0.0.1", "10.0.0.2"],
            )
        ])
        result = await ingest_scan_results(
            batch,
            db=mock_db,
            x_agent_fingerprint=agent.certificate_fingerprint,
            x_agent_id=None,
        )

        assert result.received == 1
        assert result.upserted == 1
        assert result.errors == 0
        mock_db.add.assert_called_once()


# ---------------------------------------------------------------------------
# Device configs
# ---------------------------------------------------------------------------

class TestIngestDeviceConfigs:
    @pytest.mark.asyncio
    async def test_inserts_new_device(self) -> None:
        from server.api.data import ingest_device_configs

        agent = _make_agent()
        mock_db = AsyncMock(spec=AsyncSession)

        agent_result = MagicMock()
        agent_result.scalar_one_or_none.return_value = agent

        no_device = MagicMock()
        no_device.scalar_one_or_none.return_value = None

        mock_db.execute = AsyncMock(side_effect=[agent_result, no_device])
        mock_db.add = MagicMock()
        mock_db.commit = AsyncMock()

        batch = DeviceConfigBatch(device_configs=[
            DeviceConfigRecord(
                ip_address="192.168.1.1",
                hostname="core-sw01",
                device_type="switch",
                vendor="cisco",
                model="Catalyst 9300",
                firmware_version="17.9.4",
            )
        ])
        result = await ingest_device_configs(
            batch,
            db=mock_db,
            x_agent_fingerprint=agent.certificate_fingerprint,
            x_agent_id=None,
        )

        assert result.received == 1
        assert result.upserted == 1
        mock_db.add.assert_called_once()

    @pytest.mark.asyncio
    async def test_updates_existing_device(self) -> None:
        from server.api.data import ingest_device_configs

        agent = _make_agent()
        existing_device = NetworkDevice(
            id=uuid.uuid4(),
            ip_address="192.168.1.1",
            vendor="cisco",
            firmware_version="17.9.3",
        )
        mock_db = AsyncMock(spec=AsyncSession)

        agent_result = MagicMock()
        agent_result.scalar_one_or_none.return_value = agent

        device_result = MagicMock()
        device_result.scalar_one_or_none.return_value = existing_device

        mock_db.execute = AsyncMock(side_effect=[agent_result, device_result])
        mock_db.add = MagicMock()
        mock_db.commit = AsyncMock()

        batch = DeviceConfigBatch(device_configs=[
            DeviceConfigRecord(
                ip_address="192.168.1.1",
                firmware_version="17.9.4",
            )
        ])
        result = await ingest_device_configs(
            batch,
            db=mock_db,
            x_agent_fingerprint=agent.certificate_fingerprint,
            x_agent_id=None,
        )

        assert result.upserted == 1
        assert existing_device.firmware_version == "17.9.4"
        mock_db.add.assert_not_called()


# ---------------------------------------------------------------------------
# Topology edges
# ---------------------------------------------------------------------------

class TestIngestTopologyEdges:
    @pytest.mark.asyncio
    async def test_skips_edge_with_missing_host(self) -> None:
        from server.api.data import ingest_topology_edges

        agent = _make_agent()
        mock_db = AsyncMock(spec=AsyncSession)

        agent_result = MagicMock()
        agent_result.scalar_one_or_none.return_value = agent

        # source found, target not found
        source_host = _make_host(fqdn="src.example.com")
        src_result = MagicMock()
        src_result.scalar_one_or_none.return_value = source_host

        no_host = MagicMock()
        no_host.scalar_one_or_none.return_value = None
        no_host.scalars.return_value.first.return_value = None

        mock_db.execute = AsyncMock(side_effect=[agent_result, src_result, no_host])
        mock_db.add = MagicMock()
        mock_db.commit = AsyncMock()

        batch = TopologyEdgeBatch(topology_edges=[
            TopologyEdgeRecord(
                source_fqdn="src.example.com",
                target_ip="10.99.99.99",
                edge_type="lldp",
            )
        ])
        result = await ingest_topology_edges(
            batch,
            db=mock_db,
            x_agent_fingerprint=agent.certificate_fingerprint,
            x_agent_id=None,
        )

        assert result.errors == 1
        assert result.upserted == 0

    @pytest.mark.asyncio
    async def test_inserts_new_edge(self) -> None:
        from server.api.data import ingest_topology_edges

        agent = _make_agent()
        source = _make_host(fqdn="src.example.com", ips=["10.0.0.1"])
        target = _make_host(fqdn="dst.example.com", ips=["10.0.0.2"])
        mock_db = AsyncMock(spec=AsyncSession)

        agent_result = MagicMock()
        agent_result.scalar_one_or_none.return_value = agent

        src_result = MagicMock()
        src_result.scalar_one_or_none.return_value = source

        dst_result = MagicMock()
        dst_result.scalar_one_or_none.return_value = target

        no_edge = MagicMock()
        no_edge.scalar_one_or_none.return_value = None

        mock_db.execute = AsyncMock(side_effect=[agent_result, src_result, dst_result, no_edge])
        mock_db.add = MagicMock()
        mock_db.commit = AsyncMock()

        batch = TopologyEdgeBatch(topology_edges=[
            TopologyEdgeRecord(
                source_fqdn="src.example.com",
                target_fqdn="dst.example.com",
                edge_type="arp",
            )
        ])
        result = await ingest_topology_edges(
            batch,
            db=mock_db,
            x_agent_fingerprint=agent.certificate_fingerprint,
            x_agent_id=None,
        )

        assert result.received == 1
        assert result.upserted == 1
        mock_db.add.assert_called_once()
