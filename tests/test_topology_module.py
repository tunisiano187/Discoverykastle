"""
Tests for server/modules/builtin/topology/module.py.

Strategy: mock AsyncSession scalars; no PostgreSQL required.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from unittest.mock import AsyncMock, MagicMock

import pytest

from server.modules.builtin.topology.module import Module
from server.modules.base import ModuleCapability


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _db_returning(*query_results) -> AsyncMock:
    """Build a mock DB that returns different scalars() iterables per execute() call."""
    db = AsyncMock()
    mocks = []
    for items in query_results:
        mr = MagicMock()
        mr.scalars.return_value = items
        mocks.append(mr)
    db.execute = AsyncMock(side_effect=mocks)
    return db


def _host(fqdn: str | None = "web01.example.com", os: str = "Ubuntu") -> MagicMock:
    h = MagicMock()
    h.id = uuid.uuid4()
    h.fqdn = fqdn
    h.ip_addresses = ["10.0.0.1"]
    h.os = os
    h.last_seen = datetime(2024, 1, 15, 12, 0, 0)
    return h


def _device(hostname: str | None = "switch01", ip: str = "10.0.0.254") -> MagicMock:
    d = MagicMock()
    d.id = uuid.uuid4()
    d.hostname = hostname
    d.ip_address = ip
    d.device_type = "switch"
    d.vendor = "Cisco"
    d.model = "Catalyst 2960"
    return d


def _network(cidr: str = "10.0.0.0/24", description: str | None = None) -> MagicMock:
    n = MagicMock()
    n.id = uuid.uuid4()
    n.cidr = cidr
    n.description = description
    n.scan_authorized = True
    return n


def _edge(edge_type: str = "connected") -> MagicMock:
    e = MagicMock()
    e.id = uuid.uuid4()
    e.source_host_id = uuid.uuid4()
    e.target_host_id = uuid.uuid4()
    e.edge_type = edge_type
    return e


# ---------------------------------------------------------------------------
# Manifest
# ---------------------------------------------------------------------------

class TestManifest:
    def test_name(self) -> None:
        assert Module.manifest.name == "builtin-topology"

    def test_topology_and_export_capabilities(self) -> None:
        caps = Module.manifest.capabilities
        assert ModuleCapability.TOPOLOGY in caps
        assert ModuleCapability.EXPORT in caps

    def test_is_builtin(self) -> None:
        assert Module.manifest.builtin is True


# ---------------------------------------------------------------------------
# build_graph
# ---------------------------------------------------------------------------

class TestBuildGraph:
    @pytest.mark.asyncio
    async def test_empty_graph_has_no_nodes_or_edges(self) -> None:
        m = Module()
        db = _db_returning([], [], [], [])
        result = await m.build_graph(db)
        assert result == {"nodes": [], "edges": []}

    @pytest.mark.asyncio
    async def test_host_node_type_is_host(self) -> None:
        m = Module()
        db = _db_returning([_host()], [], [], [])
        result = await m.build_graph(db)
        host_nodes = [n for n in result["nodes"] if n["data"]["type"] == "host"]
        assert len(host_nodes) == 1

    @pytest.mark.asyncio
    async def test_host_label_uses_fqdn(self) -> None:
        m = Module()
        h = _host(fqdn="myserver.local")
        db = _db_returning([h], [], [], [])
        result = await m.build_graph(db)
        node = result["nodes"][0]
        assert node["data"]["label"] == "myserver.local"

    @pytest.mark.asyncio
    async def test_host_label_falls_back_to_ip_when_no_fqdn(self) -> None:
        m = Module()
        h = _host(fqdn=None)
        h.ip_addresses = ["192.168.1.5"]
        db = _db_returning([h], [], [], [])
        result = await m.build_graph(db)
        assert result["nodes"][0]["data"]["label"] == "192.168.1.5"

    @pytest.mark.asyncio
    async def test_device_node_type_is_device(self) -> None:
        m = Module()
        db = _db_returning([], [_device()], [], [])
        result = await m.build_graph(db)
        device_nodes = [n for n in result["nodes"] if n["data"]["type"] == "device"]
        assert len(device_nodes) == 1

    @pytest.mark.asyncio
    async def test_device_label_falls_back_to_ip_when_no_hostname(self) -> None:
        m = Module()
        d = _device(hostname=None, ip="10.0.0.254")
        db = _db_returning([], [d], [], [])
        result = await m.build_graph(db)
        device_nodes = [n for n in result["nodes"] if n["data"]["type"] == "device"]
        assert device_nodes[0]["data"]["label"] == "10.0.0.254"

    @pytest.mark.asyncio
    async def test_network_node_type_is_network(self) -> None:
        m = Module()
        db = _db_returning([], [], [_network()], [])
        result = await m.build_graph(db)
        net_nodes = [n for n in result["nodes"] if n["data"]["type"] == "network"]
        assert len(net_nodes) == 1

    @pytest.mark.asyncio
    async def test_network_label_uses_description_when_set(self) -> None:
        m = Module()
        db = _db_returning([], [], [_network(description="Main LAN")], [])
        result = await m.build_graph(db)
        net_nodes = [n for n in result["nodes"] if n["data"]["type"] == "network"]
        assert net_nodes[0]["data"]["label"] == "Main LAN"

    @pytest.mark.asyncio
    async def test_network_label_falls_back_to_cidr(self) -> None:
        m = Module()
        db = _db_returning([], [], [_network(description=None)], [])
        result = await m.build_graph(db)
        net_nodes = [n for n in result["nodes"] if n["data"]["type"] == "network"]
        assert net_nodes[0]["data"]["label"] == "10.0.0.0/24"

    @pytest.mark.asyncio
    async def test_edge_present_in_result(self) -> None:
        m = Module()
        db = _db_returning([], [], [], [_edge("connected")])
        result = await m.build_graph(db)
        assert len(result["edges"]) == 1
        assert result["edges"][0]["data"]["type"] == "connected"

    @pytest.mark.asyncio
    async def test_mixed_nodes_and_edges(self) -> None:
        m = Module()
        db = _db_returning([_host()], [_device()], [_network()], [_edge()])
        result = await m.build_graph(db)
        assert len(result["nodes"]) == 3
        assert len(result["edges"]) == 1


# ---------------------------------------------------------------------------
# export
# ---------------------------------------------------------------------------

class TestExport:
    @pytest.mark.asyncio
    async def test_export_markdown_returns_string(self) -> None:
        m = Module()
        db = _db_returning([], [], [], [], [], [], [], [])
        result = await m.export("markdown", db)
        assert result is not None
        assert isinstance(result, str)

    @pytest.mark.asyncio
    async def test_export_md_alias_works(self) -> None:
        m = Module()
        db = _db_returning([], [], [], [], [], [], [], [])
        result = await m.export("md", db)
        assert result is not None

    @pytest.mark.asyncio
    async def test_export_unknown_format_returns_none(self) -> None:
        m = Module()
        db = AsyncMock()
        result = await m.export("pdf", db)
        assert result is None
