"""
Tests for team assignment endpoints:
  PATCH /api/v1/inventory/hosts/{id}/team
  PATCH /api/v1/inventory/networks/{id}/team

And team_id support in the host ingestion endpoint:
  POST /api/v1/data/hosts
"""

from __future__ import annotations

import uuid
from datetime import datetime
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

_TEAM_ID = uuid.UUID("bbbbbbbb-0000-0000-0000-000000000001")
_HOST_ID = uuid.UUID("cccccccc-0000-0000-0000-000000000010")
_NET_ID = uuid.UUID("cccccccc-0000-0000-0000-000000000020")
_AGENT_ID = uuid.UUID("dddddddd-0000-0000-0000-000000000001")
_NOW = datetime(2026, 1, 1, 12, 0, 0)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_host(host_id=_HOST_ID, team_id=None):
    h = MagicMock()
    h.id = host_id
    h.fqdn = "host.example.com"
    h.ip_addresses = ["10.0.0.5"]
    h.os = "Linux"
    h.os_version = "Ubuntu 22.04"
    h.team_id = team_id
    h.first_seen = _NOW
    h.last_seen = _NOW
    h.created_at = _NOW
    h.updated_at = _NOW
    return h


def _make_network(net_id=_NET_ID, team_id=None):
    n = MagicMock()
    n.id = net_id
    n.cidr = "10.0.0.0/24"
    n.description = "LAN"
    n.domain_name = "example.com"
    n.team_id = team_id
    n.scan_authorized = False
    n.scan_depth = 0
    n.created_at = _NOW
    n.updated_at = _NOW
    return n


def _make_team(team_id=_TEAM_ID):
    t = MagicMock()
    t.id = team_id
    t.name = "red-team"
    t.description = None
    t.created_by = "admin"
    return t


def _make_agent(agent_id=_AGENT_ID):
    a = MagicMock()
    a.id = agent_id
    a.certificate_fingerprint = "fp-abc"
    return a


# ---------------------------------------------------------------------------
# PATCH /hosts/{host_id}/team — assign host to team
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_assign_host_team_sets_team_id():
    """PATCH /hosts/{id}/team with a valid team_id sets host.team_id."""
    from server.api.inventory import assign_host_team, TeamAssignment

    host = _make_host(team_id=None)
    team = _make_team()

    async def get_side(model, pk):
        if pk == _HOST_ID:
            return host
        if pk == _TEAM_ID:
            return team
        return None

    mock_db = AsyncMock()
    mock_db.get = get_side
    mock_db.commit = AsyncMock()
    mock_db.refresh = AsyncMock()

    body = TeamAssignment(team_id=_TEAM_ID)
    await assign_host_team(host_id=_HOST_ID, body=body, _="alice", db=mock_db)

    assert host.team_id == _TEAM_ID
    mock_db.commit.assert_called_once()
    mock_db.refresh.assert_called_once_with(host)


@pytest.mark.asyncio
async def test_assign_host_team_unassign_sets_null():
    """PATCH /hosts/{id}/team with team_id=null clears host.team_id."""
    from server.api.inventory import assign_host_team, TeamAssignment

    host = _make_host(team_id=_TEAM_ID)

    mock_db = AsyncMock()

    async def get_side(model, pk):
        if pk == _HOST_ID:
            return host
        return None

    mock_db.get = get_side
    mock_db.commit = AsyncMock()
    mock_db.refresh = AsyncMock()

    body = TeamAssignment(team_id=None)
    await assign_host_team(host_id=_HOST_ID, body=body, _="alice", db=mock_db)

    assert host.team_id is None
    mock_db.commit.assert_called_once()


@pytest.mark.asyncio
async def test_assign_host_team_404_host_not_found():
    """PATCH /hosts/{id}/team returns 404 when host is missing."""
    from fastapi import HTTPException
    from server.api.inventory import assign_host_team, TeamAssignment

    mock_db = AsyncMock()
    mock_db.get = AsyncMock(return_value=None)

    with pytest.raises(HTTPException) as exc_info:
        await assign_host_team(
            host_id=_HOST_ID,
            body=TeamAssignment(team_id=_TEAM_ID),
            _="alice",
            db=mock_db,
        )
    assert exc_info.value.status_code == 404
    assert "Host" in exc_info.value.detail


@pytest.mark.asyncio
async def test_assign_host_team_404_team_not_found():
    """PATCH /hosts/{id}/team returns 404 when team_id does not exist."""
    from fastapi import HTTPException
    from server.api.inventory import assign_host_team, TeamAssignment

    host = _make_host(team_id=None)

    async def get_side(model, pk):
        if pk == _HOST_ID:
            return host
        return None  # team not found

    mock_db = AsyncMock()
    mock_db.get = get_side

    with pytest.raises(HTTPException) as exc_info:
        await assign_host_team(
            host_id=_HOST_ID,
            body=TeamAssignment(team_id=_TEAM_ID),
            _="alice",
            db=mock_db,
        )
    assert exc_info.value.status_code == 404
    assert "Team" in exc_info.value.detail


# ---------------------------------------------------------------------------
# PATCH /networks/{network_id}/team — assign network to team
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_assign_network_team_sets_team_id():
    """PATCH /networks/{id}/team with a valid team_id sets network.team_id."""
    from server.api.inventory import assign_network_team, TeamAssignment

    network = _make_network(team_id=None)
    team = _make_team()

    async def get_side(model, pk):
        if pk == _NET_ID:
            return network
        if pk == _TEAM_ID:
            return team
        return None

    mock_db = AsyncMock()
    mock_db.get = get_side
    mock_db.commit = AsyncMock()
    mock_db.refresh = AsyncMock()

    with patch("server.api.inventory.classify_cidr", return_value="private"):
        result = await assign_network_team(
            network_id=_NET_ID,
            body=TeamAssignment(team_id=_TEAM_ID),
            _="alice",
            db=mock_db,
        )

    assert network.team_id == _TEAM_ID
    assert result.team_id == _TEAM_ID
    mock_db.commit.assert_called_once()


@pytest.mark.asyncio
async def test_assign_network_team_unassign_sets_null():
    """PATCH /networks/{id}/team with team_id=null clears network.team_id."""
    from server.api.inventory import assign_network_team, TeamAssignment

    network = _make_network(team_id=_TEAM_ID)

    async def get_side(model, pk):
        if pk == _NET_ID:
            return network
        return None

    mock_db = AsyncMock()
    mock_db.get = get_side
    mock_db.commit = AsyncMock()
    mock_db.refresh = AsyncMock()

    with patch("server.api.inventory.classify_cidr", return_value="private"):
        result = await assign_network_team(
            network_id=_NET_ID,
            body=TeamAssignment(team_id=None),
            _="alice",
            db=mock_db,
        )

    assert network.team_id is None
    assert result.team_id is None


@pytest.mark.asyncio
async def test_assign_network_team_404_network_not_found():
    """PATCH /networks/{id}/team returns 404 when network is missing."""
    from fastapi import HTTPException
    from server.api.inventory import assign_network_team, TeamAssignment

    mock_db = AsyncMock()
    mock_db.get = AsyncMock(return_value=None)

    with pytest.raises(HTTPException) as exc_info:
        await assign_network_team(
            network_id=_NET_ID,
            body=TeamAssignment(team_id=_TEAM_ID),
            _="alice",
            db=mock_db,
        )
    assert exc_info.value.status_code == 404
    assert "Network" in exc_info.value.detail


@pytest.mark.asyncio
async def test_assign_network_team_404_team_not_found():
    """PATCH /networks/{id}/team returns 404 when team_id does not exist."""
    from fastapi import HTTPException
    from server.api.inventory import assign_network_team, TeamAssignment

    network = _make_network(team_id=None)

    async def get_side(model, pk):
        if pk == _NET_ID:
            return network
        return None  # team not found

    mock_db = AsyncMock()
    mock_db.get = get_side

    with pytest.raises(HTTPException) as exc_info:
        await assign_network_team(
            network_id=_NET_ID,
            body=TeamAssignment(team_id=_TEAM_ID),
            _="alice",
            db=mock_db,
        )
    assert exc_info.value.status_code == 404
    assert "Team" in exc_info.value.detail


# ---------------------------------------------------------------------------
# POST /data/hosts — team_id in HostRecord
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_ingest_hosts_new_host_sets_team_id():
    """POST /data/hosts creates new host with team_id when provided."""
    from server.api.data import ingest_hosts, HostBatch, HostRecord

    agent = _make_agent()
    created_hosts = []

    mock_db = AsyncMock()
    mock_db.commit = AsyncMock()

    def add_side(obj):
        created_hosts.append(obj)

    mock_db.add = add_side

    batch = HostBatch(hosts=[
        HostRecord(
            fqdn="server.example.com",
            ip_addresses=["10.1.2.3"],
            os="Linux",
            team_id=_TEAM_ID,
        )
    ])

    with patch("server.api.data._get_agent", AsyncMock(return_value=agent)), \
         patch("server.api.data._resolve_host", AsyncMock(return_value=None)):
        result = await ingest_hosts(
            batch=batch,
            db=mock_db,
            x_agent_fingerprint=None,
            x_agent_id=str(_AGENT_ID),
        )

    assert result.upserted == 1
    assert result.errors == 0
    assert len(created_hosts) == 1
    assert created_hosts[0].team_id == _TEAM_ID


@pytest.mark.asyncio
async def test_ingest_hosts_existing_host_team_id_not_cleared():
    """POST /data/hosts without team_id does not overwrite existing host.team_id."""
    from server.api.data import ingest_hosts, HostBatch, HostRecord

    agent = _make_agent()
    existing_host = _make_host(team_id=_TEAM_ID)
    existing_host.fqdn = "server.example.com"
    existing_host.ip_addresses = ["10.1.2.3"]

    mock_db = AsyncMock()

    async def execute_side(stmt):
        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = existing_host
        mock_result.scalars.return_value = MagicMock(first=MagicMock(return_value=existing_host))
        return mock_result

    mock_db.execute = execute_side
    mock_db.commit = AsyncMock()
    mock_db.add = MagicMock()

    batch = HostBatch(hosts=[
        HostRecord(
            fqdn="server.example.com",
            ip_addresses=["10.1.2.3"],
            os="Linux",
            team_id=None,  # no team_id submitted
        )
    ])

    with patch("server.api.data._get_agent", AsyncMock(return_value=agent)):
        result = await ingest_hosts(
            batch=batch,
            db=mock_db,
            x_agent_fingerprint=None,
            x_agent_id=str(_AGENT_ID),
        )

    assert result.upserted == 1
    # team_id must remain unchanged (not cleared)
    assert existing_host.team_id == _TEAM_ID


@pytest.mark.asyncio
async def test_ingest_hosts_existing_host_team_id_updated():
    """POST /data/hosts with a team_id updates existing host.team_id."""
    from server.api.data import ingest_hosts, HostBatch, HostRecord

    agent = _make_agent()
    new_team = uuid.UUID("eeeeeeee-0000-0000-0000-000000000099")
    existing_host = _make_host(team_id=_TEAM_ID)
    existing_host.fqdn = "server.example.com"
    existing_host.ip_addresses = ["10.1.2.3"]

    mock_db = AsyncMock()

    async def execute_side(stmt):
        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = existing_host
        mock_result.scalars.return_value = MagicMock(first=MagicMock(return_value=existing_host))
        return mock_result

    mock_db.execute = execute_side
    mock_db.commit = AsyncMock()
    mock_db.add = MagicMock()

    batch = HostBatch(hosts=[
        HostRecord(
            fqdn="server.example.com",
            ip_addresses=["10.1.2.3"],
            team_id=new_team,
        )
    ])

    with patch("server.api.data._get_agent", AsyncMock(return_value=agent)):
        await ingest_hosts(
            batch=batch,
            db=mock_db,
            x_agent_fingerprint=None,
            x_agent_id=str(_AGENT_ID),
        )

    assert existing_host.team_id == new_team


# ---------------------------------------------------------------------------
# Schema: HostRecord includes team_id field
# ---------------------------------------------------------------------------


def test_host_record_schema_has_team_id():
    """HostRecord Pydantic model includes optional team_id field."""
    from server.api.data import HostRecord

    fields = HostRecord.model_fields
    assert "team_id" in fields, "HostRecord missing team_id field"
    assert fields["team_id"].default is None


def test_team_assignment_schema():
    """TeamAssignment body schema is valid and team_id defaults to None."""
    from server.api.inventory import TeamAssignment

    body = TeamAssignment()
    assert body.team_id is None

    body2 = TeamAssignment(team_id=_TEAM_ID)
    assert body2.team_id == _TEAM_ID


def test_host_summary_includes_team_id():
    """HostSummary response schema exposes team_id."""
    from server.api.inventory import HostSummary

    fields = HostSummary.model_fields
    assert "team_id" in fields


def test_network_out_includes_team_id():
    """NetworkOut response schema exposes team_id."""
    from server.api.inventory import NetworkOut

    fields = NetworkOut.model_fields
    assert "team_id" in fields
