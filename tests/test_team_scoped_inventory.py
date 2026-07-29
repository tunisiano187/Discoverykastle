"""
Tests for team-scoped data isolation — team_id filtering on inventory and vulns.

Strategy: mock AsyncSession; no DB or real server needed.
"""

from __future__ import annotations

import ast
import uuid
from datetime import datetime
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

_TEAM_A = uuid.UUID("aaaaaaaa-0000-0000-0000-000000000001")
_HOST_A = uuid.UUID("aaaaaaaa-0000-0000-0000-000000000010")
_NET_A = uuid.UUID("aaaaaaaa-0000-0000-0000-000000000020")
_NOW = datetime(2026, 1, 1, 12, 0, 0)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_host(host_id=_HOST_A, team_id=_TEAM_A, os="Linux"):
    h = MagicMock()
    h.id = host_id
    h.fqdn = f"host-{str(host_id)[:4]}.example.com"
    h.ip_addresses = ["10.0.0.1"]
    h.os = os
    h.os_version = "Ubuntu 22.04"
    h.team_id = team_id
    h.first_seen = _NOW
    h.last_seen = _NOW
    h.created_at = _NOW
    h.updated_at = _NOW
    return h


def _make_network(net_id=_NET_A, team_id=_TEAM_A):
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


def _stmt_str(mock_db):
    """Return the compiled SQL string from the last db.execute() call."""
    stmt = mock_db.execute.call_args[0][0]
    return str(stmt.compile(compile_kwargs={"literal_binds": False}))


def _has_team_id_filter(sql: str) -> bool:
    """True if the SQL contains a WHERE predicate on team_id (not just a SELECT column)."""
    return "team_id = :" in sql or "team_id =:" in sql


# ---------------------------------------------------------------------------
# inventory: list_hosts with ?team_id=
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_list_hosts_team_filter_passes_where_clause():
    """list_hosts ?team_id= appends a WHERE team_id = ... clause."""
    from server.api.inventory import list_hosts

    mock_db = AsyncMock()
    mock_result = MagicMock()
    mock_result.scalars.return_value = iter([_make_host(team_id=_TEAM_A)])
    mock_db.execute = AsyncMock(return_value=mock_result)

    # Pass explicit values for all params — FastAPI Query() objects are not
    # resolved when calling endpoint handlers directly in unit tests.
    await list_hosts(os=None, ip=None, team_id=_TEAM_A, limit=50, offset=0, db=mock_db)

    assert _has_team_id_filter(_stmt_str(mock_db))


@pytest.mark.asyncio
async def test_list_hosts_no_team_filter_omits_where_clause():
    """list_hosts without ?team_id= does NOT filter by team_id."""
    from server.api.inventory import list_hosts

    mock_db = AsyncMock()
    mock_result = MagicMock()
    mock_result.scalars.return_value = iter([])
    mock_db.execute = AsyncMock(return_value=mock_result)

    await list_hosts(os=None, ip=None, team_id=None, limit=50, offset=0, db=mock_db)

    assert not _has_team_id_filter(_stmt_str(mock_db))


# ---------------------------------------------------------------------------
# inventory: list_networks with ?team_id=
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_list_networks_team_filter_passes_where_clause():
    """list_networks ?team_id= appends a WHERE team_id = ... clause."""
    from server.api.inventory import list_networks

    mock_db = AsyncMock()
    mock_result = MagicMock()
    mock_result.scalars.return_value = iter([_make_network(team_id=_TEAM_A)])
    mock_db.execute = AsyncMock(return_value=mock_result)

    with patch("server.api.inventory.classify_cidr", return_value="private"):
        await list_networks(authorized_only=False, team_id=_TEAM_A, db=mock_db)

    assert _has_team_id_filter(_stmt_str(mock_db))


@pytest.mark.asyncio
async def test_list_networks_no_team_filter():
    """list_networks without ?team_id= does NOT filter by team_id."""
    from server.api.inventory import list_networks

    mock_db = AsyncMock()
    mock_result = MagicMock()
    mock_result.scalars.return_value = iter([])
    mock_db.execute = AsyncMock(return_value=mock_result)

    with patch("server.api.inventory.classify_cidr", return_value="private"):
        await list_networks(authorized_only=False, team_id=None, db=mock_db)

    assert not _has_team_id_filter(_stmt_str(mock_db))


# ---------------------------------------------------------------------------
# inventory: inventory_stats with ?team_id=
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_inventory_stats_team_filter_applied():
    """inventory_stats ?team_id= scopes host and network count queries."""
    from server.api.inventory import inventory_stats

    mock_db = AsyncMock()
    call_count = 0

    async def scalar_side_effect(stmt):
        nonlocal call_count
        call_count += 1
        sql = str(stmt.compile(compile_kwargs={"literal_binds": False}))
        # First two scalar calls are host-count and network-count
        if call_count <= 2:
            assert _has_team_id_filter(sql), (
                f"Call #{call_count}: expected team_id filter in: {sql}"
            )
        return 5

    mock_db.scalar = scalar_side_effect

    mock_result = MagicMock()
    mock_result.__iter__ = lambda s: iter([])
    mock_db.execute = AsyncMock(return_value=mock_result)

    stats = await inventory_stats(team_id=_TEAM_A, db=mock_db)
    assert stats.total_hosts == 5
    assert stats.total_networks == 5


@pytest.mark.asyncio
async def test_inventory_stats_no_team_filter():
    """inventory_stats without team_id returns counts for the full dataset."""
    from server.api.inventory import inventory_stats

    mock_db = AsyncMock()

    async def scalar_side_effect(_stmt):
        return 10

    mock_db.scalar = scalar_side_effect
    mock_result = MagicMock()
    mock_result.__iter__ = lambda s: iter([])
    mock_db.execute = AsyncMock(return_value=mock_result)

    stats = await inventory_stats(team_id=None, db=mock_db)
    assert stats.total_hosts == 10


# ---------------------------------------------------------------------------
# vulns: list_vulns with ?team_id=
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_list_vulns_team_filter_appended():
    """list_vulns ?team_id= adds a WHERE hosts.team_id = ... clause."""
    from server.api.vulns import list_vulns

    mock_db = AsyncMock()
    mock_result = MagicMock()
    mock_result.__iter__ = lambda s: iter([])
    mock_db.execute = AsyncMock(return_value=mock_result)

    await list_vulns(
        operator="alice",
        severity=None,
        host_id=None,
        cve_id=None,
        team_id=_TEAM_A,
        limit=100,
        offset=0,
        db=mock_db,
    )

    assert _has_team_id_filter(_stmt_str(mock_db))


@pytest.mark.asyncio
async def test_list_vulns_no_team_filter():
    """list_vulns without ?team_id= does not filter by team_id."""
    from server.api.vulns import list_vulns

    mock_db = AsyncMock()
    mock_result = MagicMock()
    mock_result.__iter__ = lambda s: iter([])
    mock_db.execute = AsyncMock(return_value=mock_result)

    await list_vulns(
        operator="alice",
        severity=None,
        host_id=None,
        cve_id=None,
        team_id=None,
        limit=100,
        offset=0,
        db=mock_db,
    )

    assert not _has_team_id_filter(_stmt_str(mock_db))


# ---------------------------------------------------------------------------
# Model: Host.team_id and Network.team_id columns exist and are nullable
# ---------------------------------------------------------------------------


def test_host_model_has_team_id_column():
    """Host model exposes a nullable team_id FK column."""
    from server.models.host import Host

    col = Host.__table__.c.get("team_id")
    assert col is not None, "Host.team_id column missing from table definition"
    assert col.nullable is True


def test_network_model_has_team_id_column():
    """Network model exposes a nullable team_id FK column."""
    from server.models.network import Network

    col = Network.__table__.c.get("team_id")
    assert col is not None, "Network.team_id column missing from table definition"
    assert col.nullable is True


# ---------------------------------------------------------------------------
# Migration 0005: revision metadata (parsed via ast to avoid importing
# alembic.op which is a runtime context object)
# ---------------------------------------------------------------------------

_MIGRATION_PATH = (
    Path(__file__).parent.parent
    / "alembic"
    / "versions"
    / "0005_team_id_on_hosts_networks.py"
)


def _parse_migration_string_assignments() -> dict[str, str]:
    """Parse module-level annotated string assignments (revision: str = "...") from the migration."""
    tree = ast.parse(_MIGRATION_PATH.read_text())
    result: dict[str, str] = {}
    for node in tree.body:
        # Handles both `revision = "0005"` (Assign) and `revision: str = "0005"` (AnnAssign)
        if isinstance(node, ast.AnnAssign) and isinstance(node.value, ast.Constant):
            if isinstance(node.target, ast.Name):
                result[node.target.id] = node.value.value
        elif isinstance(node, ast.Assign) and isinstance(node.value, ast.Constant):
            for target in node.targets:
                if isinstance(target, ast.Name):
                    result[target.id] = node.value.value
    return result


def test_migration_0005_file_exists():
    """Migration file 0005 exists on disk."""
    assert _MIGRATION_PATH.exists(), f"Migration file not found: {_MIGRATION_PATH}"


def test_migration_0005_revision_chain():
    """Migration 0005 chains from 0004."""
    constants = _parse_migration_string_assignments()
    assert constants.get("revision") == "0005", f"Got: {constants}"
    assert constants.get("down_revision") == "0004", f"Got: {constants}"


def test_migration_0005_has_upgrade_and_downgrade():
    """Migration 0005 source defines both upgrade() and downgrade() functions."""
    tree = ast.parse(_MIGRATION_PATH.read_text())
    func_names = {
        node.name
        for node in ast.walk(tree)
        if isinstance(node, ast.FunctionDef)
    }
    assert "upgrade" in func_names
    assert "downgrade" in func_names


def test_migration_0005_adds_team_id_to_hosts():
    """Migration source adds team_id column to the hosts table."""
    src = _MIGRATION_PATH.read_text()
    assert '"hosts"' in src
    assert '"team_id"' in src


def test_migration_0005_adds_team_id_to_networks():
    """Migration source adds team_id column to the networks table."""
    src = _MIGRATION_PATH.read_text()
    assert '"networks"' in src
    assert '"team_id"' in src
