"""
Tests for tenant-isolation RBAC on /api/v1/inventory endpoints.

Verifies that non-admin users see only resources belonging to their teams
(or unassigned resources), while admins see everything.

Uses mocked DB sessions; no PostgreSQL required.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from server.api.inventory import router, _viewer
from server.database import get_db
from server.services.auth import UserContext


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_app(viewer_ctx: UserContext, db_mock: AsyncMock) -> FastAPI:
    """Return a test app with _viewer and get_db dependencies overridden."""
    app = FastAPI()
    app.include_router(router)

    async def _override_viewer():
        return viewer_ctx

    async def _override_db():
        yield db_mock

    app.dependency_overrides[_viewer] = _override_viewer
    app.dependency_overrides[get_db] = _override_db
    return app


def _make_host(team_id: uuid.UUID | None = None) -> MagicMock:
    h = MagicMock()
    h.id = uuid.uuid4()
    h.fqdn = "host.example.com"
    h.ip_addresses = ["10.0.0.1"]
    h.os = "Linux"
    h.os_version = "5.15"
    h.team_id = team_id
    h.first_seen = datetime.utcnow()
    h.last_seen = datetime.utcnow()
    return h


def _make_network(team_id: uuid.UUID | None = None) -> MagicMock:
    n = MagicMock()
    n.id = uuid.uuid4()
    n.cidr = "192.168.1.0/24"
    n.description = None
    n.domain_name = None
    n.scan_authorized = False
    n.scan_depth = 0
    n.team_id = team_id
    n.created_at = datetime.utcnow()
    return n


def _make_device(team_id: uuid.UUID | None = None) -> MagicMock:
    d = MagicMock()
    d.id = uuid.uuid4()
    d.ip_address = "10.0.0.254"
    d.hostname = "router.local"
    d.vendor = "Cisco"
    d.model = "ISR4321"
    d.firmware_version = "16.9.3"
    d.device_type = "router"
    d.team_id = team_id
    d.last_seen = datetime.utcnow()
    return d


def _make_db(rows: list) -> AsyncMock:
    """DB mock whose execute().scalars() yields *rows*."""
    db = AsyncMock()
    scalars_mock = MagicMock()
    scalars_mock.__iter__ = MagicMock(return_value=iter(rows))
    result_mock = MagicMock()
    result_mock.scalars.return_value = scalars_mock
    db.execute = AsyncMock(return_value=result_mock)
    db.scalar = AsyncMock(return_value=0)
    return db


def _viewer_ctx(username: str = "alice", role: str = "viewer") -> UserContext:
    return UserContext(username=username, role=role)


def _admin_ctx() -> UserContext:
    return UserContext(username="boss", role="admin")


# ---------------------------------------------------------------------------
# Tests — list_hosts
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
class TestListHostsRBAC:

    async def test_admin_sees_all_hosts(self) -> None:
        """Admin: get_team_ids_for_user returns None → no extra WHERE clause."""
        team_a = uuid.uuid4()
        hosts = [_make_host(team_id=team_a), _make_host(team_id=None)]
        db = _make_db(hosts)
        app = _make_app(_admin_ctx(), db)

        with patch(
            "server.api.inventory.get_team_ids_for_user",
            new=AsyncMock(return_value=None),
        ):
            client = TestClient(app)
            resp = client.get("/api/v1/inventory/hosts")
        assert resp.status_code == 200
        assert len(resp.json()) == 2

    async def test_viewer_scoped_to_team(self) -> None:
        """Non-admin: get_team_ids_for_user returns a list → WHERE is applied."""
        team_a = uuid.uuid4()
        hosts = [_make_host(team_id=team_a)]
        db = _make_db(hosts)
        app = _make_app(_viewer_ctx(), db)

        with patch(
            "server.api.inventory.get_team_ids_for_user",
            new=AsyncMock(return_value=[team_a]),
        ):
            client = TestClient(app)
            resp = client.get("/api/v1/inventory/hosts")
        assert resp.status_code == 200
        assert len(resp.json()) == 1

    async def test_viewer_no_team_gets_unassigned_only(self) -> None:
        """Non-admin with no teams: DB returns only unassigned hosts."""
        hosts = [_make_host(team_id=None)]
        db = _make_db(hosts)
        app = _make_app(_viewer_ctx(), db)

        with patch(
            "server.api.inventory.get_team_ids_for_user",
            new=AsyncMock(return_value=[]),
        ):
            client = TestClient(app)
            resp = client.get("/api/v1/inventory/hosts")
        assert resp.status_code == 200
        assert len(resp.json()) == 1

    async def test_explicit_team_id_filter_bypasses_auto_scope(self) -> None:
        """Explicit team_id query param: get_team_ids_for_user not called."""
        team_b = uuid.uuid4()
        hosts = [_make_host(team_id=team_b)]
        db = _make_db(hosts)
        app = _make_app(_admin_ctx(), db)

        mock_team_lookup = AsyncMock(return_value=None)
        with patch("server.api.inventory.get_team_ids_for_user", new=mock_team_lookup):
            client = TestClient(app)
            resp = client.get(f"/api/v1/inventory/hosts?team_id={team_b}")
        assert resp.status_code == 200
        mock_team_lookup.assert_not_called()


# ---------------------------------------------------------------------------
# Tests — list_networks
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
class TestListNetworksRBAC:

    async def test_admin_gets_all_networks(self) -> None:
        nets = [_make_network(team_id=uuid.uuid4()), _make_network(team_id=None)]
        db = _make_db(nets)
        app = _make_app(_admin_ctx(), db)

        with (
            patch("server.api.inventory.get_team_ids_for_user", new=AsyncMock(return_value=None)),
            patch("server.api.inventory.classify_cidr", return_value="private"),
        ):
            client = TestClient(app)
            resp = client.get("/api/v1/inventory/networks")
        assert resp.status_code == 200
        assert len(resp.json()) == 2

    async def test_viewer_scoped_to_team(self) -> None:
        team_a = uuid.uuid4()
        nets = [_make_network(team_id=team_a)]
        db = _make_db(nets)
        app = _make_app(_viewer_ctx(), db)

        with (
            patch("server.api.inventory.get_team_ids_for_user", new=AsyncMock(return_value=[team_a])),
            patch("server.api.inventory.classify_cidr", return_value="private"),
        ):
            client = TestClient(app)
            resp = client.get("/api/v1/inventory/networks")
        assert resp.status_code == 200
        assert len(resp.json()) == 1

    async def test_explicit_team_id_bypasses_auto_scope(self) -> None:
        team_b = uuid.uuid4()
        nets = [_make_network(team_id=team_b)]
        db = _make_db(nets)
        app = _make_app(_admin_ctx(), db)

        mock_team_lookup = AsyncMock(return_value=None)
        with (
            patch("server.api.inventory.get_team_ids_for_user", new=mock_team_lookup),
            patch("server.api.inventory.classify_cidr", return_value="private"),
        ):
            client = TestClient(app)
            resp = client.get(f"/api/v1/inventory/networks?team_id={team_b}")
        assert resp.status_code == 200
        mock_team_lookup.assert_not_called()


# ---------------------------------------------------------------------------
# Tests — list_devices
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
class TestListDevicesRBAC:

    async def test_admin_gets_all_devices(self) -> None:
        devs = [_make_device(team_id=uuid.uuid4()), _make_device(team_id=None)]
        db = _make_db(devs)
        app = _make_app(_admin_ctx(), db)

        with patch("server.api.inventory.get_team_ids_for_user", new=AsyncMock(return_value=None)):
            client = TestClient(app)
            resp = client.get("/api/v1/inventory/devices")
        assert resp.status_code == 200
        assert len(resp.json()) == 2

    async def test_viewer_scoped_to_team(self) -> None:
        team_a = uuid.uuid4()
        devs = [_make_device(team_id=team_a)]
        db = _make_db(devs)
        app = _make_app(_viewer_ctx(), db)

        with patch("server.api.inventory.get_team_ids_for_user", new=AsyncMock(return_value=[team_a])):
            client = TestClient(app)
            resp = client.get("/api/v1/inventory/devices")
        assert resp.status_code == 200
        assert len(resp.json()) == 1

    async def test_device_out_includes_team_id(self) -> None:
        """DeviceOut schema now exposes team_id."""
        team_a = uuid.uuid4()
        devs = [_make_device(team_id=team_a)]
        db = _make_db(devs)
        app = _make_app(_admin_ctx(), db)

        with patch("server.api.inventory.get_team_ids_for_user", new=AsyncMock(return_value=None)):
            client = TestClient(app)
            resp = client.get("/api/v1/inventory/devices")
        assert resp.status_code == 200
        assert resp.json()[0]["team_id"] == str(team_a)

    async def test_team_id_filter_bypasses_auto_scope(self) -> None:
        """Explicit team_id param → get_team_ids_for_user not called."""
        team_b = uuid.uuid4()
        devs = [_make_device(team_id=team_b)]
        db = _make_db(devs)
        app = _make_app(_admin_ctx(), db)

        mock_team_lookup = AsyncMock(return_value=None)
        with patch("server.api.inventory.get_team_ids_for_user", new=mock_team_lookup):
            client = TestClient(app)
            resp = client.get(f"/api/v1/inventory/devices?team_id={team_b}")
        assert resp.status_code == 200
        mock_team_lookup.assert_not_called()


# ---------------------------------------------------------------------------
# Tests — inventory_stats
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
class TestInventoryStatsRBAC:

    def _make_stats_db(self) -> AsyncMock:
        """DB mock suitable for inventory_stats (scalar + execute calls)."""
        db = AsyncMock()
        db.scalar = AsyncMock(return_value=5)

        vuln_result = MagicMock()
        vuln_result.__iter__ = MagicMock(return_value=iter([("high", 3), ("critical", 1)]))
        os_result = MagicMock()
        os_result.__iter__ = MagicMock(return_value=iter([("Linux", 4)]))

        call_count = 0

        async def _execute(stmt):
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                return vuln_result
            return os_result

        db.execute = _execute
        return db

    async def test_admin_stats_no_auto_scope(self) -> None:
        """Admin: get_team_ids_for_user returns None → unfiltered counts."""
        db = self._make_stats_db()
        app = _make_app(_admin_ctx(), db)

        with patch("server.api.inventory.get_team_ids_for_user", new=AsyncMock(return_value=None)):
            client = TestClient(app)
            resp = client.get("/api/v1/inventory/stats")
        assert resp.status_code == 200
        data = resp.json()
        assert "total_hosts" in data
        assert "total_networks" in data
        assert "total_devices" in data

    async def test_viewer_stats_scoped(self) -> None:
        """Non-admin: endpoint scopes stats to user's teams (no error)."""
        db = self._make_stats_db()
        team_a = uuid.uuid4()
        app = _make_app(_viewer_ctx(), db)

        with patch("server.api.inventory.get_team_ids_for_user", new=AsyncMock(return_value=[team_a])):
            client = TestClient(app)
            resp = client.get("/api/v1/inventory/stats")
        assert resp.status_code == 200

    async def test_explicit_team_id_bypasses_auto_scope(self) -> None:
        """Explicit team_id param: get_team_ids_for_user not called."""
        db = self._make_stats_db()
        team_b = uuid.uuid4()
        app = _make_app(_admin_ctx(), db)

        mock_team_lookup = AsyncMock(return_value=None)
        with patch("server.api.inventory.get_team_ids_for_user", new=mock_team_lookup):
            client = TestClient(app)
            resp = client.get(f"/api/v1/inventory/stats?team_id={team_b}")
        assert resp.status_code == 200
        mock_team_lookup.assert_not_called()
