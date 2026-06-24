"""
Tests for server/services/docgen.py and server/api/docs_api.py.

Strategy:
- docgen service tests: call render_* functions with MagicMock objects
- API tests: override auth + DB dependencies, verify endpoint status and content
"""

from __future__ import annotations

import uuid
from datetime import datetime
from unittest.mock import AsyncMock, MagicMock

import pytest


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_FAKE_NET_ID = uuid.UUID("11111111-2222-3333-4444-555555555555")
_FAKE_DEV_ID = uuid.UUID("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee")
_NOW = datetime(2024, 6, 1, 10, 0, 0)


def _make_network(**kwargs) -> MagicMock:
    defaults = dict(
        id=_FAKE_NET_ID,
        cidr="192.168.1.0/24",
        description="Office LAN",
        domain_name="office.local",
        scan_authorized=True,
        scan_depth=1,
        created_at=_NOW,
        updated_at=_NOW,
    )
    defaults.update(kwargs)
    net = MagicMock()
    for k, v in defaults.items():
        setattr(net, k, v)
    return net


def _make_host(**kwargs) -> MagicMock:
    defaults = dict(
        id=uuid.uuid4(),
        fqdn="server1.office.local",
        ip_addresses=["192.168.1.10"],
        os="Linux",
        os_version="Ubuntu 22.04",
        services=[MagicMock(), MagicMock()],
        first_seen=_NOW,
        last_seen=_NOW,
    )
    defaults.update(kwargs)
    host = MagicMock()
    for k, v in defaults.items():
        setattr(host, k, v)
    return host


def _make_device(**kwargs) -> MagicMock:
    defaults = dict(
        id=_FAKE_DEV_ID,
        ip_address="192.168.1.1",
        hostname="router-core",
        device_type="router",
        vendor="Cisco",
        model="ISR4321",
        firmware_version="16.9.5",
        config_snapshot="interface GigE0\n ip address 192.168.1.1 255.255.255.0",
        last_seen=_NOW,
    )
    defaults.update(kwargs)
    dev = MagicMock()
    for k, v in defaults.items():
        setattr(dev, k, v)
    return dev


def _make_db(networks=None, hosts=None, devices=None, open_alerts=0, critical_alerts=0):
    db = AsyncMock()
    call_num = [0]

    async def _execute(stmt):
        result = MagicMock()
        idx = call_num[0]
        call_num[0] += 1
        if idx == 0:
            result.scalars.return_value = networks or []
        elif idx == 1:
            result.scalars.return_value = hosts or []
        elif idx == 2:
            result.scalars.return_value = devices or []
        elif idx == 3:
            result.scalar_one.return_value = open_alerts
        elif idx == 4:
            result.scalar_one.return_value = critical_alerts
        else:
            result.scalars.return_value = []
            result.scalar_one.return_value = 0
        return result

    db.execute = AsyncMock(side_effect=_execute)
    db.get = AsyncMock(return_value=None)
    return db


# ---------------------------------------------------------------------------
# docgen service: render_executive_summary
# ---------------------------------------------------------------------------


class TestRenderExecutiveSummary:
    def test_renders_with_empty_data(self) -> None:
        from server.services.docgen import render_executive_summary

        md = render_executive_summary([], [], [], 0, 0)
        assert "# Discoverykastle — Executive Summary" in md
        assert "Networks discovered | 0" in md
        assert "No open alerts" in md

    def test_renders_networks_table(self) -> None:
        from server.services.docgen import render_executive_summary

        net = _make_network()
        md = render_executive_summary([net], [], [], 0, 0)
        assert "192.168.1.0/24" in md
        assert "Office LAN" in md
        assert "Yes" in md

    def test_renders_hosts_table(self) -> None:
        from server.services.docgen import render_executive_summary

        host = _make_host()
        md = render_executive_summary([], [host], [], 0, 0)
        assert "server1.office.local" in md
        assert "Linux" in md

    def test_truncates_hosts_at_20(self) -> None:
        from server.services.docgen import render_executive_summary

        hosts = [_make_host(fqdn=f"host{i}.local") for i in range(25)]
        md = render_executive_summary([], hosts, [], 0, 0)
        assert "5 more" in md

    def test_renders_devices_table(self) -> None:
        from server.services.docgen import render_executive_summary

        dev = _make_device()
        md = render_executive_summary([], [], [dev], 0, 0)
        assert "192.168.1.1" in md
        assert "Cisco" in md
        assert "router" in md

    def test_renders_open_alerts_warning(self) -> None:
        from server.services.docgen import render_executive_summary

        md = render_executive_summary([], [], [], 3, 1)
        assert "3 open alert" in md
        assert "critical" in md

    def test_renders_no_alerts_message_when_zero(self) -> None:
        from server.services.docgen import render_executive_summary

        md = render_executive_summary([], [], [], 0, 0)
        assert "No open alerts" in md

    def test_includes_generated_timestamp(self) -> None:
        from server.services.docgen import render_executive_summary

        md = render_executive_summary([], [], [], 0, 0)
        assert "*Generated:" in md
        assert "UTC" in md


# ---------------------------------------------------------------------------
# docgen service: render_network_report
# ---------------------------------------------------------------------------


class TestRenderNetworkReport:
    def test_renders_network_metadata(self) -> None:
        from server.services.docgen import render_network_report

        net = _make_network()
        md = render_network_report(net, [])
        assert "192.168.1.0/24" in md
        assert "Office LAN" in md
        assert "office.local" in md
        assert "Yes" in md

    def test_renders_hosts_when_present(self) -> None:
        from server.services.docgen import render_network_report

        net = _make_network()
        host = _make_host()
        md = render_network_report(net, [host])
        assert "server1.office.local" in md
        assert "Linux" in md

    def test_renders_no_hosts_message_when_empty(self) -> None:
        from server.services.docgen import render_network_report

        net = _make_network()
        md = render_network_report(net, [])
        assert "No hosts discovered" in md

    def test_uses_ip_when_fqdn_missing(self) -> None:
        from server.services.docgen import render_network_report

        net = _make_network()
        host = _make_host(fqdn=None, ip_addresses=["10.0.0.5"])
        md = render_network_report(net, [host])
        assert "10.0.0.5" in md


# ---------------------------------------------------------------------------
# docgen service: render_device_report
# ---------------------------------------------------------------------------


class TestRenderDeviceReport:
    def test_renders_device_metadata(self) -> None:
        from server.services.docgen import render_device_report

        dev = _make_device()
        md = render_device_report(dev)
        assert "192.168.1.1" in md
        assert "router-core" in md
        assert "Cisco" in md
        assert "ISR4321" in md
        assert "16.9.5" in md

    def test_renders_config_snapshot_when_present(self) -> None:
        from server.services.docgen import render_device_report

        dev = _make_device(config_snapshot="interface GigE0\n no shutdown")
        md = render_device_report(dev)
        assert "```" in md
        assert "interface GigE0" in md

    def test_renders_no_config_message_when_absent(self) -> None:
        from server.services.docgen import render_device_report

        dev = _make_device(config_snapshot=None)
        md = render_device_report(dev)
        assert "No config snapshot available" in md


# ---------------------------------------------------------------------------
# docs API tests
# ---------------------------------------------------------------------------


class TestDocsAPI:
    def _make_app(self, db):
        from fastapi import FastAPI
        from server.api.docs_api import router, _require_analyst
        from server.database import get_db

        app = FastAPI()

        async def _fake_db():
            yield db

        app.dependency_overrides[get_db] = _fake_db
        app.dependency_overrides[_require_analyst] = lambda: "analyst1"
        app.include_router(router)
        return app

    @pytest.mark.asyncio
    async def test_summary_returns_200_with_markdown(self) -> None:
        import httpx
        from server.api.docs_api import router, _require_analyst
        from server.database import get_db
        from fastapi import FastAPI

        db = _make_db(
            networks=[_make_network()],
            hosts=[_make_host()],
            devices=[_make_device()],
            open_alerts=2,
            critical_alerts=1,
        )

        app = FastAPI()

        async def _fake_db():
            yield db

        app.dependency_overrides[get_db] = _fake_db
        app.dependency_overrides[_require_analyst] = lambda: "analyst1"
        app.include_router(router)

        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="http://test"
        ) as client:
            resp = await client.get("/api/v1/docs/summary")
        assert resp.status_code == 200
        assert "Executive Summary" in resp.text
        assert "192.168.1.0/24" in resp.text

    @pytest.mark.asyncio
    async def test_summary_empty_db_returns_200(self) -> None:
        import httpx
        from server.api.docs_api import router, _require_analyst
        from server.database import get_db
        from fastapi import FastAPI

        db = _make_db()

        app = FastAPI()

        async def _fake_db():
            yield db

        app.dependency_overrides[get_db] = _fake_db
        app.dependency_overrides[_require_analyst] = lambda: "analyst1"
        app.include_router(router)

        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="http://test"
        ) as client:
            resp = await client.get("/api/v1/docs/summary")
        assert resp.status_code == 200
        assert "No open alerts" in resp.text

    @pytest.mark.asyncio
    async def test_network_report_returns_200(self) -> None:
        import httpx
        from server.api.docs_api import router, _require_analyst
        from server.database import get_db
        from fastapi import FastAPI

        net = _make_network()
        db = AsyncMock()
        db.get = AsyncMock(return_value=net)

        result = MagicMock()
        result.scalars.return_value = [_make_host()]
        db.execute = AsyncMock(return_value=result)

        app = FastAPI()

        async def _fake_db():
            yield db

        app.dependency_overrides[get_db] = _fake_db
        app.dependency_overrides[_require_analyst] = lambda: "analyst1"
        app.include_router(router)

        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="http://test"
        ) as client:
            resp = await client.get(f"/api/v1/docs/network/{_FAKE_NET_ID}")
        assert resp.status_code == 200
        assert "192.168.1.0/24" in resp.text

    @pytest.mark.asyncio
    async def test_network_report_404_when_not_found(self) -> None:
        import httpx
        from server.api.docs_api import router, _require_analyst
        from server.database import get_db
        from fastapi import FastAPI

        db = AsyncMock()
        db.get = AsyncMock(return_value=None)

        app = FastAPI()

        async def _fake_db():
            yield db

        app.dependency_overrides[get_db] = _fake_db
        app.dependency_overrides[_require_analyst] = lambda: "analyst1"
        app.include_router(router)

        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="http://test"
        ) as client:
            resp = await client.get(f"/api/v1/docs/network/{_FAKE_NET_ID}")
        assert resp.status_code == 404

    @pytest.mark.asyncio
    async def test_device_report_returns_200(self) -> None:
        import httpx
        from server.api.docs_api import router, _require_analyst
        from server.database import get_db
        from fastapi import FastAPI

        dev = _make_device()
        db = AsyncMock()
        db.get = AsyncMock(return_value=dev)

        app = FastAPI()

        async def _fake_db():
            yield db

        app.dependency_overrides[get_db] = _fake_db
        app.dependency_overrides[_require_analyst] = lambda: "analyst1"
        app.include_router(router)

        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="http://test"
        ) as client:
            resp = await client.get(f"/api/v1/docs/device/{_FAKE_DEV_ID}")
        assert resp.status_code == 200
        assert "192.168.1.1" in resp.text
        assert "Cisco" in resp.text

    @pytest.mark.asyncio
    async def test_device_report_404_when_not_found(self) -> None:
        import httpx
        from server.api.docs_api import router, _require_analyst
        from server.database import get_db
        from fastapi import FastAPI

        db = AsyncMock()
        db.get = AsyncMock(return_value=None)

        app = FastAPI()

        async def _fake_db():
            yield db

        app.dependency_overrides[get_db] = _fake_db
        app.dependency_overrides[_require_analyst] = lambda: "analyst1"
        app.include_router(router)

        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="http://test"
        ) as client:
            resp = await client.get(f"/api/v1/docs/device/{_FAKE_DEV_ID}")
        assert resp.status_code == 404

    @pytest.mark.asyncio
    async def test_export_returns_200_with_all_sections(self) -> None:
        import httpx
        from server.api.docs_api import router, _require_analyst
        from server.database import get_db
        from fastapi import FastAPI

        db = _make_db(
            networks=[_make_network()],
            hosts=[_make_host()],
            devices=[_make_device()],
            open_alerts=0,
            critical_alerts=0,
        )

        app = FastAPI()

        async def _fake_db():
            yield db

        app.dependency_overrides[get_db] = _fake_db
        app.dependency_overrides[_require_analyst] = lambda: "analyst1"
        app.include_router(router)

        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="http://test"
        ) as client:
            resp = await client.get("/api/v1/docs/export")
        assert resp.status_code == 200
        assert "Executive Summary" in resp.text
        assert "---" in resp.text  # section separator
