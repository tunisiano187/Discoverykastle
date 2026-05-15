"""
Tests for server/modules/builtin/inventory/module.py.

Strategy: mock AsyncSession to avoid PostgreSQL.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from unittest.mock import AsyncMock, MagicMock

import pytest

from server.modules.builtin.inventory.module import Module
from server.modules.base import ModuleCapability


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

def _make_host() -> MagicMock:
    host = MagicMock()
    host.id = uuid.uuid4()
    host.last_seen = None
    return host


def _db_with_scalars(service_count: int = 3, package_count: int = 10) -> AsyncMock:
    db = AsyncMock()
    db.scalar = AsyncMock(side_effect=[service_count, package_count])
    mock_rows = [(s, c) for s, c in [("critical", 1), ("high", 2), ("medium", 0)]]
    mock_result = MagicMock()
    mock_result.__iter__ = lambda self: iter(mock_rows)
    db.execute = AsyncMock(return_value=mock_result)
    return db


# ---------------------------------------------------------------------------
# Manifest
# ---------------------------------------------------------------------------

class TestManifest:
    def test_name(self) -> None:
        assert Module.manifest.name == "builtin-inventory"

    def test_inventory_capability(self) -> None:
        assert ModuleCapability.INVENTORY in Module.manifest.capabilities

    def test_is_builtin(self) -> None:
        assert Module.manifest.builtin is True


# ---------------------------------------------------------------------------
# on_host_discovered
# ---------------------------------------------------------------------------

class TestOnHostDiscovered:
    @pytest.mark.asyncio
    async def test_updates_last_seen(self) -> None:
        m = Module()
        host = _make_host()
        db = AsyncMock()
        await m.on_host_discovered(host, db)
        assert host.last_seen is not None
        assert isinstance(host.last_seen, datetime)

    @pytest.mark.asyncio
    async def test_flushes_session(self) -> None:
        m = Module()
        host = _make_host()
        db = AsyncMock()
        await m.on_host_discovered(host, db)
        db.flush.assert_awaited_once()


# ---------------------------------------------------------------------------
# get_inventory_extra
# ---------------------------------------------------------------------------

class TestGetInventoryExtra:
    @pytest.mark.asyncio
    async def test_returns_service_count(self) -> None:
        m = Module()
        db = _db_with_scalars(service_count=5, package_count=0)
        result = await m.get_inventory_extra(str(uuid.uuid4()), db)
        assert result["service_count"] == 5

    @pytest.mark.asyncio
    async def test_returns_package_count(self) -> None:
        m = Module()
        db = _db_with_scalars(service_count=0, package_count=12)
        result = await m.get_inventory_extra(str(uuid.uuid4()), db)
        assert result["package_count"] == 12

    @pytest.mark.asyncio
    async def test_vuln_counts_present_for_all_severities(self) -> None:
        m = Module()
        db = _db_with_scalars()
        result = await m.get_inventory_extra(str(uuid.uuid4()), db)
        for sev in ("critical", "high", "medium", "low"):
            assert sev in result["vuln_counts"]

    @pytest.mark.asyncio
    async def test_vuln_counts_default_to_zero_when_absent(self) -> None:
        m = Module()
        db = AsyncMock()
        db.scalar = AsyncMock(side_effect=[0, 0])
        mock_result = MagicMock()
        mock_result.__iter__ = lambda self: iter([])
        db.execute = AsyncMock(return_value=mock_result)
        result = await m.get_inventory_extra(str(uuid.uuid4()), db)
        assert result["vuln_counts"] == {"critical": 0, "high": 0, "medium": 0, "low": 0}

    @pytest.mark.asyncio
    async def test_null_scalar_treated_as_zero(self) -> None:
        m = Module()
        db = AsyncMock()
        db.scalar = AsyncMock(side_effect=[None, None])
        mock_result = MagicMock()
        mock_result.__iter__ = lambda self: iter([])
        db.execute = AsyncMock(return_value=mock_result)
        result = await m.get_inventory_extra(str(uuid.uuid4()), db)
        assert result["service_count"] == 0
        assert result["package_count"] == 0
