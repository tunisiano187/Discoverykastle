"""
Tests for server/modules/registry.py and server/modules/base.py.

Strategy: concrete stub modules; no real DB or external dependencies.
"""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock

import pytest

from server.modules.base import BaseModule, ModuleCapability, ModuleManifest
from server.modules.registry import ModuleRegistry


# ---------------------------------------------------------------------------
# Stub modules for testing
# ---------------------------------------------------------------------------

class _AlertModule(BaseModule):
    manifest = ModuleManifest(
        name="stub-alert",
        version="1.0.0",
        description="Test alert module",
        author="test",
        capabilities=[ModuleCapability.ALERT],
        builtin=False,
    )

    def __init__(self) -> None:
        super().__init__()
        self.on_agent_offline_calls: list[str] = []
        self.on_vuln_calls: list = []

    async def on_agent_offline(self, agent_id: str, db) -> None:
        self.on_agent_offline_calls.append(agent_id)

    async def on_vulnerability_found(self, vuln, host, db) -> None:
        self.on_vuln_calls.append((vuln, host))


class _InventoryModule(BaseModule):
    manifest = ModuleManifest(
        name="stub-inventory",
        version="1.0.0",
        description="Test inventory module",
        author="test",
        capabilities=[ModuleCapability.INVENTORY],
        builtin=True,
    )

    async def get_inventory_extra(self, host_id: str, db) -> dict:
        return {"extra_key": "extra_value", "host_id": host_id}


class _ExportModule(BaseModule):
    manifest = ModuleManifest(
        name="stub-export",
        version="1.0.0",
        description="Test export module",
        author="test",
        capabilities=[ModuleCapability.EXPORT],
        builtin=False,
    )

    async def export(self, format: str, db) -> str | None:
        if format == "markdown":
            return "# Export\n\nData"
        return None


class _NoCapModule(BaseModule):
    manifest = ModuleManifest(
        name="stub-nocap",
        version="1.0.0",
        description="No capabilities",
        author="test",
        capabilities=[],
        builtin=False,
    )


# ---------------------------------------------------------------------------
# ModuleRegistry — registration
# ---------------------------------------------------------------------------

class TestRegistryRegistration:
    def test_register_and_get(self) -> None:
        reg = ModuleRegistry()
        m = _AlertModule()
        reg.register(m)
        assert reg.get_module("stub-alert") is m

    def test_get_unknown_returns_none(self) -> None:
        reg = ModuleRegistry()
        assert reg.get_module("nonexistent") is None

    def test_duplicate_registration_ignored(self, caplog) -> None:
        import logging
        reg = ModuleRegistry()
        m1 = _AlertModule()
        m2 = _AlertModule()
        reg.register(m1)
        with caplog.at_level(logging.WARNING):
            reg.register(m2)
        assert reg.get_module("stub-alert") is m1

    def test_unregister_removes_module(self) -> None:
        reg = ModuleRegistry()
        reg.register(_AlertModule())
        reg.unregister("stub-alert")
        assert reg.get_module("stub-alert") is None

    def test_unregister_missing_is_noop(self) -> None:
        reg = ModuleRegistry()
        reg.unregister("does-not-exist")  # must not raise


# ---------------------------------------------------------------------------
# ModuleRegistry — list_modules
# ---------------------------------------------------------------------------

class TestListModules:
    def test_empty_registry_returns_empty_list(self) -> None:
        assert ModuleRegistry().list_modules() == []

    def test_lists_all_registered(self) -> None:
        reg = ModuleRegistry()
        reg.register(_AlertModule())
        reg.register(_InventoryModule())
        result = reg.list_modules()
        names = {m["name"] for m in result}
        assert "stub-alert" in names
        assert "stub-inventory" in names

    def test_capabilities_serialised_as_strings(self) -> None:
        reg = ModuleRegistry()
        reg.register(_AlertModule())
        entry = reg.list_modules()[0]
        assert entry["capabilities"] == ["alert"]

    def test_builtin_flag_present(self) -> None:
        reg = ModuleRegistry()
        reg.register(_InventoryModule())
        assert reg.list_modules()[0]["builtin"] is True


# ---------------------------------------------------------------------------
# ModuleRegistry — dispatch (event bus)
# ---------------------------------------------------------------------------

class TestDispatch:
    @pytest.mark.asyncio
    async def test_dispatch_agent_offline_calls_alert_modules(self) -> None:
        reg = ModuleRegistry()
        m = _AlertModule()
        reg.register(m)
        reg.register(_InventoryModule())  # no ALERT cap — should NOT be called
        db = AsyncMock()
        await reg.dispatch_agent_offline("agent-42", db)
        assert m.on_agent_offline_calls == ["agent-42"]

    @pytest.mark.asyncio
    async def test_dispatch_vulnerability_found_calls_alert_modules(self) -> None:
        reg = ModuleRegistry()
        m = _AlertModule()
        reg.register(m)
        db = AsyncMock()
        vuln = MagicMock()
        host = MagicMock()
        await reg.dispatch_vulnerability_found(vuln, host, db)
        assert len(m.on_vuln_calls) == 1
        assert m.on_vuln_calls[0] == (vuln, host)

    @pytest.mark.asyncio
    async def test_dispatch_does_not_call_wrong_capability(self) -> None:
        reg = ModuleRegistry()
        m = _InventoryModule()
        reg.register(m)
        db = AsyncMock()
        await reg.dispatch_agent_offline("agent-99", db)
        # _InventoryModule has no on_agent_offline override; default is no-op

    @pytest.mark.asyncio
    async def test_dispatch_host_discovered_no_crash_with_no_modules(self) -> None:
        reg = ModuleRegistry()
        db = AsyncMock()
        host = MagicMock()
        await reg.dispatch_host_discovered(host, db)  # must not raise

    @pytest.mark.asyncio
    async def test_failing_module_does_not_block_others(self) -> None:
        reg = ModuleRegistry()

        class _FailingAlert(_AlertModule):
            manifest = ModuleManifest(
                name="stub-failing",
                version="1.0.0",
                description="Fails",
                author="test",
                capabilities=[ModuleCapability.ALERT],
                builtin=False,
            )

            async def on_agent_offline(self, agent_id, db) -> None:
                raise RuntimeError("boom")

        m_good = _AlertModule()
        reg.register(_FailingAlert())
        reg.register(m_good)
        db = AsyncMock()
        await reg.dispatch_agent_offline("agent-x", db)
        assert m_good.on_agent_offline_calls == ["agent-x"]


# ---------------------------------------------------------------------------
# ModuleRegistry — collect helpers
# ---------------------------------------------------------------------------

class TestCollectHelpers:
    @pytest.mark.asyncio
    async def test_collect_inventory_extra_merges_results(self) -> None:
        reg = ModuleRegistry()
        reg.register(_InventoryModule())
        db = AsyncMock()
        extra = await reg.collect_inventory_extra("host-1", db)
        assert extra["extra_key"] == "extra_value"
        assert extra["host_id"] == "host-1"

    @pytest.mark.asyncio
    async def test_collect_inventory_extra_empty_with_no_inventory_modules(self) -> None:
        reg = ModuleRegistry()
        reg.register(_AlertModule())
        db = AsyncMock()
        extra = await reg.collect_inventory_extra("host-1", db)
        assert extra == {}

    @pytest.mark.asyncio
    async def test_collect_export_returns_first_non_none(self) -> None:
        reg = ModuleRegistry()
        reg.register(_ExportModule())
        db = AsyncMock()
        result = await reg.collect_export("markdown", db)
        assert result is not None
        assert "Export" in result

    @pytest.mark.asyncio
    async def test_collect_export_returns_none_when_format_unsupported(self) -> None:
        reg = ModuleRegistry()
        reg.register(_ExportModule())
        db = AsyncMock()
        result = await reg.collect_export("pdf", db)
        assert result is None

    @pytest.mark.asyncio
    async def test_collect_export_returns_none_with_no_export_modules(self) -> None:
        reg = ModuleRegistry()
        reg.register(_AlertModule())
        db = AsyncMock()
        result = await reg.collect_export("markdown", db)
        assert result is None


# ---------------------------------------------------------------------------
# BaseModule — emit_alert helper
# ---------------------------------------------------------------------------

class TestEmitAlert:
    def _db(self) -> AsyncMock:
        db = AsyncMock()
        db.add = MagicMock()  # add() is synchronous in SQLAlchemy
        return db

    @pytest.mark.asyncio
    async def test_emit_alert_adds_alert_to_db(self) -> None:
        m = _AlertModule()
        db = self._db()
        await m.emit_alert(db, "critical", "Test alert message")
        db.add.assert_called_once()
        db.flush.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_emit_alert_uses_module_name_as_source(self) -> None:
        m = _AlertModule()
        db = self._db()
        await m.emit_alert(db, "high", "msg")
        added = db.add.call_args[0][0]
        assert added.source == "stub-alert"

    @pytest.mark.asyncio
    async def test_emit_alert_custom_source_overrides_name(self) -> None:
        m = _AlertModule()
        db = self._db()
        await m.emit_alert(db, "low", "msg", source="custom-source")
        added = db.add.call_args[0][0]
        assert added.source == "custom-source"

    @pytest.mark.asyncio
    async def test_emit_alert_sets_details(self) -> None:
        m = _AlertModule()
        db = self._db()
        await m.emit_alert(db, "medium", "msg", details={"cve": "CVE-2024-9999"})
        added = db.add.call_args[0][0]
        assert added.details == {"cve": "CVE-2024-9999"}
