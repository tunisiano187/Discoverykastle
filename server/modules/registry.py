"""
Module Registry — single source of truth for all loaded modules.

The registry:
  - Holds every loaded BaseModule instance
  - Dispatches events to all modules that declare the relevant capability
  - Exposes module metadata for the management API
"""

from __future__ import annotations

import logging
from typing import Any, TYPE_CHECKING

from server.modules.base import BaseModule, ModuleCapability

if TYPE_CHECKING:
    from sqlalchemy.ext.asyncio import AsyncSession
    from server.models import Host, Vulnerability, NetworkDevice, Network, ScanResult

logger = logging.getLogger(__name__)


class ModuleRegistry:
    def __init__(self) -> None:
        self._modules: dict[str, BaseModule] = {}

    # ------------------------------------------------------------------
    # Registration
    # ------------------------------------------------------------------

    def register(self, module: BaseModule) -> None:
        name = module.manifest.name
        if name in self._modules:
            logger.warning("Module '%s' is already registered — skipping duplicate.", name)
            return
        self._modules[name] = module
        logger.info("Module registered: %s v%s", name, module.manifest.version)

    def unregister(self, name: str) -> None:
        self._modules.pop(name, None)

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    async def setup_all(self) -> None:
        for module in self._modules.values():
            try:
                await module.setup()
            except Exception:
                logger.exception("Error during setup of module '%s'", module.manifest.name)

    async def teardown_all(self) -> None:
        for module in self._modules.values():
            try:
                await module.teardown()
            except Exception:
                logger.exception("Error during teardown of module '%s'", module.manifest.name)

    # ------------------------------------------------------------------
    # Event dispatchers
    # ------------------------------------------------------------------

    async def dispatch_host_discovered(self, host: "Host", db: "AsyncSession") -> None:
        await self._dispatch_all("on_host_discovered", ModuleCapability.INVENTORY, host, db)

    async def dispatch_vulnerability_found(
        self, vuln: "Vulnerability", host: "Host", db: "AsyncSession"
    ) -> None:
        await self._dispatch_all("on_vulnerability_found", ModuleCapability.ALERT, vuln, host, db)

    async def dispatch_device_found(
        self, device: "NetworkDevice", db: "AsyncSession"
    ) -> None:
        await self._dispatch_all("on_device_found", ModuleCapability.TOPOLOGY, device, db)

    async def dispatch_network_discovered(
        self, network: "Network", db: "AsyncSession"
    ) -> None:
        await self._dispatch_all("on_network_discovered", ModuleCapability.TOPOLOGY, network, db)

    async def dispatch_scan_complete(
        self, result: "ScanResult", db: "AsyncSession"
    ) -> None:
        await self._dispatch_all("on_scan_complete", None, result, db)

    async def dispatch_agent_offline(self, agent_id: str, db: "AsyncSession") -> None:
        await self._dispatch_all("on_agent_offline", ModuleCapability.ALERT, agent_id, db)

    # ------------------------------------------------------------------
    # Aggregation helpers
    # ------------------------------------------------------------------

    async def collect_inventory_extra(
        self, host_id: str, db: "AsyncSession"
    ) -> dict[str, Any]:
        """Merge extra inventory data from all INVENTORY modules."""
        result: dict[str, Any] = {}
        for module in self._by_capability(ModuleCapability.INVENTORY):
            try:
                extra = await module.get_inventory_extra(host_id, db)
                result.update(extra)
            except Exception:
                logger.exception("Module '%s' failed get_inventory_extra", module.manifest.name)
        return result

    async def collect_export(self, format: str, db: "AsyncSession") -> bytes | str | None:
        """Return the first non-None export result from EXPORT modules."""
        for module in self._by_capability(ModuleCapability.EXPORT):
            try:
                data = await module.export(format, db)
                if data is not None:
                    return data
            except Exception:
                logger.exception("Module '%s' failed export('%s')", module.manifest.name, format)
        return None

    # ------------------------------------------------------------------
    # Introspection
    # ------------------------------------------------------------------

    def list_modules(self) -> list[dict[str, Any]]:
        return [
            {
                "name": m.manifest.name,
                "version": m.manifest.version,
                "description": m.manifest.description,
                "author": m.manifest.author,
                "capabilities": [c.value for c in m.manifest.capabilities],
                "builtin": m.manifest.builtin,
            }
            for m in self._modules.values()
        ]

    def get_module(self, name: str) -> BaseModule | None:
        return self._modules.get(name)

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    def _by_capability(self, cap: ModuleCapability | None) -> list[BaseModule]:
        if cap is None:
            return list(self._modules.values())
        return [m for m in self._modules.values() if cap in m.manifest.capabilities]

    async def _dispatch_all(
        self, method: str, cap: ModuleCapability | None, *args: Any
    ) -> None:
        for module in self._by_capability(cap):
            try:
                await getattr(module, method)(*args)
            except Exception:
                logger.exception(
                    "Module '%s' raised an error in %s", module.manifest.name, method
                )


# Global singleton — imported everywhere
registry = ModuleRegistry()
