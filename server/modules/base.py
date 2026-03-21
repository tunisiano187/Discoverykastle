"""
Base class for all Discoverykastle modules.

A module can hook into the platform lifecycle at any of the event methods below.
Only override the events your module actually needs — unneeded events are no-ops.

Example minimal module:

    from server.modules.base import BaseModule, ModuleCapability, ModuleManifest

    class MyModule(BaseModule):
        manifest = ModuleManifest(
            name="my-module",
            version="1.0.0",
            description="Does something useful",
            author="you",
            capabilities=[ModuleCapability.ALERT],
        )

        async def on_vulnerability_found(self, vuln, host, db):
            if vuln.cvss_score and vuln.cvss_score >= 9.0:
                await self.emit_alert(db, "critical", f"Critical CVE on {host.fqdn}")
"""

from __future__ import annotations

import abc
import logging
from dataclasses import dataclass, field
from enum import Enum
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from sqlalchemy.ext.asyncio import AsyncSession
    from server.models import Host, Vulnerability, NetworkDevice, Network, ScanResult

logger = logging.getLogger(__name__)


class ModuleCapability(str, Enum):
    ALERT = "alert"               # Generates alerts
    INVENTORY = "inventory"       # Enriches or manages inventory
    TOPOLOGY = "topology"         # Contributes to network topology/plan
    INTEGRATION = "integration"   # Syncs with external tools (NetBox, ServiceNow…)
    EXPORT = "export"             # Provides data export formats
    ENRICHMENT = "enrichment"     # Enriches discovered data (GeoIP, WHOIS…)
    COLLECTOR = "collector"       # Custom data collection task


@dataclass
class ModuleManifest:
    name: str
    version: str
    description: str
    author: str
    capabilities: list[ModuleCapability] = field(default_factory=list)
    config_schema: dict[str, Any] = field(default_factory=dict)
    builtin: bool = False


class BaseModule(abc.ABC):
    """
    Abstract base for all Discoverykastle modules.

    Subclass this, set `manifest`, and override any event hooks you need.
    The registry will call hooks automatically as data flows through the platform.
    """

    manifest: ModuleManifest

    def __init__(self, config: dict[str, Any] | None = None) -> None:
        self.config: dict[str, Any] = config or {}
        self.logger = logging.getLogger(f"dkastle.module.{self.manifest.name}")

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    async def setup(self) -> None:
        """Called once when the module is loaded. Use for DB setup, connections, etc."""

    async def teardown(self) -> None:
        """Called on graceful shutdown."""

    # ------------------------------------------------------------------
    # Event hooks — override what you need
    # ------------------------------------------------------------------

    async def on_host_discovered(self, host: "Host", db: "AsyncSession") -> None:
        """Triggered when a new host is added or updated."""

    async def on_vulnerability_found(
        self, vuln: "Vulnerability", host: "Host", db: "AsyncSession"
    ) -> None:
        """Triggered when a CVE is linked to a host."""

    async def on_device_found(
        self, device: "NetworkDevice", db: "AsyncSession"
    ) -> None:
        """Triggered when a network device (switch/router/firewall) is discovered."""

    async def on_network_discovered(
        self, network: "Network", db: "AsyncSession"
    ) -> None:
        """Triggered when a new subnet is found."""

    async def on_scan_complete(
        self, result: "ScanResult", db: "AsyncSession"
    ) -> None:
        """Triggered when a scan task finishes."""

    async def on_agent_offline(self, agent_id: str, db: "AsyncSession") -> None:
        """Triggered when an agent misses heartbeats and is marked offline."""

    # ------------------------------------------------------------------
    # Inventory extension point
    # ------------------------------------------------------------------

    async def get_inventory_extra(
        self, host_id: str, db: "AsyncSession"
    ) -> dict[str, Any]:
        """
        Return extra data to be merged into a host's inventory response.
        E.g., compliance score, asset tag from CMDB, VLAN description.
        """
        return {}

    # ------------------------------------------------------------------
    # Export extension point
    # ------------------------------------------------------------------

    async def export(
        self, format: str, db: "AsyncSession"
    ) -> bytes | str | None:
        """
        Produce an export artefact (CSV, PDF, JSON…).
        Return None if this module does not handle the requested format.
        """
        return None

    # ------------------------------------------------------------------
    # Helper: emit an alert without knowing about the Alert model directly
    # ------------------------------------------------------------------

    async def emit_alert(
        self,
        db: "AsyncSession",
        severity: str,
        message: str,
        source: str | None = None,
        details: dict[str, Any] | None = None,
    ) -> None:
        """
        Convenience method to create an Alert from within any module.
        Imports are deferred to avoid circular dependencies.
        """
        from server.models.alert import Alert
        from datetime import datetime

        alert = Alert(
            severity=severity,
            message=message,
            source=source or self.manifest.name,
            details=details or {},
            created_at=datetime.utcnow(),
        )
        db.add(alert)
        await db.flush()
        self.logger.info("[alert:%s] %s", severity, message)
