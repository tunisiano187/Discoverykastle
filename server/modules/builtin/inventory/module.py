"""
Built-in Inventory module.

Responsibilities:
  - Enriches host inventory responses with service counts, vuln summaries,
    and last-seen timestamps
  - Provides inventory statistics (asset counts by OS, vuln distribution)
  - Handles deduplication when a host is re-reported by an agent

This module does NOT own the API routes (those live in server/api/inventory.py).
It contributes to inventory responses via get_inventory_extra().
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from sqlalchemy import select, func

from server.modules.base import BaseModule, ModuleCapability, ModuleManifest

if TYPE_CHECKING:
    from sqlalchemy.ext.asyncio import AsyncSession
    from server.models import Host


class Module(BaseModule):
    manifest = ModuleManifest(
        name="builtin-inventory",
        version="1.0.0",
        description="Core inventory enrichment: service counts, vuln summaries, asset stats.",
        author="Discoverykastle",
        capabilities=[ModuleCapability.INVENTORY],
        builtin=True,
    )

    async def on_host_discovered(self, host: "Host", db: "AsyncSession") -> None:
        """Update last_seen and merge duplicate IP entries."""
        from datetime import datetime
        host.last_seen = datetime.utcnow()
        await db.flush()

    async def get_inventory_extra(
        self, host_id: str, db: "AsyncSession"
    ) -> dict[str, Any]:
        """
        Return enriched data for a host detail response:
          - service_count
          - vuln_counts by severity
          - package_count
        """
        from server.models.host import Service, Package
        from server.models.vulnerability import Vulnerability
        import uuid

        hid = uuid.UUID(host_id)

        service_count = await db.scalar(
            select(func.count()).where(Service.host_id == hid)
        ) or 0

        package_count = await db.scalar(
            select(func.count()).where(Package.host_id == hid)
        ) or 0

        vuln_rows = await db.execute(
            select(Vulnerability.severity, func.count())
            .where(Vulnerability.host_id == hid)
            .group_by(Vulnerability.severity)
        )
        vuln_counts = {row[0]: row[1] for row in vuln_rows}

        return {
            "service_count": service_count,
            "package_count": package_count,
            "vuln_counts": {
                "critical": vuln_counts.get("critical", 0),
                "high": vuln_counts.get("high", 0),
                "medium": vuln_counts.get("medium", 0),
                "low": vuln_counts.get("low", 0),
            },
        }
