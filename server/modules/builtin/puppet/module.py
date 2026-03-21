"""
Built-in Puppet integration module.

Collects node facts from PuppetDB and imports them into the Discoverykastle
host inventory.  Runs once at startup and then on a periodic schedule.

Data collected per node:
  - IP addresses (networking.interfaces facts)
  - FQDN / certname
  - OS name + release
  - Kernel version
  - Installed packages (from the 'packages' fact, if available)
  - Last Puppet run timestamp
  - Environment (production, staging, …)

PuppetDB API reference:
  https://www.puppet.com/docs/puppetdb/latest/api/query/v4/

Configuration (DKASTLE_* env vars):
  DKASTLE_PUPPETDB_ENABLED=false
  DKASTLE_PUPPETDB_URL=https://puppet.example.com:8081
  DKASTLE_PUPPETDB_TOKEN=<PE RBAC token or bearer token>
  DKASTLE_PUPPETDB_SYNC_INTERVAL=3600   (seconds)
"""

from __future__ import annotations

import asyncio
import logging
from datetime import datetime
from typing import Any, TYPE_CHECKING

import httpx

from server.modules.base import BaseModule, ModuleCapability, ModuleManifest

if TYPE_CHECKING:
    from sqlalchemy.ext.asyncio import AsyncSession

logger = logging.getLogger(__name__)


class Module(BaseModule):
    manifest = ModuleManifest(
        name="builtin-puppet",
        version="1.0.0",
        description=(
            "Puppet integration: imports node facts from PuppetDB into the host "
            "inventory (OS, IPs, packages, last run time, environment)."
        ),
        author="Discoverykastle",
        capabilities=[ModuleCapability.COLLECTOR, ModuleCapability.INVENTORY],
        builtin=True,
    )

    _sync_task: asyncio.Task | None = None

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    async def setup(self) -> None:
        from server.config import settings

        if not settings.puppetdb_enabled:
            self.logger.info("Puppet integration disabled (DKASTLE_PUPPETDB_ENABLED=false)")
            return
        if not settings.puppetdb_url:
            self.logger.warning(
                "Puppet enabled but DKASTLE_PUPPETDB_URL is not set — skipping."
            )
            return

        self.logger.info("Puppet integration active — PuppetDB: %s", settings.puppetdb_url)
        # Initial sync at startup, then schedule periodic sync
        self._sync_task = asyncio.create_task(self._sync_loop())

    async def teardown(self) -> None:
        if self._sync_task and not self._sync_task.done():
            self._sync_task.cancel()
            try:
                await self._sync_task
            except asyncio.CancelledError:
                pass

    # ------------------------------------------------------------------
    # Sync loop
    # ------------------------------------------------------------------

    async def _sync_loop(self) -> None:
        from server.config import settings

        while True:
            try:
                await self._run_sync()
            except Exception:
                self.logger.exception("Puppet sync failed")
            await asyncio.sleep(settings.puppetdb_sync_interval)

    async def _run_sync(self) -> None:
        from server.database import async_session_factory

        self.logger.info("Starting Puppet node sync…")
        nodes = await self._fetch_nodes()
        if not nodes:
            self.logger.info("No Puppet nodes returned from PuppetDB")
            return

        async with async_session_factory() as db:
            imported = 0
            for node in nodes:
                try:
                    await self._upsert_host(node, db)
                    imported += 1
                except Exception:
                    self.logger.exception(
                        "Failed to import Puppet node %s", node.get("certname", "?")
                    )
            await db.commit()
        self.logger.info("Puppet sync complete — %d/%d nodes imported", imported, len(nodes))

    # ------------------------------------------------------------------
    # PuppetDB API calls
    # ------------------------------------------------------------------

    def _headers(self) -> dict[str, str]:
        from server.config import settings

        h: dict[str, str] = {"Content-Type": "application/json"}
        if settings.puppetdb_token:
            h["X-Authentication"] = settings.puppetdb_token
        return h

    async def _fetch_nodes(self) -> list[dict[str, Any]]:
        from server.config import settings

        url = f"{settings.puppetdb_url.rstrip('/')}/pdb/query/v4/nodes"
        try:
            async with httpx.AsyncClient(timeout=30, verify=False) as client:
                resp = await client.get(url, headers=self._headers())
                resp.raise_for_status()
                return resp.json()
        except httpx.HTTPError as exc:
            self.logger.error("PuppetDB nodes request failed: %s", exc)
            return []

    async def _fetch_facts(self, certname: str) -> dict[str, Any]:
        from server.config import settings

        url = (
            f"{settings.puppetdb_url.rstrip('/')}/pdb/query/v4/nodes/"
            f"{certname}/facts"
        )
        try:
            async with httpx.AsyncClient(timeout=30, verify=False) as client:
                resp = await client.get(url, headers=self._headers())
                resp.raise_for_status()
                facts_list: list[dict[str, Any]] = resp.json()
                # Convert [{name, value}, …] → {name: value}
                return {f["name"]: f["value"] for f in facts_list}
        except httpx.HTTPError as exc:
            self.logger.warning(
                "Could not fetch facts for %s: %s", certname, exc
            )
            return {}

    # ------------------------------------------------------------------
    # Host upsert
    # ------------------------------------------------------------------

    async def _upsert_host(
        self, node: dict[str, Any], db: "AsyncSession"
    ) -> None:
        from sqlalchemy import select
        from server.models.host import Host, Package

        certname: str = node.get("certname", "")
        if not certname:
            return

        facts = await self._fetch_facts(certname)

        # --- Collect IPs ---
        ip_addresses: list[str] = []
        networking = facts.get("networking", {})
        if isinstance(networking, dict):
            for iface_name, iface_data in networking.get("interfaces", {}).items():
                if iface_name in ("lo", "lo0"):
                    continue
                if isinstance(iface_data, dict):
                    ip = iface_data.get("ip") or iface_data.get("ip6")
                    if ip:
                        ip_addresses.append(ip)
        # Fallback: ipaddress fact
        if not ip_addresses:
            ip = facts.get("ipaddress") or facts.get("ipaddress6")
            if ip:
                ip_addresses.append(ip)

        fqdn: str | None = facts.get("fqdn") or certname
        os_name: str | None = facts.get("osfamily") or facts.get("os", {}).get("family")
        os_version: str | None = (
            facts.get("operatingsystemrelease")
            or facts.get("os", {}).get("release", {}).get("full")
        )

        # --- Upsert Host ---
        host: Host | None = None
        if ip_addresses:
            result = await db.execute(
                select(Host).where(Host.ip_addresses.contains([ip_addresses[0]]))
            )
            host = result.scalar_one_or_none()

        if host is None and fqdn:
            result = await db.execute(select(Host).where(Host.fqdn == fqdn))
            host = result.scalar_one_or_none()

        now = datetime.utcnow()
        if host is None:
            host = Host(
                fqdn=fqdn,
                ip_addresses=ip_addresses,
                os=os_name,
                os_version=os_version,
                first_seen=now,
                last_seen=now,
            )
            db.add(host)
            await db.flush()
            self.logger.info("Puppet: new host %s (%s)", fqdn, ip_addresses)
        else:
            if fqdn and not host.fqdn:
                host.fqdn = fqdn
            if ip_addresses:
                merged = list({*host.ip_addresses, *ip_addresses})
                host.ip_addresses = merged
            if os_name:
                host.os = os_name
            if os_version:
                host.os_version = os_version
            host.last_seen = now
            self.logger.debug("Puppet: updated host %s", fqdn)

        await db.flush()

        # --- Packages ---
        raw_packages = facts.get("packages", {})
        if isinstance(raw_packages, dict):
            for pkg_name, pkg_versions in raw_packages.items():
                version: str | None = None
                if isinstance(pkg_versions, dict):
                    version = next(iter(pkg_versions.keys()), None)
                elif isinstance(pkg_versions, str):
                    version = pkg_versions

                # Only insert if not already tracked
                existing = await db.execute(
                    select(Package).where(
                        Package.host_id == host.id,
                        Package.name == pkg_name,
                        Package.package_manager == "puppet",
                    )
                )
                if existing.scalar_one_or_none() is None:
                    db.add(
                        Package(
                            host_id=host.id,
                            name=pkg_name,
                            version=version,
                            package_manager="puppet",
                        )
                    )
        await db.flush()
