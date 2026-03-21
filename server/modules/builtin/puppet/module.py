"""
Built-in Puppet integration module — server side.

Responsibility split:

  SERVER (this module)
  ─────────────────────────────────────────────────────────────────────
  • PuppetDB REST API (optional, only if PuppetDB is installed)
    The server contacts PuppetDB over HTTP.  This is only available when
    PuppetDB is part of the Puppet infrastructure; it is NOT required.
    Configured via DKASTLE_PUPPET_PUPPETDB_URL.

  • Host upsert logic shared with the data ingestion API
    When an agent submits a Puppet batch via POST /api/v1/data/puppet,
    the API endpoint calls _upsert_host() from this module directly.

  AGENT (agent/collectors/puppet.py)
  ─────────────────────────────────────────────────────────────────────
  • YAML fact cache  ($vardir/yaml/facts/*.yaml)
  • YAML run reports ($vardir/reports/<certname>/*.yaml)
  The agent running on (or near) the Puppet master reads these files,
  converts them to JSON, and POSTs them to POST /api/v1/data/puppet.
  No filesystem access is required from the Docker server container.

Configuration (DKASTLE_* env vars):
  DKASTLE_PUPPET_ENABLED=false
  DKASTLE_PUPPET_PUPPETDB_URL=https://puppet.example.com:8081  (optional)
  DKASTLE_PUPPET_PUPPETDB_TOKEN=<PE RBAC token>                (optional)
  DKASTLE_PUPPET_SYNC_INTERVAL=3600   (seconds, for PuppetDB pull)
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
        version="1.2.0",
        description=(
            "Puppet integration: pulls node facts from PuppetDB (server-side) "
            "and processes agent-submitted fact/report batches "
            "(POST /api/v1/data/puppet)."
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

        if not settings.puppet_enabled:
            self.logger.info("Puppet integration disabled (DKASTLE_PUPPET_ENABLED=false)")
            return

        if settings.puppet_puppetdb_url:
            self.logger.info(
                "Puppet integration active — PuppetDB pull from %s",
                settings.puppet_puppetdb_url,
            )
            self._sync_task = asyncio.create_task(self._puppetdb_sync_loop())
        else:
            self.logger.info(
                "Puppet integration active — agent-push mode only "
                "(no DKASTLE_PUPPET_PUPPETDB_URL configured). "
                "Agents will submit data via POST /api/v1/data/puppet."
            )

    async def teardown(self) -> None:
        if self._sync_task and not self._sync_task.done():
            self._sync_task.cancel()
            try:
                await self._sync_task
            except asyncio.CancelledError:
                pass

    # ------------------------------------------------------------------
    # PuppetDB pull loop (server-side, optional)
    # ------------------------------------------------------------------

    async def _puppetdb_sync_loop(self) -> None:
        from server.config import settings

        while True:
            try:
                await self._run_puppetdb_sync()
            except Exception:
                self.logger.exception("PuppetDB sync failed")
            await asyncio.sleep(settings.puppet_sync_interval)

    async def _run_puppetdb_sync(self) -> None:
        from server.database import async_session_factory

        self.logger.info("Starting PuppetDB node sync…")
        facts_by_node = await self._collect_puppetdb()
        if not facts_by_node:
            self.logger.info("No nodes returned from PuppetDB")
            return

        async with async_session_factory() as db:
            imported = 0
            for certname, facts in facts_by_node.items():
                try:
                    await self._upsert_host(certname, facts, db)
                    imported += 1
                except Exception:
                    self.logger.exception("Failed to import PuppetDB node %s", certname)
            await db.commit()

        self.logger.info(
            "PuppetDB sync complete — %d/%d nodes imported", imported, len(facts_by_node)
        )

    # ------------------------------------------------------------------
    # PuppetDB API client
    # ------------------------------------------------------------------

    def _puppetdb_headers(self) -> dict[str, str]:
        from server.config import settings

        h: dict[str, str] = {"Content-Type": "application/json"}
        if settings.puppet_puppetdb_token:
            h["X-Authentication"] = settings.puppet_puppetdb_token
        return h

    async def _puppetdb_get(self, url: str) -> list[Any]:
        try:
            async with httpx.AsyncClient(timeout=30, verify=False) as client:
                resp = await client.get(url, headers=self._puppetdb_headers())
                resp.raise_for_status()
                return resp.json()
        except httpx.HTTPError as exc:
            self.logger.error("PuppetDB request failed (%s): %s", url, exc)
            return []

    async def _collect_puppetdb(self) -> dict[str, dict[str, Any]]:
        from server.config import settings

        if not settings.puppet_puppetdb_url:
            return {}

        base = settings.puppet_puppetdb_url.rstrip("/")
        nodes = await self._puppetdb_get(f"{base}/pdb/query/v4/nodes")
        if not nodes:
            return {}

        result: dict[str, dict[str, Any]] = {}
        for node in nodes:
            certname: str = node.get("certname", "")
            if not certname:
                continue
            facts_list = await self._puppetdb_get(
                f"{base}/pdb/query/v4/nodes/{certname}/facts"
            )
            facts: dict[str, Any] = {
                f["name"]: f["value"] for f in facts_list if "name" in f
            }
            facts["_puppet_environment"] = node.get("catalog_environment")
            facts["_puppet_last_run"] = node.get("catalog_timestamp")
            result[certname] = facts

        self.logger.info("PuppetDB: collected %d nodes", len(result))
        return result

    # ------------------------------------------------------------------
    # Host upsert — called both by PuppetDB pull and by the data API
    # (POST /api/v1/data/puppet → server/api/data.py → this method)
    # ------------------------------------------------------------------

    async def _upsert_host(
        self, certname: str, facts: dict[str, Any], db: "AsyncSession"
    ) -> None:
        from sqlalchemy import select
        from server.models.host import Host, Package

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
        if not ip_addresses:
            for key in ("ipaddress", "ipaddress6"):
                ip = facts.get(key)
                if ip and ip not in ("127.0.0.1", "::1"):
                    ip_addresses.append(ip)

        fqdn: str | None = (
            facts.get("fqdn") or facts.get("hostname") or certname
        )
        os_name: str | None = (
            facts.get("osfamily")
            or (facts.get("os") or {}).get("family")
            or facts.get("operatingsystem")
        )
        os_version: str | None = (
            facts.get("operatingsystemrelease")
            or (facts.get("os") or {}).get("release", {}).get("full")
        )

        # --- Find or create host ---
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
                host.ip_addresses = list({*host.ip_addresses, *ip_addresses})
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
