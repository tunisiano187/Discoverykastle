"""
Built-in Ansible integration module.

Collects host facts from either:

  1. Ansible AWX / Ansible Tower REST API
     Set DKASTLE_ANSIBLE_AWX_URL + DKASTLE_ANSIBLE_AWX_TOKEN.
     Imports all hosts and their hostvars (gathered facts) from all AWX
     inventories.

  2. Local Ansible fact cache directory
     Set DKASTLE_ANSIBLE_FACT_CACHE_DIR to the path of the fact cache
     (the directory used by the `jsonfile` or `yaml` cache plugin).
     Each file named <hostname>.json or <hostname> is loaded as a fact dict.

Data collected per host:
  - IP addresses (ansible_host, ansible_default_ipv4, ansible_all_ipv4_addresses)
  - FQDN / inventory hostname
  - OS distribution + version (ansible_distribution*)
  - Kernel version (ansible_kernel)
  - Installed packages (ansible_packages, if gathered)

Configuration (DKASTLE_* env vars):
  DKASTLE_ANSIBLE_ENABLED=false
  DKASTLE_ANSIBLE_AWX_URL=https://awx.example.com
  DKASTLE_ANSIBLE_AWX_TOKEN=<OAuth2 token>
  DKASTLE_ANSIBLE_FACT_CACHE_DIR=/var/cache/ansible/facts
  DKASTLE_ANSIBLE_SYNC_INTERVAL=3600   (seconds)
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
from datetime import datetime
from pathlib import Path
from typing import Any, TYPE_CHECKING

import httpx

from server.modules.base import BaseModule, ModuleCapability, ModuleManifest

if TYPE_CHECKING:
    from sqlalchemy.ext.asyncio import AsyncSession

logger = logging.getLogger(__name__)


class Module(BaseModule):
    manifest = ModuleManifest(
        name="builtin-ansible",
        version="1.0.0",
        description=(
            "Ansible integration: imports host facts from AWX/Tower or a local "
            "fact-cache directory into the host inventory."
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

        if not settings.ansible_enabled:
            self.logger.info("Ansible integration disabled (DKASTLE_ANSIBLE_ENABLED=false)")
            return

        has_awx = bool(settings.ansible_awx_url and settings.ansible_awx_token)
        has_cache = bool(
            settings.ansible_fact_cache_dir
            and Path(settings.ansible_fact_cache_dir).is_dir()
        )

        if not has_awx and not has_cache:
            self.logger.warning(
                "Ansible enabled but neither AWX URL/token nor a valid fact cache "
                "directory is configured — skipping."
            )
            return

        mode = "AWX" if has_awx else f"fact-cache ({settings.ansible_fact_cache_dir})"
        self.logger.info("Ansible integration active — mode: %s", mode)
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
                self.logger.exception("Ansible sync failed")
            await asyncio.sleep(settings.ansible_sync_interval)

    async def _run_sync(self) -> None:
        from server.config import settings
        from server.database import async_session_factory

        self.logger.info("Starting Ansible host sync…")

        facts_by_host: dict[str, dict[str, Any]] = {}

        if settings.ansible_awx_url and settings.ansible_awx_token:
            awx_facts = await self._fetch_awx_facts()
            facts_by_host.update(awx_facts)

        if settings.ansible_fact_cache_dir:
            cache_facts = self._read_fact_cache(settings.ansible_fact_cache_dir)
            facts_by_host.update(cache_facts)

        if not facts_by_host:
            self.logger.info("No Ansible hosts returned")
            return

        async with async_session_factory() as db:
            imported = 0
            for hostname, facts in facts_by_host.items():
                try:
                    await self._upsert_host(hostname, facts, db)
                    imported += 1
                except Exception:
                    self.logger.exception(
                        "Failed to import Ansible host %s", hostname
                    )
            await db.commit()

        self.logger.info(
            "Ansible sync complete — %d/%d hosts imported", imported, len(facts_by_host)
        )

    # ------------------------------------------------------------------
    # AWX / Tower API
    # ------------------------------------------------------------------

    def _awx_headers(self) -> dict[str, str]:
        from server.config import settings

        return {
            "Authorization": f"Bearer {settings.ansible_awx_token}",
            "Content-Type": "application/json",
        }

    async def _awx_paginate(self, url: str) -> list[dict[str, Any]]:
        """Fetch all pages from an AWX list endpoint."""
        results: list[dict[str, Any]] = []
        next_url: str | None = url
        async with httpx.AsyncClient(timeout=30, verify=False) as client:
            while next_url:
                try:
                    resp = await client.get(next_url, headers=self._awx_headers())
                    resp.raise_for_status()
                    data = resp.json()
                    results.extend(data.get("results", []))
                    next_url = data.get("next")
                except httpx.HTTPError as exc:
                    self.logger.error("AWX request failed: %s", exc)
                    break
        return results

    async def _fetch_awx_facts(self) -> dict[str, dict[str, Any]]:
        from server.config import settings

        base = settings.ansible_awx_url.rstrip("/")
        hosts = await self._awx_paginate(f"{base}/api/v2/hosts/")
        facts_by_host: dict[str, dict[str, Any]] = {}

        async with httpx.AsyncClient(timeout=30, verify=False) as client:
            for host in hosts:
                name: str = host.get("name", "")
                host_id = host.get("id")
                if not name or not host_id:
                    continue
                # Fetch gathered facts (ansible facts) for this host
                try:
                    resp = await client.get(
                        f"{base}/api/v2/hosts/{host_id}/ansible_facts/",
                        headers=self._awx_headers(),
                    )
                    if resp.status_code == 200:
                        ansible_facts = resp.json()
                    else:
                        ansible_facts = {}
                except httpx.HTTPError:
                    ansible_facts = {}

                # Merge host variables into facts
                variables: dict[str, Any] = {}
                try:
                    var_text = host.get("variables", "") or ""
                    if var_text.strip().startswith("{"):
                        variables = json.loads(var_text)
                    else:
                        import yaml  # type: ignore[import]
                        variables = yaml.safe_load(var_text) or {}
                except Exception:
                    pass

                merged: dict[str, Any] = {**variables, **ansible_facts}
                facts_by_host[name] = merged

        return facts_by_host

    # ------------------------------------------------------------------
    # Local fact cache
    # ------------------------------------------------------------------

    def _read_fact_cache(self, cache_dir: str) -> dict[str, dict[str, Any]]:
        facts_by_host: dict[str, dict[str, Any]] = {}
        cache_path = Path(cache_dir)
        for entry in cache_path.iterdir():
            if not entry.is_file():
                continue
            hostname = entry.stem  # strip .json / .yaml extension
            try:
                text = entry.read_text(encoding="utf-8")
                if entry.suffix in (".yaml", ".yml"):
                    import yaml  # type: ignore[import]
                    data = yaml.safe_load(text) or {}
                else:
                    data = json.loads(text)
                # Ansible fact cache wraps facts under 'ansible_facts' key
                facts = data.get("ansible_facts", data)
                facts_by_host[hostname] = facts
            except Exception:
                self.logger.warning("Could not parse fact cache file: %s", entry)
        return facts_by_host

    # ------------------------------------------------------------------
    # Host upsert
    # ------------------------------------------------------------------

    async def _upsert_host(
        self, inventory_name: str, facts: dict[str, Any], db: "AsyncSession"
    ) -> None:
        from sqlalchemy import select
        from server.models.host import Host, Package

        # --- Collect IPs ---
        ip_addresses: list[str] = []

        # ansible_host variable takes priority
        ansible_host = facts.get("ansible_host")
        if ansible_host:
            ip_addresses.append(ansible_host)

        # Default IPv4 gateway interface
        default_v4 = facts.get("ansible_default_ipv4", {})
        if isinstance(default_v4, dict):
            ip = default_v4.get("address")
            if ip and ip not in ip_addresses:
                ip_addresses.append(ip)

        # All IPv4 addresses
        for ip in facts.get("ansible_all_ipv4_addresses", []):
            if ip and ip not in ip_addresses and not ip.startswith("127."):
                ip_addresses.append(ip)

        fqdn: str | None = (
            facts.get("ansible_fqdn")
            or facts.get("ansible_hostname")
            or inventory_name
        )
        os_name: str | None = facts.get("ansible_distribution")
        os_version: str | None = facts.get("ansible_distribution_version")

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
            self.logger.info("Ansible: new host %s (%s)", fqdn, ip_addresses)
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
            self.logger.debug("Ansible: updated host %s", fqdn)

        await db.flush()

        # --- Packages (ansible_packages fact) ---
        raw_packages = facts.get("ansible_packages", {})
        if isinstance(raw_packages, dict):
            for pkg_name, pkg_list in raw_packages.items():
                version: str | None = None
                if isinstance(pkg_list, list) and pkg_list:
                    version = pkg_list[0].get("version")

                existing = await db.execute(
                    select(Package).where(
                        Package.host_id == host.id,
                        Package.name == pkg_name,
                        Package.package_manager == "ansible",
                    )
                )
                if existing.scalar_one_or_none() is None:
                    db.add(
                        Package(
                            host_id=host.id,
                            name=pkg_name,
                            version=version,
                            package_manager="ansible",
                        )
                    )
        await db.flush()
