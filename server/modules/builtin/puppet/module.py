"""
Built-in Puppet integration module.

Collects node data from one or more Puppet data sources and imports it into
the Discoverykastle host inventory.  Runs once at startup then on a schedule.

Three data sources (configure whichever are accessible — all are optional):

  1. PuppetDB REST API  (DKASTLE_PUPPET_PUPPETDB_URL)
     Only present when PuppetDB is installed (Puppet Enterprise, or open-source
     with the puppetdb bolt-on).  Provides the richest structured data.

  2. YAML fact cache    (DKASTLE_PUPPET_FACT_CACHE_DIR)
     The Puppet master writes a YAML fact dump per node even WITHOUT PuppetDB.
     Default paths:
       Puppet 6+ / Bolt:  /opt/puppetlabs/puppet/cache/yaml/facts/
       Older open-source: /var/lib/puppet/yaml/facts/
     Each file is named <certname>.yaml and contains all Facter facts.

  3. YAML report files  (DKASTLE_PUPPET_REPORT_DIR)
     Puppet agents submit run reports to the master after each catalog apply.
     Default paths:
       Puppet 6+ / Bolt:  /opt/puppetlabs/puppet/cache/reports/<certname>/
       Older open-source: /var/lib/puppet/reports/<certname>/
     Provides: last run time, environment, run status, resource change summary.

All sources are merged per certname.  Configure what is available — a minimal
read-only mount of the Puppet master's vardir is enough for sources 2 and 3.

Data collected per node:
  - IP addresses (networking.interfaces / ipaddress fact)
  - FQDN / certname
  - OS family + release
  - Kernel version
  - Installed packages (from the 'packages' fact, if gathered)
  - Last Puppet run timestamp and status (from reports)
  - Puppet environment (production, staging, …)

Configuration (DKASTLE_* env vars):
  DKASTLE_PUPPET_ENABLED=false
  DKASTLE_PUPPET_PUPPETDB_URL=https://puppet.example.com:8081
  DKASTLE_PUPPET_PUPPETDB_TOKEN=<PE RBAC token or bearer token>
  DKASTLE_PUPPET_FACT_CACHE_DIR=/opt/puppetlabs/puppet/cache/yaml/facts
  DKASTLE_PUPPET_REPORT_DIR=/opt/puppetlabs/puppet/cache/reports
  DKASTLE_PUPPET_SYNC_INTERVAL=3600   (seconds)
"""

from __future__ import annotations

import asyncio
import logging
from datetime import datetime
from pathlib import Path
from typing import Any, TYPE_CHECKING

import httpx

from server.modules.base import BaseModule, ModuleCapability, ModuleManifest

if TYPE_CHECKING:
    from sqlalchemy.ext.asyncio import AsyncSession

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# YAML loader that handles Ruby-style object tags produced by Puppet/Facter
# ---------------------------------------------------------------------------

def _load_puppet_yaml(text: str) -> Any:
    """
    Parse a Puppet / Facter YAML file.

    Puppet's YAML output uses Ruby object tags such as:
        !ruby/object:Puppet::Node::Facts
        !ruby/sym environment
    Standard PyYAML rejects these.  We register multi-constructors that
    silently treat tagged Ruby objects as plain mappings / scalars.
    """
    import yaml  # type: ignore[import]

    class _RubyLoader(yaml.SafeLoader):
        pass

    def _ruby_object(loader: yaml.SafeLoader, tag_suffix: str, node: yaml.Node) -> Any:
        if isinstance(node, yaml.MappingNode):
            return loader.construct_mapping(node, deep=True)
        if isinstance(node, yaml.SequenceNode):
            return loader.construct_sequence(node, deep=True)
        return loader.construct_scalar(node)  # type: ignore[arg-type]

    def _ruby_sym(loader: yaml.SafeLoader, node: yaml.Node) -> str:
        return str(loader.construct_scalar(node))  # type: ignore[arg-type]

    _RubyLoader.add_multi_constructor("!ruby/object:", _ruby_object)
    _RubyLoader.add_multi_constructor("!ruby/sym", _ruby_sym)
    _RubyLoader.add_multi_constructor("!ruby/", _ruby_object)

    return yaml.load(text, Loader=_RubyLoader)  # noqa: S506 (custom safe loader)


# ---------------------------------------------------------------------------
# Module
# ---------------------------------------------------------------------------

class Module(BaseModule):
    manifest = ModuleManifest(
        name="builtin-puppet",
        version="1.1.0",
        description=(
            "Puppet integration: imports node facts and reports from PuppetDB, "
            "the YAML fact cache, or the report directory — whichever is available."
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

        sources: list[str] = []
        if settings.puppet_puppetdb_url:
            sources.append(f"PuppetDB ({settings.puppet_puppetdb_url})")
        if settings.puppet_fact_cache_dir:
            sources.append(f"fact-cache ({settings.puppet_fact_cache_dir})")
        if settings.puppet_report_dir:
            sources.append(f"reports ({settings.puppet_report_dir})")

        if not sources:
            self.logger.warning(
                "Puppet enabled but no data source is configured. "
                "Set at least one of: DKASTLE_PUPPET_PUPPETDB_URL, "
                "DKASTLE_PUPPET_FACT_CACHE_DIR, DKASTLE_PUPPET_REPORT_DIR"
            )
            return

        self.logger.info("Puppet integration active — sources: %s", ", ".join(sources))
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
            await asyncio.sleep(settings.puppet_sync_interval)

    async def _run_sync(self) -> None:
        from server.database import async_session_factory

        self.logger.info("Starting Puppet node sync…")

        # Collect facts from all available sources, keyed by certname
        facts_by_node: dict[str, dict[str, Any]] = {}

        self._merge(facts_by_node, await self._collect_puppetdb())
        self._merge(facts_by_node, self._collect_fact_cache())
        self._merge(facts_by_node, self._collect_reports())

        if not facts_by_node:
            self.logger.info("No Puppet nodes found across all configured sources")
            return

        async with async_session_factory() as db:
            imported = 0
            for certname, facts in facts_by_node.items():
                try:
                    await self._upsert_host(certname, facts, db)
                    imported += 1
                except Exception:
                    self.logger.exception("Failed to import Puppet node %s", certname)
            await db.commit()

        self.logger.info(
            "Puppet sync complete — %d/%d nodes imported", imported, len(facts_by_node)
        )

    @staticmethod
    def _merge(
        base: dict[str, dict[str, Any]],
        updates: dict[str, dict[str, Any]],
    ) -> None:
        """Merge *updates* into *base* per certname (shallow merge of fact dicts)."""
        for certname, facts in updates.items():
            if certname in base:
                base[certname].update(facts)
            else:
                base[certname] = facts

    # ------------------------------------------------------------------
    # Source 1 — PuppetDB REST API
    # ------------------------------------------------------------------

    def _puppetdb_headers(self) -> dict[str, str]:
        from server.config import settings

        h: dict[str, str] = {"Content-Type": "application/json"}
        if settings.puppet_puppetdb_token:
            h["X-Authentication"] = settings.puppet_puppetdb_token
        return h

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
            # Enrich with node-level metadata from the node record
            facts["_puppet_environment"] = node.get("catalog_environment")
            facts["_puppet_last_run"] = node.get("catalog_timestamp")
            result[certname] = facts

        self.logger.info("PuppetDB: collected %d nodes", len(result))
        return result

    async def _puppetdb_get(self, url: str) -> list[Any]:
        try:
            async with httpx.AsyncClient(timeout=30, verify=False) as client:
                resp = await client.get(url, headers=self._puppetdb_headers())
                resp.raise_for_status()
                return resp.json()
        except httpx.HTTPError as exc:
            self.logger.error("PuppetDB request failed (%s): %s", url, exc)
            return []

    # ------------------------------------------------------------------
    # Source 2 — YAML fact cache (present without PuppetDB)
    # ------------------------------------------------------------------

    def _collect_fact_cache(self) -> dict[str, dict[str, Any]]:
        from server.config import settings

        if not settings.puppet_fact_cache_dir:
            return {}

        cache_path = Path(settings.puppet_fact_cache_dir)
        if not cache_path.is_dir():
            self.logger.warning(
                "Puppet fact cache directory not found: %s", cache_path
            )
            return {}

        result: dict[str, dict[str, Any]] = {}
        for entry in sorted(cache_path.glob("*.yaml")):
            certname = entry.stem
            try:
                raw = _load_puppet_yaml(entry.read_text(encoding="utf-8"))
                # Puppet wraps facts under a 'values' key inside the Ruby object
                if isinstance(raw, dict):
                    facts: dict[str, Any] = raw.get("values", raw)
                    result[certname] = facts
            except Exception:
                self.logger.warning(
                    "Could not parse Puppet fact cache file: %s", entry, exc_info=True
                )

        self.logger.info("Fact cache: collected %d nodes from %s", len(result), cache_path)
        return result

    # ------------------------------------------------------------------
    # Source 3 — YAML report files (last run per node)
    # ------------------------------------------------------------------

    def _collect_reports(self) -> dict[str, dict[str, Any]]:
        from server.config import settings

        if not settings.puppet_report_dir:
            return {}

        report_path = Path(settings.puppet_report_dir)
        if not report_path.is_dir():
            self.logger.warning(
                "Puppet report directory not found: %s", report_path
            )
            return {}

        result: dict[str, dict[str, Any]] = {}

        # Each sub-directory is named after the certname
        for node_dir in report_path.iterdir():
            if not node_dir.is_dir():
                continue
            certname = node_dir.name

            # Pick the most recent report file (sorted lexicographically — timestamps)
            report_files = sorted(node_dir.glob("*.yaml"), reverse=True)
            if not report_files:
                continue

            try:
                raw = _load_puppet_yaml(report_files[0].read_text(encoding="utf-8"))
                if not isinstance(raw, dict):
                    continue

                # Extract the fields we care about from the report object
                report_facts: dict[str, Any] = {
                    "_puppet_last_run": raw.get("time"),
                    "_puppet_status": raw.get("status"),          # changed/unchanged/failed
                    "_puppet_environment": raw.get("environment"),
                    "_puppet_config_version": raw.get("configuration_version"),
                    "_puppet_puppet_version": raw.get("puppet_version"),
                }

                # Some reports include host information
                if "host" in raw:
                    report_facts["fqdn"] = raw["host"]

                result[certname] = {k: v for k, v in report_facts.items() if v is not None}

            except Exception:
                self.logger.warning(
                    "Could not parse Puppet report file: %s", report_files[0], exc_info=True
                )

        self.logger.info("Reports: collected %d nodes from %s", len(result), report_path)
        return result

    # ------------------------------------------------------------------
    # Host upsert (common to all sources)
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

        fqdn: str | None = facts.get("fqdn") or facts.get("hostname") or certname
        os_name: str | None = (
            facts.get("osfamily")
            or (facts.get("os", {}) or {}).get("family")
            or facts.get("operatingsystem")
        )
        os_version: str | None = (
            facts.get("operatingsystemrelease")
            or (facts.get("os", {}) or {}).get("release", {}).get("full")
        )
        puppet_env: str | None = facts.get("_puppet_environment")
        last_run: str | None = facts.get("_puppet_last_run")

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
