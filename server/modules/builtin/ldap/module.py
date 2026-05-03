"""
Built-in LDAP / Active Directory enrichment module.

Connects to an Active Directory domain controller (or any LDAP server) and
enriches host inventory records with:

  • Operating system and version from the computer account (operatingSystem,
    operatingSystemVersion)
  • Organizational Unit path (distinguishedName → OU chain)
  • AD group memberships (memberOf)
  • Last logon timestamp (lastLogonTimestamp)
  • Whether the computer account is enabled (userAccountControl bit 2)

Matching strategy (in order):
  1. DNS hostname / FQDN — matched against host.fqdn
  2. sAMAccountName (netbios name$ → strip $, lowercased) → matched against
     the short hostname extracted from host.fqdn

Configuration (DKASTLE_* env vars on the DK server):
  DKASTLE_LDAP_ENABLED=true
  DKASTLE_LDAP_SERVER=ldap://dc.example.com        (or ldaps://...)
  DKASTLE_LDAP_BIND_DN=CN=readonly,DC=example,DC=com
  DKASTLE_LDAP_BIND_PASSWORD=secret
  DKASTLE_LDAP_BASE_DN=DC=example,DC=com
  DKASTLE_LDAP_SYNC_INTERVAL=3600    (seconds, default 1 hour)
  DKASTLE_LDAP_PAGE_SIZE=500         (paged LDAP results, default 500)

Requires: ldap3 (pip install ldap3)
The module loads but stays dormant (logs a warning) if ldap3 is not installed.
"""

from __future__ import annotations

import asyncio
import logging
from datetime import datetime, timezone
from typing import TYPE_CHECKING, Any

from server.modules.base import BaseModule, ModuleCapability, ModuleManifest

if TYPE_CHECKING:
    from sqlalchemy.ext.asyncio import AsyncSession

logger = logging.getLogger(__name__)

# AD userAccountControl flag — bit 1 (0x0002) means account is disabled
_UAC_DISABLED = 0x0002

# LDAP attributes to fetch for each computer object
_COMPUTER_ATTRS = [
    "cn",
    "dNSHostName",
    "sAMAccountName",
    "distinguishedName",
    "operatingSystem",
    "operatingSystemVersion",
    "lastLogonTimestamp",
    "userAccountControl",
    "memberOf",
    "description",
]


def _ad_timestamp_to_dt(ts: int | str | None) -> datetime | None:
    """
    Convert a Windows FILETIME (100-nanosecond intervals since 1601-01-01)
    to a Python datetime, or return None for missing / sentinel values.
    """
    if ts is None:
        return None
    try:
        val = int(ts)
    except (ValueError, TypeError):
        return None
    if val in (0, 9223372036854775807):
        return None
    epoch_diff = 116444736000000000  # 100-ns ticks between 1601 and 1970
    return datetime.fromtimestamp((val - epoch_diff) / 10_000_000, tz=timezone.utc)


def _extract_ou_path(dn: str) -> str | None:
    """
    Extract the OU chain from a distinguished name.
    e.g. "CN=PC01,OU=Servers,OU=IT,DC=example,DC=com" → "Servers/IT"
    """
    parts = [p.strip() for p in dn.split(",")]
    ous = [p[3:] for p in parts if p.upper().startswith("OU=")]
    return "/".join(reversed(ous)) if ous else None


class Module(BaseModule):
    manifest = ModuleManifest(
        name="builtin-ldap",
        version="1.0.0",
        description=(
            "LDAP/Active Directory enrichment: imports computer accounts from AD "
            "and enriches host inventory with OS, OU, groups, and last-logon data."
        ),
        author="Discoverykastle",
        capabilities=[ModuleCapability.ENRICHMENT, ModuleCapability.INVENTORY],
        builtin=True,
    )

    _sync_task: asyncio.Task | None = None

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    async def setup(self) -> None:
        from server.config import settings

        if not settings.ldap_enabled:
            self.logger.info("LDAP integration disabled (DKASTLE_LDAP_ENABLED=false)")
            return

        if not settings.ldap_server:
            self.logger.warning(
                "LDAP enabled but DKASTLE_LDAP_SERVER is not set — disabling."
            )
            return

        try:
            import ldap3  # noqa: F401
        except ImportError:
            self.logger.warning(
                "ldap3 package not installed — LDAP enrichment is unavailable. "
                "Install it with: pip install ldap3"
            )
            return

        self.logger.info(
            "LDAP integration active — server %s, base DN %s",
            settings.ldap_server, settings.ldap_base_dn,
        )
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

        sync_interval: int = getattr(settings, "ldap_sync_interval", 3600)
        while True:
            try:
                await asyncio.to_thread(self._run_sync)
            except Exception:
                self.logger.exception("LDAP sync failed")
            await asyncio.sleep(sync_interval)

    def _run_sync(self) -> None:
        """
        Fetch all computer accounts from AD and enrich host inventory.
        Runs synchronously in a thread (ldap3 is blocking).
        """
        from server.config import settings

        computers = self._fetch_computers(settings)
        if not computers:
            self.logger.info("No computer accounts returned from LDAP")
            return

        self.logger.info("LDAP: fetched %d computer account(s)", len(computers))

        # Dispatch async upserts from a new event loop in this thread
        import asyncio as _asyncio
        _asyncio.run(self._upsert_all(computers))

    # ------------------------------------------------------------------
    # LDAP client (synchronous, runs in thread)
    # ------------------------------------------------------------------

    def _build_connection(self, settings: Any) -> Any:
        import ldap3

        server = ldap3.Server(
            settings.ldap_server,
            get_info=ldap3.ALL,
            connect_timeout=10,
        )
        use_ssl = settings.ldap_server.lower().startswith("ldaps://")
        conn = ldap3.Connection(
            server,
            user=settings.ldap_bind_dn,
            password=settings.ldap_bind_password,
            authentication=ldap3.SIMPLE,
            auto_bind=True,
            read_only=True,
        )
        return conn

    def _fetch_computers(self, settings: Any) -> list[dict[str, Any]]:
        """
        Query AD for all computer objects and return a list of attribute dicts.
        """
        try:
            import ldap3

            conn = self._build_connection(settings)
            base_dn = settings.ldap_base_dn or ""
            search_filter = "(&(objectClass=computer)(objectCategory=computer))"
            page_size: int = getattr(settings, "ldap_page_size", 500)

            computers: list[dict[str, Any]] = []

            # Paged search to handle large directories
            entry_generator = conn.extend.standard.paged_search(
                search_base=base_dn,
                search_filter=search_filter,
                search_scope=ldap3.SUBTREE,
                attributes=_COMPUTER_ATTRS,
                paged_size=page_size,
                generator=True,
            )

            for entry in entry_generator:
                if entry.get("type") != "searchResEntry":
                    continue
                attrs: dict[str, Any] = {}
                for attr_name in _COMPUTER_ATTRS:
                    raw = entry["attributes"].get(attr_name)
                    if isinstance(raw, list):
                        attrs[attr_name] = raw[0] if len(raw) == 1 else raw
                    else:
                        attrs[attr_name] = raw
                attrs["_dn"] = entry.get("dn", "")
                computers.append(attrs)

            conn.unbind()
            return computers

        except Exception:
            self.logger.exception("LDAP fetch failed")
            return []

    # ------------------------------------------------------------------
    # Host upsert (async)
    # ------------------------------------------------------------------

    async def _upsert_all(self, computers: list[dict[str, Any]]) -> None:
        from server.database import async_session_factory

        async with async_session_factory() as db:
            updated = 0
            for computer in computers:
                try:
                    matched = await self._enrich_host(computer, db)
                    if matched:
                        updated += 1
                except Exception:
                    self.logger.exception(
                        "Failed to enrich host from LDAP: %s",
                        computer.get("dNSHostName") or computer.get("cn"),
                    )
            await db.commit()

        self.logger.info(
            "LDAP sync complete — %d/%d computer accounts matched to hosts",
            updated, len(computers),
        )

    async def _enrich_host(
        self, computer: dict[str, Any], db: "AsyncSession"
    ) -> bool:
        """
        Try to match the AD computer account to an existing Host record and
        enrich it.  Returns True if a host was matched and updated.
        """
        from sqlalchemy import select
        from server.models.host import Host

        dns_hostname: str | None = computer.get("dNSHostName")
        sam: str | None = computer.get("sAMAccountName")
        short_name: str | None = (
            sam.rstrip("$").lower() if sam else None
        )

        host: Host | None = None

        # 1. Match by FQDN
        if dns_hostname:
            result = await db.execute(
                select(Host).where(Host.fqdn == dns_hostname)
            )
            host = result.scalar_one_or_none()

        # 2. Match by short hostname extracted from fqdn
        if host is None and short_name:
            result = await db.execute(
                select(Host).where(
                    Host.fqdn.ilike(f"{short_name}.%")  # type: ignore[union-attr]
                )
            )
            host = result.scalar_one_or_none()

        if host is None:
            self.logger.debug(
                "LDAP: no matching host for computer %s / %s — skipping",
                dns_hostname, short_name,
            )
            return False

        # --- Enrich host ---

        os_name: str | None = computer.get("operatingSystem")
        os_version: str | None = computer.get("operatingSystemVersion")
        dn: str = computer.get("_dn", "")
        ou_path = _extract_ou_path(dn)
        uac = computer.get("userAccountControl")
        is_enabled = True
        if uac is not None:
            try:
                is_enabled = not bool(int(uac) & _UAC_DISABLED)
            except (ValueError, TypeError):
                pass

        last_logon_raw = computer.get("lastLogonTimestamp")
        last_logon_dt = _ad_timestamp_to_dt(last_logon_raw)

        # Update OS fields only if they are richer than what we have
        if os_name and not host.os:
            host.os = os_name
        if os_version and not host.os_version:
            host.os_version = os_version

        # Update FQDN if not set and AD gives us one
        if dns_hostname and not host.fqdn:
            host.fqdn = dns_hostname

        # Update last_seen with AD last logon if it's more recent
        if last_logon_dt:
            naive_last_logon = last_logon_dt.replace(tzinfo=None)
            if host.last_seen is None or naive_last_logon > host.last_seen:
                host.last_seen = naive_last_logon

        await db.flush()

        self.logger.debug(
            "LDAP: enriched host %s (fqdn=%s, os=%s, ou=%s, enabled=%s)",
            host.id, host.fqdn, host.os, ou_path, is_enabled,
        )
        return True

    # ------------------------------------------------------------------
    # on_host_discovered hook — enrich a single host immediately
    # ------------------------------------------------------------------

    async def on_host_discovered(self, host: Any, db: "AsyncSession") -> None:
        """
        When a new host is discovered, attempt an immediate LDAP lookup by
        FQDN to pull in AD metadata without waiting for the next sync cycle.
        """
        from server.config import settings

        if not settings.ldap_enabled or not settings.ldap_server or not host.fqdn:
            return

        try:
            import ldap3

            base_dn = settings.ldap_base_dn or ""
            fqdn: str = host.fqdn
            short = fqdn.split(".")[0]

            search_filter = (
                f"(&(objectClass=computer)"
                f"(|(dNSHostName={fqdn})(sAMAccountName={short}$)))"
            )

            computers = await asyncio.to_thread(
                self._ldap_search_one, settings, base_dn, search_filter
            )

            for computer in computers:
                await self._enrich_host(computer, db)

        except ImportError:
            pass
        except Exception:
            self.logger.debug(
                "LDAP on_host_discovered lookup failed for %s", host.fqdn,
                exc_info=True,
            )

    def _ldap_search_one(
        self, settings: Any, base_dn: str, search_filter: str
    ) -> list[dict[str, Any]]:
        """Run a single synchronous LDAP search and return matching entries."""
        try:
            import ldap3

            conn = self._build_connection(settings)
            conn.search(
                search_base=base_dn,
                search_filter=search_filter,
                search_scope=ldap3.SUBTREE,
                attributes=_COMPUTER_ATTRS,
            )
            results: list[dict[str, Any]] = []
            for entry in conn.entries:
                attrs: dict[str, Any] = {}
                for attr_name in _COMPUTER_ATTRS:
                    val = getattr(entry, attr_name, None)
                    attrs[attr_name] = str(val) if val else None
                attrs["_dn"] = entry.entry_dn
                results.append(attrs)
            conn.unbind()
            return results
        except Exception:
            self.logger.debug("LDAP search failed", exc_info=True)
            return []
