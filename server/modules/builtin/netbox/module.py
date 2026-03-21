"""
Built-in NetBox integration module.

Bidirectional sync between Discoverykastle and a NetBox instance (REST API v4).

On startup (setup()):
  - Imports all existing NetBox data into Discoverykastle inventory:
      ipam/prefixes/      → Network records
      ipam/ip-addresses/  → Host records
      dcim/devices/       → NetworkDevice records
      dcim/interfaces/    → NetworkInterface records

On discovery events (push):
  - Upserts newly discovered assets back to NetBox

Manual controls (API):
  POST /api/v1/netbox/import  → re-run import from NetBox
  POST /api/v1/netbox/sync    → push local inventory to NetBox

Configuration (env vars or modules/netbox/config.yaml):
  netbox_url:    https://netbox.example.com
  netbox_token:  your-api-token
  sync_enabled:  true
"""

from __future__ import annotations

import logging
from datetime import datetime
from typing import TYPE_CHECKING, Any, AsyncIterator

import httpx

from server.modules.base import BaseModule, ModuleCapability, ModuleManifest

if TYPE_CHECKING:
    from sqlalchemy.ext.asyncio import AsyncSession
    from server.models import Host, NetworkDevice, Network

logger = logging.getLogger(__name__)


class Module(BaseModule):
    manifest = ModuleManifest(
        name="builtin-netbox",
        version="1.1.0",
        description="Bidirectional sync with NetBox: import on startup, push on discovery.",
        author="Discoverykastle",
        capabilities=[ModuleCapability.INTEGRATION],
        config_schema={
            "netbox_url": {"type": "string", "description": "Base URL of NetBox instance"},
            "netbox_token": {"type": "string", "description": "NetBox API token"},
            "sync_enabled": {"type": "boolean", "default": False},
        },
        builtin=True,
    )

    def __init__(self, config: dict[str, Any] | None = None) -> None:
        super().__init__(config)
        from server.config import settings

        self._url = (
            self.config.get("netbox_url")
            or settings.netbox_url
            or ""
        ).rstrip("/")
        self._token = (
            self.config.get("netbox_token")
            or settings.netbox_token
            or ""
        )
        self._enabled = self.config.get("sync_enabled", settings.netbox_sync_enabled)
        self.last_import_at: datetime | None = None
        self.last_import_counts: dict[str, int] = {}

    @property
    def _ready(self) -> bool:
        return self._enabled and bool(self._url) and bool(self._token)

    @property
    def _headers(self) -> dict[str, str]:
        return {
            "Authorization": f"Token {self._token}",
            "Content-Type": "application/json",
            "Accept": "application/json",
        }

    # ------------------------------------------------------------------
    # Lifecycle — import from NetBox at startup
    # ------------------------------------------------------------------

    async def setup(self) -> None:
        if not self._ready:
            self.logger.info(
                "NetBox integration disabled or not configured — skipping import."
            )
            return

        self.logger.info("NetBox configured at %s — running initial import...", self._url)
        from server.database import AsyncSessionLocal

        try:
            async with AsyncSessionLocal() as db:
                counts = await self.import_from_netbox(db)
                await db.commit()
        except Exception:
            # Import failure must never prevent the application from starting.
            self.logger.exception(
                "NetBox initial import failed — the application will continue without NetBox data. "
                "Fix the configuration and re-run via POST /api/v1/netbox/import."
            )
            return

        self.last_import_at = datetime.utcnow()
        self.last_import_counts = counts
        self.logger.info(
            "NetBox initial import complete: %s",
            ", ".join(f"{k}={v}" for k, v in counts.items()),
        )

    # ------------------------------------------------------------------
    # Import: NetBox → Discoverykastle
    # ------------------------------------------------------------------

    async def import_from_netbox(self, db: "AsyncSession") -> dict[str, int]:
        """
        Pull all data from NetBox and upsert into the local inventory.

        Deduplication strategy:
          - Before the loop, load all existing keys (CIDRs, IPs, hostnames) into
            in-memory sets so that SELECT queries inside the loop are not needed
            for the "already seen?" check.
          - Records added during this run are tracked in the same sets immediately,
            preventing duplicates even if NetBox returns the same item twice
            (e.g. paginated data that overlaps, or a retry).
          - A periodic flush (every BATCH_SIZE inserts) keeps the session cache
            from growing unbounded on large inventories.

        Returns counts of created/updated objects per type.
        """
        if not self._ready:
            return {"error": 1, "message": "NetBox integration not configured or disabled"}

        counts: dict[str, int] = {
            "prefixes_created": 0,
            "prefixes_updated": 0,
            "hosts_created": 0,
            "hosts_updated": 0,
            "devices_created": 0,
            "devices_updated": 0,
            "interfaces_created": 0,
        }

        # Each step is isolated: a failure in one step is recorded but does NOT
        # prevent the other steps from running.
        steps = [
            ("prefixes", self._import_prefixes, "prefixes_created", "prefixes_updated"),
            ("ip_addresses", self._import_ip_addresses, "hosts_created", "hosts_updated"),
            ("devices", self._import_devices, "devices_created", "devices_updated"),
        ]
        for label, fn, key_created, key_updated in steps:
            try:
                counts[key_created], counts[key_updated] = await fn(db)
            except Exception:
                self.logger.exception("NetBox import step '%s' failed — skipping", label)
                counts[f"{label}_error"] = 1

        try:
            counts["interfaces_created"] = await self._import_interfaces(db)
        except Exception:
            self.logger.exception("NetBox import step 'interfaces' failed — skipping")
            counts["interfaces_error"] = 1

        return counts

    async def _import_prefixes(self, db: "AsyncSession") -> tuple[int, int]:
        """Import NetBox prefixes → Network records. Returns (created, updated)."""
        from server.models.network import Network
        from sqlalchemy import select

        BATCH = 50
        created = updated = 0

        # Pre-load existing CIDRs to avoid per-row SELECTs and catch within-run dupes
        existing_cidrs: dict[str, Network] = {}
        for row in (await db.execute(select(Network))).scalars():
            existing_cidrs[row.cidr] = row

        skipped = 0
        pending = 0
        async for item in self._paginate("/api/ipam/prefixes/"):
            try:
                cidr = item.get("prefix")
                if not cidr:
                    continue

                desc = item.get("description") or (item.get("vrf") or {}).get("name") or None

                if cidr in existing_cidrs:
                    net = existing_cidrs[cidr]
                    if desc and not net.description:
                        net.description = desc
                        updated += 1
                else:
                    net = Network(cidr=cidr, description=desc, scan_authorized=False)
                    db.add(net)
                    existing_cidrs[cidr] = net  # track immediately — prevents within-run dupes
                    created += 1
                    pending += 1
                    if pending >= BATCH:
                        await db.flush()
                        pending = 0
            except Exception:
                skipped += 1
                self.logger.warning(
                    "Skipping malformed prefix item (id=%s): %s",
                    item.get("id", "?"), item.get("prefix", "<no prefix>"),
                    exc_info=True,
                )

        if skipped:
            self.logger.warning("_import_prefixes: skipped %d item(s) due to errors", skipped)

        await db.flush()
        return created, updated

    async def _import_ip_addresses(self, db: "AsyncSession") -> tuple[int, int]:
        """Import NetBox IP addresses → Host records. Returns (created, updated)."""
        from server.models.host import Host
        from sqlalchemy import select

        BATCH = 50
        created = updated = 0

        # Pre-load existing IPs (flatten ip_addresses arrays into a dict ip → Host)
        existing_ips: dict[str, Host] = {}
        for row in (await db.execute(select(Host))).scalars():
            for ip in row.ip_addresses:
                existing_ips[ip] = row

        skipped = 0
        pending = 0
        async for item in self._paginate("/api/ipam/ip-addresses/"):
            try:
                raw = item.get("address", "")
                ip = raw.split("/")[0] if "/" in raw else raw
                if not ip:
                    continue

                dns_name = item.get("dns_name") or None
                cf = item.get("custom_fields") or {}
                os_hint = cf.get("os") or cf.get("operating_system") or None

                if ip in existing_ips:
                    host = existing_ips[ip]
                    changed = False
                    if dns_name and not host.fqdn:
                        host.fqdn = dns_name
                        changed = True
                    if os_hint and not host.os:
                        host.os = os_hint
                        changed = True
                    if changed:
                        updated += 1
                else:
                    host = Host(ip_addresses=[ip], fqdn=dns_name, os=os_hint)
                    db.add(host)
                    existing_ips[ip] = host  # prevent within-run dupes
                    created += 1
                    pending += 1
                    if pending >= BATCH:
                        await db.flush()
                        pending = 0
            except Exception:
                skipped += 1
                self.logger.warning(
                    "Skipping malformed ip-address item (id=%s): %s",
                    item.get("id", "?"), item.get("address", "<no address>"),
                    exc_info=True,
                )

        if skipped:
            self.logger.warning("_import_ip_addresses: skipped %d item(s) due to errors", skipped)

        await db.flush()
        return created, updated

    async def _import_devices(self, db: "AsyncSession") -> tuple[int, int]:
        """Import NetBox DCIM devices → NetworkDevice records. Returns (created, updated)."""
        from server.models.device import NetworkDevice
        from sqlalchemy import select

        BATCH = 50
        created = updated = 0

        # Pre-load existing devices by hostname and by IP
        existing_by_hostname: dict[str, NetworkDevice] = {}
        existing_by_ip: dict[str, NetworkDevice] = {}
        for row in (await db.execute(select(NetworkDevice))).scalars():
            if row.hostname:
                existing_by_hostname[row.hostname] = row
            existing_by_ip[row.ip_address] = row

        skipped = 0
        pending = 0
        async for item in self._paginate("/api/dcim/devices/"):
            try:
                hostname = item.get("name") or None

                # Resolve primary IP — skip device if neither hostname nor IP is available
                primary_ip_obj = item.get("primary_ip") or item.get("primary_ip4") or {}
                raw_ip = primary_ip_obj.get("address", "")
                ip = raw_ip.split("/")[0] if "/" in raw_ip else raw_ip or None

                if not hostname and not ip:
                    continue

                device_role = (item.get("role") or item.get("device_role") or {}).get("name", "")
                device_type_obj = item.get("device_type") or {}
                vendor = (device_type_obj.get("manufacturer") or {}).get("name") or None
                model = device_type_obj.get("model") or None
                platform = (item.get("platform") or {}).get("name") or None

                # Match by hostname first, then by IP to avoid duplicates
                existing = (
                    existing_by_hostname.get(hostname) if hostname else None
                ) or (
                    existing_by_ip.get(ip) if ip else None
                )

                if existing:
                    changed = False
                    if ip and existing.ip_address != ip:
                        existing.ip_address = ip
                        changed = True
                    if platform and not existing.firmware_version:
                        existing.firmware_version = platform
                        changed = True
                    if vendor and not existing.vendor:
                        existing.vendor = vendor
                        changed = True
                    if changed:
                        updated += 1
                    # Keep lookup maps consistent
                    if hostname:
                        existing_by_hostname[hostname] = existing
                    if ip:
                        existing_by_ip[ip] = existing
                else:
                    dev = NetworkDevice(
                        ip_address=ip or "",
                        hostname=hostname,
                        vendor=vendor,
                        model=model,
                        firmware_version=platform,
                        device_type=_map_device_role(device_role),
                    )
                    db.add(dev)
                    if hostname:
                        existing_by_hostname[hostname] = dev
                    if ip:
                        existing_by_ip[ip] = dev
                    created += 1
                    pending += 1
                    if pending >= BATCH:
                        await db.flush()
                        pending = 0
            except Exception:
                skipped += 1
                self.logger.warning(
                    "Skipping malformed device item (id=%s): %s",
                    item.get("id", "?"), item.get("name", "<no name>"),
                    exc_info=True,
                )

        if skipped:
            self.logger.warning("_import_devices: skipped %d item(s) due to errors", skipped)

        await db.flush()
        return created, updated

    async def _import_interfaces(self, db: "AsyncSession") -> int:
        """
        Import NetBox DCIM interfaces → NetworkInterface records.

        Only imports interfaces for devices that have an associated host_id.
        Newly imported devices (from _import_devices above) won't have a host_id
        until an agent scans them and links the records — this is expected.
        """
        from server.models.device import NetworkDevice
        from server.models.network import NetworkInterface
        from sqlalchemy import select, and_

        BATCH = 50
        created = 0

        # Pre-load devices that have a host_id (only those can have interfaces)
        devices_with_host: dict[str, NetworkDevice] = {}
        for row in (await db.execute(
            select(NetworkDevice).where(NetworkDevice.host_id.isnot(None))
        )).scalars():
            if row.hostname:
                devices_with_host[row.hostname] = row

        if not devices_with_host:
            return 0  # Nothing to do

        # Pre-load existing interface names per host_id to prevent dupes
        existing_ifaces: set[tuple] = set()
        for row in (await db.execute(select(NetworkInterface))).scalars():
            existing_ifaces.add((row.host_id, row.name))

        skipped = 0
        pending = 0
        async for item in self._paginate("/api/dcim/interfaces/"):
            try:
                device_obj = item.get("device") or {}
                hostname = device_obj.get("name")
                if not hostname or hostname not in devices_with_host:
                    continue

                device = devices_with_host[hostname]
                iface_name = item.get("name") or ""
                if not iface_name:
                    continue

                key = (device.host_id, iface_name)
                if key in existing_ifaces:
                    continue

                db.add(NetworkInterface(
                    host_id=device.host_id,
                    name=iface_name,
                    mac_address=item.get("mac_address") or None,
                    is_up=item.get("enabled", True),
                    interface_type=(item.get("type") or {}).get("value") or None,
                ))
                existing_ifaces.add(key)  # prevent within-run dupes
                created += 1
                pending += 1
                if pending >= BATCH:
                    await db.flush()
                    pending = 0
            except Exception:
                skipped += 1
                self.logger.warning(
                    "Skipping malformed interface item (id=%s): %s",
                    item.get("id", "?"), item.get("name", "<no name>"),
                    exc_info=True,
                )

        if skipped:
            self.logger.warning("_import_interfaces: skipped %d item(s) due to errors", skipped)

        await db.flush()
        return created

    # ------------------------------------------------------------------
    # Event hooks — push newly discovered assets to NetBox
    # ------------------------------------------------------------------

    async def on_host_discovered(self, host: "Host", db: "AsyncSession") -> None:
        if not self._ready:
            return
        try:
            for ip in host.ip_addresses:
                await self._upsert_ip_address(ip, host.fqdn)
        except Exception:
            self.logger.exception("on_host_discovered: failed to push host to NetBox (fqdn=%s)", host.fqdn)

    async def on_network_discovered(self, network: "Network", db: "AsyncSession") -> None:
        if not self._ready:
            return
        try:
            await self._upsert_prefix(network.cidr, network.description)
        except Exception:
            self.logger.exception("on_network_discovered: failed to push prefix %s to NetBox", network.cidr)

    async def on_device_found(self, device: "NetworkDevice", db: "AsyncSession") -> None:
        if not self._ready:
            return
        try:
            await self._upsert_device(device)
        except Exception:
            self.logger.exception("on_device_found: failed to push device %s to NetBox", device.hostname)

    # ------------------------------------------------------------------
    # Push: Discoverykastle → NetBox (full sync)
    # ------------------------------------------------------------------

    async def full_sync(self, db: "AsyncSession") -> dict[str, int]:
        """Push all current inventory to NetBox. Returns counts per object type."""
        if not self._ready:
            return {"error": 1, "message": "NetBox integration not configured or disabled"}

        from sqlalchemy import select
        from server.models.host import Host
        from server.models.device import NetworkDevice
        from server.models.network import Network

        counts: dict[str, int] = {"ip_addresses": 0, "prefixes": 0, "devices": 0}

        host_rows = await db.execute(select(Host))
        for host in host_rows.scalars():
            for ip in host.ip_addresses:
                if await self._upsert_ip_address(ip, host.fqdn):
                    counts["ip_addresses"] += 1

        net_rows = await db.execute(select(Network))
        for network in net_rows.scalars():
            if await self._upsert_prefix(network.cidr, network.description):
                counts["prefixes"] += 1

        dev_rows = await db.execute(select(NetworkDevice))
        for device in dev_rows.scalars():
            if await self._upsert_device(device):
                counts["devices"] += 1

        return counts

    # ------------------------------------------------------------------
    # NetBox push helpers
    # ------------------------------------------------------------------

    async def _upsert_ip_address(self, address: str, dns_name: str | None = None) -> bool:
        if "/" not in address:
            address = f"{address}/32"
        payload: dict[str, Any] = {"address": address, "status": "active"}
        if dns_name:
            payload["dns_name"] = dns_name
        return await self._netbox_upsert("/api/ipam/ip-addresses/", {"address": address}, payload)

    async def _upsert_prefix(self, cidr: str, description: str | None = None) -> bool:
        payload: dict[str, Any] = {"prefix": cidr, "status": "active"}
        if description:
            payload["description"] = description[:200]
        return await self._netbox_upsert("/api/ipam/prefixes/", {"prefix": cidr}, payload)

    async def _upsert_device(self, device: "NetworkDevice") -> bool:
        if not device.hostname:
            return False
        payload: dict[str, Any] = {
            "name": device.hostname,
            "status": "active",
            "comments": f"Discovered by Discoverykastle. IP: {device.ip_address}",
        }
        if device.model:
            payload["model"] = device.model[:50]
        return await self._netbox_upsert("/api/dcim/devices/", {"name": device.hostname}, payload)

    async def _netbox_upsert(
        self,
        endpoint: str,
        filter_param: dict[str, str],
        payload: dict[str, Any],
    ) -> bool:
        url = self._url + endpoint
        try:
            async with httpx.AsyncClient(headers=self._headers, timeout=10) as client:
                resp = await client.get(url, params=filter_param)
                resp.raise_for_status()
                results = resp.json().get("results", [])
                if results:
                    patch = await client.patch(f"{url}{results[0]['id']}/", json=payload)
                    patch.raise_for_status()
                else:
                    post = await client.post(url, json=payload)
                    post.raise_for_status()
                return True
        except httpx.HTTPStatusError as e:
            self.logger.warning(
                "NetBox API error on %s: %s %s",
                endpoint, e.response.status_code, e.response.text[:200],
            )
        except Exception:
            self.logger.exception("NetBox upsert failed for endpoint %s", endpoint)
        return False

    # ------------------------------------------------------------------
    # Pagination helper — follows NetBox's next/offset pagination
    # ------------------------------------------------------------------

    async def _paginate(self, endpoint: str) -> AsyncIterator[dict[str, Any]]:
        """Yield all results from a NetBox list endpoint, handling pagination."""
        url = self._url + endpoint
        params: dict[str, Any] = {"limit": 100, "offset": 0}
        async with httpx.AsyncClient(headers=self._headers, timeout=30) as client:
            while url:
                try:
                    resp = await client.get(url, params=params)
                    resp.raise_for_status()
                    data = resp.json()
                except httpx.HTTPStatusError as e:
                    self.logger.warning(
                        "NetBox pagination error on %s: %s", endpoint, e.response.status_code
                    )
                    return
                except Exception:
                    self.logger.exception("NetBox pagination failed for %s", endpoint)
                    return

                for item in data.get("results", []):
                    yield item

                # Follow next page — NetBox returns absolute URL in "next"
                next_url = data.get("next")
                if next_url:
                    url = next_url
                    params = {}  # URL already contains offset
                else:
                    return


# ------------------------------------------------------------------
# Helpers
# ------------------------------------------------------------------

def _map_device_role(role: str) -> str:
    """Map a NetBox device role name to a Discoverykastle device_type."""
    role_lower = role.lower()
    if any(k in role_lower for k in ("router", "gateway", "core")):
        return "router"
    if any(k in role_lower for k in ("switch", "access", "distribution")):
        return "switch"
    if any(k in role_lower for k in ("firewall", "fw", "security")):
        return "firewall"
    if any(k in role_lower for k in ("ap", "access point", "wifi", "wireless")):
        return "access_point"
    return role_lower or "unknown"
