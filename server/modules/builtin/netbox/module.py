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

        async with AsyncSessionLocal() as db:
            counts = await self.import_from_netbox(db)
            await db.commit()

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
        Returns counts of imported objects per type.
        """
        if not self._ready:
            return {"error": 1, "message": "NetBox integration not configured or disabled"}

        counts: dict[str, int] = {
            "prefixes": 0,
            "ip_addresses": 0,
            "devices": 0,
            "interfaces": 0,
        }

        counts["prefixes"] = await self._import_prefixes(db)
        counts["ip_addresses"] = await self._import_ip_addresses(db)
        counts["devices"] = await self._import_devices(db)
        counts["interfaces"] = await self._import_interfaces(db)

        return counts

    async def _import_prefixes(self, db: "AsyncSession") -> int:
        """Import NetBox prefixes as Network records."""
        from server.models.network import Network
        from sqlalchemy import select

        count = 0
        async for item in self._paginate("/api/ipam/prefixes/"):
            cidr = item.get("prefix")
            if not cidr:
                continue

            existing = await db.scalar(select(Network).where(Network.cidr == cidr))
            if existing:
                # Update description if NetBox has one
                desc = item.get("description") or (item.get("vrf") or {}).get("name")
                if desc:
                    existing.description = desc
            else:
                desc = item.get("description") or (item.get("vrf") or {}).get("name")
                status = item.get("status", {}).get("value", "active")
                db.add(Network(
                    cidr=cidr,
                    description=desc,
                    scan_authorized=False,  # Operator must explicitly authorize scans
                ))
                count += 1

        await db.flush()
        return count

    async def _import_ip_addresses(self, db: "AsyncSession") -> int:
        """Import NetBox IP addresses as Host records."""
        from server.models.host import Host
        from sqlalchemy import select

        count = 0
        async for item in self._paginate("/api/ipam/ip-addresses/"):
            address = item.get("address", "")
            # Strip CIDR mask to get bare IP
            ip = address.split("/")[0] if "/" in address else address
            if not ip:
                continue

            existing = await db.scalar(
                select(Host).where(Host.ip_addresses.contains([ip]))
            )
            if existing:
                # Enrich with NetBox DNS name if missing
                dns_name = item.get("dns_name") or ""
                if dns_name and not existing.fqdn:
                    existing.fqdn = dns_name
            else:
                dns_name = item.get("dns_name") or None
                # Pull OS hint from custom fields if present
                cf = item.get("custom_fields") or {}
                os_hint = cf.get("os") or cf.get("operating_system") or None
                db.add(Host(
                    ip_addresses=[ip],
                    fqdn=dns_name or None,
                    os=os_hint,
                ))
                count += 1

        await db.flush()
        return count

    async def _import_devices(self, db: "AsyncSession") -> int:
        """Import NetBox DCIM devices as NetworkDevice records."""
        from server.models.device import NetworkDevice
        from sqlalchemy import select

        count = 0
        async for item in self._paginate("/api/dcim/devices/"):
            hostname = item.get("name")
            if not hostname:
                continue

            # Resolve primary IP
            primary_ip_obj = item.get("primary_ip") or item.get("primary_ip4") or {}
            ip_with_mask = primary_ip_obj.get("address", "")
            ip = ip_with_mask.split("/")[0] if "/" in ip_with_mask else ip_with_mask
            if not ip:
                ip = "0.0.0.0"  # Will be updated when agent discovers the host

            existing = await db.scalar(
                select(NetworkDevice).where(NetworkDevice.hostname == hostname)
            )
            if existing:
                existing.ip_address = ip or existing.ip_address
                existing.firmware_version = (
                    item.get("platform", {}) or {}
                ).get("name") or existing.firmware_version
            else:
                device_role = (item.get("role") or item.get("device_role") or {}).get("name", "")
                device_type_obj = item.get("device_type") or {}
                manufacturer = (device_type_obj.get("manufacturer") or {}).get("name")
                model = device_type_obj.get("model")
                platform = (item.get("platform") or {}).get("name")

                db.add(NetworkDevice(
                    ip_address=ip,
                    hostname=hostname,
                    vendor=manufacturer,
                    model=model,
                    firmware_version=platform,
                    device_type=_map_device_role(device_role),
                ))
                count += 1

        await db.flush()
        return count

    async def _import_interfaces(self, db: "AsyncSession") -> int:
        """Import NetBox DCIM interfaces as NetworkInterface records."""
        from server.models.device import NetworkDevice
        from server.models.network import NetworkInterface
        from sqlalchemy import select

        count = 0
        async for item in self._paginate("/api/dcim/interfaces/"):
            device_obj = item.get("device") or {}
            hostname = device_obj.get("name")
            if not hostname:
                continue

            device = await db.scalar(
                select(NetworkDevice).where(NetworkDevice.hostname == hostname)
            )
            if not device or not device.host_id:
                continue  # No associated host yet — skip

            iface_name = item.get("name", "")
            existing = await db.scalar(
                select(NetworkInterface).where(
                    NetworkInterface.host_id == device.host_id,
                    NetworkInterface.name == iface_name,
                )
            )
            if existing:
                continue

            mac = item.get("mac_address") or None
            enabled = item.get("enabled", True)
            db.add(NetworkInterface(
                host_id=device.host_id,
                name=iface_name,
                mac_address=mac,
                is_up=enabled,
                interface_type=item.get("type", {}).get("value") if item.get("type") else None,
            ))
            count += 1

        await db.flush()
        return count

    # ------------------------------------------------------------------
    # Event hooks — push newly discovered assets to NetBox
    # ------------------------------------------------------------------

    async def on_host_discovered(self, host: "Host", db: "AsyncSession") -> None:
        if not self._ready:
            return
        for ip in host.ip_addresses:
            await self._upsert_ip_address(ip, host.fqdn)

    async def on_network_discovered(self, network: "Network", db: "AsyncSession") -> None:
        if not self._ready:
            return
        await self._upsert_prefix(network.cidr, network.description)

    async def on_device_found(self, device: "NetworkDevice", db: "AsyncSession") -> None:
        if not self._ready:
            return
        await self._upsert_device(device)

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
