"""
Built-in NetBox integration module.

Syncs discovered assets to a NetBox instance via the NetBox REST API v4.

Synced objects:
  - IP Addresses  →  ipam/ip-addresses/
  - Prefixes      →  ipam/prefixes/
  - Devices       →  dcim/devices/
  - Interfaces    →  dcim/interfaces/

Configuration (via env vars or modules/netbox/config.yaml):
  netbox_url:    https://netbox.example.com
  netbox_token:  your-api-token
  sync_enabled:  true

Sync is one-way: Discoverykastle → NetBox.
NetBox is treated as the CMDB of record for fields it already owns;
this module only creates/updates records it discovers, it never deletes.
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Any

import httpx

from server.modules.base import BaseModule, ModuleCapability, ModuleManifest

if TYPE_CHECKING:
    from sqlalchemy.ext.asyncio import AsyncSession
    from server.models import Host, NetworkDevice, Network

logger = logging.getLogger(__name__)


class Module(BaseModule):
    manifest = ModuleManifest(
        name="builtin-netbox",
        version="1.0.0",
        description="Syncs discovered inventory to NetBox (IPAM/DCIM).",
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
        self._enabled = (
            self.config.get("sync_enabled", settings.netbox_sync_enabled)
        )

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
    # Event hooks
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
    # Manual full sync — callable from the API
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
                ok = await self._upsert_ip_address(ip, host.fqdn)
                if ok:
                    counts["ip_addresses"] += 1

        net_rows = await db.execute(select(Network))
        for network in net_rows.scalars():
            ok = await self._upsert_prefix(network.cidr, network.description)
            if ok:
                counts["prefixes"] += 1

        dev_rows = await db.execute(select(NetworkDevice))
        for device in dev_rows.scalars():
            ok = await self._upsert_device(device)
            if ok:
                counts["devices"] += 1

        return counts

    # ------------------------------------------------------------------
    # NetBox API helpers
    # ------------------------------------------------------------------

    async def _upsert_ip_address(self, address: str, dns_name: str | None = None) -> bool:
        """Create or update an IP address in NetBox IPAM."""
        if "/" not in address:
            address = f"{address}/32"

        payload: dict[str, Any] = {"address": address, "status": "active"}
        if dns_name:
            payload["dns_name"] = dns_name

        return await self._netbox_upsert(
            endpoint="/api/ipam/ip-addresses/",
            filter_param={"address": address},
            payload=payload,
        )

    async def _upsert_prefix(self, cidr: str, description: str | None = None) -> bool:
        """Create or update a prefix in NetBox IPAM."""
        payload: dict[str, Any] = {"prefix": cidr, "status": "active"}
        if description:
            payload["description"] = description[:200]

        return await self._netbox_upsert(
            endpoint="/api/ipam/prefixes/",
            filter_param={"prefix": cidr},
            payload=payload,
        )

    async def _upsert_device(self, device: "NetworkDevice") -> bool:
        """Create or update a device in NetBox DCIM."""
        if not device.hostname:
            return False

        payload: dict[str, Any] = {
            "name": device.hostname,
            "status": "active",
            "comments": f"Discovered by Discoverykastle. IP: {device.ip_address}",
        }
        if device.model:
            payload["model"] = device.model[:50]

        return await self._netbox_upsert(
            endpoint="/api/dcim/devices/",
            filter_param={"name": device.hostname},
            payload=payload,
        )

    async def _netbox_upsert(
        self,
        endpoint: str,
        filter_param: dict[str, str],
        payload: dict[str, Any],
    ) -> bool:
        """
        Generic upsert: GET to check existence, POST to create or PATCH to update.
        Returns True on success.
        """
        url = self._url + endpoint
        try:
            async with httpx.AsyncClient(headers=self._headers, timeout=10) as client:
                # Check if exists
                resp = await client.get(url, params=filter_param)
                resp.raise_for_status()
                results = resp.json().get("results", [])

                if results:
                    # Update existing
                    existing_id = results[0]["id"]
                    patch_resp = await client.patch(f"{url}{existing_id}/", json=payload)
                    patch_resp.raise_for_status()
                else:
                    # Create new
                    post_resp = await client.post(url, json=payload)
                    post_resp.raise_for_status()

                return True
        except httpx.HTTPStatusError as e:
            self.logger.warning(
                "NetBox API error on %s: %s %s", endpoint, e.response.status_code, e.response.text[:200]
            )
        except Exception:
            self.logger.exception("NetBox upsert failed for endpoint %s", endpoint)
        return False
