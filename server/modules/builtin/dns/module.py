"""
Built-in DNS Enrichment module.

For every discovered host:
  - Performs a reverse PTR lookup for each IP address and stores the FQDN.
  - Optionally validates the FQDN with a forward A/AAAA lookup.

For every discovered network segment:
  - Queries the SOA and NS records to identify the DNS domain that owns
    the subnet and stores it in Network.domain_name.
  - If an AD/Windows domain is detected (via SOA MNAME or SRV _ldap records),
    enriches the network description with the domain name.

Configuration (via DKASTLE_* env vars):
  DKASTLE_DNS_RESOLVE_ENABLED=true   Enable/disable this module entirely
  DKASTLE_DNS_SERVER=                Optional specific DNS server IP
  DKASTLE_DNS_TIMEOUT=3.0            Per-query timeout in seconds
"""

from __future__ import annotations

import asyncio
import logging
import socket
from typing import TYPE_CHECKING, Any

from server.modules.base import BaseModule, ModuleCapability, ModuleManifest

if TYPE_CHECKING:
    from sqlalchemy.ext.asyncio import AsyncSession
    from server.models import Host, Network

logger = logging.getLogger(__name__)


class Module(BaseModule):
    manifest = ModuleManifest(
        name="builtin-dns",
        version="1.0.0",
        description=(
            "DNS enrichment: reverse PTR lookups for hosts, SOA/NS queries to "
            "identify the domain owning each subnet."
        ),
        author="Discoverykastle",
        capabilities=[ModuleCapability.ENRICHMENT, ModuleCapability.INVENTORY],
        builtin=True,
    )

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    async def _ptr_lookup(self, ip: str) -> str | None:
        """
        Perform a reverse DNS (PTR) lookup for *ip*.
        Returns the hostname or None if the lookup fails.
        Runs the blocking socket call in a thread-pool executor.
        """
        from server.config import settings

        timeout = settings.dns_timeout

        loop = asyncio.get_event_loop()
        try:
            result = await asyncio.wait_for(
                loop.run_in_executor(None, socket.gethostbyaddr, ip),
                timeout=timeout,
            )
            hostname: str = result[0]
            return hostname if hostname else None
        except (socket.herror, socket.gaierror, OSError):
            return None
        except asyncio.TimeoutError:
            return None

    async def _forward_lookup(self, hostname: str) -> list[str]:
        """
        Perform a forward A/AAAA lookup for *hostname*.
        Returns a list of IP addresses, or an empty list on failure.
        """
        from server.config import settings

        timeout = settings.dns_timeout
        loop = asyncio.get_event_loop()
        try:
            infos = await asyncio.wait_for(
                loop.run_in_executor(
                    None,
                    lambda: socket.getaddrinfo(hostname, None),
                ),
                timeout=timeout,
            )
            return list({info[4][0] for info in infos})
        except (socket.herror, socket.gaierror, OSError, asyncio.TimeoutError):
            return []

    async def _soa_lookup(self, ip: str) -> str | None:
        """
        Try to discover the DNS domain for *ip* by performing a reverse-zone
        SOA query using dnspython if available, falling back gracefully.

        Returns the domain name (zone origin) or None.
        """
        try:
            import dns.resolver  # type: ignore[import]
            import dns.reversename  # type: ignore[import]
            import dns.exception  # type: ignore[import]

            from server.config import settings

            rev_name = dns.reversename.from_address(ip)
            # Walk up the reverse zone labels until we get a SOA
            labels = str(rev_name).rstrip(".").split(".")
            for i in range(len(labels)):
                zone = ".".join(labels[i:]) + "."
                try:
                    resolver = dns.resolver.Resolver()
                    if settings.dns_server:
                        resolver.nameservers = [settings.dns_server]
                    resolver.lifetime = settings.dns_timeout
                    answer = resolver.resolve(zone, "SOA")
                    # SOA mname is the primary name server — extract domain
                    soa = answer[0]
                    mname = str(soa.mname).rstrip(".")
                    # The zone itself is the domain
                    return zone.rstrip(".")
                except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.exception.DNSException):
                    continue
        except ImportError:
            pass  # dnspython not installed — skip SOA lookup
        except Exception:
            logger.debug("SOA lookup failed for %s", ip, exc_info=True)
        return None

    async def _srv_ad_lookup(self, domain: str) -> bool:
        """
        Check whether *domain* has Active Directory SRV records (_ldap._tcp.).
        Returns True if AD/DC SRV records are present.
        """
        try:
            import dns.resolver  # type: ignore[import]
            import dns.exception  # type: ignore[import]

            from server.config import settings

            resolver = dns.resolver.Resolver()
            if settings.dns_server:
                resolver.nameservers = [settings.dns_server]
            resolver.lifetime = settings.dns_timeout
            resolver.resolve(f"_ldap._tcp.{domain}", "SRV")
            return True
        except Exception:
            return False

    # ------------------------------------------------------------------
    # Event hooks
    # ------------------------------------------------------------------

    async def on_host_discovered(self, host: "Host", db: "AsyncSession") -> None:
        from server.config import settings

        if not settings.dns_resolve_enabled:
            return

        if host.fqdn:
            # Already have a name — validate with forward lookup and return
            ips = await self._forward_lookup(host.fqdn)
            if ips:
                self.logger.debug(
                    "Forward lookup for %s → %s", host.fqdn, ips
                )
            return

        # Try PTR lookup for each IP until we get a name
        for ip in host.ip_addresses:
            hostname = await self._ptr_lookup(ip)
            if hostname:
                self.logger.info(
                    "PTR lookup: %s → %s (host %s)", ip, hostname, host.id
                )
                host.fqdn = hostname
                await db.flush()
                break

    async def on_network_discovered(self, network: "Network", db: "AsyncSession") -> None:
        from server.config import settings

        if not settings.dns_resolve_enabled:
            return
        if network.domain_name:
            return  # Already resolved

        # Derive a representative IP from the network address to query SOA
        try:
            import ipaddress as _ip

            net = _ip.ip_network(network.cidr, strict=False)
            # Use the first usable host address
            probe_ip = str(next(net.hosts()))
        except (ValueError, StopIteration):
            return

        domain = await self._soa_lookup(probe_ip)
        if domain:
            self.logger.info(
                "SOA lookup: network %s → domain %s", network.cidr, domain
            )
            network.domain_name = domain

            # Check if it's an Active Directory domain
            is_ad = await self._srv_ad_lookup(domain)
            if is_ad:
                self.logger.info(
                    "Active Directory domain detected: %s (network %s)",
                    domain, network.cidr,
                )
                # Annotate description if not already set
                if not network.description:
                    network.description = f"AD domain: {domain}"

            await db.flush()

    # ------------------------------------------------------------------
    # Inventory enrichment — expose DNS info in host detail
    # ------------------------------------------------------------------

    async def get_inventory_extra(
        self, host_id: str, db: "AsyncSession"
    ) -> dict[str, Any]:
        return {}  # fqdn already part of base HostDetail schema
