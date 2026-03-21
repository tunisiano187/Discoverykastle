"""
IP address utilities for Discoverykastle.

Provides helpers to determine whether an IP address or CIDR range is
private (RFC 1918, RFC 4193, loopback, link-local) or publicly routable.

This is used to enforce the policy that public IPs require explicit human
authorization before a scan is allowed to proceed.
"""

from __future__ import annotations

import ipaddress


# All reserved / non-public address spaces (IPv4 + IPv6)
_PRIVATE_NETWORKS: list[ipaddress.IPv4Network | ipaddress.IPv6Network] = [
    # IPv4 RFC 1918
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    # IPv4 special-use
    ipaddress.ip_network("127.0.0.0/8"),       # Loopback
    ipaddress.ip_network("169.254.0.0/16"),    # Link-local (APIPA)
    ipaddress.ip_network("100.64.0.0/10"),     # Shared address space (RFC 6598)
    ipaddress.ip_network("192.0.0.0/24"),      # IETF Protocol Assignments
    ipaddress.ip_network("192.0.2.0/24"),      # Documentation (TEST-NET-1)
    ipaddress.ip_network("198.18.0.0/15"),     # Benchmarking
    ipaddress.ip_network("198.51.100.0/24"),   # Documentation (TEST-NET-2)
    ipaddress.ip_network("203.0.113.0/24"),    # Documentation (TEST-NET-3)
    ipaddress.ip_network("240.0.0.0/4"),       # Reserved (class E)
    ipaddress.ip_network("255.255.255.255/32"),# Broadcast
    # IPv6 special-use
    ipaddress.ip_network("::1/128"),           # Loopback
    ipaddress.ip_network("fc00::/7"),          # Unique Local (RFC 4193)
    ipaddress.ip_network("fe80::/10"),         # Link-local
    ipaddress.ip_network("::ffff:0:0/96"),     # IPv4-mapped
]


def is_private_ip(ip: str) -> bool:
    """
    Return True if the IP address is private/reserved (not publicly routable).

    Covers RFC 1918, loopback, link-local, and other special-use ranges.
    Returns True for unparseable strings (fail-safe: treat unknown as private).
    """
    try:
        addr = ipaddress.ip_address(ip)
        return any(addr in net for net in _PRIVATE_NETWORKS)
    except ValueError:
        return True  # fail-safe


def is_public_ip(ip: str) -> bool:
    """
    Return True if the IP address is publicly routable.
    """
    return not is_private_ip(ip)


def is_private_cidr(cidr: str) -> bool:
    """
    Return True only when every address in the CIDR block is private/reserved.

    A /8 that straddles private and public space returns False.
    """
    try:
        network = ipaddress.ip_network(cidr, strict=False)
        # Check network address and broadcast against all private ranges
        for priv_net in _PRIVATE_NETWORKS:
            if network.subnet_of(priv_net):  # type: ignore[arg-type]
                return True
        return False
    except (ValueError, TypeError):
        return False


def cidr_contains_public_ips(cidr: str) -> bool:
    """
    Return True if the CIDR range contains *any* publicly routable address.
    """
    return not is_private_cidr(cidr)


def classify_cidr(cidr: str) -> str:
    """
    Classify a CIDR block.

    Returns:
        "private"  — fully within reserved address space
        "public"   — first address is publicly routable (and block is not private)
        "mixed"    — straddles private and public (unusual; treat as public for safety)
        "unknown"  — could not parse the CIDR
    """
    try:
        network = ipaddress.ip_network(cidr, strict=False)
        if is_private_cidr(cidr):
            return "private"
        # If any host address is private the block is mixed
        first = next(network.hosts(), None)
        if first is None:
            # Host-route /32 or /128
            first = network.network_address
        if is_private_ip(str(first)):
            return "mixed"
        return "public"
    except ValueError:
        return "unknown"
