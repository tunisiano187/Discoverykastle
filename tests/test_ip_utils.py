"""
Tests for server/services/ip_utils.py — IP/CIDR classification helpers.
"""

from __future__ import annotations

import pytest

from server.services.ip_utils import (
    is_private_ip,
    is_public_ip,
    is_private_cidr,
    cidr_contains_public_ips,
    classify_cidr,
)


class TestIsPrivateIp:
    # RFC 1918
    def test_rfc1918_10(self) -> None:
        assert is_private_ip("10.0.0.1")

    def test_rfc1918_172(self) -> None:
        assert is_private_ip("172.16.0.1")
        assert is_private_ip("172.31.255.255")

    def test_rfc1918_192(self) -> None:
        assert is_private_ip("192.168.1.100")

    def test_loopback(self) -> None:
        assert is_private_ip("127.0.0.1")
        assert is_private_ip("127.0.0.255")

    def test_link_local(self) -> None:
        assert is_private_ip("169.254.0.1")
        assert is_private_ip("169.254.255.255")

    def test_shared_address_space_rfc6598(self) -> None:
        assert is_private_ip("100.64.0.1")
        assert is_private_ip("100.127.255.255")

    def test_documentation_ranges(self) -> None:
        assert is_private_ip("192.0.2.1")       # TEST-NET-1
        assert is_private_ip("198.51.100.1")    # TEST-NET-2
        assert is_private_ip("203.0.113.1")     # TEST-NET-3

    def test_ipv6_loopback(self) -> None:
        assert is_private_ip("::1")

    def test_ipv6_unique_local(self) -> None:
        assert is_private_ip("fc00::1")
        assert is_private_ip("fd12:3456:789a::1")

    def test_ipv6_link_local(self) -> None:
        assert is_private_ip("fe80::1")

    def test_public_ipv4_is_not_private(self) -> None:
        assert not is_private_ip("8.8.8.8")
        assert not is_private_ip("1.1.1.1")
        assert not is_private_ip("203.0.114.0")  # one past TEST-NET-3

    def test_invalid_string_is_private_failsafe(self) -> None:
        assert is_private_ip("not-an-ip")
        assert is_private_ip("")
        assert is_private_ip("999.999.999.999")


class TestIsPublicIp:
    def test_google_dns_is_public(self) -> None:
        assert is_public_ip("8.8.8.8")

    def test_rfc1918_not_public(self) -> None:
        assert not is_public_ip("192.168.0.1")

    def test_loopback_not_public(self) -> None:
        assert not is_public_ip("127.0.0.1")


class TestIsPrivateCidr:
    def test_rfc1918_slash24(self) -> None:
        assert is_private_cidr("192.168.1.0/24")

    def test_rfc1918_slash8(self) -> None:
        assert is_private_cidr("10.0.0.0/8")

    def test_loopback(self) -> None:
        assert is_private_cidr("127.0.0.0/8")

    def test_public_slash24_not_private(self) -> None:
        assert not is_private_cidr("8.8.8.0/24")

    def test_mixed_block_not_private(self) -> None:
        # A /7 that contains both private (10.x) and public (11.x) is NOT fully private
        assert not is_private_cidr("10.0.0.0/7")

    def test_host_route_private(self) -> None:
        assert is_private_cidr("10.1.2.3/32")

    def test_invalid_returns_false(self) -> None:
        assert not is_private_cidr("not-a-cidr")

    def test_ipv6_unique_local(self) -> None:
        assert is_private_cidr("fc00::/7")


class TestCidrContainsPublicIps:
    def test_public_block(self) -> None:
        assert cidr_contains_public_ips("8.8.8.0/24")

    def test_private_block_no_public(self) -> None:
        assert not cidr_contains_public_ips("192.168.0.0/16")


class TestClassifyCidr:
    def test_private(self) -> None:
        assert classify_cidr("10.0.0.0/8") == "private"
        assert classify_cidr("192.168.100.0/24") == "private"

    def test_public(self) -> None:
        assert classify_cidr("8.8.8.0/24") == "public"
        assert classify_cidr("1.1.1.0/24") == "public"

    def test_unknown_on_garbage(self) -> None:
        assert classify_cidr("garbage") == "unknown"

    def test_host_route_private(self) -> None:
        assert classify_cidr("10.1.2.3/32") == "private"

    def test_host_route_public(self) -> None:
        assert classify_cidr("8.8.8.8/32") == "public"
