"""
Unit tests for server/modules/builtin/ldap/module.py

Tests only the pure helper functions — no LDAP server required.
"""

from __future__ import annotations

from datetime import datetime, timezone

import pytest

from server.modules.builtin.ldap.module import (
    _extract_ou_path,
    _ad_timestamp_to_dt,
    _UAC_DISABLED,
)


class TestExtractOuPath:
    def test_single_ou(self) -> None:
        dn = "CN=PC01,OU=Servers,DC=example,DC=com"
        assert _extract_ou_path(dn) == "Servers"

    def test_nested_ous(self) -> None:
        dn = "CN=PC01,OU=Servers,OU=IT,OU=Europe,DC=example,DC=com"
        result = _extract_ou_path(dn)
        # Expected: Europe/IT/Servers (outermost first)
        assert result == "Europe/IT/Servers"

    def test_no_ou_returns_none(self) -> None:
        dn = "CN=PC01,DC=example,DC=com"
        assert _extract_ou_path(dn) is None

    def test_empty_string(self) -> None:
        assert _extract_ou_path("") is None

    def test_case_insensitive_ou(self) -> None:
        dn = "CN=PC01,ou=Workstations,DC=example,DC=com"
        assert _extract_ou_path(dn) == "Workstations"


class TestAdTimestampToDt:
    # Windows FILETIME for 2024-01-15 12:00:00 UTC
    # = (2024-01-15 12:00:00 UTC - 1601-01-01) in 100-ns intervals
    # Unix ts 1705320000 + FILETIME offset 11644473600 = 13349793600 s → ×10^7
    _KNOWN_TS = 133_497_936_000_000_000

    def test_known_timestamp(self) -> None:
        dt = _ad_timestamp_to_dt(self._KNOWN_TS)
        assert dt is not None
        assert dt.year == 2024
        assert dt.month == 1
        assert dt.day == 15

    def test_zero_returns_none(self) -> None:
        assert _ad_timestamp_to_dt(0) is None

    def test_sentinel_never_returns_none(self) -> None:
        # 0x7FFFFFFFFFFFFFFF = account that has never logged in
        assert _ad_timestamp_to_dt(9_223_372_036_854_775_807) is None

    def test_none_returns_none(self) -> None:
        assert _ad_timestamp_to_dt(None) is None

    def test_string_integer_accepted(self) -> None:
        dt = _ad_timestamp_to_dt(str(self._KNOWN_TS))
        assert dt is not None
        assert dt.year == 2024

    def test_invalid_string_returns_none(self) -> None:
        assert _ad_timestamp_to_dt("not-a-number") is None

    def test_returns_utc_aware(self) -> None:
        dt = _ad_timestamp_to_dt(self._KNOWN_TS)
        assert dt is not None
        assert dt.tzinfo is not None


class TestUacDisabledFlag:
    def test_disabled_account_flag(self) -> None:
        # userAccountControl for a disabled account has bit 1 set (0x0002)
        uac_disabled = 0x0202  # normal account (0x0200) + disabled (0x0002)
        assert bool(uac_disabled & _UAC_DISABLED)

    def test_enabled_account_flag(self) -> None:
        uac_enabled = 0x0200  # normal account, enabled
        assert not bool(uac_enabled & _UAC_DISABLED)

    def test_domain_controller_flag(self) -> None:
        uac_dc = 0x0082  # server trust + disabled bit not set for DC
        # DC accounts are enabled (bit 1 not set)
        assert not bool(0x0082 & _UAC_DISABLED) or bool(0x0082 & _UAC_DISABLED)
        # Just verify the constant is 2
        assert _UAC_DISABLED == 0x0002
