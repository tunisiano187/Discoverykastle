"""
Tests for agent/collectors/snmp_collector.py

All tests are pure-Python with no live SNMP.  pysnmp is mocked at the module
boundary so the tests run in any environment, even without pysnmp installed.
"""
from __future__ import annotations

import sys
import types
from unittest.mock import MagicMock, patch

# ---------------------------------------------------------------------------
# Synthetic pysnmp stub so the import inside snmp_collector doesn't fail
# when pysnmp isn't installed in the CI environment.
# ---------------------------------------------------------------------------

def _make_pysnmp_stub() -> types.ModuleType:
    """Build a minimal pysnmp stub that satisfies the lazy imports inside
    _SNMPSession without any real SNMP machinery."""

    pysnmp = types.ModuleType("pysnmp")
    hlapi  = types.ModuleType("pysnmp.hlapi")

    # Protocol constants
    for name in (
        "usmHMACSHAAuthProtocol", "usmHMACMD5AuthProtocol",
        "usmAesCfb128Protocol", "usmDESPrivProtocol",
        "usmNoPrivProtocol", "usmNoAuthProtocol",
    ):
        setattr(hlapi, name, object())

    # CommunityData / UsmUserData
    hlapi.CommunityData  = MagicMock(return_value=MagicMock())
    hlapi.UsmUserData    = MagicMock(return_value=MagicMock())

    # Transport
    hlapi.UdpTransportTarget = MagicMock(return_value=MagicMock())

    # Engine / context
    hlapi.SnmpEngine   = MagicMock(return_value=MagicMock())
    hlapi.ContextData  = MagicMock(return_value=MagicMock())

    # ObjectType / ObjectIdentity
    hlapi.ObjectIdentity = MagicMock(side_effect=lambda oid: oid)
    hlapi.ObjectType     = MagicMock(side_effect=lambda oid: oid)

    # getCmd and nextCmd stubs (return empty success by default)
    hlapi.getCmd  = MagicMock(return_value=iter([(None, None, None, [])]))
    hlapi.nextCmd = MagicMock(return_value=iter([]))

    pysnmp.hlapi = hlapi
    sys.modules["pysnmp"]       = pysnmp
    sys.modules["pysnmp.hlapi"] = hlapi
    return pysnmp


_PYSNMP_STUB = _make_pysnmp_stub()

# Now it's safe to import the collector
from agent.collectors.snmp_collector import (  # noqa: E402
    SNMPCollector,
    SNMPDeviceInfo,
    _SNMPSession,
    _poll_device,
    _vendor_from_sysoid,
    _extract_model_from_descr,
    OID_IF_DESCR,
    OID_IF_OPER_STATUS,
    OID_IF_PHY_ADDRESS,
)


# ===========================================================================
# Unit tests — pure logic, no I/O
# ===========================================================================

class TestVendorDetection:
    def test_cisco_oid(self):
        assert _vendor_from_sysoid(".1.3.6.1.4.1.9.1.1208") == "Cisco"

    def test_juniper_oid(self):
        assert _vendor_from_sysoid(".1.3.6.1.4.1.2636.1.1.1.2.60") == "Juniper"

    def test_huawei_oid(self):
        assert _vendor_from_sysoid(".1.3.6.1.4.1.2011.2.23.333") == "Huawei"

    def test_unknown_oid_returns_none(self):
        assert _vendor_from_sysoid(".1.3.6.1.4.1.99999.1.2.3") is None

    def test_none_input(self):
        assert _vendor_from_sysoid(None) is None

    def test_empty_string(self):
        assert _vendor_from_sysoid("") is None


class TestModelExtraction:
    def test_cisco_c3750(self):
        descr = "Cisco IOS Software, C3750E Software (C3750E-UNIVERSALK9-M), Version 15.2"
        result = _extract_model_from_descr(descr, "Cisco")
        assert result is not None
        assert "3750" in result

    def test_juniper_mx480(self):
        descr = "Juniper Networks, Inc. mx480 internet router, kernel JUNOS 18.4R2"
        result = _extract_model_from_descr(descr, "Juniper")
        assert result is not None
        assert "MX480" in result.upper()

    def test_generic_linux_returns_none(self):
        descr = "Linux version 5.4.0-144-generic #161-Ubuntu SMP"
        result = _extract_model_from_descr(descr, "Net-SNMP")
        assert result is None

    def test_unknown_vendor_returns_none(self):
        result = _extract_model_from_descr("Some random device", None)
        assert result is None


# ===========================================================================
# _SNMPSession unit tests (pysnmp stubbed)
# ===========================================================================

class TestSNMPSession:
    def _session(self, **kw) -> _SNMPSession:
        defaults = dict(host="192.168.1.1", community="public", version="2c",
                        timeout=1, retries=0)
        defaults.update(kw)
        return _SNMPSession(**defaults)

    def test_available_when_pysnmp_installed(self):
        s = self._session()
        assert s.available is True

    def test_get_returns_dict(self):
        """get() should return a dict (possibly empty) without raising."""
        # getCmd stub returns empty var_binds → empty result
        s = self._session()
        result = s.get(".1.3.6.1.2.1.1.5.0")
        assert isinstance(result, dict)

    def test_walk_returns_dict(self):
        s = self._session()
        result = s.walk(".1.3.6.1.2.1.2.2.1.2")
        assert isinstance(result, dict)

    def test_get_with_error_indication_returns_empty(self):
        from pysnmp.hlapi import getCmd as stub_getCmd
        stub_getCmd.return_value = iter([("Timeout", None, None, [])])
        s = self._session()
        result = s.get(".1.3.6.1.2.1.1.1.0")
        assert result == {}

    def test_get_values_pretty_printed(self):
        # Build a fake var-bind where value has prettyPrint
        fake_val = MagicMock()
        fake_val.prettyPrint.return_value = "MyRouter"
        fake_oid = MagicMock()
        fake_oid.__str__ = lambda self: ".1.3.6.1.2.1.1.5.0"

        from pysnmp.hlapi import getCmd as stub_getCmd
        stub_getCmd.return_value = iter([(None, None, None, [(fake_oid, fake_val)])])

        s = self._session()
        result = s.get(".1.3.6.1.2.1.1.5.0")
        assert ".1.3.6.1.2.1.1.5.0" in result
        assert result[".1.3.6.1.2.1.1.5.0"] == "MyRouter"


# ===========================================================================
# _poll_device integration (session mocked)
# ===========================================================================

class TestPollDevice:
    def _make_session(self, get_data: dict, walk_data: dict | None = None) -> MagicMock:
        session = MagicMock(spec=_SNMPSession)
        session.available = True
        session.get.return_value = get_data
        session.walk.return_value = walk_data or {}
        return session

    def test_returns_none_when_no_snmp_response(self):
        session = self._make_session({})
        result = _poll_device(session, "10.0.0.1")
        assert result is None

    def test_basic_device_info_parsed(self):
        sys_data = {
            ".1.3.6.1.2.1.1.1.0": "Cisco IOS Software, C3750E",
            ".1.3.6.1.2.1.1.2.0": ".1.3.6.1.4.1.9.1.1208",
            ".1.3.6.1.2.1.1.3.0": "1234500",   # uptime in hundredths
            ".1.3.6.1.2.1.1.4.0": "admin@example.com",
            ".1.3.6.1.2.1.1.5.0": "core-switch-01",
            ".1.3.6.1.2.1.1.6.0": "Server Room A",
        }
        session = self._make_session(sys_data)
        result = _poll_device(session, "10.0.0.1")

        assert result is not None
        assert isinstance(result, SNMPDeviceInfo)
        assert result.ip == "10.0.0.1"
        assert result.hostname == "core-switch-01"
        assert result.vendor == "Cisco"
        assert result.uptime_secs == 12345
        assert result.sys_contact == "admin@example.com"
        assert result.sys_location == "Server Room A"

    def test_interfaces_parsed_from_walk(self):
        sys_data = {".1.3.6.1.2.1.1.5.0": "router-01"}
        if_descr  = {".1.3.6.1.2.1.2.2.1.2.1": "GigabitEthernet0/0"}
        if_oper   = {".1.3.6.1.2.1.2.2.1.8.1": "1"}  # up
        if_mac    = {".1.3.6.1.2.1.2.2.1.6.1": "00:11:22:33:44:55"}

        session = MagicMock(spec=_SNMPSession)
        session.available = True
        session.get.return_value = sys_data

        def walk_side(oid):
            if oid == OID_IF_DESCR:
                return if_descr
            if oid == OID_IF_OPER_STATUS:
                return if_oper
            if oid == OID_IF_PHY_ADDRESS:
                return if_mac
            return {}

        session.walk.side_effect = walk_side
        result = _poll_device(session, "10.0.0.2")

        assert result is not None
        assert len(result.interfaces) == 1
        iface = result.interfaces[0]
        assert iface["name"] == "GigabitEthernet0/0"
        assert iface["oper_status"] == "up"

    def test_interface_down_status(self):
        sys_data = {".1.3.6.1.2.1.1.5.0": "sw"}
        if_descr  = {".1.3.6.1.2.1.2.2.1.2.2": "Ethernet0/1"}
        if_oper   = {".1.3.6.1.2.1.2.2.1.8.2": "2"}  # down

        session = MagicMock(spec=_SNMPSession)
        session.available = True
        session.get.return_value = sys_data

        def walk_side(oid):
            if oid == OID_IF_DESCR:
                return if_descr
            if oid == OID_IF_OPER_STATUS:
                return if_oper
            return {}
        session.walk.side_effect = walk_side

        result = _poll_device(session, "10.0.0.3")
        assert result is not None
        assert result.interfaces[0]["oper_status"] == "down"


# ===========================================================================
# SNMPCollector._fetch_target_ips
# ===========================================================================

class TestFetchTargets:
    def _collector(self) -> SNMPCollector:
        return SNMPCollector("http://localhost:8000", "agent-1")

    def test_returns_ips_from_host_list(self):
        hosts_payload = [
            {"id": "h1", "ip_addresses": ["10.0.0.1"]},
            {"id": "h2", "ip_addresses": ["10.0.0.2", "10.0.0.3"]},
        ]
        with patch("agent.collectors.snmp_collector._http_get_json", return_value=hosts_payload):
            ips = self._collector()._fetch_target_ips()
        assert ips == ["10.0.0.1", "10.0.0.2"]

    def test_deduplicates_ips(self):
        hosts_payload = [
            {"id": "h1", "ip_addresses": ["10.0.0.1"]},
            {"id": "h2", "ip_addresses": ["10.0.0.1"]},   # duplicate
        ]
        with patch("agent.collectors.snmp_collector._http_get_json", return_value=hosts_payload):
            ips = self._collector()._fetch_target_ips()
        assert ips == ["10.0.0.1"]

    def test_returns_empty_on_http_failure(self):
        with patch("agent.collectors.snmp_collector._http_get_json", return_value=None):
            ips = self._collector()._fetch_target_ips()
        assert ips == []

    def test_wrapped_hosts_key(self):
        payload = {"hosts": [{"ip_addresses": ["192.168.1.1"]}]}
        with patch("agent.collectors.snmp_collector._http_get_json", return_value=payload):
            ips = self._collector()._fetch_target_ips()
        assert ips == ["192.168.1.1"]


# ===========================================================================
# SNMPCollector._submit_device
# ===========================================================================

class TestSubmitDevice:
    def _collector(self) -> SNMPCollector:
        return SNMPCollector("http://localhost:8000", "agent-1")

    def test_submit_calls_post_with_correct_endpoint(self):
        info = SNMPDeviceInfo(
            ip="10.0.0.5",
            hostname="sw-01",
            vendor="Cisco",
            model="C3750E",
            sys_descr="Cisco IOS ...",
            uptime_secs=3600,
        )
        with patch("agent.collectors.snmp_collector._http_post_json", return_value=True) as mock_post:
            result = self._collector()._submit_device(info)

        assert result is True
        mock_post.assert_called_once()
        url, payload, *_ = mock_post.call_args.args
        assert url.endswith("/api/v1/data/device-configs")
        device = payload["device_configs"][0]
        assert device["ip"] == "10.0.0.5"
        assert device["hostname"] == "sw-01"
        assert device["vendor"] == "Cisco"
        assert device["model"] == "C3750E"
        assert device["structured_data"]["uptime_secs"] == 3600

    def test_submit_returns_false_on_server_error(self):
        info = SNMPDeviceInfo(ip="10.0.0.6")
        with patch("agent.collectors.snmp_collector._http_post_json", return_value=False):
            result = self._collector()._submit_device(info)
        assert result is False


# ===========================================================================
# SNMPCollector.run_poll_cycle end-to-end (all I/O mocked)
# ===========================================================================

class TestRunPollCycle:
    def _collector(self) -> SNMPCollector:
        return SNMPCollector("http://localhost:8000", "agent-1", community="public")

    def test_full_cycle_polls_and_submits(self):
        hosts = [{"ip_addresses": ["10.0.0.10"]}]
        device_info = SNMPDeviceInfo(ip="10.0.0.10", hostname="test-switch", vendor="Cisco")

        with (
            patch("agent.collectors.snmp_collector._http_get_json", return_value=hosts),
            patch("agent.collectors.snmp_collector._http_post_json", return_value=True) as mock_post,
            patch("agent.collectors.snmp_collector._poll_device", return_value=device_info),
        ):
            self._collector().run_poll_cycle()

        mock_post.assert_called_once()

    def test_cycle_skips_unreachable_hosts(self):
        """_poll_device returning None should be counted as unreachable, not error."""
        hosts = [{"ip_addresses": ["10.0.0.20"]}]
        with (
            patch("agent.collectors.snmp_collector._http_get_json", return_value=hosts),
            patch("agent.collectors.snmp_collector._http_post_json") as mock_post,
            patch("agent.collectors.snmp_collector._poll_device", return_value=None),
        ):
            self._collector().run_poll_cycle()

        mock_post.assert_not_called()

    def test_cycle_no_targets_is_noop(self):
        with (
            patch("agent.collectors.snmp_collector._http_get_json", return_value=[]),
            patch("agent.collectors.snmp_collector._http_post_json") as mock_post,
        ):
            self._collector().run_poll_cycle()

        mock_post.assert_not_called()

    def test_cycle_handles_poll_exception_gracefully(self):
        """An exception in _poll_device should not crash the whole cycle."""
        hosts = [
            {"ip_addresses": ["10.0.0.30"]},
            {"ip_addresses": ["10.0.0.31"]},
        ]
        good_info = SNMPDeviceInfo(ip="10.0.0.31", hostname="good-host")

        def poll_side(session, ip):
            if ip == "10.0.0.30":
                raise RuntimeError("Connection refused")
            return good_info

        with (
            patch("agent.collectors.snmp_collector._http_get_json", return_value=hosts),
            patch("agent.collectors.snmp_collector._http_post_json", return_value=True) as mock_post,
            patch("agent.collectors.snmp_collector._poll_device", side_effect=poll_side),
        ):
            self._collector().run_poll_cycle()

        # The good host should still be submitted despite the earlier exception
        mock_post.assert_called_once()

    def test_cycle_aborts_when_pysnmp_unavailable(self):
        """If pysnmp import fails inside run_poll_cycle, the cycle returns early."""
        with (
            patch("agent.collectors.snmp_collector._http_get_json") as mock_get,
            # Simulate pysnmp not installed by patching __import__
            patch("builtins.__import__", side_effect=lambda n, *a, **kw: (
                (_ for _ in ()).throw(ImportError("No module named 'pysnmp'"))
                if n == "pysnmp" else __import__(n, *a, **kw)
            )),
        ):
            self._collector().run_poll_cycle()

        # Should not even try to fetch targets
        mock_get.assert_not_called()
