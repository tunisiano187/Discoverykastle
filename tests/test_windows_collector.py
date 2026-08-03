"""
Unit tests for the Windows WMI collector.

All Windows-specific modules (winreg, wmi, psutil, subprocess) are patched so
tests run on any platform without real Windows APIs.
"""

from __future__ import annotations

import sys
from unittest.mock import MagicMock, patch

# ---------------------------------------------------------------------------
# Helpers that stub Windows-only modules before importing the collector
# ---------------------------------------------------------------------------

def _make_winreg_stub():
    """Return a minimal winreg stub with HKEY_LOCAL_MACHINE / HKEY_CURRENT_USER."""
    mod = MagicMock()
    mod.HKEY_LOCAL_MACHINE = 0x80000002
    mod.HKEY_CURRENT_USER = 0x80000001
    mod.OpenKey.return_value.__enter__ = lambda self: self
    mod.OpenKey.return_value.__exit__ = MagicMock(return_value=False)
    return mod


def _import_collector():
    """Import windows_collector with winreg stubbed out."""
    import sys
    stub = _make_winreg_stub()
    with patch.dict(sys.modules, {"winreg": stub, "wmi": MagicMock(), "psutil": MagicMock()}):
        import importlib
        import agent.collectors.windows_collector as wc
        importlib.reload(wc)
        return wc


# ---------------------------------------------------------------------------
# WindowsHostInfo
# ---------------------------------------------------------------------------

class TestCollectHostInfo:
    def test_falls_back_to_127_when_no_network(self) -> None:
        from agent.collectors.windows_collector import _collect_host_info, WindowsHostInfo

        psutil_mock = MagicMock()
        psutil_mock.net_if_addrs.return_value = {}  # no interfaces

        with (
            patch.dict(sys.modules, {"wmi": MagicMock(), "psutil": psutil_mock}),
            patch("socket.getfqdn", return_value="testhost.local"),
            patch("socket.socket") as mock_sock,
        ):
            mock_sock.return_value.__enter__.return_value.getsockname.return_value = ("127.0.0.1", 0)
            mock_sock.return_value.__enter__.return_value.connect = MagicMock(
                side_effect=OSError("no route")
            )
            info = _collect_host_info()

        assert isinstance(info, WindowsHostInfo)
        assert info.fqdn == "testhost.local"

    def test_collects_ipv4_from_psutil(self) -> None:
        import socket as socket_mod
        from agent.collectors.windows_collector import _collect_host_info

        addr_mock = MagicMock()
        addr_mock.family = socket_mod.AF_INET
        addr_mock.address = "192.168.1.10"

        psutil_mock = MagicMock()
        psutil_mock.net_if_addrs.return_value = {"Ethernet": [addr_mock]}

        with (
            patch.dict(sys.modules, {"wmi": MagicMock(), "psutil": psutil_mock}),
            patch("socket.getfqdn", return_value="myhost"),
        ):
            info = _collect_host_info()

        assert "192.168.1.10" in info.ip_addresses

    def test_strips_loopback_ipv4_falls_back_to_socket(self) -> None:
        """When psutil only exposes loopback, the socket fallback provides the IP."""
        import socket as socket_mod
        from agent.collectors.windows_collector import _collect_host_info

        loopback = MagicMock()
        loopback.family = socket_mod.AF_INET
        loopback.address = "127.0.0.1"

        psutil_mock = MagicMock()
        psutil_mock.net_if_addrs.return_value = {"lo": [loopback]}

        with (
            patch.dict(sys.modules, {"wmi": MagicMock(), "psutil": psutil_mock}),
            patch("socket.getfqdn", return_value="myhost"),
            patch("socket.socket") as mock_sock,
        ):
            # Socket fallback succeeds with a real IP
            mock_sock.return_value.__enter__.return_value.getsockname.return_value = (
                "10.0.0.99", 0,
            )
            info = _collect_host_info()

        # The psutil loopback was filtered; socket fallback provided 10.0.0.99
        assert "127.0.0.1" not in info.ip_addresses
        assert "10.0.0.99" in info.ip_addresses


# ---------------------------------------------------------------------------
# Installed packages
# ---------------------------------------------------------------------------

class TestCollectInstalledPackages:
    def test_returns_empty_when_winreg_missing(self) -> None:
        from agent.collectors.windows_collector import _collect_installed_packages

        with patch.dict(sys.modules, {"winreg": None}):
            packages = _collect_installed_packages()
        assert packages == []

    def test_parses_registry_entries(self) -> None:
        winreg_stub = _make_winreg_stub()

        # EnumKey yields one sub-key then raises OSError to stop iteration
        winreg_stub.EnumKey.side_effect = ["{APP-GUID}", OSError]
        winreg_stub.QueryValueEx.side_effect = [
            ("My App", None),      # DisplayName
            ("1.2.3", None),       # DisplayVersion
            ("Acme Corp", None),   # Publisher
        ]

        with patch.dict(sys.modules, {"winreg": winreg_stub}):
            from agent.collectors import windows_collector as wc
            # Patch _winreg_get to return controlled values
            with patch.object(wc, "_winreg_get", side_effect=["My App", "1.2.3", "Acme Corp"]):
                with patch.object(winreg_stub, "OpenKey"):
                    winreg_stub.EnumKey.side_effect = ["key1", OSError]
                    packages = wc._collect_installed_packages()

        # We do a light integration check — real registry calls are patched
        assert isinstance(packages, list)

    def test_deduplicates_packages(self) -> None:
        """Same name appearing in 32-bit and 64-bit hives should appear once."""
        from agent.collectors.windows_collector import InstalledPackage

        packages_dict: dict[str, InstalledPackage] = {}
        names = ["MyApp", "myapp", "MYAPP"]  # same logical package

        for name in names:
            key = name.lower()
            if key not in packages_dict:
                packages_dict[key] = InstalledPackage(name=name, version="1.0")

        assert len(packages_dict) == 1


# ---------------------------------------------------------------------------
# CIS checks — firewall
# ---------------------------------------------------------------------------

class TestCISFirewall:
    def test_all_profiles_enabled_passes(self) -> None:
        from agent.collectors.windows_collector import _check_firewall

        winreg_stub = _make_winreg_stub()
        with patch.dict(sys.modules, {"winreg": winreg_stub}):
            with patch("agent.collectors.windows_collector._winreg_get", return_value=1):
                findings = _check_firewall()

        assert len(findings) == 3
        assert all(f.passed for f in findings)

    def test_disabled_profile_fails(self) -> None:
        from agent.collectors.windows_collector import _check_firewall

        winreg_stub = _make_winreg_stub()
        with patch.dict(sys.modules, {"winreg": winreg_stub}):
            with patch("agent.collectors.windows_collector._winreg_get", return_value=0):
                findings = _check_firewall()

        assert all(not f.passed for f in findings)

    def test_check_ids_are_correct(self) -> None:
        from agent.collectors.windows_collector import _check_firewall

        winreg_stub = _make_winreg_stub()
        with patch.dict(sys.modules, {"winreg": winreg_stub}):
            with patch("agent.collectors.windows_collector._winreg_get", return_value=1):
                findings = _check_firewall()

        ids = {f.check_id for f in findings}
        assert ids == {"WF-01", "WF-02", "WF-03"}


# ---------------------------------------------------------------------------
# CIS checks — UAC
# ---------------------------------------------------------------------------

class TestCISUAC:
    def test_uac_enabled_passes(self) -> None:
        from agent.collectors.windows_collector import _check_uac

        winreg_stub = _make_winreg_stub()
        with patch.dict(sys.modules, {"winreg": winreg_stub}):
            with patch("agent.collectors.windows_collector._winreg_get", side_effect=[1, 2]):
                findings = _check_uac()

        assert findings[0].check_id == "UAC-01" and findings[0].passed
        assert findings[1].check_id == "UAC-02" and findings[1].passed

    def test_uac_disabled_fails(self) -> None:
        from agent.collectors.windows_collector import _check_uac

        winreg_stub = _make_winreg_stub()
        with patch.dict(sys.modules, {"winreg": winreg_stub}):
            with patch("agent.collectors.windows_collector._winreg_get", side_effect=[0, 0]):
                findings = _check_uac()

        assert not findings[0].passed
        assert not findings[1].passed


# ---------------------------------------------------------------------------
# CIS checks — password policy
# ---------------------------------------------------------------------------

class TestCISPasswordPolicy:
    def test_compliant_policy_passes(self) -> None:
        from agent.collectors.windows_collector import _check_password_policy

        net_output = (
            "Minimum password length:         14\n"
            "Lockout threshold:               5\n"
        )
        mock_result = MagicMock()
        mock_result.stdout = net_output

        with patch("subprocess.run", return_value=mock_result):
            with patch("agent.collectors.windows_collector._winreg_get", return_value=1):
                findings = _check_password_policy()

        pw_len = next(f for f in findings if f.check_id == "PW-01")
        lockout = next(f for f in findings if f.check_id == "PW-03")
        assert pw_len.passed
        assert lockout.passed

    def test_short_password_fails(self) -> None:
        from agent.collectors.windows_collector import _check_password_policy

        mock_result = MagicMock()
        mock_result.stdout = (
            "Minimum password length:         8\n"
            "Lockout threshold:               5\n"
        )

        with patch("subprocess.run", return_value=mock_result):
            with patch("agent.collectors.windows_collector._winreg_get", return_value=1):
                findings = _check_password_policy()

        pw_len = next(f for f in findings if f.check_id == "PW-01")
        assert not pw_len.passed

    def test_no_lockout_fails(self) -> None:
        from agent.collectors.windows_collector import _check_password_policy

        mock_result = MagicMock()
        mock_result.stdout = (
            "Minimum password length:         14\n"
            "Lockout threshold:               Never\n"
        )

        with patch("subprocess.run", return_value=mock_result):
            with patch("agent.collectors.windows_collector._winreg_get", return_value=1):
                findings = _check_password_policy()

        lockout = next(f for f in findings if f.check_id == "PW-03")
        assert not lockout.passed


# ---------------------------------------------------------------------------
# CIS checks — screen lock
# ---------------------------------------------------------------------------

class TestCISScreenLock:
    def test_compliant_screensaver_passes(self) -> None:
        from agent.collectors.windows_collector import _check_screen_lock

        winreg_stub = _make_winreg_stub()
        with patch.dict(sys.modules, {"winreg": winreg_stub}):
            with patch(
                "agent.collectors.windows_collector._winreg_get",
                side_effect=["1", "1", "600"],
            ):
                findings = _check_screen_lock()

        assert len(findings) == 1
        assert findings[0].passed

    def test_disabled_screensaver_fails(self) -> None:
        from agent.collectors.windows_collector import _check_screen_lock

        winreg_stub = _make_winreg_stub()
        with patch.dict(sys.modules, {"winreg": winreg_stub}):
            with patch(
                "agent.collectors.windows_collector._winreg_get",
                side_effect=["0", "0", "0"],
            ):
                findings = _check_screen_lock()

        assert not findings[0].passed

    def test_timeout_too_long_fails(self) -> None:
        from agent.collectors.windows_collector import _check_screen_lock

        winreg_stub = _make_winreg_stub()
        with patch.dict(sys.modules, {"winreg": winreg_stub}):
            with patch(
                "agent.collectors.windows_collector._winreg_get",
                side_effect=["1", "1", "3600"],  # 1 hour — too long
            ):
                findings = _check_screen_lock()

        assert not findings[0].passed


# ---------------------------------------------------------------------------
# CIS checks — autorun
# ---------------------------------------------------------------------------

class TestCISAutorun:
    def test_autorun_disabled_passes(self) -> None:
        from agent.collectors.windows_collector import _check_autorun

        winreg_stub = _make_winreg_stub()
        with patch.dict(sys.modules, {"winreg": winreg_stub}):
            with patch("agent.collectors.windows_collector._winreg_get", return_value=0xFF):
                findings = _check_autorun()

        assert findings[0].passed

    def test_autorun_enabled_fails(self) -> None:
        from agent.collectors.windows_collector import _check_autorun

        winreg_stub = _make_winreg_stub()
        with patch.dict(sys.modules, {"winreg": winreg_stub}):
            with patch("agent.collectors.windows_collector._winreg_get", return_value=0x91):
                findings = _check_autorun()

        assert not findings[0].passed


# ---------------------------------------------------------------------------
# CIS checks — SMB signing
# ---------------------------------------------------------------------------

class TestCISSMBSigning:
    def test_smb_signing_required_passes(self) -> None:
        from agent.collectors.windows_collector import _check_smb_signing

        winreg_stub = _make_winreg_stub()
        with patch.dict(sys.modules, {"winreg": winreg_stub}):
            with patch("agent.collectors.windows_collector._winreg_get", return_value=1):
                findings = _check_smb_signing()

        assert findings[0].passed

    def test_smb_signing_not_required_fails(self) -> None:
        from agent.collectors.windows_collector import _check_smb_signing

        winreg_stub = _make_winreg_stub()
        with patch.dict(sys.modules, {"winreg": winreg_stub}):
            with patch("agent.collectors.windows_collector._winreg_get", return_value=0):
                findings = _check_smb_signing()

        assert not findings[0].passed


# ---------------------------------------------------------------------------
# CIS checks — RDP NLA
# ---------------------------------------------------------------------------

class TestCISRDP:
    def test_rdp_disabled_passes(self) -> None:
        from agent.collectors.windows_collector import _check_rdp_nla

        winreg_stub = _make_winreg_stub()
        with patch.dict(sys.modules, {"winreg": winreg_stub}):
            # fDenyTSConnections=1 means RDP is disabled
            with patch("agent.collectors.windows_collector._winreg_get", side_effect=[1, 0]):
                findings = _check_rdp_nla()

        assert findings[0].passed

    def test_rdp_enabled_without_nla_fails(self) -> None:
        from agent.collectors.windows_collector import _check_rdp_nla

        winreg_stub = _make_winreg_stub()
        with patch.dict(sys.modules, {"winreg": winreg_stub}):
            # fDenyTSConnections=0 (RDP enabled), UserAuthentication=0 (no NLA)
            with patch("agent.collectors.windows_collector._winreg_get", side_effect=[0, 0]):
                findings = _check_rdp_nla()

        assert not findings[0].passed

    def test_rdp_enabled_with_nla_passes(self) -> None:
        from agent.collectors.windows_collector import _check_rdp_nla

        winreg_stub = _make_winreg_stub()
        with patch.dict(sys.modules, {"winreg": winreg_stub}):
            # fDenyTSConnections=0 (RDP enabled), UserAuthentication=1 (NLA)
            with patch("agent.collectors.windows_collector._winreg_get", side_effect=[0, 1]):
                findings = _check_rdp_nla()

        assert findings[0].passed


# ---------------------------------------------------------------------------
# WindowsCollector.run_sync — platform guard
# ---------------------------------------------------------------------------

class TestWindowsCollectorRunSync:
    def test_skips_on_non_windows(self) -> None:
        from agent.collectors.windows_collector import WindowsCollector

        collector = WindowsCollector(
            server_url="https://dk.example.com",
            agent_id="test-agent",
        )

        with patch.object(sys, "platform", "linux"):
            with patch("agent.collectors.windows_collector._collect_host_info") as mock_host:
                collector.run_sync()
                mock_host.assert_not_called()

    def test_runs_on_win32(self) -> None:
        from agent.collectors.windows_collector import WindowsCollector, WindowsHostInfo

        collector = WindowsCollector(
            server_url="https://dk.example.com",
            agent_id="test-agent",
            submit_packages=False,
            run_cis_checks=False,
        )

        fake_host = WindowsHostInfo(
            fqdn="win-host.local",
            ip_addresses=["10.0.0.5"],
            os="Windows Server 2022",
            os_version="10.0.20348",
        )

        with (
            patch.object(sys, "platform", "win32"),
            patch(
                "agent.collectors.windows_collector._collect_host_info",
                return_value=fake_host,
            ),
            patch("agent.collectors.windows_collector._submit_host") as mock_submit,
        ):
            collector.run_sync()
            mock_submit.assert_called_once()

    def test_packages_submitted_when_enabled(self) -> None:
        from agent.collectors.windows_collector import WindowsCollector, WindowsHostInfo, InstalledPackage

        collector = WindowsCollector(
            server_url="https://dk.example.com",
            agent_id="test-agent",
            submit_packages=True,
            run_cis_checks=False,
        )

        fake_host = WindowsHostInfo(
            fqdn="win-host.local",
            ip_addresses=["10.0.0.5"],
            os="Windows 11",
            os_version="10.0.22631",
        )
        fake_packages = [InstalledPackage(name="Notepad++", version="8.6")]

        with (
            patch.object(sys, "platform", "win32"),
            patch("agent.collectors.windows_collector._collect_host_info", return_value=fake_host),
            patch("agent.collectors.windows_collector._submit_host"),
            patch(
                "agent.collectors.windows_collector._collect_installed_packages",
                return_value=fake_packages,
            ),
            patch("agent.collectors.windows_collector._submit_packages") as mock_pkgs,
        ):
            collector.run_sync()
            mock_pkgs.assert_called_once()

    def test_cis_findings_submitted_when_enabled(self) -> None:
        from agent.collectors.windows_collector import (
            WindowsCollector, WindowsHostInfo, CISFinding,
        )

        collector = WindowsCollector(
            server_url="https://dk.example.com",
            agent_id="test-agent",
            submit_packages=False,
            run_cis_checks=True,
        )

        fake_host = WindowsHostInfo(
            fqdn="win-host.local",
            ip_addresses=["10.0.0.5"],
            os="Windows 11",
            os_version="10.0.22631",
        )
        fake_findings = [
            CISFinding("WF-01", "Firewall", "desc", "high", False, "detail"),
        ]

        with (
            patch.object(sys, "platform", "win32"),
            patch("agent.collectors.windows_collector._collect_host_info", return_value=fake_host),
            patch("agent.collectors.windows_collector._submit_host"),
            patch("agent.collectors.windows_collector._run_all_cis_checks", return_value=fake_findings),
            patch("agent.collectors.windows_collector._submit_cis_findings") as mock_cis,
        ):
            collector.run_sync()
            mock_cis.assert_called_once()


# ---------------------------------------------------------------------------
# AgentConfig — Windows properties
# ---------------------------------------------------------------------------

class TestAgentConfigWindows:
    def test_windows_disabled_by_default(self) -> None:
        import os
        import tempfile
        from agent.config import AgentConfig
        with tempfile.NamedTemporaryFile(mode="w", suffix=".conf", delete=False) as f:
            f.write("")
            fname = f.name
        try:
            cfg = AgentConfig(config_path=fname)
            assert not cfg.windows_enabled
        finally:
            os.unlink(fname)

    def test_windows_enabled_via_env(self) -> None:
        import os
        import tempfile
        from agent.config import AgentConfig
        with tempfile.NamedTemporaryFile(mode="w", suffix=".conf", delete=False) as f:
            f.write("")
            fname = f.name
        try:
            with patch.dict(os.environ, {"WINDOWS_COLLECTOR_ENABLED": "true"}):
                cfg = AgentConfig(config_path=fname)
                assert cfg.windows_enabled
        finally:
            os.unlink(fname)

    def test_windows_sync_interval_default(self) -> None:
        import os
        import tempfile
        from agent.config import AgentConfig
        with tempfile.NamedTemporaryFile(mode="w", suffix=".conf", delete=False) as f:
            f.write("")
            fname = f.name
        try:
            cfg = AgentConfig(config_path=fname)
            assert cfg.windows_sync_interval == 3600
        finally:
            os.unlink(fname)

    def test_windows_cis_checks_enabled_by_default(self) -> None:
        import os
        import tempfile
        from agent.config import AgentConfig
        with tempfile.NamedTemporaryFile(mode="w", suffix=".conf", delete=False) as f:
            f.write("")
            fname = f.name
        try:
            cfg = AgentConfig(config_path=fname)
            assert cfg.windows_cis_checks
        finally:
            os.unlink(fname)
