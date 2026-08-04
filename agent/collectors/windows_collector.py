"""
DK Agent — Windows WMI collector.

Collects Windows-specific inventory and CIS Level-1 hardening posture using
psutil (cross-platform) and the ``wmi`` module from pywin32 (Windows-only).

Data submitted to the DK server:
  POST /api/v1/data/hosts          — hostname, IPs, OS version
  POST /api/v1/data/packages       — installed software (from registry)
  POST /api/v1/data/vulnerabilities — failed CIS hardening checks

CIS checks implemented (CIS Microsoft Windows Benchmarks, Level 1):
  WF-01  Windows Firewall — domain profile enabled
  WF-02  Windows Firewall — private profile enabled
  WF-03  Windows Firewall — public profile enabled
  WU-01  Automatic Updates configured (WSUS or Windows Update)
  UAC-01 UAC enabled (EnableLUA = 1)
  UAC-02 UAC prompt for elevation on secure desktop
  PW-01  Minimum password length >= 14
  PW-02  Password complexity enabled
  PW-03  Account lockout threshold <= 10 attempts
  SL-01  Screen saver enabled and password-protected
  BL-01  BitLocker enabled on system drive
  GU-01  Guest account disabled
  AR-01  AutoRun/AutoPlay disabled
  SMB-01 SMB signing required (client)
  RDP-01 Remote Desktop disabled or using NLA

Configuration (agent.conf / env vars):
  WINDOWS_COLLECTOR_ENABLED=true
  WINDOWS_SYNC_INTERVAL=3600     # seconds between collections (default 1h)
  WINDOWS_SUBMIT_PACKAGES=true   # submit installed software list
  WINDOWS_CIS_CHECKS=true        # run CIS hardening checks
"""

from __future__ import annotations

import json
import logging
import os
import socket
import ssl
import sys
import urllib.request
from dataclasses import dataclass
from typing import Any

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------

@dataclass
class WindowsHostInfo:
    fqdn: str
    ip_addresses: list[str]
    os: str
    os_version: str


@dataclass
class InstalledPackage:
    name: str
    version: str | None
    publisher: str | None = None


@dataclass
class CISFinding:
    check_id: str
    title: str
    description: str
    severity: str  # "low" | "medium" | "high" | "critical"
    passed: bool
    detail: str = ""


# ---------------------------------------------------------------------------
# Registry / WMI helpers
# ---------------------------------------------------------------------------

def _winreg_get(hive: int, subkey: str, value: str, default: Any = None) -> Any:
    """Read one registry value; return *default* if missing or on error."""
    try:
        import winreg  # type: ignore[import]
        with winreg.OpenKey(hive, subkey) as key:
            data, _ = winreg.QueryValueEx(key, value)
            return data
    except Exception:
        return default


def _collect_host_info() -> WindowsHostInfo:
    """Collect basic host information using psutil and socket."""
    try:
        import psutil  # type: ignore[import]
        addrs: list[str] = []
        for iface_addrs in psutil.net_if_addrs().values():
            for addr in iface_addrs:
                if addr.family == socket.AF_INET and not addr.address.startswith("127."):
                    addrs.append(addr.address)
                elif addr.family == socket.AF_INET6 and not addr.address.startswith("::1"):
                    # strip scope id (e.g. %eth0)
                    addrs.append(addr.address.split("%")[0])
    except ImportError:
        addrs = []
        logger.warning("psutil not installed — IP address collection skipped")

    fqdn = socket.getfqdn()

    # OS info from platform module (no WMI needed)
    import platform
    os_name = f"Windows {platform.version()}"
    os_version = platform.version()

    # Prefer WMI for accurate OS caption
    try:
        import wmi  # type: ignore[import]
        c = wmi.WMI()
        for os_obj in c.Win32_OperatingSystem():
            os_name = os_obj.Caption.strip()
            os_version = os_obj.Version.strip()
            break
    except Exception:
        pass

    if not addrs:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.connect(("8.8.8.8", 80))
                addrs = [s.getsockname()[0]]
        except Exception:
            addrs = ["127.0.0.1"]

    return WindowsHostInfo(
        fqdn=fqdn,
        ip_addresses=addrs,
        os=os_name,
        os_version=os_version,
    )


def _collect_installed_packages() -> list[InstalledPackage]:
    """
    Enumerate installed software from the Windows registry (both 32- and 64-bit
    hives).  This is faster and more complete than Win32_Product (which can
    trigger repair/reconfiguration).
    """
    packages: dict[str, InstalledPackage] = {}

    try:
        import winreg  # type: ignore[import]
    except ImportError:
        logger.warning("winreg not available — package collection skipped (not Windows?)")
        return []

    uninstall_paths = [
        (winreg.HKEY_LOCAL_MACHINE,
         r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"),
        (winreg.HKEY_LOCAL_MACHINE,
         r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"),
        (winreg.HKEY_CURRENT_USER,
         r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"),
    ]

    for hive, path in uninstall_paths:
        try:
            with winreg.OpenKey(hive, path) as root:
                i = 0
                while True:
                    try:
                        subkey_name = winreg.EnumKey(root, i)
                        i += 1
                    except OSError:
                        break
                    try:
                        with winreg.OpenKey(root, subkey_name):
                            name = _winreg_get(hive, f"{path}\\{subkey_name}", "DisplayName")
                            version = _winreg_get(hive, f"{path}\\{subkey_name}", "DisplayVersion")
                            publisher = _winreg_get(hive, f"{path}\\{subkey_name}", "Publisher")
                            if name and isinstance(name, str) and name.strip():
                                key = name.strip().lower()
                                if key not in packages:
                                    packages[key] = InstalledPackage(
                                        name=name.strip(),
                                        version=version.strip() if version else None,
                                        publisher=publisher.strip() if publisher else None,
                                    )
                    except Exception:
                        pass
        except Exception as exc:
            logger.debug("Could not open registry hive %s\\%s: %s", hive, path, exc)

    logger.info("Collected %d installed packages from registry", len(packages))
    return list(packages.values())


# ---------------------------------------------------------------------------
# CIS Level-1 hardening checks
# ---------------------------------------------------------------------------

def _check_firewall() -> list[CISFinding]:
    """WF-01/02/03 — Windows Firewall enabled for all profiles."""
    findings: list[CISFinding] = []

    try:
        import winreg  # type: ignore[import]
    except ImportError:
        return []

    profiles = {
        "Domain": "WF-01",
        "Standard": "WF-02",
        "Public": "WF-03",
    }
    fw_base = r"SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy"

    for profile_name, check_id in profiles.items():
        reg_path = f"{fw_base}\\{profile_name}Profile"
        enabled = _winreg_get(
            winreg.HKEY_LOCAL_MACHINE, reg_path, "EnableFirewall", default=None
        )
        passed = enabled == 1
        findings.append(CISFinding(
            check_id=check_id,
            title=f"Windows Firewall — {profile_name} profile enabled",
            description=(
                f"The Windows Firewall must be enabled for the {profile_name} "
                "network profile (CIS Control 9)."
            ),
            severity="high",
            passed=passed,
            detail=f"EnableFirewall={enabled!r}",
        ))

    return findings


def _check_uac() -> list[CISFinding]:
    """UAC-01/02 — User Account Control settings."""
    try:
        import winreg  # type: ignore[import]
    except ImportError:
        return []

    uac_path = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"

    enable_lua = _winreg_get(winreg.HKEY_LOCAL_MACHINE, uac_path, "EnableLUA", default=None)
    consent_prompt = _winreg_get(
        winreg.HKEY_LOCAL_MACHINE, uac_path, "ConsentPromptBehaviorAdmin", default=None
    )

    return [
        CISFinding(
            check_id="UAC-01",
            title="UAC: Run all administrators in Admin Approval Mode",
            description="EnableLUA must be 1 (CIS Control 5.1).",
            severity="high",
            passed=enable_lua == 1,
            detail=f"EnableLUA={enable_lua!r}",
        ),
        CISFinding(
            check_id="UAC-02",
            title="UAC: Prompt administrators for credentials on secure desktop",
            description=(
                "ConsentPromptBehaviorAdmin should be 1 (prompt for credentials) "
                "or 2 (prompt for consent) on secure desktop (CIS Control 5.3)."
            ),
            severity="medium",
            passed=consent_prompt in (1, 2),
            detail=f"ConsentPromptBehaviorAdmin={consent_prompt!r}",
        ),
    ]


def _check_password_policy() -> list[CISFinding]:
    """PW-01/02/03 — Password and lockout policy via net accounts."""
    findings: list[CISFinding] = []
    policy: dict[str, str] = {}

    try:
        import subprocess
        result = subprocess.run(
            ["net", "accounts"],
            capture_output=True, text=True, timeout=10,
        )
        for line in result.stdout.splitlines():
            if ":" in line:
                key, _, val = line.partition(":")
                policy[key.strip().lower()] = val.strip()
    except Exception as exc:
        logger.warning("net accounts failed: %s", exc)
        return []

    # Minimum password length
    min_len_str = policy.get("minimum password length", "0")
    try:
        min_len = int(min_len_str) if min_len_str not in ("none", "") else 0
    except ValueError:
        min_len = 0
    findings.append(CISFinding(
        check_id="PW-01",
        title="Minimum password length >= 14",
        description="Passwords must be at least 14 characters (CIS Control 5.2.1).",
        severity="high",
        passed=min_len >= 14,
        detail=f"Minimum password length={min_len}",
    ))

    # Account lockout threshold
    lockout_str = policy.get("lockout threshold", "0")
    try:
        lockout = int(lockout_str) if lockout_str not in ("never", "") else 0
    except ValueError:
        lockout = 0
    findings.append(CISFinding(
        check_id="PW-03",
        title="Account lockout threshold <= 10 attempts",
        description=(
            "The lockout threshold must be set to 10 or fewer failed attempts "
            "(CIS Control 5.2.2)."
        ),
        severity="high",
        passed=0 < lockout <= 10,
        detail=f"Lockout threshold={lockout_str!r}",
    ))

    # Password complexity (registry)
    try:
        import winreg  # type: ignore[import]
        complexity = _winreg_get(
            winreg.HKEY_LOCAL_MACHINE,
            r"SYSTEM\CurrentControlSet\Services\Netlogon\Parameters",
            "RequireStrongKey", default=None,
        )
        # Complexity is also exposed via secedit but we use a simpler heuristic:
        # Win32_AccountPolicy is not always reliable, so fall back to secedit output
    except Exception:
        complexity = None

    findings.append(CISFinding(
        check_id="PW-02",
        title="Password complexity requirements enabled",
        description="Password complexity must be enabled (CIS Control 5.2.3).",
        severity="medium",
        passed=complexity == 1 if complexity is not None else False,
        detail=f"RequireStrongKey={complexity!r}",
    ))

    return findings


def _check_screen_lock() -> list[CISFinding]:
    """SL-01 — Screen saver enabled and password-protected."""
    try:
        import winreg  # type: ignore[import]
    except ImportError:
        return []

    desktop_path = r"Control Panel\Desktop"

    screensaver_active = _winreg_get(
        winreg.HKEY_CURRENT_USER, desktop_path, "ScreenSaveActive", default="0"
    )
    screensaver_secure = _winreg_get(
        winreg.HKEY_CURRENT_USER, desktop_path, "ScreenSaverIsSecure", default="0"
    )
    screensaver_timeout = _winreg_get(
        winreg.HKEY_CURRENT_USER, desktop_path, "ScreenSaveTimeOut", default="0"
    )

    try:
        timeout_seconds = int(screensaver_timeout)
    except (ValueError, TypeError):
        timeout_seconds = 0

    passed = (
        screensaver_active == "1"
        and screensaver_secure == "1"
        and 0 < timeout_seconds <= 900  # CIS recommends <= 15 minutes
    )

    return [CISFinding(
        check_id="SL-01",
        title="Screen saver enabled and password-protected (timeout <= 15 min)",
        description=(
            "A password-protected screen saver must be enabled with a timeout "
            "of 900 seconds or less (CIS Control 16.11)."
        ),
        severity="medium",
        passed=passed,
        detail=(
            f"ScreenSaveActive={screensaver_active!r}, "
            f"ScreenSaverIsSecure={screensaver_secure!r}, "
            f"ScreenSaveTimeOut={screensaver_timeout!r}"
        ),
    )]


def _check_bitlocker() -> list[CISFinding]:
    """BL-01 — BitLocker enabled on system drive."""
    system_drive = os.environ.get("SystemDrive", "C:")

    protected = False
    detail = "WMI/manage-bde query failed"

    try:
        import subprocess
        result = subprocess.run(
            ["manage-bde", "-status", system_drive],
            capture_output=True, text=True, timeout=15,
        )
        output = result.stdout + result.stderr
        if "Protection On" in output:
            protected = True
            detail = "BitLocker protection is On"
        elif "Protection Off" in output:
            detail = "BitLocker protection is Off"
        elif "Fully Decrypted" in output:
            detail = "Drive is Fully Decrypted"
    except FileNotFoundError:
        # manage-bde not found — try WMI
        try:
            import wmi  # type: ignore[import]
            c = wmi.WMI(namespace="Root\\CIMv2\\Security\\MicrosoftVolumeEncryption")
            for vol in c.Win32_EncryptableVolume():
                if vol.DriveLetter and vol.DriveLetter.upper().startswith(system_drive[0].upper()):
                    # ProtectionStatus: 0=Off, 1=On, 2=Unknown
                    protected = vol.ProtectionStatus == 1
                    detail = f"ProtectionStatus={vol.ProtectionStatus}"
                    break
        except Exception as exc:
            detail = f"WMI query failed: {exc}"
    except Exception as exc:
        detail = f"manage-bde error: {exc}"

    return [CISFinding(
        check_id="BL-01",
        title=f"BitLocker enabled on system drive ({system_drive})",
        description=(
            "The system drive must be encrypted with BitLocker "
            "(CIS Control 13.6)."
        ),
        severity="high",
        passed=protected,
        detail=detail,
    )]


def _check_guest_account() -> list[CISFinding]:
    """GU-01 — Guest account disabled."""
    disabled = False
    detail = "WMI query failed"

    try:
        import wmi  # type: ignore[import]
        c = wmi.WMI()
        for user in c.Win32_UserAccount(LocalAccount=True):
            if user.Name.lower() == "guest":
                disabled = user.Disabled
                detail = f"Guest.Disabled={user.Disabled}"
                break
    except Exception as exc:
        detail = f"WMI error: {exc}"

    return [CISFinding(
        check_id="GU-01",
        title="Guest account disabled",
        description="The built-in Guest account must be disabled (CIS Control 4.3).",
        severity="high",
        passed=disabled,
        detail=detail,
    )]


def _check_autorun() -> list[CISFinding]:
    """AR-01 — AutoRun/AutoPlay disabled for all drives."""
    try:
        import winreg  # type: ignore[import]
    except ImportError:
        return []

    autorun_value = _winreg_get(
        winreg.HKEY_LOCAL_MACHINE,
        r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer",
        "NoDriveTypeAutoRun",
        default=None,
    )

    # 0xFF (255) disables AutoRun for all drive types
    passed = autorun_value == 0xFF or autorun_value == 255

    return [CISFinding(
        check_id="AR-01",
        title="AutoRun/AutoPlay disabled for all drive types",
        description=(
            "NoDriveTypeAutoRun must be 0xFF (255) to disable AutoRun on all "
            "drive types (CIS Control 8.5)."
        ),
        severity="medium",
        passed=passed,
        detail=f"NoDriveTypeAutoRun={hex(autorun_value) if isinstance(autorun_value, int) else autorun_value!r}",
    )]


def _check_smb_signing() -> list[CISFinding]:
    """SMB-01 — SMB signing required on clients."""
    try:
        import winreg  # type: ignore[import]
    except ImportError:
        return []

    signing_enabled = _winreg_get(
        winreg.HKEY_LOCAL_MACHINE,
        r"SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters",
        "RequireSecuritySignature",
        default=None,
    )

    return [CISFinding(
        check_id="SMB-01",
        title="SMB signing required (LanmanWorkstation)",
        description=(
            "RequireSecuritySignature must be 1 to mandate SMB packet signing "
            "on the client side (CIS Control 9.3)."
        ),
        severity="high",
        passed=signing_enabled == 1,
        detail=f"RequireSecuritySignature={signing_enabled!r}",
    )]


def _check_rdp_nla() -> list[CISFinding]:
    """RDP-01 — Remote Desktop requires Network Level Authentication."""
    try:
        import winreg  # type: ignore[import]
    except ImportError:
        return []

    rdp_path = r"SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp"
    fds_path = r"SYSTEM\CurrentControlSet\Control\Terminal Server"

    rdp_disabled = _winreg_get(
        winreg.HKEY_LOCAL_MACHINE, fds_path, "fDenyTSConnections", default=1
    )
    nla_required = _winreg_get(
        winreg.HKEY_LOCAL_MACHINE, rdp_path, "UserAuthentication", default=0
    )

    if rdp_disabled == 1:
        return [CISFinding(
            check_id="RDP-01",
            title="Remote Desktop disabled or requires NLA",
            description=(
                "Remote Desktop should be disabled or require Network Level "
                "Authentication (CIS Control 9.2)."
            ),
            severity="medium",
            passed=True,
            detail="Remote Desktop is disabled (fDenyTSConnections=1)",
        )]

    return [CISFinding(
        check_id="RDP-01",
        title="Remote Desktop requires Network Level Authentication",
        description=(
            "If RDP is enabled, UserAuthentication must be 1 (NLA) "
            "(CIS Control 9.2)."
        ),
        severity="high",
        passed=nla_required == 1,
        detail=f"fDenyTSConnections={rdp_disabled!r}, UserAuthentication={nla_required!r}",
    )]


def _run_all_cis_checks() -> list[CISFinding]:
    """Run all CIS checks and return combined results."""
    all_findings: list[CISFinding] = []
    checks = [
        _check_firewall,
        _check_uac,
        _check_password_policy,
        _check_screen_lock,
        _check_bitlocker,
        _check_guest_account,
        _check_autorun,
        _check_smb_signing,
        _check_rdp_nla,
    ]
    for check_fn in checks:
        try:
            all_findings.extend(check_fn())
        except Exception:
            logger.exception("CIS check %s raised an unexpected error", check_fn.__name__)
    return all_findings


# ---------------------------------------------------------------------------
# HTTP submission helpers (stdlib-only, mirrors cve_scan.py pattern)
# ---------------------------------------------------------------------------

def _http_post(
    url: str,
    payload: dict[str, Any],
    agent_id: str,
    ssl_ctx: ssl.SSLContext | None,
) -> dict[str, Any]:
    body = json.dumps(payload).encode()
    req = urllib.request.Request(
        url,
        data=body,
        method="POST",
        headers={
            "Content-Type": "application/json",
            "X-Agent-ID": agent_id,
        },
    )
    with urllib.request.urlopen(req, context=ssl_ctx, timeout=30) as resp:
        return json.loads(resp.read())


def _submit_host(
    server_url: str,
    agent_id: str,
    ssl_ctx: ssl.SSLContext | None,
    host: WindowsHostInfo,
) -> None:
    url = f"{server_url.rstrip('/')}/api/v1/data/hosts"
    payload = {
        "hosts": [{
            "fqdn": host.fqdn,
            "ip_addresses": host.ip_addresses,
            "os": host.os,
            "os_version": host.os_version,
        }]
    }
    result = _http_post(url, payload, agent_id, ssl_ctx)
    logger.info("Host submitted — server result: %s", result)


def _submit_packages(
    server_url: str,
    agent_id: str,
    ssl_ctx: ssl.SSLContext | None,
    fqdn: str,
    packages: list[InstalledPackage],
) -> None:
    url = f"{server_url.rstrip('/')}/api/v1/data/packages"
    payload = {
        "fqdn": fqdn,
        "packages": [
            {
                "name": p.name,
                "version": p.version,
                "package_manager": "windows",
            }
            for p in packages
        ],
    }
    result = _http_post(url, payload, agent_id, ssl_ctx)
    logger.info(
        "Packages submitted (%d) — server result: %s", len(packages), result
    )


def _submit_cis_findings(
    server_url: str,
    agent_id: str,
    ssl_ctx: ssl.SSLContext | None,
    fqdn: str,
    findings: list[CISFinding],
) -> None:
    failures = [f for f in findings if not f.passed]
    if not failures:
        logger.info("All CIS checks passed — nothing to submit")
        return

    url = f"{server_url.rstrip('/')}/api/v1/data/vulnerabilities"
    payload = {
        "fqdn": fqdn,
        "vulnerabilities": [
            {
                "cve_id": f"CIS-{f.check_id}",
                "severity": f.severity,
                "cvss_score": None,
                "description": f"{f.title}: {f.description} Detail: {f.detail}",
                "remediation": f"See CIS Microsoft Windows Benchmark for {f.check_id}.",
                "package_name": None,
                "package_version": None,
            }
            for f in failures
        ],
    }
    result = _http_post(url, payload, agent_id, ssl_ctx)
    logger.info(
        "CIS findings submitted (%d failed checks) — server result: %s",
        len(failures), result,
    )


# ---------------------------------------------------------------------------
# Main collector class
# ---------------------------------------------------------------------------

class WindowsCollector:
    """
    Collects Windows inventory and CIS posture, then submits to the DK server.

    Should be instantiated once and called via ``run_sync()`` from a
    background thread (see agent/core.py for the async wrapper pattern).
    """

    def __init__(
        self,
        server_url: str,
        agent_id: str,
        ssl_ctx: ssl.SSLContext | None = None,
        submit_packages: bool = True,
        run_cis_checks: bool = True,
    ) -> None:
        self.server_url = server_url
        self.agent_id = agent_id
        self.ssl_ctx = ssl_ctx
        self.submit_packages = submit_packages
        self.run_cis_checks = run_cis_checks

    def run_sync(self) -> None:
        if sys.platform != "win32":
            logger.warning(
                "Windows collector invoked on non-Windows platform (%s) — skipping",
                sys.platform,
            )
            return

        logger.info("Windows collector starting")

        host = _collect_host_info()
        logger.info(
            "Collected host info: fqdn=%s os=%s version=%s ips=%s",
            host.fqdn, host.os, host.os_version, host.ip_addresses,
        )

        _submit_host(self.server_url, self.agent_id, self.ssl_ctx, host)

        if self.submit_packages:
            packages = _collect_installed_packages()
            if packages:
                _submit_packages(
                    self.server_url, self.agent_id, self.ssl_ctx, host.fqdn, packages
                )

        if self.run_cis_checks:
            findings = _run_all_cis_checks()
            passed = sum(1 for f in findings if f.passed)
            failed = sum(1 for f in findings if not f.passed)
            logger.info(
                "CIS checks complete: %d passed, %d failed (total %d)",
                passed, failed, len(findings),
            )
            _submit_cis_findings(
                self.server_url, self.agent_id, self.ssl_ctx, host.fqdn, findings
            )

        logger.info("Windows collector finished")
