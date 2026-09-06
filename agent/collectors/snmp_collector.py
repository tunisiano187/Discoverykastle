"""
DK Agent — SNMP collector.

Polls network devices via SNMP (v1/v2c/v3) to collect system information and
interface data, then submits results to the DK server via:

  POST /api/v1/data/device-configs  — device configuration / metadata snapshots

Typical SNMP OIDs queried:
  • sysDescr       (.1.3.6.1.2.1.1.1.0)  — free-form system description
  • sysObjectID    (.1.3.6.1.2.1.1.2.0)  — enterprise OID → vendor detection
  • sysUpTime      (.1.3.6.1.2.1.1.3.0)  — uptime in hundredths of a second
  • sysContact     (.1.3.6.1.2.1.1.4.0)
  • sysName        (.1.3.6.1.2.1.1.5.0)  — FQDN / hostname
  • sysLocation    (.1.3.6.1.2.1.1.6.0)
  • ifDescr table  (.1.3.6.1.2.1.2.2.1.2) — interface names
  • ifOperStatus   (.1.3.6.1.2.1.2.2.1.8) — interface oper state

Device targets are fetched from GET /api/v1/inventory/hosts (all known hosts)
and GET /api/v1/inventory/networks (for subnet-level context).

Configuration (agent.conf / env vars):
  SNMP_ENABLED=false
  SNMP_COMMUNITY=public            # v1/v2c community string
  SNMP_VERSION=2c                  # 1 | 2c | 3
  SNMP_TIMEOUT=5                   # per-request timeout in seconds
  SNMP_RETRIES=2                   # number of retries per request
  SNMP_POLL_INTERVAL=900           # seconds between full poll cycles (15 min)
  SNMP_PORT=161
  # SNMPv3 only:
  SNMPV3_USERNAME=
  SNMPV3_AUTH_PROTOCOL=SHA         # SHA | MD5
  SNMPV3_AUTH_PASSPHRASE=
  SNMPV3_PRIV_PROTOCOL=AES        # AES | DES
  SNMPV3_PRIV_PASSPHRASE=

Vendor detection (via sysObjectID prefix):
  1.3.6.1.4.1.9    → Cisco
  1.3.6.1.4.1.2636 → Juniper
  1.3.6.1.4.1.2011 → Huawei
  1.3.6.1.4.1.11   → HP/Aruba
  1.3.6.1.4.1.6527 → Nokia/Alcatel-Lucent
  1.3.6.1.4.1.3375 → F5
  1.3.6.1.4.1.8072 → Net-SNMP (generic Linux/BSD)
"""

from __future__ import annotations

import json
import logging
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from typing import Any

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# OID constants
# ---------------------------------------------------------------------------

# System group (RFC 1213 / MIB-II)
OID_SYS_DESCR      = ".1.3.6.1.2.1.1.1.0"
OID_SYS_OBJECT_ID  = ".1.3.6.1.2.1.1.2.0"
OID_SYS_UPTIME     = ".1.3.6.1.2.1.1.3.0"
OID_SYS_CONTACT    = ".1.3.6.1.2.1.1.4.0"
OID_SYS_NAME       = ".1.3.6.1.2.1.1.5.0"
OID_SYS_LOCATION   = ".1.3.6.1.2.1.1.6.0"
OID_SYS_SERVICES   = ".1.3.6.1.2.1.1.7.0"

# Interface table
OID_IF_DESCR        = ".1.3.6.1.2.1.2.2.1.2"  # table column (walk)
OID_IF_OPER_STATUS  = ".1.3.6.1.2.1.2.2.1.8"  # table column (walk)
OID_IF_PHY_ADDRESS  = ".1.3.6.1.2.1.2.2.1.6"  # MAC address

# Well-known sysObjectID prefixes → vendor
_VENDOR_OID_MAP: dict[str, str] = {
    ".1.3.6.1.4.1.9.":    "Cisco",
    ".1.3.6.1.4.1.2636.": "Juniper",
    ".1.3.6.1.4.1.2011.": "Huawei",
    ".1.3.6.1.4.1.11.":   "HP",
    ".1.3.6.1.4.1.6527.": "Nokia",
    ".1.3.6.1.4.1.3375.": "F5",
    ".1.3.6.1.4.1.8072.": "Net-SNMP",
    ".1.3.6.1.4.1.1916.": "Extreme",
    ".1.3.6.1.4.1.4874.": "Juniper",  # alternate Juniper OID space
    ".1.3.6.1.4.1.25506.": "H3C",
}


def _vendor_from_sysoid(oid: str | None) -> str | None:
    """Map a sysObjectID to a vendor name, or None if unrecognised."""
    if not oid:
        return None
    for prefix, vendor in _VENDOR_OID_MAP.items():
        if oid.startswith(prefix):
            return vendor
    return None


# ---------------------------------------------------------------------------
# Parsed device snapshot
# ---------------------------------------------------------------------------

@dataclass
class SNMPDeviceInfo:
    ip: str
    hostname: str | None = None
    vendor: str | None = None
    model: str | None = None
    sys_descr: str | None = None
    sys_object_id: str | None = None
    sys_contact: str | None = None
    sys_location: str | None = None
    uptime_secs: int | None = None
    interfaces: list[dict[str, Any]] = field(default_factory=list)


# ---------------------------------------------------------------------------
# HTTP helpers (stdlib urllib — no httpx in agent collector)
# ---------------------------------------------------------------------------

def _http_get_json(url: str, headers: dict[str, str]) -> Any:
    req = urllib.request.Request(url, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            return json.loads(resp.read())
    except urllib.error.URLError as exc:
        logger.error("GET %s failed: %s", url, exc)
        return None


def _http_post_json(
    url: str,
    payload: Any,
    headers: dict[str, str],
    ssl_ctx: Any = None,
) -> bool:
    data = json.dumps(payload).encode()
    req = urllib.request.Request(
        url,
        data=data,
        headers={**headers, "Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=30, context=ssl_ctx) as resp:
            return resp.status < 300
    except urllib.error.HTTPError as exc:
        body = exc.read().decode(errors="replace")[:300]
        logger.error("POST %s → HTTP %d: %s", url, exc.code, body)
        return False
    except urllib.error.URLError as exc:
        logger.error("POST %s failed: %s", url, exc)
        return False


# ---------------------------------------------------------------------------
# SNMP session wrapper
# ---------------------------------------------------------------------------

class _SNMPSession:
    """
    Thin wrapper around pysnmp that hides v1/v2c/v3 differences.

    pysnmp is imported lazily so the rest of the agent doesn't fail on import
    if the library isn't installed.
    """

    def __init__(
        self,
        host: str,
        port: int = 161,
        community: str = "public",
        version: str = "2c",
        timeout: int = 5,
        retries: int = 2,
        # SNMPv3 kwargs (ignored for v1/v2c)
        v3_username: str = "",
        v3_auth_protocol: str = "SHA",
        v3_auth_passphrase: str = "",
        v3_priv_protocol: str = "AES",
        v3_priv_passphrase: str = "",
    ) -> None:
        self.host = host
        self.port = port
        self.community = community
        self.version = version
        self.timeout = timeout
        self.retries = retries
        self.v3_username = v3_username
        self.v3_auth_protocol = v3_auth_protocol
        self.v3_auth_passphrase = v3_auth_passphrase
        self.v3_priv_protocol = v3_priv_protocol
        self.v3_priv_passphrase = v3_priv_passphrase

        # Lazy import
        try:
            import pysnmp  # noqa: F401
            self._available = True
        except ImportError:
            self._available = False
            logger.warning(
                "pysnmp not installed — SNMP collector disabled. "
                "Install it with: pip install pysnmp"
            )

    @property
    def available(self) -> bool:
        return self._available

    def _make_engine(self) -> Any:
        from pysnmp.hlapi import SnmpEngine  # type: ignore[import]
        return SnmpEngine()

    def _make_auth(self) -> Any:
        """Return a CommunityData or UsmUserData object."""
        from pysnmp.hlapi import CommunityData, UsmUserData  # type: ignore[import]
        from pysnmp.hlapi import (  # type: ignore[import]
            usmHMACSHAAuthProtocol, usmHMACMD5AuthProtocol,
            usmAesCfb128Protocol, usmDESPrivProtocol, usmNoPrivProtocol,
            usmNoAuthProtocol,
        )

        if self.version in ("1", "2c"):
            mp_model = 0 if self.version == "1" else 1
            return CommunityData(self.community, mpModel=mp_model)

        # SNMPv3
        auth_proto_map = {
            "SHA": usmHMACSHAAuthProtocol,
            "MD5": usmHMACMD5AuthProtocol,
        }
        priv_proto_map = {
            "AES": usmAesCfb128Protocol,
            "DES": usmDESPrivProtocol,
        }
        auth_proto = auth_proto_map.get(self.v3_auth_protocol.upper(), usmHMACSHAAuthProtocol)
        priv_proto = priv_proto_map.get(self.v3_priv_protocol.upper(), usmAesCfb128Protocol)

        if self.v3_auth_passphrase and self.v3_priv_passphrase:
            return UsmUserData(
                self.v3_username,
                authKey=self.v3_auth_passphrase,
                privKey=self.v3_priv_passphrase,
                authProtocol=auth_proto,
                privProtocol=priv_proto,
            )
        elif self.v3_auth_passphrase:
            return UsmUserData(
                self.v3_username,
                authKey=self.v3_auth_passphrase,
                authProtocol=auth_proto,
                privProtocol=usmNoPrivProtocol,
            )
        else:
            return UsmUserData(self.v3_username, authProtocol=usmNoAuthProtocol)

    def _make_transport(self) -> Any:
        from pysnmp.hlapi import UdpTransportTarget  # type: ignore[import]
        return UdpTransportTarget(
            (self.host, self.port),
            timeout=self.timeout,
            retries=self.retries,
        )

    def get(self, *oids: str) -> dict[str, str]:
        """
        Perform a synchronous SNMP GET for the given OIDs.
        Returns a dict mapping each OID to its string value (or empty string on error).
        """
        if not self._available:
            return {}
        from pysnmp.hlapi import (  # type: ignore[import]
            getCmd, ContextData, ObjectType, ObjectIdentity,
        )

        engine = self._make_engine()
        auth = self._make_auth()
        transport = self._make_transport()
        var_binds = [ObjectType(ObjectIdentity(oid)) for oid in oids]

        results: dict[str, str] = {}
        error_indication, error_status, error_index, var_binds_out = next(
            getCmd(engine, auth, transport, ContextData(), *var_binds)
        )

        if error_indication:
            logger.debug("SNMP GET %s %s: %s", self.host, oids, error_indication)
            return results
        if error_status:
            logger.debug(
                "SNMP GET %s: error_status=%s at %s",
                self.host, error_status.prettyPrint(),
                error_index and var_binds_out[int(error_index) - 1][0] or "?",
            )
            return results

        for vb in var_binds_out:
            oid_str = str(vb[0])
            val = vb[1]
            # Normalize: OctetString → str, Integer → int str, etc.
            try:
                if hasattr(val, "prettyPrint"):
                    results[oid_str] = val.prettyPrint()
                else:
                    results[oid_str] = str(val)
            except Exception:
                results[oid_str] = ""
        return results

    def walk(self, oid: str) -> dict[str, str]:
        """
        Perform a synchronous SNMP walk (nextCmd) starting at *oid*.
        Returns a dict mapping full OID strings to their string values.
        """
        if not self._available:
            return {}
        from pysnmp.hlapi import (  # type: ignore[import]
            nextCmd, ContextData, ObjectType, ObjectIdentity,
        )

        engine = self._make_engine()
        auth = self._make_auth()
        transport = self._make_transport()
        target_oid = ObjectIdentity(oid)

        results: dict[str, str] = {}
        for error_indication, error_status, _error_index, var_binds_out in nextCmd(
            engine, auth, transport, ContextData(),
            ObjectType(target_oid),
            lexicographicMode=False,
        ):
            if error_indication:
                logger.debug("SNMP WALK %s %s: %s", self.host, oid, error_indication)
                break
            if error_status:
                logger.debug("SNMP WALK %s error: %s", self.host, error_status.prettyPrint())
                break
            for vb in var_binds_out:
                oid_str = str(vb[0])
                val = vb[1]
                try:
                    results[oid_str] = val.prettyPrint() if hasattr(val, "prettyPrint") else str(val)
                except Exception:
                    results[oid_str] = ""
        return results


# ---------------------------------------------------------------------------
# High-level SNMP poller
# ---------------------------------------------------------------------------

def _poll_device(session: _SNMPSession, ip: str) -> SNMPDeviceInfo | None:
    """
    Poll a single device via SNMP and return an SNMPDeviceInfo, or None on
    complete failure (host unreachable / no SNMP response).
    """
    # --- System group GET ---
    sys_oids = [
        OID_SYS_DESCR,
        OID_SYS_OBJECT_ID,
        OID_SYS_UPTIME,
        OID_SYS_CONTACT,
        OID_SYS_NAME,
        OID_SYS_LOCATION,
    ]
    sys_data = session.get(*sys_oids)
    if not sys_data:
        logger.debug("No SNMP response from %s — skipping", ip)
        return None

    # Helper: extract value by suffix match (pysnmp returns full numeric OIDs)
    def _get_by_suffix(suffix: str) -> str | None:
        for k, v in sys_data.items():
            if k.endswith(suffix) or k == suffix:
                return v or None
        return None

    sys_descr = _get_by_suffix("1.1.0") or _get_by_suffix(OID_SYS_DESCR)
    sys_object_id = _get_by_suffix("1.2.0") or _get_by_suffix(OID_SYS_OBJECT_ID)
    sys_name = _get_by_suffix("1.5.0") or _get_by_suffix(OID_SYS_NAME)
    sys_contact = _get_by_suffix("1.4.0") or _get_by_suffix(OID_SYS_CONTACT)
    sys_location = _get_by_suffix("1.6.0") or _get_by_suffix(OID_SYS_LOCATION)

    raw_uptime = _get_by_suffix("1.3.0") or _get_by_suffix(OID_SYS_UPTIME)
    uptime_secs: int | None = None
    if raw_uptime:
        try:
            # sysUpTime is in hundredths of a second
            uptime_secs = int(raw_uptime) // 100
        except (ValueError, TypeError):
            pass

    vendor = _vendor_from_sysoid(sys_object_id)

    # --- Parse vendor/model from sysDescr (best-effort) ---
    model: str | None = None
    if sys_descr:
        model = _extract_model_from_descr(sys_descr, vendor)

    info = SNMPDeviceInfo(
        ip=ip,
        hostname=sys_name,
        vendor=vendor,
        model=model,
        sys_descr=sys_descr,
        sys_object_id=sys_object_id,
        sys_contact=sys_contact,
        sys_location=sys_location,
        uptime_secs=uptime_secs,
    )

    # --- Interface table walk ---
    if_descr = session.walk(OID_IF_DESCR)
    if_oper  = session.walk(OID_IF_OPER_STATUS)
    if_mac   = session.walk(OID_IF_PHY_ADDRESS)

    # Build interface index → name mapping from OID suffix
    interfaces: list[dict[str, Any]] = []
    for oid_str, if_name in if_descr.items():
        # OID ends with .<ifIndex>
        idx = oid_str.rsplit(".", 1)[-1]
        oper_key = next(
            (k for k in if_oper if k.rsplit(".", 1)[-1] == idx), None
        )
        mac_key = next(
            (k for k in if_mac if k.rsplit(".", 1)[-1] == idx), None
        )
        oper_status_raw = if_oper.get(oper_key, "") if oper_key else ""
        # ifOperStatus: 1=up, 2=down, 3=testing, ...
        oper_map = {"1": "up", "2": "down", "3": "testing", "4": "unknown",
                    "5": "dormant", "6": "notPresent", "7": "lowerLayerDown"}
        oper_status = oper_map.get(oper_status_raw, oper_status_raw or "unknown")

        interfaces.append({
            "index": idx,
            "name": if_name,
            "oper_status": oper_status,
            "mac": if_mac.get(mac_key, "") if mac_key else "",
        })

    info.interfaces = interfaces
    return info


def _extract_model_from_descr(descr: str, vendor: str | None) -> str | None:
    """
    Best-effort extraction of a model string from sysDescr.

    Examples:
      Cisco IOS Software, C3750E, Version 15.2... → "C3750E"
      Juniper Networks, Inc. mx480 internet router → "MX480"
      Linux version 5.4.0 #1 SMP ... → None (generic, skip)
    """
    import re

    descr_lower = descr.lower()

    if vendor == "Cisco":
        # Look for: "Cisco IOS ... <platform>, ..." or "Cisco <platform>"
        m = re.search(r"\b([A-Z]{1,3}\d{3,6}[A-Z0-9\-]*)\b", descr)
        if m:
            return m.group(1)

    if vendor == "Juniper":
        # "juniper networks, inc. mx480" or "ex4300"
        m = re.search(r"\b([a-z]{2}\d{3,5}[a-z0-9\-]*)\b", descr_lower)
        if m:
            return m.group(1).upper()

    if vendor == "Huawei":
        # "Huawei Versatile Routing Platform Software VRP ... S5700-28"
        m = re.search(r"\b([A-Z]\d{4}[A-Z0-9\-]+)\b", descr)
        if m:
            return m.group(1)

    if vendor == "HP":
        m = re.search(r"\bHP\s+([A-Z0-9\-]+)\b", descr, re.IGNORECASE)
        if m:
            return m.group(1)

    # Generic fallback: skip — model too vague
    return None


# ---------------------------------------------------------------------------
# Main collector class
# ---------------------------------------------------------------------------

class SNMPCollector:
    """
    Periodically polls known network hosts via SNMP and submits device
    configuration / metadata snapshots to the DK server.

    Lifecycle: instantiated by agent/core.py, run via asyncio.to_thread().
    """

    def __init__(
        self,
        server_url: str,
        agent_id: str,
        ssl_ctx: Any = None,
        community: str = "public",
        version: str = "2c",
        snmp_port: int = 161,
        timeout: int = 5,
        retries: int = 2,
        # SNMPv3
        v3_username: str = "",
        v3_auth_protocol: str = "SHA",
        v3_auth_passphrase: str = "",
        v3_priv_protocol: str = "AES",
        v3_priv_passphrase: str = "",
    ) -> None:
        self.server_url = server_url.rstrip("/")
        self.agent_id = agent_id
        self.ssl_ctx = ssl_ctx
        self.community = community
        self.version = version
        self.snmp_port = snmp_port
        self.timeout = timeout
        self.retries = retries
        self.v3_username = v3_username
        self.v3_auth_protocol = v3_auth_protocol
        self.v3_auth_passphrase = v3_auth_passphrase
        self.v3_priv_protocol = v3_priv_protocol
        self.v3_priv_passphrase = v3_priv_passphrase
        self._auth_headers: dict[str, str] = {"X-Agent-ID": agent_id}

    # ------------------------------------------------------------------
    # Target discovery: fetch known hosts from the server inventory
    # ------------------------------------------------------------------

    def _fetch_target_ips(self) -> list[str]:
        """
        Return a de-duplicated list of IP addresses to poll via SNMP.
        Sources:
          1. GET /api/v1/inventory/hosts  — all known hosts (primary IPs)
        """
        url = f"{self.server_url}/api/v1/inventory/hosts"
        data = _http_get_json(url, self._auth_headers)
        if not data:
            logger.warning("Could not fetch host inventory from server")
            return []

        ips: list[str] = []
        hosts = data if isinstance(data, list) else data.get("hosts", [])
        for host in hosts:
            # Prefer the first IP address
            addrs = host.get("ip_addresses") or []
            if isinstance(addrs, list) and addrs:
                ips.append(addrs[0])
            elif isinstance(addrs, str) and addrs:
                ips.append(addrs)

        # Deduplicate while preserving order
        seen: set[str] = set()
        unique: list[str] = []
        for ip in ips:
            if ip not in seen:
                seen.add(ip)
                unique.append(ip)

        logger.info("SNMP poll targets: %d IPs from host inventory", len(unique))
        return unique

    # ------------------------------------------------------------------
    # Submit device snapshot to server
    # ------------------------------------------------------------------

    def _submit_device(self, info: SNMPDeviceInfo) -> bool:
        """
        Submit a single SNMPDeviceInfo as a device-config record.
        Uses POST /api/v1/data/device-configs.
        """
        now = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())

        structured_data: dict[str, Any] = {
            "snmp_collected_at": now,
            "sys_object_id": info.sys_object_id,
            "sys_contact": info.sys_contact,
            "sys_location": info.sys_location,
            "interfaces": info.interfaces,
        }
        if info.uptime_secs is not None:
            structured_data["uptime_secs"] = info.uptime_secs

        payload = {
            "device_configs": [
                {
                    "ip": info.ip,
                    "hostname": info.hostname,
                    "vendor": info.vendor,
                    "model": info.model,
                    "config_snapshot": info.sys_descr or "",
                    "structured_data": structured_data,
                }
            ]
        }

        ok = _http_post_json(
            f"{self.server_url}/api/v1/data/device-configs",
            payload,
            self._auth_headers,
            self.ssl_ctx,
        )
        if ok:
            logger.debug(
                "Submitted SNMP snapshot for %s (%s %s)",
                info.ip, info.vendor or "unknown vendor", info.model or "",
            )
        return ok

    # ------------------------------------------------------------------
    # Main poll cycle
    # ------------------------------------------------------------------

    def run_poll_cycle(self) -> None:
        """
        Run one full SNMP poll cycle: fetch targets → poll each via SNMP →
        submit results to the server.
        Intended to be called from asyncio.to_thread() by agent/core.py.
        """
        # Quick sanity-check: can we import pysnmp?
        try:
            import pysnmp  # noqa: F401
        except ImportError:
            logger.warning(
                "pysnmp not installed — SNMP collector disabled. "
                "Install with: pip install pysnmp"
            )
            return

        targets = self._fetch_target_ips()
        if not targets:
            logger.info("No SNMP targets — skipping poll cycle")
            return

        submitted = 0
        unreachable = 0
        errors = 0

        for ip in targets:
            session = _SNMPSession(
                host=ip,
                port=self.snmp_port,
                community=self.community,
                version=self.version,
                timeout=self.timeout,
                retries=self.retries,
                v3_username=self.v3_username,
                v3_auth_protocol=self.v3_auth_protocol,
                v3_auth_passphrase=self.v3_auth_passphrase,
                v3_priv_protocol=self.v3_priv_protocol,
                v3_priv_passphrase=self.v3_priv_passphrase,
            )
            if not session.available:
                # pysnmp import failed — already logged, abort whole cycle
                return

            try:
                info = _poll_device(session, ip)
            except Exception:
                logger.exception("Unexpected error polling %s via SNMP", ip)
                errors += 1
                continue

            if info is None:
                unreachable += 1
                continue

            ok = self._submit_device(info)
            if ok:
                submitted += 1
            else:
                errors += 1

        logger.info(
            "SNMP poll cycle complete — %d targets, %d submitted, "
            "%d unreachable, %d errors",
            len(targets), submitted, unreachable, errors,
        )
