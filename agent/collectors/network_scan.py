"""
DK Agent — Network scanner collector.

Runs nmap against authorized network CIDRs and submits results to the DK
server via:
  POST /api/v1/data/hosts        — discovered hosts
  POST /api/v1/data/services     — open ports + banners
  POST /api/v1/data/scan-results — raw scan metadata

Authorization policy (enforced both here and server-side):
  • Private RFC-1918 / RFC-6598 / loopback CIDRs → scan freely.
  • Public CIDRs → the server must have scan_authorized=True on the network
    record before the agent will proceed.  The agent fetches the list of
    authorized networks from GET /api/v1/inventory/networks?authorized=true
    before each scan cycle.

nmap invocation:
  • Uses python-nmap (wrapper around the nmap binary).
  • Falls back gracefully if nmap is not installed: logs a warning and skips.
  • Default scan: -sV -O --open -T4  (service version + OS detect, open ports)
  • Privileged (root/SYSTEM): SYN scan (-sS), otherwise TCP connect (-sT).
  • All scans are time-limited (configurable, default 10 min per CIDR).

Configuration (agent.conf / env vars):
  NMAP_ENABLED=true
  NMAP_SCAN_INTERVAL=3600        # seconds between full scan cycles
  NMAP_EXTRA_ARGS=               # extra nmap flags (e.g. --script vuln)
  NMAP_TIMEOUT=600               # max seconds per CIDR scan
  NMAP_SCAN_PRIVATE=true         # scan RFC-1918 CIDRs automatically
  NMAP_SCAN_PUBLIC=false         # scan public CIDRs (requires auth from server)
"""

from __future__ import annotations

import json
import logging
import os
import platform
import shutil
import socket
import subprocess
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from typing import Any

logger = logging.getLogger(__name__)

# Private address ranges — mirrors server/services/ip_utils.py (no dep on server)
_PRIVATE_PREFIXES = (
    "10.", "172.16.", "172.17.", "172.18.", "172.19.", "172.20.", "172.21.",
    "172.22.", "172.23.", "172.24.", "172.25.", "172.26.", "172.27.", "172.28.",
    "172.29.", "172.30.", "172.31.", "192.168.", "127.", "169.254.", "100.64.",
    "fc", "fd", "fe80", "::1",
)


def _is_private_cidr(cidr: str) -> bool:
    """
    Quick heuristic: true when the network address is in a private range.
    The server enforces the full RFC classification — this is only used for
    the agent-side pre-check to avoid unnecessary API calls.
    """
    addr = cidr.split("/")[0].lower()
    return any(addr.startswith(p) for p in _PRIVATE_PREFIXES)


def _is_root() -> bool:
    """Return True when running with root / SYSTEM privileges."""
    if platform.system() == "Windows":
        try:
            import ctypes
            return bool(ctypes.windll.shell32.IsUserAnAdmin())
        except Exception:
            return False
    return os.geteuid() == 0


# ---------------------------------------------------------------------------
# Parsed scan results
# ---------------------------------------------------------------------------

@dataclass
class DiscoveredHost:
    ip: str
    fqdn: str | None = None
    os: str | None = None
    os_version: str | None = None
    services: list["DiscoveredService"] = field(default_factory=list)


@dataclass
class DiscoveredService:
    port: int
    protocol: str
    service_name: str | None = None
    version: str | None = None
    banner: str | None = None


# ---------------------------------------------------------------------------
# nmap XML parser (stdlib only)
# ---------------------------------------------------------------------------

def _parse_nmap_xml(xml_output: str) -> list[DiscoveredHost]:
    """
    Parse nmap XML output (from -oX -) into DiscoveredHost objects.
    Uses only stdlib xml.etree.ElementTree.
    """
    import xml.etree.ElementTree as ET

    hosts: list[DiscoveredHost] = []
    try:
        root = ET.fromstring(xml_output)
    except ET.ParseError as exc:
        logger.warning("nmap XML parse error: %s", exc)
        return hosts

    for host_el in root.findall("host"):
        # Status — only process hosts that are up
        status_el = host_el.find("status")
        if status_el is None or status_el.get("state") != "up":
            continue

        # Primary IP address
        ip: str | None = None
        for addr_el in host_el.findall("address"):
            if addr_el.get("addrtype") == "ipv4":
                ip = addr_el.get("addr")
                break
        if not ip:
            for addr_el in host_el.findall("address"):
                if addr_el.get("addrtype") == "ipv6":
                    ip = addr_el.get("addr")
                    break
        if not ip:
            continue

        # Hostname (PTR)
        fqdn: str | None = None
        hostnames_el = host_el.find("hostnames")
        if hostnames_el is not None:
            for hn in hostnames_el.findall("hostname"):
                if hn.get("type") in ("PTR", "user"):
                    fqdn = hn.get("name")
                    break

        # OS detection
        os_name: str | None = None
        os_version: str | None = None
        os_el = host_el.find("os")
        if os_el is not None:
            best = None
            best_acc = -1
            for osmatch in os_el.findall("osmatch"):
                acc = int(osmatch.get("accuracy", "0"))
                if acc > best_acc:
                    best_acc = acc
                    best = osmatch
            if best is not None:
                raw = best.get("name", "")
                # Split "Ubuntu 22.04" → os="Ubuntu", version="22.04"
                parts = raw.split(" ", 1)
                os_name = parts[0] if parts else raw
                os_version = parts[1] if len(parts) > 1 else None

        dhost = DiscoveredHost(ip=ip, fqdn=fqdn, os=os_name, os_version=os_version)

        # Open ports / services
        ports_el = host_el.find("ports")
        if ports_el is not None:
            for port_el in ports_el.findall("port"):
                state_el = port_el.find("state")
                if state_el is None or state_el.get("state") != "open":
                    continue
                portid = int(port_el.get("portid", "0"))
                proto = port_el.get("protocol", "tcp")

                svc_name: str | None = None
                version: str | None = None
                banner: str | None = None

                service_el = port_el.find("service")
                if service_el is not None:
                    svc_name = service_el.get("name")
                    product = service_el.get("product", "")
                    ver = service_el.get("version", "")
                    if product or ver:
                        version = f"{product} {ver}".strip()

                # Script output (banner grab)
                for script_el in port_el.findall("script"):
                    if script_el.get("id") in ("banner", "http-server-header"):
                        banner = script_el.get("output", "")[:512]
                        break

                dhost.services.append(
                    DiscoveredService(
                        port=portid,
                        protocol=proto,
                        service_name=svc_name,
                        version=version,
                        banner=banner,
                    )
                )

        hosts.append(dhost)

    return hosts


# ---------------------------------------------------------------------------
# nmap runner
# ---------------------------------------------------------------------------

def _run_nmap(cidr: str, extra_args: str = "", timeout: int = 600) -> str | None:
    """
    Run nmap against *cidr* and return the raw XML output, or None on failure.

    Chooses between SYN scan (privileged) and TCP-connect scan (unprivileged).
    Always outputs XML to stdout (-oX -).
    """
    nmap_bin = shutil.which("nmap")
    if nmap_bin is None:
        logger.warning("nmap binary not found in PATH — skipping network scan")
        return None

    scan_type = "-sS" if _is_root() else "-sT"
    cmd = [
        nmap_bin,
        scan_type,          # SYN or TCP-connect
        "-sV",              # service version detection
        "-O",               # OS detection (requires root; nmap ignores if unprivileged)
        "--open",           # only report open ports
        "-T4",              # aggressive timing
        "-oX", "-",         # XML output to stdout
    ]

    if extra_args:
        cmd.extend(extra_args.split())

    cmd.append(cidr)

    logger.info("Running nmap: %s", " ".join(cmd))

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        if result.returncode not in (0, 1):  # nmap returns 1 on partial failure
            logger.error(
                "nmap exited with code %d for %s:\n%s",
                result.returncode, cidr, result.stderr[:500],
            )
            return None
        return result.stdout
    except subprocess.TimeoutExpired:
        logger.warning("nmap scan of %s timed out after %ds", cidr, timeout)
        return None
    except Exception as exc:
        logger.error("nmap execution failed: %s", exc)
        return None


# ---------------------------------------------------------------------------
# HTTP helpers (stdlib urllib, no httpx dependency in agent collector)
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
# Main collector
# ---------------------------------------------------------------------------

class NetworkScanCollector:
    """
    Periodically runs nmap on authorized CIDRs and submits results to the
    DK server.

    Lifecycle: instantiated by agent/core.py, run via asyncio.to_thread().
    """

    def __init__(
        self,
        server_url: str,
        agent_id: str,
        ssl_ctx: Any = None,
        extra_nmap_args: str = "",
        nmap_timeout: int = 600,
        scan_private: bool = True,
        scan_public: bool = False,
    ) -> None:
        self.server_url = server_url.rstrip("/")
        self.agent_id = agent_id
        self.ssl_ctx = ssl_ctx
        self.extra_nmap_args = extra_nmap_args
        self.nmap_timeout = nmap_timeout
        self.scan_private = scan_private
        self.scan_public = scan_public
        self._auth_headers = {"X-Agent-ID": agent_id}

    # ------------------------------------------------------------------
    # Fetch the list of networks to scan from the server
    # ------------------------------------------------------------------

    def _fetch_authorized_networks(self) -> list[str]:
        """
        Return a list of CIDRs that the server has authorized for scanning.

        For private CIDRs: all networks in inventory are eligible (no explicit
        authorization required) when self.scan_private is True.
        For public CIDRs: only those with scan_authorized=True are returned.
        """
        url = f"{self.server_url}/api/v1/inventory/networks"
        data = _http_get_json(url, self._auth_headers)
        if not data or not isinstance(data, list):
            logger.warning("Could not fetch network list from server")
            return []

        cidrs: list[str] = []
        for net in data:
            cidr = net.get("cidr", "")
            if not cidr:
                continue
            ip_class = net.get("ip_class", "unknown")
            scan_authorized = net.get("scan_authorized", False)

            if ip_class == "private" and self.scan_private:
                cidrs.append(cidr)
            elif ip_class in ("public", "mixed") and self.scan_public and scan_authorized:
                cidrs.append(cidr)
            elif ip_class in ("public", "mixed") and not scan_authorized:
                logger.debug(
                    "Skipping public CIDR %s — no scan authorization on server", cidr
                )

        logger.info("Scan targets: %d authorized CIDRs", len(cidrs))
        return cidrs

    # ------------------------------------------------------------------
    # Submit results
    # ------------------------------------------------------------------

    def _submit_hosts(self, hosts: list[DiscoveredHost]) -> None:
        if not hosts:
            return
        payload = {
            "hosts": [
                {
                    "fqdn": h.fqdn,
                    "ip_addresses": [h.ip],
                    "os": h.os,
                    "os_version": h.os_version,
                }
                for h in hosts
            ]
        }
        ok = _http_post_json(
            f"{self.server_url}/api/v1/data/hosts",
            payload,
            self._auth_headers,
            self.ssl_ctx,
        )
        if ok:
            logger.info("Submitted %d hosts to server", len(hosts))

    def _submit_services(self, hosts: list[DiscoveredHost]) -> None:
        services = []
        for h in hosts:
            for svc in h.services:
                services.append({
                    "host_ip": h.ip,
                    "host_fqdn": h.fqdn,
                    "port": svc.port,
                    "protocol": svc.protocol,
                    "service_name": svc.service_name,
                    "version": svc.version,
                    "banner": svc.banner,
                })
        if not services:
            return
        ok = _http_post_json(
            f"{self.server_url}/api/v1/data/services",
            {"services": services},
            self._auth_headers,
            self.ssl_ctx,
        )
        if ok:
            logger.info("Submitted %d services to server", len(services))

    def _submit_scan_result(
        self, cidr: str, started_at: float, hosts_found: list[str], raw_xml: str
    ) -> None:
        payload = {
            "cidr": cidr,
            "started_at": time.strftime(
                "%Y-%m-%dT%H:%M:%SZ", time.gmtime(started_at)
            ),
            "completed_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "hosts_found": hosts_found,
            "raw_output": raw_xml[:65536] if raw_xml else "",
        }
        _http_post_json(
            f"{self.server_url}/api/v1/data/scan-results",
            payload,
            self._auth_headers,
            self.ssl_ctx,
        )

    # ------------------------------------------------------------------
    # Main scan cycle
    # ------------------------------------------------------------------

    def run_scan_cycle(self) -> None:
        """
        Run one full scan cycle: fetch authorized targets → nmap each → submit.
        Intended to be called from asyncio.to_thread() by agent/core.py.
        """
        if shutil.which("nmap") is None:
            logger.warning(
                "nmap not found — install nmap to enable active network scanning. "
                "On Ubuntu/Debian: sudo apt install nmap"
            )
            return

        targets = self._fetch_authorized_networks()
        if not targets:
            logger.info("No scan targets available — skipping scan cycle")
            return

        total_hosts = 0
        for cidr in targets:
            logger.info("Scanning CIDR %s", cidr)
            started_at = time.time()

            xml_output = _run_nmap(
                cidr,
                extra_args=self.extra_nmap_args,
                timeout=self.nmap_timeout,
            )
            if xml_output is None:
                continue

            hosts = _parse_nmap_xml(xml_output)
            logger.info(
                "CIDR %s: %d host(s) found (%d services)",
                cidr, len(hosts), sum(len(h.services) for h in hosts),
            )

            self._submit_hosts(hosts)
            self._submit_services(hosts)
            self._submit_scan_result(
                cidr=cidr,
                started_at=started_at,
                hosts_found=[h.ip for h in hosts],
                raw_xml=xml_output,
            )
            total_hosts += len(hosts)

        logger.info(
            "Scan cycle complete — %d CIDRs scanned, %d total hosts found",
            len(targets), total_hosts,
        )
