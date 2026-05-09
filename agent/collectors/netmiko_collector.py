"""
DK Agent — Network device collector (Netmiko).

Connects to network devices (switches, routers, firewalls) via SSH and
collects:
  • Basic inventory: hostname, vendor, model, firmware/OS version
  • Running configuration (sanitized — passwords redacted)
  • Interface list with IP addresses and status
  • VLAN table (where applicable)
  • ARP table → topology edges (host↔device links)
  • LLDP/CDP neighbours → topology edges (device↔device links)
  • Routing table summary

Results are submitted to the DK server via:
  POST /api/v1/data/device-configs
  POST /api/v1/data/topology-edges

Supported device types (via Netmiko device_type):
  • cisco_ios, cisco_ios_xe, cisco_ios_xr, cisco_nxos
  • cisco_asa
  • juniper_junos
  • arista_eos
  • mikrotik_routeros
  • hp_procurve, hp_comware
  • fortinet (FortiOS)
  • linux (fallback for any SSH host)

Configuration (agent.conf / env vars):
  NETMIKO_ENABLED=true
  NETMIKO_SYNC_INTERVAL=3600
  NETMIKO_DEVICES_FILE=/etc/discoverykastle/network_devices.json
    — JSON array of device definitions:
      [{"host":"192.168.1.1","device_type":"cisco_ios","username":"ro","password":"xxx"}, ...]
  NETMIKO_TIMEOUT=30
  NETMIKO_REDACT_CONFIG=true   — replace passwords in config (default: true)

Requires: netmiko (pip install netmiko)
The module loads but stays dormant (logs a warning) when netmiko is absent.
"""

from __future__ import annotations

import json
import logging
import os
import re
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

# Regex patterns to redact sensitive values from device configs
_REDACT_PATTERNS = [
    re.compile(r"(password\s+)\S+", re.IGNORECASE),
    re.compile(r"(secret\s+)\S+", re.IGNORECASE),
    re.compile(r"(community\s+)\S+", re.IGNORECASE),
    re.compile(r"(key-string\s+)\S+", re.IGNORECASE),
    re.compile(r"(pre-shared-key\s+)\S+", re.IGNORECASE),
]


def _redact_config(config: str) -> str:
    for pattern in _REDACT_PATTERNS:
        config = pattern.sub(r"\g<1><REDACTED>", config)
    return config


# ---------------------------------------------------------------------------
# Device command sets per platform
# ---------------------------------------------------------------------------

_COMMANDS: dict[str, dict[str, str]] = {
    "cisco_ios": {
        "version": "show version",
        "interfaces": "show ip interface brief",
        "vlans": "show vlan brief",
        "arp": "show arp",
        "lldp": "show lldp neighbors detail",
        "cdp": "show cdp neighbors detail",
        "config": "show running-config",
    },
    "cisco_nxos": {
        "version": "show version",
        "interfaces": "show ip interface brief",
        "vlans": "show vlan brief",
        "arp": "show ip arp",
        "lldp": "show lldp neighbors detail",
        "config": "show running-config",
    },
    "juniper_junos": {
        "version": "show version",
        "interfaces": "show interfaces terse",
        "arp": "show arp",
        "lldp": "show lldp neighbors",
        "config": "show configuration | display set",
    },
    "arista_eos": {
        "version": "show version",
        "interfaces": "show ip interface brief",
        "vlans": "show vlan",
        "arp": "show arp",
        "lldp": "show lldp neighbors detail",
        "config": "show running-config",
    },
    "mikrotik_routeros": {
        "version": "system resource print",
        "interfaces": "ip address print",
        "arp": "ip arp print",
        "config": "export compact",
    },
    "hp_procurve": {
        "version": "show system-information",
        "interfaces": "show interfaces brief",
        "vlans": "show vlans",
        "lldp": "show lldp info remote-device",
        "config": "show running-config",
    },
    "fortinet": {
        "version": "get system status",
        "interfaces": "get system interface",
        "arp": "get system arp",
        "config": "show full-configuration",
    },
}

# Map generic device types to command sets
_CMD_ALIASES: dict[str, str] = {
    "cisco_ios_xe": "cisco_ios",
    "cisco_ios_xr": "cisco_ios",
    "cisco_asa": "cisco_ios",
    "hp_comware": "hp_procurve",
}


def _get_commands(device_type: str) -> dict[str, str]:
    key = _CMD_ALIASES.get(device_type, device_type)
    return _COMMANDS.get(key, _COMMANDS["cisco_ios"])


# ---------------------------------------------------------------------------
# Output parsers (best-effort, no TextFSM dependency)
# ---------------------------------------------------------------------------

def _parse_version_ios(output: str) -> dict[str, str | None]:
    """Extract vendor/model/firmware from 'show version' (IOS-style)."""
    result: dict[str, str | None] = {"vendor": "Cisco", "model": None, "firmware_version": None}
    for line in output.splitlines():
        if "Cisco IOS" in line or "Cisco Nexus" in line:
            result["firmware_version"] = line.strip()[:100]
        if m := re.search(r"[Cc]isco\s+(\S+)\s+(?:processor|chassis)", line):
            result["model"] = m.group(1)
        if m := re.search(r"[Vv]ersion\s+([\d.()A-Za-z]+)", line):
            result["firmware_version"] = m.group(1)
    return result


def _parse_hostname(output: str) -> str | None:
    """Try to extract hostname from version/system output."""
    for line in output.splitlines():
        if m := re.search(r"[Hh]ostname[:\s]+(\S+)", line):
            return m.group(1).strip(".,")
        if line.strip().startswith("hostname "):
            return line.strip().split()[1]
    return None


def _parse_arp_ios(output: str) -> list[dict[str, str]]:
    """
    Parse 'show arp' output into [{ip, mac, interface}].
    IOS format: Protocol Address Age(min) Hardware Addr Type Interface
    """
    entries: list[dict[str, str]] = []
    for line in output.splitlines():
        parts = line.split()
        if len(parts) >= 6 and re.match(r"\d+\.\d+\.\d+\.\d+", parts[1]):
            entries.append({"ip": parts[1], "mac": parts[3], "interface": parts[-1]})
    return entries


def _parse_lldp_neighbors(output: str) -> list[dict[str, str]]:
    """
    Best-effort LLDP neighbour parser — extracts (local_port, remote_host, remote_ip).
    """
    neighbours: list[dict[str, str]] = []
    current: dict[str, str] = {}
    for line in output.splitlines():
        line = line.strip()
        if "System Name:" in line or "Device ID:" in line:
            if current:
                neighbours.append(current)
            current = {"remote_host": line.split(":", 1)[-1].strip()}
        elif "Management Address:" in line or "IP address:" in line:
            current["remote_ip"] = line.split(":", 1)[-1].strip()
        elif "Local Port id:" in line or "Local Intf:" in line or "Local Interface:" in line:
            current["local_port"] = line.split(":", 1)[-1].strip()
    if current:
        neighbours.append(current)
    return neighbours


# ---------------------------------------------------------------------------
# Device connection + data collection
# ---------------------------------------------------------------------------

def _collect_device(device_def: dict[str, Any], redact: bool, timeout: int) -> dict[str, Any] | None:
    """
    Connect to a single device via Netmiko, run commands, and return a
    structured dict ready for submission to the DK server.
    """
    try:
        from netmiko import ConnectHandler, NetmikoTimeoutException, NetmikoAuthenticationException  # type: ignore[import]
    except ImportError:
        logger.warning("netmiko not installed — install it with: pip install netmiko")
        return None

    host = device_def.get("host", "")
    device_type = device_def.get("device_type", "cisco_ios")
    username = device_def.get("username", "")
    password = device_def.get("password", "")
    port = int(device_def.get("port", 22))

    connect_params = {
        "device_type": device_type,
        "host": host,
        "username": username,
        "password": password,
        "port": port,
        "timeout": timeout,
        "session_timeout": timeout,
        "fast_cli": False,
    }
    # Optional SSH key auth
    if device_def.get("key_file"):
        connect_params["key_file"] = device_def["key_file"]
        connect_params["use_keys"] = True

    logger.info("Connecting to device %s (%s)", host, device_type)

    raw_outputs: dict[str, str] = {}
    try:
        with ConnectHandler(**connect_params) as conn:
            cmds = _get_commands(device_type)
            for cmd_name, cmd in cmds.items():
                try:
                    raw_outputs[cmd_name] = conn.send_command(cmd, read_timeout=timeout)
                except Exception as exc:
                    logger.debug("Command '%s' failed on %s: %s", cmd, host, exc)
                    raw_outputs[cmd_name] = ""
    except NetmikoTimeoutException:
        logger.warning("Timeout connecting to device %s", host)
        return None
    except NetmikoAuthenticationException:
        logger.warning("Authentication failed for device %s", host)
        return None
    except Exception as exc:
        logger.warning("Failed to connect to device %s: %s", host, exc)
        return None

    # --- Parse collected data ---
    version_out = raw_outputs.get("version", "")
    parsed_version = _parse_version_ios(version_out)

    hostname = (
        device_def.get("hostname")
        or _parse_hostname(version_out)
        or host
    )

    config_raw = raw_outputs.get("config", "")
    if redact and config_raw:
        config_raw = _redact_config(config_raw)

    # ARP → topology candidates
    arp_entries = _parse_arp_ios(raw_outputs.get("arp", ""))

    # LLDP neighbours → topology
    lldp_neighbours = _parse_lldp_neighbors(
        raw_outputs.get("lldp", "") or raw_outputs.get("cdp", "")
    )

    structured = {
        "arp_table": arp_entries,
        "lldp_neighbours": lldp_neighbours,
        "interface_summary": raw_outputs.get("interfaces", "")[:4000],
        "vlan_summary": raw_outputs.get("vlans", "")[:2000],
    }

    return {
        "ip_address": host,
        "hostname": hostname,
        "device_type": device_def.get("device_type_label") or device_type.replace("_", " ").title(),
        "vendor": parsed_version.get("vendor") or device_def.get("vendor"),
        "model": parsed_version.get("model") or device_def.get("model"),
        "firmware_version": parsed_version.get("firmware_version"),
        "config_snapshot": config_raw[:65536] if config_raw else None,
        "structured_data": json.dumps(structured),
        "_arp_entries": arp_entries,
        "_lldp_neighbours": lldp_neighbours,
    }


# ---------------------------------------------------------------------------
# HTTP submit
# ---------------------------------------------------------------------------

def _post_json(url: str, payload: Any, headers: dict[str, str], ssl_ctx: Any = None) -> bool:
    data = json.dumps(payload).encode()
    req = urllib.request.Request(
        url, data=data,
        headers={**headers, "Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=30, context=ssl_ctx) as resp:
            return resp.status < 300
    except Exception as exc:
        logger.error("POST %s failed: %s", url, exc)
        return False


# ---------------------------------------------------------------------------
# Main collector
# ---------------------------------------------------------------------------

class NetmikoCollector:
    """
    Connects to network devices and submits inventory + topology data to the DK server.
    Intended to be called from asyncio.to_thread() in agent/core.py.
    """

    def __init__(
        self,
        server_url: str,
        agent_id: str,
        devices_file: str,
        ssl_ctx: Any = None,
        timeout: int = 30,
        redact_config: bool = True,
    ) -> None:
        self.server_url = server_url.rstrip("/")
        self.agent_id = agent_id
        self.devices_file = devices_file
        self.ssl_ctx = ssl_ctx
        self.timeout = timeout
        self.redact_config = redact_config
        self._headers = {"X-Agent-ID": agent_id}

    def _load_devices(self) -> list[dict[str, Any]]:
        path = Path(self.devices_file)
        if not path.exists():
            logger.warning("Netmiko devices file not found: %s", self.devices_file)
            return []
        try:
            return json.loads(path.read_text(encoding="utf-8"))
        except Exception as exc:
            logger.error("Failed to load devices file %s: %s", self.devices_file, exc)
            return []

    def run_sync(self) -> None:
        """Run one full sync cycle across all configured devices."""
        devices = self._load_devices()
        if not devices:
            logger.info("Netmiko: no devices configured")
            return

        logger.info("Netmiko: collecting from %d device(s)", len(devices))

        device_configs: list[dict[str, Any]] = []
        topology_edges: list[dict[str, Any]] = []

        for device_def in devices:
            result = _collect_device(device_def, self.redact_config, self.timeout)
            if result is None:
                continue

            # Strip internal keys before submission
            arp_entries = result.pop("_arp_entries", [])
            lldp_neighbours = result.pop("_lldp_neighbours", [])

            device_configs.append(result)

            # Build topology edges from LLDP neighbours
            for nbr in lldp_neighbours:
                remote_ip = nbr.get("remote_ip", "")
                if remote_ip:
                    topology_edges.append({
                        "source_ip": result["ip_address"],
                        "target_ip": remote_ip,
                        "edge_type": "lldp",
                        "source_port": nbr.get("local_port"),
                    })

        # Submit device configs
        if device_configs:
            ok = _post_json(
                f"{self.server_url}/api/v1/data/device-configs",
                {"device_configs": device_configs},
                self._headers,
                self.ssl_ctx,
            )
            if ok:
                logger.info("Submitted %d device config(s)", len(device_configs))

        # Submit topology edges
        if topology_edges:
            ok = _post_json(
                f"{self.server_url}/api/v1/data/topology-edges",
                {"topology_edges": topology_edges},
                self._headers,
                self.ssl_ctx,
            )
            if ok:
                logger.info("Submitted %d topology edge(s)", len(topology_edges))

        logger.info("Netmiko sync complete")
