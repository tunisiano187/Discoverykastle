"""
DK Agent — Ansible fact-cache collector.

Reads Ansible gathered facts from a local fact-cache directory and submits
host data to the DK server.  This mirrors what the server-side Ansible module
does for AWX pull, but runs on the Ansible controller host itself where the
fact-cache files live — no Docker / server filesystem access needed.

Supported cache formats:
  • jsonfile plugin  — one JSON file per host (hostname.json or just hostname)
  • yaml plugin      — one YAML file per host (hostname.yaml / hostname.yml)

Data submitted per host:
  • IP addresses (ansible_host, ansible_default_ipv4, ansible_all_ipv4_addresses)
  • FQDN / inventory hostname
  • OS (ansible_distribution + ansible_distribution_version)
  • Installed packages (ansible_packages)
  • Network interfaces (ansible_interfaces + per-interface facts)

Configuration (agent.conf / env vars):
  ANSIBLE_FACT_CACHE_DIR=/var/cache/ansible/facts
  ANSIBLE_ENABLED=true
  ANSIBLE_SYNC_INTERVAL=3600
  ANSIBLE_BATCH_SIZE=50
"""

from __future__ import annotations

import json
import logging
import os
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Fact-cache reader
# ---------------------------------------------------------------------------

def _load_fact_file(path: Path) -> dict[str, Any] | None:
    """Load a single fact-cache file (JSON or YAML). Returns facts dict or None."""
    try:
        text = path.read_text(encoding="utf-8")
        if path.suffix in (".yaml", ".yml"):
            try:
                import yaml  # type: ignore[import]
                data = yaml.safe_load(text) or {}
            except ImportError:
                logger.warning("PyYAML not installed — cannot read %s", path)
                return None
        else:
            data = json.loads(text)
        # Ansible fact-cache wraps everything under 'ansible_facts' key
        return data.get("ansible_facts", data)
    except Exception:
        logger.warning("Could not parse fact-cache file: %s", path)
        return None


def read_fact_cache(cache_dir: str) -> dict[str, dict[str, Any]]:
    """
    Read all fact-cache files from *cache_dir*.
    Returns a dict of {inventory_hostname: facts_dict}.
    """
    facts_by_host: dict[str, dict[str, Any]] = {}
    cache_path = Path(cache_dir)

    if not cache_path.is_dir():
        logger.warning("Ansible fact-cache dir does not exist: %s", cache_dir)
        return {}

    for entry in cache_path.iterdir():
        if not entry.is_file():
            continue
        hostname = entry.stem  # strip extension
        facts = _load_fact_file(entry)
        if facts is not None:
            facts_by_host[hostname] = facts

    logger.info("Ansible fact-cache: read %d host(s) from %s", len(facts_by_host), cache_dir)
    return facts_by_host


# ---------------------------------------------------------------------------
# Fact extraction helpers
# ---------------------------------------------------------------------------

def _extract_ips(facts: dict[str, Any], inventory_name: str) -> list[str]:
    ips: list[str] = []

    # ansible_host variable takes priority
    host_var = facts.get("ansible_host")
    if host_var and isinstance(host_var, str):
        ips.append(host_var)

    # Default IPv4 gateway interface
    default_v4 = facts.get("ansible_default_ipv4", {})
    if isinstance(default_v4, dict):
        addr = default_v4.get("address")
        if addr and addr not in ips:
            ips.append(addr)

    # All IPv4 addresses
    for addr in facts.get("ansible_all_ipv4_addresses", []):
        if addr and not addr.startswith("127.") and addr not in ips:
            ips.append(addr)

    return ips


def _extract_interfaces(facts: dict[str, Any]) -> list[dict[str, Any]]:
    """Extract per-interface data from ansible_interfaces + per-iface facts."""
    interfaces: list[dict[str, Any]] = []
    iface_names: list[str] = facts.get("ansible_interfaces", [])

    for name in iface_names:
        if name in ("lo",):
            continue
        # Ansible stores per-interface facts as ansible_<iface_name> (with - replaced by _)
        key = f"ansible_{name.replace('-', '_').replace('.', '_')}"
        iface = facts.get(key, {})
        if not isinstance(iface, dict):
            continue

        ipv4 = iface.get("ipv4", {})
        interfaces.append({
            "name": name,
            "ip_address": ipv4.get("address") if isinstance(ipv4, dict) else None,
            "netmask": ipv4.get("netmask") if isinstance(ipv4, dict) else None,
            "mac_address": iface.get("macaddress"),
            "interface_type": iface.get("type"),
            "is_up": iface.get("active", True),
        })

    return interfaces


def _extract_packages(facts: dict[str, Any]) -> list[dict[str, Any]]:
    """Extract installed packages from ansible_packages fact."""
    packages: list[dict[str, Any]] = []
    raw = facts.get("ansible_packages", {})
    if not isinstance(raw, dict):
        return []
    for pkg_name, pkg_list in raw.items():
        version: str | None = None
        if isinstance(pkg_list, list) and pkg_list:
            version = pkg_list[0].get("version")
        packages.append({"name": pkg_name, "version": version, "package_manager": "ansible"})
    return packages


# ---------------------------------------------------------------------------
# HTTP submit (stdlib only)
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
    except urllib.error.HTTPError as exc:
        body = exc.read().decode(errors="replace")[:300]
        logger.error("POST %s → HTTP %d: %s", url, exc.code, body)
        return False
    except Exception as exc:
        logger.error("POST %s failed: %s", url, exc)
        return False


# ---------------------------------------------------------------------------
# Main collector
# ---------------------------------------------------------------------------

class AnsibleFactCacheCollector:
    """
    Reads the local Ansible fact-cache and submits host data to the DK server.
    Intended to be called from asyncio.to_thread() in agent/core.py.
    """

    def __init__(
        self,
        server_url: str,
        agent_id: str,
        cache_dir: str,
        ssl_ctx: Any = None,
        batch_size: int = 50,
    ) -> None:
        self.server_url = server_url.rstrip("/")
        self.agent_id = agent_id
        self.cache_dir = cache_dir
        self.ssl_ctx = ssl_ctx
        self.batch_size = batch_size
        self._headers = {"X-Agent-ID": agent_id}

    def run_sync(self) -> None:
        """Run one full sync cycle: read fact-cache → submit hosts/packages/interfaces."""
        facts_by_host = read_fact_cache(self.cache_dir)
        if not facts_by_host:
            logger.info("Ansible fact-cache: nothing to submit")
            return

        hosts_payload: list[dict[str, Any]] = []
        packages_payload: list[dict[str, Any]] = []
        interfaces_payload: list[dict[str, Any]] = []

        for inventory_name, facts in facts_by_host.items():
            ip_addresses = _extract_ips(facts, inventory_name)
            fqdn: str = (
                facts.get("ansible_fqdn")
                or facts.get("ansible_hostname")
                or inventory_name
            )
            os_name: str | None = facts.get("ansible_distribution")
            os_version: str | None = facts.get("ansible_distribution_version")

            hosts_payload.append({
                "fqdn": fqdn,
                "ip_addresses": ip_addresses,
                "os": os_name,
                "os_version": os_version,
            })

            for pkg in _extract_packages(facts):
                packages_payload.append({**pkg, "host_fqdn": fqdn, "host_ip": ip_addresses[0] if ip_addresses else None})

            for iface in _extract_interfaces(facts):
                interfaces_payload.append({**iface, "host_fqdn": fqdn})

        # Submit hosts in batches
        submitted_hosts = 0
        for i in range(0, len(hosts_payload), self.batch_size):
            batch = hosts_payload[i : i + self.batch_size]
            if _post_json(
                f"{self.server_url}/api/v1/data/hosts",
                {"hosts": batch},
                self._headers,
                self.ssl_ctx,
            ):
                submitted_hosts += len(batch)

        # Submit packages in batches
        submitted_pkgs = 0
        for i in range(0, len(packages_payload), self.batch_size):
            batch = packages_payload[i : i + self.batch_size]
            if _post_json(
                f"{self.server_url}/api/v1/data/packages",
                {"packages": batch},
                self._headers,
                self.ssl_ctx,
            ):
                submitted_pkgs += len(batch)

        # Submit interfaces
        if interfaces_payload:
            _post_json(
                f"{self.server_url}/api/v1/data/interfaces",
                {"interfaces": interfaces_payload},
                self._headers,
                self.ssl_ctx,
            )

        logger.info(
            "Ansible sync complete — %d/%d hosts, %d packages submitted",
            submitted_hosts, len(hosts_payload), submitted_pkgs,
        )
