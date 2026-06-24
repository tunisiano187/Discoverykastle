"""
Documentation generator — produces Markdown reports from collected inventory data.

Supported report types:
  executive_summary  — high-level overview: networks, hosts, devices, alerts
  network            — detail for one network (hosts, interfaces, scan results)
  device             — detail for one network device (config snapshot, metadata)
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any


def _now_utc() -> str:
    return datetime.now(tz=timezone.utc).strftime("%Y-%m-%d %H:%M UTC")


# ---------------------------------------------------------------------------
# Executive summary
# ---------------------------------------------------------------------------


def render_executive_summary(
    networks: list[Any],
    hosts: list[Any],
    devices: list[Any],
    open_alerts: int,
    critical_alerts: int,
) -> str:
    lines: list[str] = [
        "# Discoverykastle — Executive Summary",
        "",
        f"*Generated: {_now_utc()}*",
        "",
        "## Overview",
        "",
        "| Metric | Count |",
        "|--------|-------|",
        f"| Networks discovered | {len(networks)} |",
        f"| Hosts discovered | {len(hosts)} |",
        f"| Network devices | {len(devices)} |",
        f"| Open alerts | {open_alerts} |",
        f"| Critical alerts | {critical_alerts} |",
        "",
    ]

    if networks:
        lines += [
            "## Networks",
            "",
            "| CIDR | Description | Scan Authorized |",
            "|------|-------------|-----------------|",
        ]
        for net in networks:
            desc = getattr(net, "description", None) or "—"
            authorized = "Yes" if getattr(net, "scan_authorized", False) else "No"
            lines.append(f"| `{net.cidr}` | {desc} | {authorized} |")
        lines.append("")

    if hosts:
        lines += [
            "## Hosts (top 20)",
            "",
            "| FQDN / IP | OS | First Seen |",
            "|-----------|-----|------------|",
        ]
        for host in hosts[:20]:
            fqdn = getattr(host, "fqdn", None) or ", ".join(host.ip_addresses or []) or "—"
            os_str = getattr(host, "os", None) or "—"
            first_seen = getattr(host, "first_seen", None)
            first_seen_str = first_seen.strftime("%Y-%m-%d") if first_seen else "—"
            lines.append(f"| {fqdn} | {os_str} | {first_seen_str} |")
        if len(hosts) > 20:
            lines.append(f"| *… and {len(hosts) - 20} more* | | |")
        lines.append("")

    if devices:
        lines += [
            "## Network Devices",
            "",
            "| IP | Type | Vendor | Model |",
            "|----|------|--------|-------|",
        ]
        for dev in devices:
            ip = getattr(dev, "ip_address", "—")
            dtype = getattr(dev, "device_type", None) or "—"
            vendor = getattr(dev, "vendor", None) or "—"
            model = getattr(dev, "model", None) or "—"
            lines.append(f"| `{ip}` | {dtype} | {vendor} | {model} |")
        lines.append("")

    if open_alerts == 0:
        lines += ["## Security", "", "> No open alerts.", ""]
    else:
        severity = "critical" if critical_alerts > 0 else "warning"
        lines += [
            "## Security",
            "",
            f"> **{open_alerts} open alert(s)** — {critical_alerts} critical.",
            f"> Severity: {severity}.",
            "",
        ]

    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Network report
# ---------------------------------------------------------------------------


def render_network_report(network: Any, hosts: list[Any]) -> str:
    desc = getattr(network, "description", None) or "No description"
    domain = getattr(network, "domain_name", None) or "—"
    authorized = "Yes" if getattr(network, "scan_authorized", False) else "No"
    depth = getattr(network, "scan_depth", 0)
    created_at = getattr(network, "created_at", None)
    created_str = created_at.strftime("%Y-%m-%d") if created_at else "—"

    lines: list[str] = [
        f"# Network Report: `{network.cidr}`",
        "",
        f"*Generated: {_now_utc()}*",
        "",
        "## Metadata",
        "",
        f"- **Description:** {desc}",
        f"- **Domain:** {domain}",
        f"- **Scan Authorized:** {authorized}",
        f"- **Scan Depth:** {depth}",
        f"- **Discovered:** {created_str}",
        "",
    ]

    if hosts:
        lines += [
            f"## Hosts ({len(hosts)})",
            "",
            "| FQDN / IP | OS | Services | Last Seen |",
            "|-----------|-----|----------|-----------|",
        ]
        for host in hosts:
            fqdn = getattr(host, "fqdn", None) or ", ".join(host.ip_addresses or []) or "—"
            os_str = getattr(host, "os", None) or "—"
            services = getattr(host, "services", [])
            svc_count = len(services) if services else 0
            last_seen = getattr(host, "last_seen", None)
            last_str = last_seen.strftime("%Y-%m-%d") if last_seen else "—"
            lines.append(f"| {fqdn} | {os_str} | {svc_count} | {last_str} |")
        lines.append("")
    else:
        lines += ["## Hosts", "", "> No hosts discovered on this network yet.", ""]

    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Device report
# ---------------------------------------------------------------------------


def render_device_report(device: Any) -> str:
    ip = getattr(device, "ip_address", "—")
    hostname = getattr(device, "hostname", None) or "—"
    dtype = getattr(device, "device_type", None) or "—"
    vendor = getattr(device, "vendor", None) or "—"
    model = getattr(device, "model", None) or "—"
    firmware = getattr(device, "firmware_version", None) or "—"
    last_seen = getattr(device, "last_seen", None)
    last_str = last_seen.strftime("%Y-%m-%d %H:%M") if last_seen else "—"

    lines: list[str] = [
        f"# Device Report: `{ip}`",
        "",
        f"*Generated: {_now_utc()}*",
        "",
        "## Metadata",
        "",
        f"- **Hostname:** {hostname}",
        f"- **IP:** `{ip}`",
        f"- **Type:** {dtype}",
        f"- **Vendor:** {vendor}",
        f"- **Model:** {model}",
        f"- **Firmware:** {firmware}",
        f"- **Last Seen:** {last_str}",
        "",
    ]

    config = getattr(device, "config_snapshot", None)
    if config:
        lines += [
            "## Configuration Snapshot",
            "",
            "```",
            config.strip(),
            "```",
            "",
        ]
    else:
        lines += ["## Configuration Snapshot", "", "> No config snapshot available.", ""]

    return "\n".join(lines)
