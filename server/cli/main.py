"""
dkctl — Discoverykastle admin CLI.

Talks to the DK server REST API. No direct DB access required.

Configuration (in order of priority):
  1. CLI flags:        --url, --token
  2. Environment vars: DKASTLE_URL, DKASTLE_TOKEN
  3. Config file:      ~/.dkastle/config.yaml

Usage examples:
  dkctl agents list
  dkctl agents token
  dkctl hosts list --limit 20
  dkctl networks list
  dkctl vulns summary
  dkctl vulns list --severity critical
  dkctl alerts list
  dkctl status
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path
from typing import Any

# ---------------------------------------------------------------------------
# Config helpers
# ---------------------------------------------------------------------------

_CONFIG_FILE = Path.home() / ".dkastle" / "config.yaml"


def _load_file_config() -> dict[str, str]:
    if not _CONFIG_FILE.exists():
        return {}
    try:
        import yaml  # type: ignore[import]
        return yaml.safe_load(_CONFIG_FILE.read_text()) or {}
    except Exception:
        return {}


def _resolve(cli_val: str | None, env_var: str, file_key: str, file_cfg: dict[str, str]) -> str:
    return cli_val or os.environ.get(env_var, "") or file_cfg.get(file_key, "")


# ---------------------------------------------------------------------------
# HTTP client
# ---------------------------------------------------------------------------

class APIClient:
    def __init__(self, url: str, token: str, verify_tls: bool = True) -> None:
        self.base = url.rstrip("/")
        self.token = token
        self.verify_tls = verify_tls

    def _request(self, method: str, path: str, **kwargs: Any) -> Any:
        import urllib.error
        import urllib.request
        import ssl

        url = f"{self.base}{path}"
        body = kwargs.get("json")
        data = json.dumps(body).encode() if body is not None else None

        ctx = ssl.create_default_context()
        if not self.verify_tls:
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE

        req = urllib.request.Request(
            url,
            data=data,
            method=method,
            headers={
                "Authorization": f"Bearer {self.token}",
                "Content-Type": "application/json",
                "Accept": "application/json",
            },
        )
        try:
            with urllib.request.urlopen(req, context=ctx, timeout=15) as resp:
                return json.loads(resp.read())
        except urllib.error.HTTPError as exc:
            body_bytes = exc.read()
            try:
                detail = json.loads(body_bytes).get("detail", exc.reason)
            except Exception:
                detail = exc.reason
            _die(f"HTTP {exc.code}: {detail}")
        except urllib.error.URLError as exc:
            _die(f"Cannot reach server at {self.base}: {exc.reason}")

    def get(self, path: str) -> Any:
        return self._request("GET", path)

    def post(self, path: str, **kwargs: Any) -> Any:
        return self._request("POST", path, **kwargs)

    def patch(self, path: str, **kwargs: Any) -> Any:
        return self._request("PATCH", path, **kwargs)


# ---------------------------------------------------------------------------
# Output helpers
# ---------------------------------------------------------------------------

def _die(msg: str) -> None:
    print(f"error: {msg}", file=sys.stderr)
    sys.exit(1)


def _print_table(rows: list[dict[str, Any]], columns: list[str]) -> None:
    if not rows:
        print("(no results)")
        return
    # Column widths
    widths = {col: len(col) for col in columns}
    for row in rows:
        for col in columns:
            widths[col] = max(widths[col], len(str(row.get(col, ""))))

    header = "  ".join(col.upper().ljust(widths[col]) for col in columns)
    print(header)
    print("-" * len(header))
    for row in rows:
        print("  ".join(str(row.get(col, "")).ljust(widths[col]) for col in columns))


def _output(data: Any, as_json: bool) -> None:
    if as_json:
        print(json.dumps(data, indent=2, default=str))


# ---------------------------------------------------------------------------
# Sub-command handlers
# ---------------------------------------------------------------------------

def cmd_status(client: APIClient, args: argparse.Namespace) -> None:
    data = client.get("/api/v1/version")
    if args.json:
        _output(data, True)
        return
    print(f"Server version : {data.get('version', '?')}")
    print(f"Agent version  : {data.get('agent_version', '?')}")


def cmd_agents_list(client: APIClient, args: argparse.Namespace) -> None:
    data = client.get("/api/v1/agents/")
    if args.json:
        _output(data, True)
        return
    _print_table(
        data,
        ["id", "hostname", "ip_address", "status", "last_seen"],
    )


def cmd_agents_token(client: APIClient, args: argparse.Namespace) -> None:
    """Generate a new one-time enrollment token."""
    data = client.post("/api/v1/agents/enrollment-token")
    if args.json:
        _output(data, True)
        return
    token = data.get("token", data)
    print(f"Enrollment token: {token}")
    print("This token is valid for one enrollment. Keep it secret.")


def cmd_hosts_list(client: APIClient, args: argparse.Namespace) -> None:
    path = f"/api/v1/inventory/hosts?limit={args.limit}"
    data = client.get(path)
    if args.json:
        _output(data, True)
        return
    _print_table(
        data,
        ["id", "ip_address", "fqdn", "os", "last_seen"],
    )


def cmd_networks_list(client: APIClient, args: argparse.Namespace) -> None:
    data = client.get("/api/v1/inventory/networks")
    if args.json:
        _output(data, True)
        return
    _print_table(
        data,
        ["cidr", "ip_class", "domain_name", "scan_authorized", "scan_depth"],
    )


def cmd_vulns_summary(client: APIClient, args: argparse.Namespace) -> None:
    data = client.get("/api/v1/vulns/summary")
    if args.json:
        _output(data, True)
        return
    counts = data.get("by_severity", {})
    print(f"Critical : {counts.get('critical', 0)}")
    print(f"High     : {counts.get('high', 0)}")
    print(f"Medium   : {counts.get('medium', 0)}")
    print(f"Low      : {counts.get('low', 0)}")
    print(f"Total    : {data.get('total', 0)}")


def cmd_vulns_list(client: APIClient, args: argparse.Namespace) -> None:
    qs = f"?limit={args.limit}"
    if args.severity:
        qs += f"&severity={args.severity}"
    data = client.get(f"/api/v1/vulns/{qs}")
    if args.json:
        _output(data, True)
        return
    _print_table(
        data,
        ["cve_id", "severity", "cvss_score", "host_count", "package_name"],
    )


def cmd_alerts_list(client: APIClient, args: argparse.Namespace) -> None:
    data = client.get("/api/v1/alerts/")
    if args.json:
        _output(data, True)
        return
    _print_table(
        data,
        ["id", "severity", "alert_type", "message", "created_at"],
    )


# ---------------------------------------------------------------------------
# Report generator
# ---------------------------------------------------------------------------

def _md_table(rows: list[dict], cols: list[str]) -> str:
    if not rows:
        return "_None_\n"
    header = "| " + " | ".join(c.replace("_", " ").title() for c in cols) + " |"
    sep    = "| " + " | ".join("---" for _ in cols) + " |"
    lines  = [header, sep]
    for row in rows:
        lines.append("| " + " | ".join(str(row.get(c, "")).replace("|", "\\|") for c in cols) + " |")
    return "\n".join(lines) + "\n"


def cmd_report(client: APIClient, args: argparse.Namespace) -> None:
    """Generate a full Markdown infrastructure report."""
    from datetime import datetime, timezone

    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    # Collect data (failures are non-fatal — section shows empty)
    def _get(path: str) -> list:
        try:
            result = client.get(path)
            return result if isinstance(result, list) else []
        except SystemExit:
            return []

    def _get_obj(path: str) -> dict:
        try:
            result = client.get(path)
            return result if isinstance(result, dict) else {}
        except SystemExit:
            return {}

    version   = _get_obj("/api/v1/version")
    hosts     = _get(f"/api/v1/inventory/hosts?limit={args.limit}")
    networks  = _get("/api/v1/inventory/networks")
    vuln_sum  = _get_obj("/api/v1/vulns/summary")
    top_vulns = _get("/api/v1/vulns/?limit=20&severity=critical") + \
                _get("/api/v1/vulns/?limit=20&severity=high")
    agents    = _get("/api/v1/agents/")
    alerts    = _get("/api/v1/alerts/")
    devices   = _get("/api/v1/inventory/devices")

    sev = vuln_sum.get("by_severity", {})
    total_vulns = vuln_sum.get("total", sum(sev.values()))

    lines = [
        "# Infrastructure Report",
        "",
        f"Generated : {now}  ",
        f"Server    : {client.base}  ",
        f"Version   : {version.get('version', '?')}",
        "",
        "---",
        "",
        "## Summary",
        "",
        "| | Count |",
        "|---|---|",
        f"| Hosts discovered | {len(hosts)} |",
        f"| Networks | {len(networks)} |",
        f"| Network devices | {len(devices)} |",
        f"| Agents online | {sum(1 for a in agents if a.get('status') == 'online')} / {len(agents)} |",
        f"| Vulnerabilities (total) | {total_vulns} |",
        f"| &nbsp;&nbsp;Critical | {sev.get('critical', 0)} |",
        f"| &nbsp;&nbsp;High | {sev.get('high', 0)} |",
        f"| &nbsp;&nbsp;Medium | {sev.get('medium', 0)} |",
        f"| &nbsp;&nbsp;Low | {sev.get('low', 0)} |",
        f"| Open alerts | {len(alerts)} |",
        "",
        "---",
        "",
        "## Networks",
        "",
        _md_table(networks, ["cidr", "ip_class", "domain_name", "scan_authorized"]),
        "",
        f"## Hosts ({len(hosts)})",
        "",
        _md_table(hosts[:args.limit], ["ip_address", "fqdn", "os", "last_seen"]),
        "",
        f"## Network Devices ({len(devices)})",
        "",
        _md_table(devices, ["ip_address", "hostname", "device_type", "vendor", "firmware_version"]),
        "",
        "## Critical & High Vulnerabilities",
        "",
        _md_table(top_vulns, ["cve_id", "severity", "cvss_score", "package_name"]),
        "",
        "## Agents",
        "",
        _md_table(agents, ["id", "hostname", "ip_address", "status", "last_seen"]),
        "",
        "## Recent Alerts",
        "",
        _md_table(alerts[:20], ["severity", "alert_type", "message", "created_at"]),
        "",
        "---",
        "",
        f"_Report generated by dkctl — Discoverykastle {version.get('version', '')}_",
    ]

    report = "\n".join(lines)

    if args.output:
        import pathlib
        pathlib.Path(args.output).write_text(report, encoding="utf-8")
        print(f"Report written to {args.output}")
    else:
        print(report)


# ---------------------------------------------------------------------------
# Argument parser
# ---------------------------------------------------------------------------

def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="dkctl",
        description="Discoverykastle admin CLI — manages a DK server over its REST API.",
    )
    parser.add_argument("--url", metavar="URL", help="DK server URL (env: DKASTLE_URL)")
    parser.add_argument("--token", metavar="TOKEN", help="API bearer token (env: DKASTLE_TOKEN)")
    parser.add_argument("--no-verify-tls", action="store_true", help="Skip TLS certificate verification")
    parser.add_argument("--json", action="store_true", help="Output raw JSON")

    sub = parser.add_subparsers(dest="command", metavar="COMMAND")
    sub.required = True

    # status
    sub.add_parser("status", help="Show server version and health")

    # agents
    agents = sub.add_parser("agents", help="Manage agents")
    agent_sub = agents.add_subparsers(dest="agents_cmd", metavar="SUBCOMMAND")
    agent_sub.required = True
    agent_sub.add_parser("list", help="List registered agents")
    agent_sub.add_parser("token", help="Generate a new enrollment token")

    # hosts
    hosts = sub.add_parser("hosts", help="Browse discovered hosts")
    host_sub = hosts.add_subparsers(dest="hosts_cmd", metavar="SUBCOMMAND")
    host_sub.required = True
    host_list = host_sub.add_parser("list", help="List hosts")
    host_list.add_argument("--limit", type=int, default=50, metavar="N")

    # networks
    networks = sub.add_parser("networks", help="Browse discovered networks")
    net_sub = networks.add_subparsers(dest="networks_cmd", metavar="SUBCOMMAND")
    net_sub.required = True
    net_sub.add_parser("list", help="List networks")

    # vulns
    vulns = sub.add_parser("vulns", help="Browse vulnerabilities")
    vuln_sub = vulns.add_subparsers(dest="vulns_cmd", metavar="SUBCOMMAND")
    vuln_sub.required = True
    vuln_sub.add_parser("summary", help="Show vulnerability summary by severity")
    vuln_list = vuln_sub.add_parser("list", help="List CVEs")
    vuln_list.add_argument("--limit", type=int, default=50, metavar="N")
    vuln_list.add_argument("--severity", choices=["critical", "high", "medium", "low"])

    # alerts
    alerts = sub.add_parser("alerts", help="Browse alerts")
    alert_sub = alerts.add_subparsers(dest="alerts_cmd", metavar="SUBCOMMAND")
    alert_sub.required = True
    alert_sub.add_parser("list", help="List recent alerts")

    # report
    rep = sub.add_parser("report", help="Generate a full Markdown infrastructure report")
    rep.add_argument(
        "--output", "-o", metavar="FILE",
        help="Write report to FILE instead of stdout",
    )
    rep.add_argument(
        "--limit", type=int, default=200, metavar="N",
        help="Max hosts to include (default: 200)",
    )

    return parser


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main() -> None:
    parser = _build_parser()
    args = parser.parse_args()

    file_cfg = _load_file_config()
    url = _resolve(args.url, "DKASTLE_URL", "url", file_cfg)
    token = _resolve(args.token, "DKASTLE_TOKEN", "token", file_cfg)

    if not url:
        _die(
            "Server URL not set. Use --url, set DKASTLE_URL, "
            f"or add 'url:' to {_CONFIG_FILE}"
        )
    if not token:
        _die(
            "API token not set. Use --token, set DKASTLE_TOKEN, "
            f"or add 'token:' to {_CONFIG_FILE}"
        )

    client = APIClient(url, token, verify_tls=not args.no_verify_tls)

    dispatch: dict[tuple[str, ...], Any] = {
        ("status",):                    cmd_status,
        ("agents", "list"):             cmd_agents_list,
        ("agents", "token"):            cmd_agents_token,
        ("hosts",  "list"):             cmd_hosts_list,
        ("networks", "list"):           cmd_networks_list,
        ("vulns",  "summary"):          cmd_vulns_summary,
        ("vulns",  "list"):             cmd_vulns_list,
        ("alerts", "list"):             cmd_alerts_list,
        ("report",):                    cmd_report,
    }

    key: tuple[str, ...]
    if args.command == "status":
        key = ("status",)
    elif args.command == "report":
        key = ("report",)
    elif args.command == "agents":
        key = ("agents", args.agents_cmd)
    elif args.command == "hosts":
        key = ("hosts", args.hosts_cmd)
    elif args.command == "networks":
        key = ("networks", args.networks_cmd)
    elif args.command == "vulns":
        key = ("vulns", args.vulns_cmd)
    elif args.command == "alerts":
        key = ("alerts", args.alerts_cmd)
    else:
        parser.print_help()
        sys.exit(1)

    handler = dispatch.get(key)
    if handler is None:
        parser.print_help()
        sys.exit(1)

    handler(client, args)


if __name__ == "__main__":
    main()
