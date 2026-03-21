"""
Agent-side Puppet collector.

Runs on the host that has access to the Puppet master's vardir (either directly
on the Puppet master, or on a host with a read-only bind/NFS mount of vardir).

Reads two data sources:
  1. YAML fact cache  — $vardir/yaml/facts/<certname>.yaml
  2. YAML run reports — $vardir/reports/<certname>/<timestamp>.yaml  (last only)

Converts the data to JSON and sends a single batch to the server via:
  POST /api/v1/data/puppet

Configuration — all via environment variables:

  DKASTLE_SERVER_URL          Base URL of the Discoverykastle server
                              e.g. https://discoverykastle.example.com:8443
  DKASTLE_AGENT_ID            UUID of this agent (from registration)
  DKASTLE_AGENT_CERT          Path to the agent's mTLS client certificate (PEM)
  DKASTLE_AGENT_KEY           Path to the agent's mTLS private key (PEM)
  DKASTLE_AGENT_CA            Path to the server's CA certificate (PEM)

  PUPPET_FACT_CACHE_DIR       Path to the Puppet YAML fact cache directory
                              Default: /opt/puppetlabs/puppet/cache/yaml/facts
                              Older:   /var/lib/puppet/yaml/facts
  PUPPET_REPORT_DIR           Path to the Puppet run report directory
                              Default: /opt/puppetlabs/puppet/cache/reports
                              Older:   /var/lib/puppet/reports
  PUPPET_BATCH_SIZE           Number of nodes per HTTP request (default: 50)

Usage (standalone or called by the agent scheduler):
  python -m agent.collectors.puppet
  python agent/collectors/puppet.py
"""

from __future__ import annotations

import json
import logging
import os
import ssl
import sys
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Default Puppet vardir paths (Puppet 6+ and older open-source)
# ---------------------------------------------------------------------------

_FACT_CACHE_CANDIDATES = [
    "/opt/puppetlabs/puppet/cache/yaml/facts",   # Puppet 6+ / PE
    "/var/lib/puppet/yaml/facts",                 # Older open-source Puppet
]

_REPORT_CANDIDATES = [
    "/opt/puppetlabs/puppet/cache/reports",       # Puppet 6+ / PE
    "/var/lib/puppet/reports",                    # Older open-source Puppet
]


def _resolve_dir(env_var: str, candidates: list[str]) -> Path | None:
    """Return the configured or first-existing candidate directory."""
    explicit = os.environ.get(env_var, "").strip()
    if explicit:
        p = Path(explicit)
        if p.is_dir():
            return p
        logger.warning("%s=%s does not exist or is not a directory", env_var, explicit)
        return None
    for candidate in candidates:
        p = Path(candidate)
        if p.is_dir():
            return p
    return None


# ---------------------------------------------------------------------------
# YAML loader for Ruby-tagged Puppet files
# ---------------------------------------------------------------------------

def _load_puppet_yaml(text: str) -> Any:
    """
    Parse a Puppet/Facter YAML file that may contain Ruby object tags such as
    !ruby/object:Puppet::Node::Facts or !ruby/sym environment.
    """
    import yaml  # type: ignore[import]

    class _RubyLoader(yaml.SafeLoader):
        pass

    def _ruby_any(loader: yaml.SafeLoader, tag_suffix: str, node: yaml.Node) -> Any:
        if isinstance(node, yaml.MappingNode):
            return loader.construct_mapping(node, deep=True)
        if isinstance(node, yaml.SequenceNode):
            return loader.construct_sequence(node, deep=True)
        return loader.construct_scalar(node)  # type: ignore[arg-type]

    _RubyLoader.add_multi_constructor("!ruby/object:", _ruby_any)
    _RubyLoader.add_multi_constructor("!ruby/sym", _ruby_any)
    _RubyLoader.add_multi_constructor("!ruby/", _ruby_any)

    return yaml.load(text, Loader=_RubyLoader)  # noqa: S506


# ---------------------------------------------------------------------------
# Fact cache reader
# ---------------------------------------------------------------------------

def read_fact_cache(fact_dir: Path) -> dict[str, dict[str, Any]]:
    """
    Read all <certname>.yaml files from the Puppet fact cache directory.

    Returns a mapping:  certname → facts dict
    """
    result: dict[str, dict[str, Any]] = {}
    for entry in sorted(fact_dir.glob("*.yaml")):
        certname = entry.stem
        try:
            raw = _load_puppet_yaml(entry.read_text(encoding="utf-8"))
            # Puppet wraps facts under a 'values' key inside the Ruby object
            facts: dict[str, Any] = raw.get("values", raw) if isinstance(raw, dict) else {}
            result[certname] = facts
        except Exception as exc:
            logger.warning("Could not parse fact cache file %s: %s", entry, exc)
    logger.info("Fact cache: read %d nodes from %s", len(result), fact_dir)
    return result


# ---------------------------------------------------------------------------
# Report reader
# ---------------------------------------------------------------------------

def read_reports(report_dir: Path) -> dict[str, dict[str, Any]]:
    """
    Read the most recent run report per node from the Puppet report directory.

    Directory structure:  <report_dir>/<certname>/<timestamp>.yaml

    Returns a mapping:  certname → report summary dict
    """
    result: dict[str, dict[str, Any]] = {}
    for node_dir in sorted(report_dir.iterdir()):
        if not node_dir.is_dir():
            continue
        certname = node_dir.name
        # Most recent report = lexicographically last filename
        report_files = sorted(node_dir.glob("*.yaml"), reverse=True)
        if not report_files:
            continue
        try:
            raw = _load_puppet_yaml(report_files[0].read_text(encoding="utf-8"))
            if not isinstance(raw, dict):
                continue
            result[certname] = {
                "last_run": raw.get("time"),
                "status": raw.get("status"),
                "environment": raw.get("environment"),
                "puppet_version": raw.get("puppet_version"),
                "config_version": str(raw.get("configuration_version", "")),
            }
        except Exception as exc:
            logger.warning("Could not parse report file %s: %s", report_files[0], exc)
    logger.info("Reports: read %d nodes from %s", len(result), report_dir)
    return result


# ---------------------------------------------------------------------------
# Payload assembly
# ---------------------------------------------------------------------------

def build_payload(
    facts_by_node: dict[str, dict[str, Any]],
    reports_by_node: dict[str, dict[str, Any]],
) -> dict[str, Any]:
    """
    Merge facts and reports into the JSON payload expected by
    POST /api/v1/data/puppet.

    Payload schema:
    {
      "nodes": [
        {
          "certname": "web01.example.com",
          "facts": { ... },          // Facter fact dict
          "report": {                // optional
            "last_run": "...",
            "status": "changed",
            "environment": "production",
            "puppet_version": "8.3.0",
            "config_version": "..."
          }
        }
      ]
    }
    """
    all_certnames = set(facts_by_node) | set(reports_by_node)
    nodes = []
    for certname in sorted(all_certnames):
        node: dict[str, Any] = {"certname": certname}
        facts = facts_by_node.get(certname)
        if facts is not None:
            node["facts"] = facts
        report = reports_by_node.get(certname)
        if report is not None:
            # Strip None values to keep payload lean
            node["report"] = {k: v for k, v in report.items() if v is not None}
        nodes.append(node)
    return {"nodes": nodes}


# ---------------------------------------------------------------------------
# HTTP submission
# ---------------------------------------------------------------------------

def _build_ssl_context() -> ssl.SSLContext | None:
    """Build an mTLS SSL context from environment variables."""
    cert = os.environ.get("DKASTLE_AGENT_CERT", "")
    key = os.environ.get("DKASTLE_AGENT_KEY", "")
    ca = os.environ.get("DKASTLE_AGENT_CA", "")

    if not (cert and key):
        logger.warning(
            "DKASTLE_AGENT_CERT / DKASTLE_AGENT_KEY not set — "
            "submitting without client certificate (mTLS disabled)"
        )
        return None

    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.load_cert_chain(cert, key)
    if ca:
        ctx.load_verify_locations(ca)
    else:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    return ctx


def submit_batch(
    server_url: str,
    agent_id: str,
    payload: dict[str, Any],
    batch_size: int = 50,
) -> tuple[int, int]:
    """
    Send nodes to the server in batches.

    Returns (total_imported, total_errors) by parsing server responses.
    Uses the stdlib urllib so no extra dependencies are needed on the agent.
    """
    import urllib.request
    import urllib.error

    ssl_ctx = _build_ssl_context()
    endpoint = f"{server_url.rstrip('/')}/api/v1/data/puppet"
    nodes: list[Any] = payload.get("nodes", [])

    total_imported = 0
    total_errors = 0

    for i in range(0, len(nodes), batch_size):
        chunk = nodes[i : i + batch_size]
        body = json.dumps({"nodes": chunk}).encode("utf-8")
        req = urllib.request.Request(
            endpoint,
            data=body,
            method="POST",
            headers={
                "Content-Type": "application/json",
                "X-Agent-ID": agent_id,
            },
        )
        try:
            with urllib.request.urlopen(req, context=ssl_ctx, timeout=60) as resp:
                result = json.loads(resp.read())
                total_imported += result.get("imported", 0)
                total_errors += result.get("errors", 0)
                logger.info(
                    "Batch %d-%d: imported=%d errors=%d",
                    i, i + len(chunk),
                    result.get("imported", 0),
                    result.get("errors", 0),
                )
        except urllib.error.HTTPError as exc:
            logger.error("HTTP %s when submitting batch %d-%d: %s", exc.code, i, i + len(chunk), exc)
            total_errors += len(chunk)
        except Exception as exc:
            logger.error("Failed to submit batch %d-%d: %s", i, i + len(chunk), exc)
            total_errors += len(chunk)

    return total_imported, total_errors


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def collect_and_submit() -> None:
    """
    Main collection routine.  Call this from the agent scheduler or run
    this file directly.
    """
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )

    server_url = os.environ.get("DKASTLE_SERVER_URL", "").strip()
    agent_id = os.environ.get("DKASTLE_AGENT_ID", "").strip()

    if not server_url:
        logger.error("DKASTLE_SERVER_URL is not set — cannot submit Puppet data")
        sys.exit(1)
    if not agent_id:
        logger.error("DKASTLE_AGENT_ID is not set — cannot submit Puppet data")
        sys.exit(1)

    batch_size = int(os.environ.get("PUPPET_BATCH_SIZE", "50"))

    fact_dir = _resolve_dir("PUPPET_FACT_CACHE_DIR", _FACT_CACHE_CANDIDATES)
    report_dir = _resolve_dir("PUPPET_REPORT_DIR", _REPORT_CANDIDATES)

    if fact_dir is None and report_dir is None:
        logger.error(
            "No Puppet data sources found. Set PUPPET_FACT_CACHE_DIR and/or "
            "PUPPET_REPORT_DIR, or ensure the default Puppet vardir paths exist."
        )
        sys.exit(1)

    facts_by_node: dict[str, dict[str, Any]] = {}
    reports_by_node: dict[str, dict[str, Any]] = {}

    if fact_dir:
        facts_by_node = read_fact_cache(fact_dir)
    if report_dir:
        reports_by_node = read_reports(report_dir)

    if not facts_by_node and not reports_by_node:
        logger.info("No Puppet node data found — nothing to submit")
        return

    payload = build_payload(facts_by_node, reports_by_node)
    total_nodes = len(payload["nodes"])
    logger.info("Submitting %d nodes to %s", total_nodes, server_url)

    imported, errors = submit_batch(server_url, agent_id, payload, batch_size)
    logger.info(
        "Done — %d/%d nodes imported, %d errors", imported, total_nodes, errors
    )
    if errors:
        sys.exit(1)


if __name__ == "__main__":
    collect_and_submit()
