"""
DK agent configuration loader.

Configuration is read from a single key=value config file (one per line,
comments with #, blank lines ignored) and can be overridden by environment
variables.

Default config file locations (first found wins):
  Linux   : /etc/discoverykastle/agent.conf
  Windows : C:\\ProgramData\\Discoverykastle\\Agent\\agent.conf

Override with: --config /path/to/agent.conf  or  DKASTLE_AGENT_CONFIG=...

After first registration the agent writes DKASTLE_AGENT_ID and the
certificate paths back to the config file so they are persisted across
restarts.
"""

from __future__ import annotations

import os
import sys
import logging
from pathlib import Path

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Platform defaults
# ---------------------------------------------------------------------------

def _default_config_path() -> Path:
    if sys.platform == "win32":
        base = Path(os.environ.get("ProgramData", r"C:\ProgramData"))
        return base / "Discoverykastle" / "Agent" / "agent.conf"
    return Path("/etc/discoverykastle/agent.conf")


def _default_data_dir() -> Path:
    """Directory where the agent stores certs and state."""
    if sys.platform == "win32":
        base = Path(os.environ.get("ProgramData", r"C:\ProgramData"))
        return base / "Discoverykastle" / "Agent"
    return Path("/var/lib/discoverykastle/agent")


def _default_log_file() -> Path:
    if sys.platform == "win32":
        base = Path(os.environ.get("ProgramData", r"C:\ProgramData"))
        return base / "Discoverykastle" / "Agent" / "logs" / "agent.log"
    return Path("/var/log/discoverykastle/agent.log")


# ---------------------------------------------------------------------------
# Config file parser (simple key=value, no external deps)
# ---------------------------------------------------------------------------

def _load_conf_file(path: Path) -> dict[str, str]:
    """Parse a key=value config file. Returns a dict of string values."""
    result: dict[str, str] = {}
    if not path.exists():
        return result
    with path.open(encoding="utf-8") as fh:
        for lineno, raw in enumerate(fh, 1):
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            if "=" not in line:
                logger.warning("agent.conf line %d: missing '=' — skipped", lineno)
                continue
            key, _, value = line.partition("=")
            result[key.strip()] = value.strip()
    return result


def _save_conf_file(path: Path, updates: dict[str, str]) -> None:
    """
    Update or append key=value pairs in the config file.
    Existing keys are updated in-place; new keys are appended.
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    lines: list[str] = []
    updated: set[str] = set()

    if path.exists():
        with path.open(encoding="utf-8") as fh:
            for raw in fh:
                line = raw.rstrip("\n")
                stripped = line.strip()
                if stripped and not stripped.startswith("#") and "=" in stripped:
                    key = stripped.partition("=")[0].strip()
                    if key in updates:
                        lines.append(f"{key}={updates[key]}")
                        updated.add(key)
                        continue
                lines.append(line)

    for key, value in updates.items():
        if key not in updated:
            lines.append(f"{key}={value}")

    with path.open("w", encoding="utf-8") as fh:
        fh.write("\n".join(lines) + "\n")


# ---------------------------------------------------------------------------
# AgentConfig
# ---------------------------------------------------------------------------

class AgentConfig:
    """
    Merged configuration: config file + environment variables.
    Environment variables always take precedence.
    """

    def __init__(self, config_path: Path | None = None) -> None:
        env_path = os.environ.get("DKASTLE_AGENT_CONFIG", "")
        self.config_path: Path = (
            Path(config_path) if config_path
            else Path(env_path) if env_path
            else _default_config_path()
        )
        self._file: dict[str, str] = _load_conf_file(self.config_path)

    def _get(self, key: str, default: str = "") -> str:
        return os.environ.get(key) or self._file.get(key, default)

    # ---- DK server connection ----

    @property
    def server_url(self) -> str:
        return self._get("DKASTLE_SERVER_URL")

    @property
    def enroll_token(self) -> str:
        return self._get("DKASTLE_ENROLL_TOKEN")

    # ---- Agent identity (set after registration) ----

    @property
    def agent_id(self) -> str:
        return self._get("DKASTLE_AGENT_ID")

    @property
    def agent_cert(self) -> str:
        return self._get("DKASTLE_AGENT_CERT")

    @property
    def agent_key(self) -> str:
        return self._get("DKASTLE_AGENT_KEY")

    @property
    def agent_ca(self) -> str:
        return self._get("DKASTLE_AGENT_CA")

    @property
    def data_dir(self) -> Path:
        return Path(self._get("DKASTLE_AGENT_DATA_DIR") or str(_default_data_dir()))

    @property
    def is_registered(self) -> bool:
        return bool(self.agent_id and self.agent_cert and self.agent_key)

    # ---- Behaviour ----

    @property
    def heartbeat_interval(self) -> int:
        return int(self._get("DKASTLE_HEARTBEAT_INTERVAL", "30"))

    @property
    def log_level(self) -> str:
        return self._get("DKASTLE_LOG_LEVEL", "INFO").upper()

    @property
    def log_file(self) -> str:
        return self._get("DKASTLE_LOG_FILE") or str(_default_log_file())

    # ---- Puppet collector ----

    @property
    def puppet_enabled(self) -> bool:
        return self._get("PUPPET_ENABLED", "false").lower() in ("1", "true", "yes")

    @property
    def puppet_fact_cache_dir(self) -> str:
        return self._get("PUPPET_FACT_CACHE_DIR")

    @property
    def puppet_report_dir(self) -> str:
        return self._get("PUPPET_REPORT_DIR")

    @property
    def puppet_sync_interval(self) -> int:
        return int(self._get("PUPPET_SYNC_INTERVAL", "3600"))

    @property
    def puppet_batch_size(self) -> int:
        return int(self._get("PUPPET_BATCH_SIZE", "50"))

    # ---- Network scanner (nmap) ----

    @property
    def nmap_enabled(self) -> bool:
        return self._get("NMAP_ENABLED", "false").lower() in ("1", "true", "yes")

    @property
    def nmap_scan_interval(self) -> int:
        return int(self._get("NMAP_SCAN_INTERVAL", "3600"))

    @property
    def nmap_extra_args(self) -> str:
        return self._get("NMAP_EXTRA_ARGS", "")

    @property
    def nmap_timeout(self) -> int:
        return int(self._get("NMAP_TIMEOUT", "600"))

    @property
    def nmap_scan_private(self) -> bool:
        return self._get("NMAP_SCAN_PRIVATE", "true").lower() not in ("0", "false", "no")

    @property
    def nmap_scan_public(self) -> bool:
        return self._get("NMAP_SCAN_PUBLIC", "false").lower() in ("1", "true", "yes")

    # ---- CVE scanner ----

    @property
    def cve_scan_enabled(self) -> bool:
        return self._get("CVE_SCAN_ENABLED", "false").lower() in ("1", "true", "yes")

    @property
    def cve_scan_interval(self) -> int:
        return int(self._get("CVE_SCAN_INTERVAL", "86400"))

    @property
    def cve_grype_path(self) -> str:
        return self._get("CVE_GRYPE_PATH", "")

    @property
    def nvd_api_key(self) -> str:
        return self._get("NVD_API_KEY", "")

    @property
    def cve_nvd_batch_delay(self) -> float:
        return float(self._get("CVE_NVD_BATCH_DELAY", "0.25"))

    @property
    def cve_max_packages(self) -> int:
        return int(self._get("CVE_MAX_PACKAGES", "500"))

    # ---- Persistence ----

    def save(self, updates: dict[str, str]) -> None:
        """Persist key=value pairs back to the config file."""
        _save_conf_file(self.config_path, updates)
        self._file.update(updates)
