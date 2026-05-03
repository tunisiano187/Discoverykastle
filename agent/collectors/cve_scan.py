"""
DK Agent — CVE scanner collector.

Reads installed packages from the host and matches them against known CVEs
using two complementary sources (in order of preference):

  1. Grype (https://github.com/anchore/grype) — if the binary is present.
     Grype performs offline CVE matching using a local DB and covers OS
     packages (dpkg, rpm), language packages (pip, npm, gem, cargo…) and
     container images.  It outputs SARIF / JSON which we parse directly.

  2. NVD REST API v2 (https://nvd.nist.gov/developers/vulnerabilities)
     Fallback when Grype is not available.  For each installed package we
     query NVD's /cves/2.0 endpoint by keyword (cpeName or keywordSearch).
     Rate-limited to 5 req/s without an API key (50 req/s with NVD_API_KEY).

Results are submitted to the DK server via:
  POST /api/v1/data/vulnerabilities

Configuration (agent.conf / env vars):
  CVE_SCAN_ENABLED=true
  CVE_SCAN_INTERVAL=86400         # seconds (default 24h)
  CVE_GRYPE_PATH=                 # path to grype binary (default: auto-detect)
  NVD_API_KEY=                    # optional, raises NVD rate limit
  CVE_NVD_BATCH_DELAY=0.25        # seconds between NVD requests (default 0.25)
  CVE_MAX_PACKAGES=500            # max packages to query NVD for (default 500)
"""

from __future__ import annotations

import json
import logging
import os
import shutil
import subprocess
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

NVD_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"

# Severity thresholds (CVSS v3 base score)
_SEVERITY_MAP = [
    (9.0, "critical"),
    (7.0, "high"),
    (4.0, "medium"),
    (0.1, "low"),
]


def _cvss_to_severity(score: float) -> str:
    for threshold, label in _SEVERITY_MAP:
        if score >= threshold:
            return label
    return "none"


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------

@dataclass
class InstalledPackage:
    name: str
    version: str | None = None
    package_manager: str = "unknown"


@dataclass
class CVEFinding:
    cve_id: str
    severity: str
    cvss_score: float | None
    description: str | None
    remediation: str | None
    package_name: str
    package_version: str | None


# ---------------------------------------------------------------------------
# Package inventory readers (cross-platform)
# ---------------------------------------------------------------------------

def _read_dpkg_packages() -> list[InstalledPackage]:
    """Read installed packages from dpkg (Debian/Ubuntu)."""
    dpkg = shutil.which("dpkg-query")
    if dpkg is None:
        return []
    try:
        result = subprocess.run(
            [dpkg, "-W", "-f=${Package}\t${Version}\n"],
            capture_output=True, text=True, timeout=30,
        )
        packages = []
        for line in result.stdout.splitlines():
            parts = line.strip().split("\t")
            if len(parts) == 2:
                packages.append(InstalledPackage(
                    name=parts[0], version=parts[1], package_manager="dpkg"
                ))
        return packages
    except Exception:
        logger.debug("dpkg-query failed", exc_info=True)
        return []


def _read_rpm_packages() -> list[InstalledPackage]:
    """Read installed packages from rpm (RHEL/CentOS/Fedora)."""
    rpm = shutil.which("rpm")
    if rpm is None:
        return []
    try:
        result = subprocess.run(
            [rpm, "-qa", "--queryformat=%{NAME}\t%{VERSION}-%{RELEASE}\n"],
            capture_output=True, text=True, timeout=30,
        )
        packages = []
        for line in result.stdout.splitlines():
            parts = line.strip().split("\t")
            if len(parts) == 2:
                packages.append(InstalledPackage(
                    name=parts[0], version=parts[1], package_manager="rpm"
                ))
        return packages
    except Exception:
        logger.debug("rpm query failed", exc_info=True)
        return []


def _read_pip_packages() -> list[InstalledPackage]:
    """Read installed Python packages."""
    pip = shutil.which("pip3") or shutil.which("pip")
    if pip is None:
        return []
    try:
        result = subprocess.run(
            [pip, "list", "--format=json"],
            capture_output=True, text=True, timeout=30,
        )
        packages = []
        for item in json.loads(result.stdout):
            packages.append(InstalledPackage(
                name=item["name"], version=item["version"], package_manager="pip"
            ))
        return packages
    except Exception:
        logger.debug("pip list failed", exc_info=True)
        return []


def _read_windows_packages() -> list[InstalledPackage]:
    """Read installed software from Windows registry via PowerShell."""
    if os.name != "nt":
        return []
    ps = shutil.which("powershell") or shutil.which("pwsh")
    if ps is None:
        return []
    try:
        script = (
            "Get-ItemProperty "
            "HKLM:\\Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*, "
            "HKLM:\\Software\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\* "
            "| Where-Object { $_.DisplayName } "
            "| Select-Object DisplayName,DisplayVersion "
            "| ConvertTo-Json -Compress"
        )
        result = subprocess.run(
            [ps, "-NoProfile", "-Command", script],
            capture_output=True, text=True, timeout=60,
        )
        data = json.loads(result.stdout)
        if isinstance(data, dict):
            data = [data]
        packages = []
        for item in data:
            name = item.get("DisplayName", "").strip()
            version = item.get("DisplayVersion") or None
            if name:
                packages.append(InstalledPackage(
                    name=name, version=version, package_manager="windows"
                ))
        return packages
    except Exception:
        logger.debug("Windows package read failed", exc_info=True)
        return []


def collect_installed_packages() -> list[InstalledPackage]:
    """Collect installed packages from all available sources."""
    packages: list[InstalledPackage] = []
    packages.extend(_read_dpkg_packages())
    packages.extend(_read_rpm_packages())
    packages.extend(_read_pip_packages())
    packages.extend(_read_windows_packages())
    # Deduplicate by (name, version, manager)
    seen: set[tuple[str, str | None, str]] = set()
    unique: list[InstalledPackage] = []
    for p in packages:
        key = (p.name.lower(), p.version, p.package_manager)
        if key not in seen:
            seen.add(key)
            unique.append(p)
    return unique


# ---------------------------------------------------------------------------
# Grype scanner
# ---------------------------------------------------------------------------

def _grype_scan(grype_path: str) -> list[CVEFinding] | None:
    """
    Run Grype against the local filesystem / SBOM and parse JSON output.
    Returns None if Grype is unavailable or fails.
    """
    try:
        result = subprocess.run(
            [grype_path, "dir:/", "-o", "json", "--quiet", "--add-cpes-if-none"],
            capture_output=True, text=True, timeout=300,
        )
        if result.returncode != 0:
            logger.warning("Grype exited %d: %s", result.returncode, result.stderr[:300])
            return None

        data = json.loads(result.stdout)
        findings: list[CVEFinding] = []

        for match in data.get("matches", []):
            vuln = match.get("vulnerability", {})
            cve_id: str = vuln.get("id", "")
            if not cve_id.startswith("CVE-"):
                # Grype may return GHSA-*, skip non-CVE IDs
                related = [r for r in vuln.get("relatedVulnerabilities", [])
                           if r.get("id", "").startswith("CVE-")]
                cve_id = related[0]["id"] if related else cve_id

            severity = vuln.get("severity", "unknown").lower()
            cvss_score: float | None = None
            for cvss in vuln.get("cvss", []):
                score = cvss.get("metrics", {}).get("baseScore")
                if score is not None:
                    cvss_score = float(score)
                    break

            artifact = match.get("artifact", {})
            pkg_name = artifact.get("name", "")
            pkg_version = artifact.get("version")

            description = vuln.get("description", "")[:1000] if vuln.get("description") else None
            # Grype does not provide remediation — point to NVD
            remediation = f"See https://nvd.nist.gov/vuln/detail/{cve_id}" if cve_id.startswith("CVE-") else None

            findings.append(CVEFinding(
                cve_id=cve_id,
                severity=severity,
                cvss_score=cvss_score,
                description=description,
                remediation=remediation,
                package_name=pkg_name,
                package_version=pkg_version,
            ))

        logger.info("Grype found %d CVE matches", len(findings))
        return findings

    except subprocess.TimeoutExpired:
        logger.warning("Grype scan timed out")
        return None
    except Exception:
        logger.warning("Grype scan failed", exc_info=True)
        return None


# ---------------------------------------------------------------------------
# NVD API fallback
# ---------------------------------------------------------------------------

def _nvd_search(keyword: str, api_key: str | None, delay: float) -> list[dict[str, Any]]:
    """Query NVD CVE API for a single keyword, return a list of CVE items."""
    params = {
        "keywordSearch": keyword,
        "resultsPerPage": "20",
    }
    url = f"{NVD_BASE}?{urllib.parse.urlencode(params)}"
    headers: dict[str, str] = {"Accept": "application/json"}
    if api_key:
        headers["apiKey"] = api_key

    time.sleep(delay)
    try:
        req = urllib.request.Request(url, headers=headers)
        with urllib.request.urlopen(req, timeout=15) as resp:
            data = json.loads(resp.read())
            return data.get("vulnerabilities", [])
    except urllib.error.HTTPError as exc:
        if exc.code == 403:
            logger.warning("NVD API rate limited — increase CVE_NVD_BATCH_DELAY")
        elif exc.code != 404:
            logger.debug("NVD API error %d for %s", exc.code, keyword)
        return []
    except Exception:
        logger.debug("NVD request failed for %s", keyword, exc_info=True)
        return []


def _nvd_item_to_finding(item: dict[str, Any], pkg: InstalledPackage) -> CVEFinding | None:
    """Convert a raw NVD CVE item dict to a CVEFinding."""
    cve = item.get("cve", {})
    cve_id: str = cve.get("id", "")
    if not cve_id:
        return None

    # Description (English preferred)
    descriptions = cve.get("descriptions", [])
    description: str | None = None
    for d in descriptions:
        if d.get("lang") == "en":
            description = d.get("value", "")[:1000]
            break

    # CVSS score (v3.1 preferred, fall back to v3.0, then v2)
    cvss_score: float | None = None
    severity = "unknown"
    metrics = cve.get("metrics", {})
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        if key in metrics and metrics[key]:
            m = metrics[key][0]
            cvss_data = m.get("cvssData", {})
            score = cvss_data.get("baseScore")
            if score is not None:
                cvss_score = float(score)
                severity = _cvss_to_severity(cvss_score)
                break

    # References → look for patch / vendor advisory as remediation
    remediation: str | None = None
    for ref in cve.get("references", []):
        tags = ref.get("tags", [])
        if any(t in tags for t in ("Patch", "Vendor Advisory", "Mitigation")):
            remediation = ref.get("url")
            break
    if remediation is None:
        remediation = f"See https://nvd.nist.gov/vuln/detail/{cve_id}"

    return CVEFinding(
        cve_id=cve_id,
        severity=severity,
        cvss_score=cvss_score,
        description=description,
        remediation=remediation,
        package_name=pkg.name,
        package_version=pkg.version,
    )


def _nvd_scan(
    packages: list[InstalledPackage],
    api_key: str | None,
    delay: float,
    max_packages: int,
) -> list[CVEFinding]:
    """
    Query NVD API for each package (up to max_packages) and collect findings.
    """
    findings: list[CVEFinding] = []
    queried = 0

    for pkg in packages[:max_packages]:
        items = _nvd_search(pkg.name, api_key, delay)
        for item in items:
            finding = _nvd_item_to_finding(item, pkg)
            if finding:
                findings.append(finding)
        queried += 1

    logger.info("NVD API: queried %d packages, found %d CVEs", queried, len(findings))
    return findings


# ---------------------------------------------------------------------------
# HTTP submit helper
# ---------------------------------------------------------------------------

def _submit_vulnerabilities(
    server_url: str,
    agent_id: str,
    findings: list[CVEFinding],
    ssl_ctx: Any = None,
    batch_size: int = 100,
) -> None:
    """Submit CVE findings to POST /api/v1/data/vulnerabilities in batches."""
    import urllib.request

    headers = {
        "X-Agent-ID": agent_id,
        "Content-Type": "application/json",
    }
    total = 0
    for i in range(0, len(findings), batch_size):
        batch = findings[i : i + batch_size]
        payload = {
            "vulnerabilities": [
                {
                    "cve_id": f.cve_id,
                    "severity": f.severity,
                    "cvss_score": f.cvss_score,
                    "description": f.description,
                    "remediation": f.remediation,
                    "package_name": f.package_name,
                    "package_version": f.package_version,
                }
                for f in batch
            ]
        }
        data = json.dumps(payload).encode()
        req = urllib.request.Request(
            f"{server_url.rstrip('/')}/api/v1/data/vulnerabilities",
            data=data,
            headers=headers,
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=30, context=ssl_ctx) as resp:
                if resp.status < 300:
                    total += len(batch)
        except Exception as exc:
            logger.error("Failed to submit vuln batch: %s", exc)

    logger.info("Submitted %d/%d vulnerabilities to server", total, len(findings))


# ---------------------------------------------------------------------------
# Main collector
# ---------------------------------------------------------------------------

class CVEScanCollector:
    """
    Scans the local host for CVEs and submits findings to the DK server.

    Uses Grype if available, falls back to NVD API queries per package.
    Intended to be called from asyncio.to_thread() by agent/core.py.
    """

    def __init__(
        self,
        server_url: str,
        agent_id: str,
        ssl_ctx: Any = None,
        grype_path: str = "",
        nvd_api_key: str = "",
        nvd_batch_delay: float = 0.25,
        max_packages: int = 500,
    ) -> None:
        self.server_url = server_url
        self.agent_id = agent_id
        self.ssl_ctx = ssl_ctx
        self.grype_path = grype_path or shutil.which("grype") or ""
        self.nvd_api_key = nvd_api_key or ""
        self.nvd_batch_delay = nvd_batch_delay
        self.max_packages = max_packages

    def run_scan(self) -> None:
        """
        Run one CVE scan cycle.
        Intended to be called from asyncio.to_thread() by agent/core.py.
        """
        findings: list[CVEFinding] | None = None

        # Prefer Grype for comprehensive, offline scanning
        if self.grype_path:
            logger.info("CVE scan: using Grype (%s)", self.grype_path)
            findings = _grype_scan(self.grype_path)

        # Fall back to NVD API if Grype is unavailable or failed
        if findings is None:
            logger.info("CVE scan: using NVD API (Grype not available)")
            packages = collect_installed_packages()
            logger.info("Found %d installed packages", len(packages))
            if not packages:
                logger.warning("No packages found — skipping CVE scan")
                return
            findings = _nvd_scan(
                packages,
                api_key=self.nvd_api_key or None,
                delay=self.nvd_batch_delay,
                max_packages=self.max_packages,
            )

        if not findings:
            logger.info("CVE scan complete — no vulnerabilities found")
            return

        critical = sum(1 for f in findings if f.severity == "critical")
        high = sum(1 for f in findings if f.severity == "high")
        logger.info(
            "CVE scan complete — %d findings (%d critical, %d high)",
            len(findings), critical, high,
        )

        _submit_vulnerabilities(
            self.server_url,
            self.agent_id,
            findings,
            ssl_ctx=self.ssl_ctx,
        )
