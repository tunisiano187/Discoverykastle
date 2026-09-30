"""
NVD Monitor — server-side CVE watcher.

Polls the NVD REST API v2 for recently published/modified CVEs, cross-
references them against packages already known to the server, and fires
the standard vulnerability alert pipeline when a match is found.

This gives near-real-time alerting when a new CVE is published that
affects software already installed on managed hosts — without waiting
for the next agent scan cycle (which could be 24 hours away).

Configuration (via server settings / env vars):
  DKASTLE_NVD_MONITOR_ENABLED=true
  DKASTLE_NVD_MONITOR_POLL_INTERVAL=3600   # seconds (default 1 hour)
  DKASTLE_NVD_API_KEY=<key>                # optional — raises rate limit
  DKASTLE_NVD_MONITOR_INITIAL_WINDOW=86400 # seconds back on first run

How it works
============
1. On startup the background task records ``now - nvd_monitor_initial_window``
   as the "start of window" for the very first NVD query.
2. Each poll queries::

       GET https://services.nvd.nist.gov/rest/json/cves/2.0
           ?pubStartDate=<last_checked>&pubEndDate=<now>
           &resultsPerPage=2000

3. For each CVE, the affected product names are extracted from its CPE
   matches (``cpe:2.3:a:<vendor>:<product>:...``).
4. The packages table is queried for rows whose ``name`` matches any
   affected product (case-insensitive substring).
5. For each matching (host, package, CVE) triple:
   a. Skip if a Vulnerability record for this (host_id, cve_id) already
      exists — the agent already reported it.
   b. Otherwise insert a new Vulnerability and call
      ``registry.dispatch_vulnerability_found`` so the alert module fires.

Rate limiting
=============
Without an API key NVD allows 5 requests/second with a rolling 30-second
window.  We add a conservative 0.7 s delay between requests to stay well
under that limit.  With an API key the delay is reduced to 0.1 s.
"""

from __future__ import annotations

import asyncio
import json
import logging
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timedelta, timezone
from typing import Any

from server.modules.base import BaseModule, ModuleCapability, ModuleManifest
from server.modules.registry import registry

logger = logging.getLogger(__name__)

_NVD_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"
_RESULTS_PER_PAGE = 2000


def _cvss_to_severity(score: float | None) -> str:
    if score is None:
        return "medium"
    if score >= 9.0:
        return "critical"
    if score >= 7.0:
        return "high"
    if score >= 4.0:
        return "medium"
    return "low"


def _extract_products(cve_item: dict[str, Any]) -> set[str]:
    """Return lowercase product names from all CPE matches in a CVE item."""
    products: set[str] = set()
    try:
        configs = cve_item.get("cve", {}).get("configurations", [])
        for cfg in configs:
            for node in cfg.get("nodes", []):
                for cpe_match in node.get("cpeMatch", []):
                    cpe = cpe_match.get("criteria", "")
                    # cpe:2.3:a:<vendor>:<product>:<version>:...
                    parts = cpe.split(":")
                    if len(parts) >= 5 and parts[2] == "a":
                        products.add(parts[4].lower().replace("_", "-").replace("_", " "))
    except Exception:
        pass
    return products


def _fetch_nvd_page(
    start_dt: datetime,
    end_dt: datetime,
    api_key: str | None,
    start_index: int = 0,
) -> dict[str, Any]:
    """Synchronous NVD fetch — called via asyncio.to_thread."""
    fmt = "%Y-%m-%dT%H:%M:%S.000"
    params: dict[str, Any] = {
        "pubStartDate": start_dt.strftime(fmt),
        "pubEndDate": end_dt.strftime(fmt),
        "resultsPerPage": _RESULTS_PER_PAGE,
        "startIndex": start_index,
    }
    url = f"{_NVD_BASE}?{urllib.parse.urlencode(params)}"
    headers: dict[str, str] = {"Accept": "application/json"}
    if api_key:
        headers["apiKey"] = api_key

    req = urllib.request.Request(url, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            return json.loads(resp.read().decode())
    except urllib.error.HTTPError as exc:
        logger.warning("NVD HTTP %s: %s", exc.code, exc.reason)
        return {}
    except Exception as exc:
        logger.warning("NVD fetch error: %s", exc)
        return {}


class Module(BaseModule):
    manifest = ModuleManifest(
        name="nvd-monitor",
        version="1.0.0",
        description=(
            "Server-side NVD poller: alerts on new critical/high CVEs that "
            "affect packages already known to the platform."
        ),
        author="Discoverykastle",
        capabilities=[ModuleCapability.ALERT],
        builtin=True,
    )

    def __init__(self, config: dict[str, Any] | None = None) -> None:
        super().__init__(config)
        self._task: asyncio.Task | None = None
        self._last_checked: datetime | None = None

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    async def setup(self) -> None:
        from server.config import settings

        if not settings.nvd_monitor_enabled:
            self.logger.info("NVD monitor disabled (DKASTLE_NVD_MONITOR_ENABLED=false)")
            return

        self._task = asyncio.create_task(self._poll_loop(), name="nvd-monitor")
        self.logger.info(
            "NVD monitor active — poll every %ds", settings.nvd_monitor_poll_interval
        )

    async def teardown(self) -> None:
        if self._task and not self._task.done():
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass

    # ------------------------------------------------------------------
    # Background polling loop
    # ------------------------------------------------------------------

    async def _poll_loop(self) -> None:
        from server.config import settings

        while True:
            try:
                await self._run_poll()
            except Exception:
                self.logger.exception("NVD monitor poll cycle failed")
            await asyncio.sleep(settings.nvd_monitor_poll_interval)

    async def _run_poll(self) -> None:
        from server.config import settings
        from server.database import AsyncSessionLocal

        now = datetime.now(tz=timezone.utc)

        if self._last_checked is None:
            start = now - timedelta(seconds=settings.nvd_monitor_initial_window)
        else:
            start = self._last_checked

        api_key = settings.nvd_api_key
        delay = 0.1 if api_key else 0.7

        self.logger.debug(
            "NVD poll: window %s → %s",
            start.strftime("%Y-%m-%dT%H:%M:%SZ"),
            now.strftime("%Y-%m-%dT%H:%M:%SZ"),
        )

        # Paginate through NVD results
        start_index = 0
        total_results: int | None = None
        new_cves: list[dict[str, Any]] = []

        while True:
            data = await asyncio.to_thread(
                _fetch_nvd_page, start, now, api_key, start_index
            )
            if not data:
                break

            if total_results is None:
                total_results = data.get("totalResults", 0)

            vulnerabilities = data.get("vulnerabilities", [])
            new_cves.extend(vulnerabilities)

            fetched = start_index + len(vulnerabilities)
            if fetched >= (total_results or 0) or not vulnerabilities:
                break

            start_index = fetched
            await asyncio.sleep(delay)

        self.logger.info("NVD poll: fetched %d CVEs in window", len(new_cves))
        self._last_checked = now

        if not new_cves:
            return

        async with AsyncSessionLocal() as db:
            matched = await self._match_cves_to_packages(new_cves, db)
            self.logger.info("NVD monitor: %d new matches found", len(matched))

    async def _match_cves_to_packages(
        self,
        cve_items: list[dict[str, Any]],
        db,
    ) -> int:
        """
        For each CVE, find matching packages and create vulnerability records.
        Returns the number of new vulnerability records created.
        """
        from sqlalchemy import select, and_
        from sqlalchemy.exc import IntegrityError

        from server.models.host import Package, Host
        from server.models.vulnerability import Vulnerability

        created = 0

        for item in cve_items:
            cve_data = item.get("cve", {})
            cve_id: str = cve_data.get("id", "")
            if not cve_id:
                continue

            # Extract CVSS score (prefer v3.1 > v3.0 > v2)
            cvss_score: float | None = None
            metrics = cve_data.get("metrics", {})
            for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
                entries = metrics.get(key, [])
                if entries:
                    try:
                        cvss_score = float(
                            entries[0].get("cvssData", {}).get("baseScore", 0) or 0
                        )
                    except (TypeError, ValueError):
                        pass
                    break

            severity = _cvss_to_severity(cvss_score)

            # Skip medium/low CVEs to reduce noise
            if severity not in ("critical", "high"):
                continue

            # Extract description (English preferred)
            description = ""
            for desc in cve_data.get("descriptions", []):
                if desc.get("lang") == "en":
                    description = desc.get("value", "")
                    break

            products = _extract_products(item)
            if not products:
                continue

            # Query packages whose name matches any affected product
            for product in products:
                # Use ILIKE for case-insensitive partial match
                from sqlalchemy import func

                pkg_q = select(Package).where(
                    func.lower(Package.name).contains(product.lower())
                )
                pkg_result = await db.execute(pkg_q)
                packages = list(pkg_result.scalars())

                for pkg in packages:
                    # Check if this (host_id, cve_id) pair already exists
                    existing_q = select(Vulnerability).where(
                        and_(
                            Vulnerability.host_id == pkg.host_id,
                            Vulnerability.cve_id == cve_id,
                        )
                    )
                    existing = await db.scalar(existing_q)
                    if existing:
                        continue  # Agent already reported this

                    # Load the host for the alert pipeline
                    host = await db.get(Host, pkg.host_id)
                    if not host:
                        continue

                    vuln = Vulnerability(
                        host_id=pkg.host_id,
                        package_id=pkg.id,
                        cve_id=cve_id,
                        severity=severity,
                        cvss_score=cvss_score,
                        description=description,
                        remediation=f"Update {pkg.name} to a version that fixes {cve_id}",
                    )
                    db.add(vuln)
                    try:
                        await db.flush()
                    except IntegrityError:
                        await db.rollback()
                        continue

                    await registry.dispatch_vulnerability_found(vuln, host, db)
                    created += 1

        await db.commit()
        return created
