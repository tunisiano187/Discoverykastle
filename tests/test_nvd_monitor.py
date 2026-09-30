"""
Tests for the NVD Monitor module.

Covers:
  • _extract_products — CPE string parsing
  • _cvss_to_severity — CVSS score → severity label
  • Module.setup — disabled when nvd_monitor_enabled=False
  • Module.setup — background task created when enabled
  • Module._match_cves_to_packages — skips medium/low CVEs
  • Module._match_cves_to_packages — creates vulnerability + dispatches alert
  • Module._match_cves_to_packages — skips existing vulnerability (deduplication)
  • Module._match_cves_to_packages — skips CVEs with no product CPEs
  • Module.teardown — cancels background task
  • _fetch_nvd_page — HTTP error handled gracefully
"""

from __future__ import annotations

import asyncio
import uuid
from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from server.modules.builtin.nvd_monitor.module import (
    Module,
    _cvss_to_severity,
    _extract_products,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_cve_item(
    cve_id: str = "CVE-2026-99999",
    cvss_score: float = 9.5,
    product: str = "openssl",
    description: str = "A critical flaw",
) -> dict:
    return {
        "cve": {
            "id": cve_id,
            "descriptions": [{"lang": "en", "value": description}],
            "metrics": {
                "cvssMetricV31": [
                    {"cvssData": {"baseScore": cvss_score}}
                ]
            },
            "configurations": [
                {
                    "nodes": [
                        {
                            "cpeMatch": [
                                {
                                    "criteria": f"cpe:2.3:a:openssl:{product}:3.0.0:*:*:*:*:*:*:*",
                                    "vulnerable": True,
                                }
                            ]
                        }
                    ]
                }
            ],
        }
    }


def _make_package(name: str = "openssl", version: str = "3.0.0") -> MagicMock:
    pkg = MagicMock()
    pkg.id = uuid.uuid4()
    pkg.host_id = uuid.uuid4()
    pkg.name = name
    pkg.version = version
    return pkg


def _make_host(host_id: uuid.UUID | None = None) -> MagicMock:
    h = MagicMock()
    h.id = host_id or uuid.uuid4()
    h.fqdn = "server.local"
    h.ip_addresses = ["10.0.0.1"]
    return h


# ---------------------------------------------------------------------------
# Unit tests — pure helpers
# ---------------------------------------------------------------------------

class TestCvssToSeverity:
    def test_critical(self) -> None:
        assert _cvss_to_severity(9.0) == "critical"
        assert _cvss_to_severity(10.0) == "critical"

    def test_high(self) -> None:
        assert _cvss_to_severity(7.0) == "high"
        assert _cvss_to_severity(8.9) == "high"

    def test_medium(self) -> None:
        assert _cvss_to_severity(4.0) == "medium"
        assert _cvss_to_severity(6.9) == "medium"

    def test_low(self) -> None:
        assert _cvss_to_severity(0.1) == "low"
        assert _cvss_to_severity(3.9) == "low"

    def test_none_returns_medium(self) -> None:
        assert _cvss_to_severity(None) == "medium"


class TestExtractProducts:
    def test_extracts_product_from_cpe(self) -> None:
        item = _make_cve_item(product="openssl")
        products = _extract_products(item)
        assert "openssl" in products

    def test_empty_configurations(self) -> None:
        item = {"cve": {"configurations": []}}
        assert _extract_products(item) == set()

    def test_missing_cve_key(self) -> None:
        assert _extract_products({}) == set()

    def test_multiple_products(self) -> None:
        item = {
            "cve": {
                "configurations": [
                    {
                        "nodes": [
                            {
                                "cpeMatch": [
                                    {"criteria": "cpe:2.3:a:vendor:libcurl:7.81.0:*:*:*:*:*:*:*"},
                                    {"criteria": "cpe:2.3:a:vendor:openssl:1.1.1:*:*:*:*:*:*:*"},
                                ]
                            }
                        ]
                    }
                ]
            }
        }
        products = _extract_products(item)
        assert "libcurl" in products
        assert "openssl" in products

    def test_ignores_non_application_cpe(self) -> None:
        item = {
            "cve": {
                "configurations": [
                    {
                        "nodes": [
                            {
                                "cpeMatch": [
                                    # "o" = OS type, not "a" = application
                                    {"criteria": "cpe:2.3:o:linux:kernel:5.15:*:*:*:*:*:*:*"},
                                ]
                            }
                        ]
                    }
                ]
            }
        }
        products = _extract_products(item)
        assert "kernel" not in products


# ---------------------------------------------------------------------------
# Module lifecycle
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
class TestModuleLifecycle:

    async def test_setup_disabled_when_flag_off(self) -> None:
        """setup() does nothing when nvd_monitor_enabled=False."""
        m = Module()
        with patch("server.modules.builtin.nvd_monitor.module.asyncio.create_task") as mock_ct:
            with patch("server.config.settings") as mock_settings:
                mock_settings.nvd_monitor_enabled = False
                await m.setup()
        mock_ct.assert_not_called()
        assert m._task is None

    async def test_setup_creates_task_when_enabled(self) -> None:
        """setup() creates a background task when enabled."""
        m = Module()
        fake_task = MagicMock(spec=asyncio.Task)

        with patch("server.config.settings") as mock_settings:
            mock_settings.nvd_monitor_enabled = True
            mock_settings.nvd_monitor_poll_interval = 3600
            with patch("asyncio.create_task", return_value=fake_task) as mock_ct:
                await m.setup()

        mock_ct.assert_called_once()
        assert m._task is fake_task

    async def test_teardown_cancels_task(self) -> None:
        """teardown() cancels the running background task."""
        m = Module()

        cancelled = asyncio.CancelledError()

        async def _coro_that_raises():
            raise cancelled

        # Create a real coroutine-based future so `await m._task` works.
        real_task = asyncio.ensure_future(_coro_that_raises())
        # Let it start but not finish yet (it will raise CancelledError on await)
        m._task = real_task

        # Call teardown — it calls cancel() then awaits the task
        try:
            await m.teardown()
        except Exception:
            pass

        # The task should be done (cancelled or errored)
        assert real_task.done()

    async def test_teardown_noop_when_no_task(self) -> None:
        """teardown() is a no-op when setup never ran."""
        m = Module()
        await m.teardown()  # Should not raise


# ---------------------------------------------------------------------------
# _match_cves_to_packages
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
class TestMatchCvesToPackages:

    _SENTINEL = object()

    def _make_db(self, packages: list, existing_vuln=None, host=_SENTINEL) -> AsyncMock:
        db = AsyncMock()

        # scalars() for package query
        pkg_scalars = MagicMock()
        pkg_scalars.__iter__ = MagicMock(return_value=iter(packages))
        pkg_result = MagicMock()
        pkg_result.scalars.return_value = pkg_scalars
        db.execute = AsyncMock(return_value=pkg_result)

        # scalar() for existing vulnerability check
        db.scalar = AsyncMock(return_value=existing_vuln)

        # get() for host lookup — use _SENTINEL to distinguish "not passed" from explicit None
        resolved_host = _make_host() if host is TestMatchCvesToPackages._SENTINEL else host
        db.get = AsyncMock(return_value=resolved_host)

        db.add = MagicMock()
        db.flush = AsyncMock()
        db.commit = AsyncMock()
        db.rollback = AsyncMock()
        return db

    async def test_skips_medium_cvss(self) -> None:
        """CVEs with CVSS < 7.0 are skipped entirely."""
        m = Module()
        db = self._make_db(packages=[])
        cves = [_make_cve_item(cvss_score=5.0)]

        with patch("server.modules.registry.registry"):
            result = await m._match_cves_to_packages(cves, db)

        assert result == 0
        db.add.assert_not_called()

    async def test_creates_vulnerability_for_critical_cve(self) -> None:
        """A critical CVE matching a known package creates a Vulnerability."""
        m = Module()
        pkg = _make_package(name="openssl")
        host = _make_host(pkg.host_id)
        db = self._make_db(packages=[pkg], existing_vuln=None, host=host)
        cves = [_make_cve_item(cve_id="CVE-2026-1111", cvss_score=9.5, product="openssl")]

        with patch("server.modules.builtin.nvd_monitor.module.registry") as mock_reg:
            mock_reg.dispatch_vulnerability_found = AsyncMock()
            result = await m._match_cves_to_packages(cves, db)

        assert result == 1
        db.add.assert_called_once()
        vuln = db.add.call_args[0][0]
        assert vuln.cve_id == "CVE-2026-1111"
        assert vuln.severity == "critical"
        assert vuln.host_id == pkg.host_id
        mock_reg.dispatch_vulnerability_found.assert_awaited_once()

    async def test_skips_existing_vulnerability(self) -> None:
        """If a Vulnerability record already exists for (host, CVE), skip."""
        m = Module()
        pkg = _make_package(name="openssl")
        existing = MagicMock()  # existing vuln
        db = self._make_db(packages=[pkg], existing_vuln=existing)
        cves = [_make_cve_item(cvss_score=9.5, product="openssl")]

        with patch("server.modules.builtin.nvd_monitor.module.registry") as mock_reg:
            mock_reg.dispatch_vulnerability_found = AsyncMock()
            result = await m._match_cves_to_packages(cves, db)

        assert result == 0
        db.add.assert_not_called()
        mock_reg.dispatch_vulnerability_found.assert_not_awaited()

    async def test_skips_cve_with_no_products(self) -> None:
        """CVEs whose configurations list is empty produce no DB writes."""
        m = Module()
        db = self._make_db(packages=[])
        cves = [{"cve": {"id": "CVE-2026-2222", "metrics": {
            "cvssMetricV31": [{"cvssData": {"baseScore": 9.9}}]
        }, "descriptions": [], "configurations": []}}]

        result = await m._match_cves_to_packages(cves, db)
        assert result == 0

    async def test_skips_cve_without_id(self) -> None:
        """Items missing a CVE ID are silently skipped."""
        m = Module()
        db = self._make_db(packages=[])
        cves = [{"cve": {"id": "", "metrics": {}, "descriptions": [], "configurations": []}}]

        result = await m._match_cves_to_packages(cves, db)
        assert result == 0

    async def test_high_cvss_creates_high_severity(self) -> None:
        """CVSS 7.0–8.9 → severity='high'."""
        m = Module()
        pkg = _make_package(name="curl")
        host = _make_host(pkg.host_id)
        db = self._make_db(packages=[pkg], existing_vuln=None, host=host)
        cves = [_make_cve_item(cve_id="CVE-2026-3333", cvss_score=7.5, product="curl")]

        with patch("server.modules.builtin.nvd_monitor.module.registry") as mock_reg:
            mock_reg.dispatch_vulnerability_found = AsyncMock()
            await m._match_cves_to_packages(cves, db)

        vuln = db.add.call_args[0][0]
        assert vuln.severity == "high"

    async def test_skips_when_host_not_found(self) -> None:
        """If the host record is gone, no alert is created."""
        m = Module()
        pkg = _make_package(name="openssl")
        db = self._make_db(packages=[pkg], existing_vuln=None, host=None)
        # host=None → db.get returns None
        cves = [_make_cve_item(cvss_score=9.5, product="openssl")]

        with patch("server.modules.builtin.nvd_monitor.module.registry") as mock_reg:
            mock_reg.dispatch_vulnerability_found = AsyncMock()
            result = await m._match_cves_to_packages(cves, db)

        assert result == 0
        db.add.assert_not_called()


# ---------------------------------------------------------------------------
# _fetch_nvd_page
# ---------------------------------------------------------------------------

class TestFetchNvdPage:

    def test_returns_empty_dict_on_http_error(self) -> None:
        from server.modules.builtin.nvd_monitor.module import _fetch_nvd_page
        import urllib.error

        start = datetime(2026, 1, 1, tzinfo=timezone.utc)
        end = datetime(2026, 1, 2, tzinfo=timezone.utc)

        with patch(
            "urllib.request.urlopen",
            side_effect=urllib.error.HTTPError(
                url="", code=429, msg="Too Many Requests", hdrs=None, fp=None
            ),
        ):
            result = _fetch_nvd_page(start, end, api_key=None)

        assert result == {}

    def test_returns_empty_dict_on_network_error(self) -> None:
        from server.modules.builtin.nvd_monitor.module import _fetch_nvd_page

        start = datetime(2026, 1, 1, tzinfo=timezone.utc)
        end = datetime(2026, 1, 2, tzinfo=timezone.utc)

        with patch("urllib.request.urlopen", side_effect=OSError("connection refused")):
            result = _fetch_nvd_page(start, end, api_key=None)

        assert result == {}

    def test_includes_api_key_header(self) -> None:
        from server.modules.builtin.nvd_monitor.module import _fetch_nvd_page

        start = datetime(2026, 1, 1, tzinfo=timezone.utc)
        end = datetime(2026, 1, 2, tzinfo=timezone.utc)

        mock_resp = MagicMock()
        mock_resp.__enter__ = MagicMock(return_value=mock_resp)
        mock_resp.__exit__ = MagicMock(return_value=False)
        mock_resp.read.return_value = b'{"totalResults": 0, "vulnerabilities": []}'

        with patch("urllib.request.urlopen", return_value=mock_resp):
            with patch("urllib.request.Request") as mock_req_cls:
                mock_req_cls.return_value = MagicMock()
                _fetch_nvd_page(start, end, api_key="my-key")

        _, kwargs = mock_req_cls.call_args
        headers = kwargs.get("headers", {})
        assert headers.get("apiKey") == "my-key"
