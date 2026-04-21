"""
Tests for the vulnerability read API — /api/v1/vulns

Strategy
--------
* FastAPI TestClient with mocked DB session and operator dependency.
* ORM objects constructed directly (no real DB needed).
* Aggregate queries (summary) are tested via mocked db.execute returns.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from unittest.mock import AsyncMock, MagicMock

import pytest
from fastapi import FastAPI
from starlette.testclient import TestClient

from server.models.host import Host
from server.models.vulnerability import Vulnerability


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_host(
    host_id: uuid.UUID | None = None,
    fqdn: str | None = "host.example.com",
    ip_addresses: list[str] | None = None,
) -> Host:
    h = Host(
        id=host_id or uuid.uuid4(),
        fqdn=fqdn,
        ip_addresses=ip_addresses or ["10.0.0.1"],
    )
    return h


def _make_vuln(
    vuln_id: uuid.UUID | None = None,
    host_id: uuid.UUID | None = None,
    cve_id: str = "CVE-2024-1234",
    severity: str = "high",
    cvss_score: float | None = 7.5,
    description: str | None = "Test vuln",
    remediation: str | None = "Patch it",
    package_id: uuid.UUID | None = None,
) -> Vulnerability:
    v = Vulnerability(
        id=vuln_id or uuid.uuid4(),
        host_id=host_id or uuid.uuid4(),
        cve_id=cve_id,
        severity=severity,
        cvss_score=cvss_score,
        description=description,
        remediation=remediation,
        package_id=package_id,
        first_seen=datetime(2024, 1, 1),
    )
    return v


def _make_api_app(mock_db: AsyncMock) -> FastAPI:
    from server.api.vulns import router
    from server.services.auth import require_operator
    from server.database import get_db

    app = FastAPI()
    app.include_router(router)
    app.dependency_overrides[require_operator] = lambda: "admin"
    app.dependency_overrides[get_db] = lambda: mock_db
    return app


# ---------------------------------------------------------------------------
# GET /api/v1/vulns — list
# ---------------------------------------------------------------------------


class TestListVulns:
    def test_returns_200_with_results(self) -> None:
        host = _make_host()
        vuln = _make_vuln(host_id=host.id)

        mock_db = AsyncMock()
        mock_db.execute = AsyncMock(return_value=iter([(vuln, host)]))

        with TestClient(_make_api_app(mock_db)) as client:
            resp = client.get("/api/v1/vulns")

        assert resp.status_code == 200
        data = resp.json()
        assert isinstance(data, list)
        assert len(data) == 1
        assert data[0]["cve_id"] == "CVE-2024-1234"
        assert data[0]["severity"] == "high"
        assert data[0]["host_id"] == str(host.id)

    def test_returns_empty_list_when_no_vulns(self) -> None:
        mock_db = AsyncMock()
        mock_db.execute = AsyncMock(return_value=iter([]))

        with TestClient(_make_api_app(mock_db)) as client:
            resp = client.get("/api/v1/vulns")

        assert resp.status_code == 200
        assert resp.json() == []

    def test_package_id_is_string_or_null(self) -> None:
        host = _make_host()
        pkg_id = uuid.uuid4()
        vuln = _make_vuln(host_id=host.id, package_id=pkg_id)

        mock_db = AsyncMock()
        mock_db.execute = AsyncMock(return_value=iter([(vuln, host)]))

        with TestClient(_make_api_app(mock_db)) as client:
            resp = client.get("/api/v1/vulns")

        assert resp.json()[0]["package_id"] == str(pkg_id)

    def test_null_package_id_serialised_as_null(self) -> None:
        host = _make_host()
        vuln = _make_vuln(host_id=host.id, package_id=None)

        mock_db = AsyncMock()
        mock_db.execute = AsyncMock(return_value=iter([(vuln, host)]))

        with TestClient(_make_api_app(mock_db)) as client:
            resp = client.get("/api/v1/vulns")

        assert resp.json()[0]["package_id"] is None

    def test_requires_operator_auth(self) -> None:
        from server.api.vulns import router
        from server.database import get_db

        mock_db = AsyncMock()
        app = FastAPI()
        app.include_router(router)
        app.dependency_overrides[get_db] = lambda: mock_db

        with TestClient(app) as client:
            resp = client.get("/api/v1/vulns")

        assert resp.status_code in (401, 403)

    def test_multiple_results_returned(self) -> None:
        host = _make_host()
        v1 = _make_vuln(host_id=host.id, cve_id="CVE-2024-0001", severity="critical")
        v2 = _make_vuln(host_id=host.id, cve_id="CVE-2024-0002", severity="medium")

        mock_db = AsyncMock()
        mock_db.execute = AsyncMock(return_value=iter([(v1, host), (v2, host)]))

        with TestClient(_make_api_app(mock_db)) as client:
            resp = client.get("/api/v1/vulns")

        assert len(resp.json()) == 2


# ---------------------------------------------------------------------------
# GET /api/v1/vulns/summary
# ---------------------------------------------------------------------------


class TestVulnSummary:
    def _make_totals_row(self, total: int = 10, unique_cves: int = 3, affected_hosts: int = 2) -> MagicMock:
        row = MagicMock()
        row.total = total
        row.unique_cves = unique_cves
        row.affected_hosts = affected_hosts
        return row

    def _make_sev_row(self, severity: str, cnt: int) -> MagicMock:
        row = MagicMock()
        row.severity = severity
        row.cnt = cnt
        return row

    def _make_top_row(self, cve_id: str, affected_hosts: int, severity: str, cvss_score: float) -> MagicMock:
        row = MagicMock()
        row.cve_id = cve_id
        row.affected_hosts = affected_hosts
        row.severity = severity
        row.cvss_score = cvss_score
        return row

    def test_summary_returns_200(self) -> None:
        totals = self._make_totals_row()
        sev_rows = [self._make_sev_row("high", 5), self._make_sev_row("critical", 3)]
        top_rows = [self._make_top_row("CVE-2024-1234", 2, "high", 7.5)]

        totals_result = MagicMock()
        totals_result.one = MagicMock(return_value=totals)

        sev_result = MagicMock()
        sev_result.__iter__ = MagicMock(return_value=iter(sev_rows))

        top_result = MagicMock()
        top_result.__iter__ = MagicMock(return_value=iter(top_rows))

        mock_db = AsyncMock()
        mock_db.execute = AsyncMock(side_effect=[totals_result, sev_result, top_result])

        with TestClient(_make_api_app(mock_db)) as client:
            resp = client.get("/api/v1/vulns/summary")

        assert resp.status_code == 200
        data = resp.json()
        assert data["total"] == 10
        assert data["unique_cves"] == 3
        assert data["affected_hosts"] == 2

    def test_summary_severity_counts(self) -> None:
        totals = self._make_totals_row()
        sev_rows = [
            self._make_sev_row("critical", 2),
            self._make_sev_row("high", 4),
            self._make_sev_row("medium", 3),
            self._make_sev_row("low", 1),
        ]
        top_result = MagicMock()
        top_result.__iter__ = MagicMock(return_value=iter([]))

        totals_result = MagicMock()
        totals_result.one = MagicMock(return_value=totals)
        sev_result = MagicMock()
        sev_result.__iter__ = MagicMock(return_value=iter(sev_rows))

        mock_db = AsyncMock()
        mock_db.execute = AsyncMock(side_effect=[totals_result, sev_result, top_result])

        with TestClient(_make_api_app(mock_db)) as client:
            resp = client.get("/api/v1/vulns/summary")

        by_sev = resp.json()["by_severity"]
        assert by_sev["critical"] == 2
        assert by_sev["high"] == 4
        assert by_sev["medium"] == 3
        assert by_sev["low"] == 1
        assert by_sev["none"] == 0

    def test_summary_top_cves(self) -> None:
        totals = self._make_totals_row()
        sev_result = MagicMock()
        sev_result.__iter__ = MagicMock(return_value=iter([]))
        top_rows = [
            self._make_top_row("CVE-2024-9999", 5, "critical", 9.8),
            self._make_top_row("CVE-2024-1111", 3, "high", 7.0),
        ]

        totals_result = MagicMock()
        totals_result.one = MagicMock(return_value=totals)
        top_result = MagicMock()
        top_result.__iter__ = MagicMock(return_value=iter(top_rows))

        mock_db = AsyncMock()
        mock_db.execute = AsyncMock(side_effect=[totals_result, sev_result, top_result])

        with TestClient(_make_api_app(mock_db)) as client:
            resp = client.get("/api/v1/vulns/summary")

        top = resp.json()["top_cves"]
        assert len(top) == 2
        assert top[0]["cve_id"] == "CVE-2024-9999"
        assert top[0]["affected_hosts"] == 5
        assert top[0]["severity"] == "critical"

    def test_summary_unknown_severity_bucketed(self) -> None:
        totals = self._make_totals_row()
        sev_rows = [self._make_sev_row("informational", 7)]
        top_result = MagicMock()
        top_result.__iter__ = MagicMock(return_value=iter([]))

        totals_result = MagicMock()
        totals_result.one = MagicMock(return_value=totals)
        sev_result = MagicMock()
        sev_result.__iter__ = MagicMock(return_value=iter(sev_rows))

        mock_db = AsyncMock()
        mock_db.execute = AsyncMock(side_effect=[totals_result, sev_result, top_result])

        with TestClient(_make_api_app(mock_db)) as client:
            resp = client.get("/api/v1/vulns/summary")

        assert resp.json()["by_severity"]["unknown"] == 7


# ---------------------------------------------------------------------------
# GET /api/v1/vulns/{cve_id}
# ---------------------------------------------------------------------------


class TestGetCve:
    def test_returns_cve_detail(self) -> None:
        host = _make_host()
        vuln = _make_vuln(host_id=host.id, cve_id="CVE-2024-5678", severity="critical", cvss_score=9.8)

        mock_db = AsyncMock()
        mock_db.execute = AsyncMock(return_value=iter([(vuln, host)]))

        with TestClient(_make_api_app(mock_db)) as client:
            resp = client.get("/api/v1/vulns/CVE-2024-5678")

        assert resp.status_code == 200
        data = resp.json()
        assert data["cve_id"] == "CVE-2024-5678"
        assert data["severity"] == "critical"
        assert data["cvss_score"] == 9.8
        assert data["affected_host_count"] == 1

    def test_cve_id_normalised_to_upper(self) -> None:
        host = _make_host()
        vuln = _make_vuln(host_id=host.id, cve_id="CVE-2024-0001")

        mock_db = AsyncMock()
        mock_db.execute = AsyncMock(return_value=iter([(vuln, host)]))

        with TestClient(_make_api_app(mock_db)) as client:
            resp = client.get("/api/v1/vulns/cve-2024-0001")

        assert resp.status_code == 200
        assert resp.json()["cve_id"] == "CVE-2024-0001"

    def test_404_when_not_found(self) -> None:
        mock_db = AsyncMock()
        mock_db.execute = AsyncMock(return_value=iter([]))

        with TestClient(_make_api_app(mock_db)) as client:
            resp = client.get("/api/v1/vulns/CVE-9999-0000")

        assert resp.status_code == 404

    def test_multiple_hosts_in_detail(self) -> None:
        h1 = _make_host(fqdn="host1.example.com", ip_addresses=["10.0.0.1"])
        h2 = _make_host(fqdn="host2.example.com", ip_addresses=["10.0.0.2"])
        v1 = _make_vuln(host_id=h1.id, cve_id="CVE-2024-1234", cvss_score=8.0)
        v2 = _make_vuln(host_id=h2.id, cve_id="CVE-2024-1234", cvss_score=7.0)

        mock_db = AsyncMock()
        mock_db.execute = AsyncMock(return_value=iter([(v1, h1), (v2, h2)]))

        with TestClient(_make_api_app(mock_db)) as client:
            resp = client.get("/api/v1/vulns/CVE-2024-1234")

        data = resp.json()
        assert data["affected_host_count"] == 2
        assert len(data["affected_hosts"]) == 2

    def test_affected_host_fields(self) -> None:
        host = _make_host(fqdn="db.internal", ip_addresses=["192.168.1.10", "192.168.1.11"])
        pkg_id = uuid.uuid4()
        vuln = _make_vuln(host_id=host.id, cve_id="CVE-2024-1234", package_id=pkg_id)

        mock_db = AsyncMock()
        mock_db.execute = AsyncMock(return_value=iter([(vuln, host)]))

        with TestClient(_make_api_app(mock_db)) as client:
            resp = client.get("/api/v1/vulns/CVE-2024-1234")

        affected = resp.json()["affected_hosts"][0]
        assert affected["host_id"] == str(host.id)
        assert affected["fqdn"] == "db.internal"
        assert "192.168.1.10" in affected["ip_addresses"]
        assert affected["package_id"] == str(pkg_id)

    def test_summary_route_not_matched_by_cve_param(self) -> None:
        """GET /summary should NOT be routed to /{cve_id} endpoint."""
        totals = MagicMock()
        totals.total = 0
        totals.unique_cves = 0
        totals.affected_hosts = 0

        totals_result = MagicMock()
        totals_result.one = MagicMock(return_value=totals)
        sev_result = MagicMock()
        sev_result.__iter__ = MagicMock(return_value=iter([]))
        top_result = MagicMock()
        top_result.__iter__ = MagicMock(return_value=iter([]))

        mock_db = AsyncMock()
        mock_db.execute = AsyncMock(side_effect=[totals_result, sev_result, top_result])

        with TestClient(_make_api_app(mock_db)) as client:
            resp = client.get("/api/v1/vulns/summary")

        # Must return VulnSummary shape, not 404
        assert resp.status_code == 200
        assert "by_severity" in resp.json()
