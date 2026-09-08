"""
Tests for the CVE / vulnerability alert logic in the builtin-alerts module.

Covers:
  • on_vulnerability_found — CVSS score path (≥9.0 critical, ≥7.0 high, <7.0 skip)
  • on_vulnerability_found — no-CVSS fallback (severity string as tiebreaker)
  • on_vulnerability_found — deduplication (unacknowledged duplicate suppressed)
  • on_vulnerability_found — acknowledged duplicates allow re-alert
  • on_vulnerability_found — host_label falls back correctly
"""

from __future__ import annotations

import uuid
from unittest.mock import AsyncMock, MagicMock, patch

import pytest


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_vuln(
    cve_id: str = "CVE-2024-99999",
    severity: str = "high",
    cvss_score: float | None = 9.5,
) -> MagicMock:
    v = MagicMock()
    v.cve_id = cve_id
    v.severity = severity
    v.cvss_score = cvss_score
    v.description = "A serious bug"
    v.remediation = "Upgrade to 1.2.3"
    return v


def _make_host(
    fqdn: str | None = "server.local",
    ip_addresses: list[str] | None = None,
) -> MagicMock:
    h = MagicMock()
    h.id = uuid.uuid4()
    h.fqdn = fqdn
    # Use explicit sentinel so that empty list [] is preserved correctly
    h.ip_addresses = ["10.0.0.1"] if ip_addresses is None else ip_addresses
    return h


def _make_db(existing_alerts: list[MagicMock] | None = None) -> AsyncMock:
    """Return an AsyncMock DB whose scalars() yields existing_alerts."""
    db = AsyncMock()
    scalars_mock = MagicMock()
    scalars_mock.__iter__ = MagicMock(return_value=iter(existing_alerts or []))
    result_mock = MagicMock()
    result_mock.scalars.return_value = scalars_mock
    db.execute = AsyncMock(return_value=result_mock)
    db.flush = AsyncMock()
    db.add = MagicMock()
    return db


def _make_module():
    from server.modules.builtin.alerts.module import Module
    m = Module()
    m.logger = MagicMock()
    return m


# ---------------------------------------------------------------------------
# Tests — CVSS score path
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
class TestCVSSScorePath:

    async def test_cvss_critical_creates_alert(self) -> None:
        """CVSS ≥ 9.0 → critical alert."""
        m = _make_module()
        vuln = _make_vuln(cvss_score=9.5, severity="critical")
        host = _make_host()
        db = _make_db()

        with patch.object(m, "_notify", new_callable=AsyncMock):
            await m.on_vulnerability_found(vuln, host, db)

        db.add.assert_called_once()
        created = db.add.call_args[0][0]
        assert created.severity == "critical"

    async def test_cvss_high_creates_alert(self) -> None:
        """CVSS ≥ 7.0 and < 9.0 → high alert."""
        m = _make_module()
        vuln = _make_vuln(cvss_score=8.1, severity="high")
        host = _make_host()
        db = _make_db()

        with patch.object(m, "_notify", new_callable=AsyncMock):
            await m.on_vulnerability_found(vuln, host, db)

        db.add.assert_called_once()
        created = db.add.call_args[0][0]
        assert created.severity == "high"

    async def test_cvss_medium_skipped(self) -> None:
        """CVSS < 7.0 → no alert created."""
        m = _make_module()
        vuln = _make_vuln(cvss_score=5.9, severity="medium")
        host = _make_host()
        db = _make_db()

        with patch.object(m, "_notify", new_callable=AsyncMock):
            await m.on_vulnerability_found(vuln, host, db)

        db.add.assert_not_called()

    async def test_cvss_zero_skipped(self) -> None:
        """CVSS of 0.0 → no alert (edge case)."""
        m = _make_module()
        vuln = _make_vuln(cvss_score=0.0, severity="low")
        host = _make_host()
        db = _make_db()

        with patch.object(m, "_notify", new_callable=AsyncMock):
            await m.on_vulnerability_found(vuln, host, db)

        db.add.assert_not_called()


# ---------------------------------------------------------------------------
# Tests — no-CVSS fallback (severity string)
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
class TestNoCSVSSFallback:

    async def test_no_cvss_critical_severity_creates_alert(self) -> None:
        """cvss_score=None, severity='critical' → alert fires using severity label."""
        m = _make_module()
        vuln = _make_vuln(cvss_score=None, severity="critical")
        host = _make_host()
        db = _make_db()

        with patch.object(m, "_notify", new_callable=AsyncMock):
            await m.on_vulnerability_found(vuln, host, db)

        db.add.assert_called_once()
        created = db.add.call_args[0][0]
        assert created.severity == "critical"

    async def test_no_cvss_high_severity_creates_alert(self) -> None:
        """cvss_score=None, severity='high' → alert fires."""
        m = _make_module()
        vuln = _make_vuln(cvss_score=None, severity="high")
        host = _make_host()
        db = _make_db()

        with patch.object(m, "_notify", new_callable=AsyncMock):
            await m.on_vulnerability_found(vuln, host, db)

        db.add.assert_called_once()
        created = db.add.call_args[0][0]
        assert created.severity == "high"

    async def test_no_cvss_medium_severity_skipped(self) -> None:
        """cvss_score=None, severity='medium' → no alert (below threshold)."""
        m = _make_module()
        vuln = _make_vuln(cvss_score=None, severity="medium")
        host = _make_host()
        db = _make_db()

        with patch.object(m, "_notify", new_callable=AsyncMock):
            await m.on_vulnerability_found(vuln, host, db)

        db.add.assert_not_called()

    async def test_no_cvss_score_str_contains_na(self) -> None:
        """When score is None the message contains 'n/a'."""
        m = _make_module()
        vuln = _make_vuln(cvss_score=None, severity="critical")
        host = _make_host()
        db = _make_db()

        with patch.object(m, "_notify", new_callable=AsyncMock):
            await m.on_vulnerability_found(vuln, host, db)

        created = db.add.call_args[0][0]
        assert "n/a" in created.message


# ---------------------------------------------------------------------------
# Tests — deduplication
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
class TestCVEAlertDeduplication:

    def _make_existing_alert(
        self, cve_id: str, host_id: str, acknowledged: bool = False
    ) -> MagicMock:
        a = MagicMock()
        a.alert_type = "vulnerability"
        a.acknowledged = acknowledged
        a.details = {"cve_id": cve_id, "host_id": host_id}
        return a

    async def test_duplicate_unacknowledged_suppressed(self) -> None:
        """If an unacknowledged alert for same cve_id+host_id exists → skip."""
        m = _make_module()
        host = _make_host()
        vuln = _make_vuln(cvss_score=9.5, severity="critical")
        existing = self._make_existing_alert(
            cve_id=vuln.cve_id, host_id=str(host.id), acknowledged=False
        )
        db = _make_db(existing_alerts=[existing])

        with patch.object(m, "_notify", new_callable=AsyncMock):
            await m.on_vulnerability_found(vuln, host, db)

        db.add.assert_not_called()

    async def test_acknowledged_duplicate_allows_new_alert(self) -> None:
        """If the prior alert was acknowledged, fire a new one."""
        m = _make_module()
        host = _make_host()
        vuln = _make_vuln(cvss_score=9.5, severity="critical")
        acknowledged = self._make_existing_alert(
            cve_id=vuln.cve_id, host_id=str(host.id), acknowledged=True
        )
        db = _make_db(existing_alerts=[acknowledged])

        with patch.object(m, "_notify", new_callable=AsyncMock):
            await m.on_vulnerability_found(vuln, host, db)

        db.add.assert_called_once()

    async def test_different_host_not_suppressed(self) -> None:
        """An alert for the same CVE but a different host must still fire."""
        m = _make_module()
        host = _make_host()
        vuln = _make_vuln(cvss_score=9.5, severity="critical")
        # Existing alert is for a different host_id
        existing = self._make_existing_alert(
            cve_id=vuln.cve_id, host_id=str(uuid.uuid4()), acknowledged=False
        )
        db = _make_db(existing_alerts=[existing])

        with patch.object(m, "_notify", new_callable=AsyncMock):
            await m.on_vulnerability_found(vuln, host, db)

        db.add.assert_called_once()

    async def test_different_cve_not_suppressed(self) -> None:
        """A different CVE on the same host must still fire."""
        m = _make_module()
        host = _make_host()
        vuln = _make_vuln(cve_id="CVE-2024-99999", cvss_score=9.5)
        existing = self._make_existing_alert(
            cve_id="CVE-2024-11111", host_id=str(host.id), acknowledged=False
        )
        db = _make_db(existing_alerts=[existing])

        with patch.object(m, "_notify", new_callable=AsyncMock):
            await m.on_vulnerability_found(vuln, host, db)

        db.add.assert_called_once()


# ---------------------------------------------------------------------------
# Tests — host_label resolution
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
class TestHostLabelResolution:

    async def test_fqdn_used_when_present(self) -> None:
        m = _make_module()
        host = _make_host(fqdn="db.example.com", ip_addresses=["10.0.0.5"])
        vuln = _make_vuln(cvss_score=9.0)
        db = _make_db()

        with patch.object(m, "_notify", new_callable=AsyncMock):
            await m.on_vulnerability_found(vuln, host, db)

        msg = db.add.call_args[0][0].message
        assert "db.example.com" in msg

    async def test_ip_used_when_no_fqdn(self) -> None:
        m = _make_module()
        host = _make_host(fqdn=None, ip_addresses=["192.168.1.50"])
        vuln = _make_vuln(cvss_score=9.0)
        db = _make_db()

        with patch.object(m, "_notify", new_callable=AsyncMock):
            await m.on_vulnerability_found(vuln, host, db)

        msg = db.add.call_args[0][0].message
        assert "192.168.1.50" in msg

    async def test_host_id_used_when_no_fqdn_no_ip(self) -> None:
        m = _make_module()
        host = _make_host(fqdn=None, ip_addresses=[])
        vuln = _make_vuln(cvss_score=9.0)
        db = _make_db()

        with patch.object(m, "_notify", new_callable=AsyncMock):
            await m.on_vulnerability_found(vuln, host, db)

        msg = db.add.call_args[0][0].message
        assert str(host.id) in msg
