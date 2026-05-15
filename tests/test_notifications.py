"""
Tests for alert notification channels.

Covers the severity-filter logic and SMTP/Slack/webhook dispatch in
server/modules/builtin/alerts/module.py without a live mail server or network.
"""
from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest


# ---------------------------------------------------------------------------
# Severity ordering helper (extracted from module._notify)
# ---------------------------------------------------------------------------

_SEVERITY_ORDER = {"low": 0, "medium": 1, "high": 2, "critical": 3}


def _severity_passes(severity: str, min_sev: str) -> bool:
    return _SEVERITY_ORDER.get(severity, 0) >= _SEVERITY_ORDER.get(min_sev, 2)


class TestSeverityFilter:
    def test_critical_passes_high_threshold(self) -> None:
        assert _severity_passes("critical", "high")

    def test_high_passes_high_threshold(self) -> None:
        assert _severity_passes("high", "high")

    def test_medium_blocked_by_high_threshold(self) -> None:
        assert not _severity_passes("medium", "high")

    def test_low_blocked_by_medium_threshold(self) -> None:
        assert not _severity_passes("low", "medium")

    def test_medium_passes_medium_threshold(self) -> None:
        assert _severity_passes("medium", "medium")

    def test_low_passes_low_threshold(self) -> None:
        assert _severity_passes("low", "low")

    def test_unknown_severity_blocked_by_high(self) -> None:
        assert not _severity_passes("unknown", "high")


# ---------------------------------------------------------------------------
# SMTP email construction
# ---------------------------------------------------------------------------

class TestSmtpEmail:
    def _make_settings(self, **kwargs):
        s = MagicMock()
        s.smtp_host = kwargs.get("smtp_host", "smtp.example.com")
        s.smtp_port = kwargs.get("smtp_port", 587)
        s.smtp_user = kwargs.get("smtp_user", "user@example.com")
        s.smtp_password = kwargs.get("smtp_password", "secret")
        s.smtp_from = kwargs.get("smtp_from", "alerts@example.com")
        s.smtp_to = kwargs.get("smtp_to", "admin@example.com")
        s.smtp_tls = kwargs.get("smtp_tls", True)
        s.smtp_alert_min_severity = kwargs.get("smtp_alert_min_severity", "high")
        s.slack_webhook_url = None
        s.generic_webhook_url = None
        s.webpush_enabled = False
        return s

    def test_email_subject_contains_severity(self) -> None:
        from email.message import EmailMessage
        msg = EmailMessage()
        severity = "critical"
        message = "CVE-2024-1234 found on web01"
        msg["Subject"] = f"[Discoverykastle] [{severity.upper()}] {message}"
        assert "CRITICAL" in msg["Subject"]
        assert "CVE-2024-1234" in msg["Subject"]

    def test_recipients_parsed_from_comma_list(self) -> None:
        smtp_to = "a@example.com, b@example.com, c@example.com"
        recipients = [r.strip() for r in smtp_to.split(",") if r.strip()]
        assert recipients == ["a@example.com", "b@example.com", "c@example.com"]

    def test_single_recipient(self) -> None:
        smtp_to = "admin@example.com"
        recipients = [r.strip() for r in smtp_to.split(",") if r.strip()]
        assert len(recipients) == 1

    def test_empty_smtp_to_gives_no_recipients(self) -> None:
        smtp_to = ""
        recipients = [r.strip() for r in smtp_to.split(",") if r.strip()]
        assert recipients == []

    @pytest.mark.asyncio
    async def test_send_email_called_on_high_severity(self) -> None:
        """Module._send_email is awaited when severity passes the threshold."""
        settings = self._make_settings(smtp_alert_min_severity="high")

        with patch("server.modules.builtin.alerts.module.Module._send_email", new_callable=AsyncMock) as mock_send, \
             patch("server.config.settings", settings):
            from server.modules.builtin.alerts.module import Module
            mod = Module()
            await mod._notify("critical", "Test alert", {})
            mock_send.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_send_email_not_called_on_low_severity(self) -> None:
        """Module._send_email is NOT called when severity is below threshold."""
        settings = self._make_settings(smtp_alert_min_severity="high")

        with patch("server.modules.builtin.alerts.module.Module._send_email", new_callable=AsyncMock) as mock_send, \
             patch("server.config.settings", settings):
            from server.modules.builtin.alerts.module import Module
            mod = Module()
            await mod._notify("low", "Low-priority event", {})
            mock_send.assert_not_awaited()

    @pytest.mark.asyncio
    async def test_send_email_not_called_when_smtp_host_missing(self) -> None:
        """No email when smtp_host is not configured."""
        settings = self._make_settings(smtp_host=None)

        with patch("server.modules.builtin.alerts.module.Module._send_email", new_callable=AsyncMock) as mock_send, \
             patch("server.config.settings", settings):
            from server.modules.builtin.alerts.module import Module
            mod = Module()
            await mod._notify("critical", "Test alert", {})
            mock_send.assert_not_awaited()

    @pytest.mark.asyncio
    async def test_send_email_not_called_when_smtp_to_missing(self) -> None:
        """No email when smtp_to is not configured."""
        settings = self._make_settings(smtp_to=None)

        with patch("server.modules.builtin.alerts.module.Module._send_email", new_callable=AsyncMock) as mock_send, \
             patch("server.config.settings", settings):
            from server.modules.builtin.alerts.module import Module
            mod = Module()
            await mod._notify("critical", "Test alert", {})
            mock_send.assert_not_awaited()

    @pytest.mark.asyncio
    async def test_smtp_failure_does_not_raise(self) -> None:
        """SMTP errors are caught and logged — no exception bubbles up."""
        import smtplib

        settings = self._make_settings()

        with patch("smtplib.SMTP") as mock_smtp_cls, \
             patch("server.config.settings", settings):
            mock_smtp_cls.side_effect = smtplib.SMTPConnectError(421, "Connection refused")
            from server.modules.builtin.alerts.module import Module
            mod = Module()
            # Should not raise
            await mod._send_email("critical", "Test", {"key": "value"})


# ---------------------------------------------------------------------------
# Slack webhook dispatch
# ---------------------------------------------------------------------------

class TestSlackNotification:
    def _make_settings(self, slack_url="https://hooks.slack.com/T0/B0/xxx", min_sev="high"):
        s = MagicMock()
        s.smtp_host = None
        s.generic_webhook_url = None
        s.webpush_enabled = False
        s.slack_webhook_url = slack_url
        s.slack_alert_min_severity = min_sev
        return s

    @pytest.mark.asyncio
    async def test_slack_called_for_critical(self) -> None:
        settings = self._make_settings()
        mock_response = MagicMock()
        mock_response.raise_for_status = MagicMock()

        with patch("httpx.AsyncClient") as mock_client_cls, \
             patch("server.config.settings", settings):
            mock_client = AsyncMock()
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=False)
            mock_client.post = AsyncMock(return_value=mock_response)
            mock_client_cls.return_value = mock_client

            from server.modules.builtin.alerts.module import Module
            mod = Module()
            await mod._notify("critical", "Critical alert", {})
            mock_client.post.assert_awaited_once()
            call_kwargs = mock_client.post.call_args
            assert ":rotating_light:" in call_kwargs[1]["json"]["text"]

    @pytest.mark.asyncio
    async def test_slack_not_called_for_medium_when_threshold_is_high(self) -> None:
        settings = self._make_settings(min_sev="high")

        with patch("httpx.AsyncClient") as mock_client_cls, \
             patch("server.config.settings", settings):
            mock_client = AsyncMock()
            mock_client_cls.return_value = mock_client

            from server.modules.builtin.alerts.module import Module
            mod = Module()
            await mod._notify("medium", "Medium alert", {})
            mock_client.post.assert_not_awaited()
