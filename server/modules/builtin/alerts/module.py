"""
Built-in Alerts module.

Generates alerts for:
  - Critical / high CVEs (CVSS ≥ 9.0 → critical, ≥ 7.0 → high)
  - Agent going offline
  - First-time discovery of a new host
  - First-time discovery of a new network segment
  - Scan failure

Alerts are persisted in the `alerts` table and optionally forwarded to
notification channels (SMTP, Slack, generic webhook) via the NotificationService.
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Any

from server.models.alert import Alert, AlertType
from server.modules.base import BaseModule, ModuleCapability, ModuleManifest

if TYPE_CHECKING:
    from sqlalchemy.ext.asyncio import AsyncSession
    from server.models import Host, Vulnerability, NetworkDevice, Network, ScanResult

logger = logging.getLogger(__name__)


class Module(BaseModule):
    manifest = ModuleManifest(
        name="builtin-alerts",
        version="1.0.0",
        description="Core alert engine: CVEs, agent offline, new hosts, scan failures.",
        author="Discoverykastle",
        capabilities=[ModuleCapability.ALERT],
        builtin=True,
    )

    # ------------------------------------------------------------------
    # Event hooks
    # ------------------------------------------------------------------

    async def on_vulnerability_found(
        self, vuln: "Vulnerability", host: "Host", db: "AsyncSession"
    ) -> None:
        score = vuln.cvss_score or 0.0
        if score >= 9.0:
            severity = "critical"
        elif score >= 7.0:
            severity = "high"
        else:
            return  # Only alert on high/critical by default

        host_label = host.fqdn or (host.ip_addresses[0] if host.ip_addresses else str(host.id))
        await self._create_alert(
            db,
            severity=severity,
            alert_type=AlertType.VULNERABILITY,
            message=f"{vuln.cve_id} (CVSS {score:.1f}) found on {host_label}",
            details={
                "cve_id": vuln.cve_id,
                "cvss_score": score,
                "host_id": str(host.id),
                "host_label": host_label,
                "description": vuln.description,
                "remediation": vuln.remediation,
            },
        )

    async def on_agent_offline(self, agent_id: str, db: "AsyncSession") -> None:
        await self._create_alert(
            db,
            severity="high",
            alert_type=AlertType.AGENT_OFFLINE,
            message=f"Agent {agent_id} has gone offline (missed heartbeats).",
            details={"agent_id": agent_id},
        )

    async def on_host_discovered(self, host: "Host", db: "AsyncSession") -> None:
        host_label = host.fqdn or (host.ip_addresses[0] if host.ip_addresses else str(host.id))
        await self._create_alert(
            db,
            severity="info",
            alert_type=AlertType.NEW_HOST,
            message=f"New host discovered: {host_label}",
            details={
                "host_id": str(host.id),
                "ip_addresses": host.ip_addresses,
                "os": host.os,
            },
        )

    async def on_network_discovered(self, network: "Network", db: "AsyncSession") -> None:
        label = network.description or network.cidr
        await self._create_alert(
            db,
            severity="info",
            alert_type=AlertType.NEW_NETWORK,
            message=f"New network segment discovered: {label} ({network.cidr})",
            details={
                "network_id": str(network.id),
                "cidr": network.cidr,
                "scan_authorized": network.scan_authorized,
            },
        )

    async def on_scan_complete(self, result: "ScanResult", db: "AsyncSession") -> None:
        if result.completed_at is None:
            # Scan timed out or failed
            await self._create_alert(
                db,
                severity="medium",
                alert_type=AlertType.SCAN_FAILED,
                message=f"Scan {result.id} did not complete successfully.",
                details={"scan_result_id": str(result.id), "agent_id": str(result.agent_id)},
            )

    # ------------------------------------------------------------------
    # Internal helper
    # ------------------------------------------------------------------

    async def _create_alert(
        self,
        db: "AsyncSession",
        severity: str,
        alert_type: AlertType,
        message: str,
        details: dict[str, Any],
    ) -> None:
        from datetime import datetime

        alert = Alert(
            severity=severity,
            alert_type=alert_type.value,
            message=message,
            source=self.manifest.name,
            details=details,
            created_at=datetime.utcnow(),
        )
        db.add(alert)
        await db.flush()
        self.logger.info("[%s] %s — %s", severity.upper(), alert_type.value, message)

        await self._notify(severity, message, details)

    async def _notify(
        self, severity: str, message: str, details: dict[str, Any]
    ) -> None:
        """Forward to configured notification channels."""
        from server.config import settings
        import httpx

        payload = {"severity": severity, "message": message, "details": details}

        if settings.slack_webhook_url and severity in ("critical", "high"):
            try:
                emoji = ":rotating_light:" if severity == "critical" else ":warning:"
                async with httpx.AsyncClient(timeout=5) as client:
                    await client.post(
                        settings.slack_webhook_url,
                        json={"text": f"{emoji} *[{severity.upper()}]* {message}"},
                    )
            except Exception:
                self.logger.warning("Failed to send Slack notification")

        if settings.generic_webhook_url:
            try:
                async with httpx.AsyncClient(timeout=5) as client:
                    await client.post(settings.generic_webhook_url, json=payload)
            except Exception:
                self.logger.warning("Failed to send generic webhook notification")

        if settings.webpush_enabled:
            try:
                from server.services.webpush import get_service
                await get_service().notify_alert(
                    severity=severity,
                    message=message,
                    alert_type=payload.get("details", {}).get("alert_type", "alert"),
                )
            except Exception:
                self.logger.warning("Failed to send Web Push notification")
