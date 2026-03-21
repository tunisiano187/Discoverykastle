"""
Web Push notification service.

Manages VAPID-authenticated push subscriptions and dispatches browser
notifications when alerts are created.

Storage: push subscriptions are kept in a local JSON file
(DKASTLE_WEBPUSH_SUB_FILE, default: webpush_subscriptions.json).
Subscriptions are browser-scoped and transient — no DB table needed.

Requires: pip install 'discoverykastle-server[webpush]'
"""

from __future__ import annotations

import asyncio
import json
import logging
import time
import uuid
from pathlib import Path
from typing import Any

logger = logging.getLogger("dkastle.service.webpush")

# Severity order — used to filter which alerts trigger a push
_SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"]


def generate_vapid_keys() -> dict[str, str]:
    """
    Generate a new VAPID key pair using the `cryptography` library
    (already a platform dependency — no extra install required).

    Returns {"private_key": "<PEM>", "public_key": "<base64url>"}.
    """
    from cryptography.hazmat.primitives.asymmetric.ec import (
        generate_private_key, SECP256R1,
    )
    from cryptography.hazmat.primitives.serialization import (
        Encoding, PublicFormat, PrivateFormat, NoEncryption,
    )
    import base64

    key = generate_private_key(SECP256R1())

    private_pem = key.private_bytes(
        Encoding.PEM, PrivateFormat.TraditionalOpenSSL, NoEncryption()
    ).decode()

    # Application server key: uncompressed EC point, base64url-encoded, no padding
    pub_bytes = key.public_key().public_bytes(Encoding.X962, PublicFormat.UncompressedPoint)
    public_key = base64.urlsafe_b64encode(pub_bytes).rstrip(b"=").decode()

    return {"private_key": private_pem, "public_key": public_key}


class WebPushService:
    """
    Singleton service that holds subscriptions in memory (loaded from disk)
    and sends Web Push messages.
    """

    def __init__(self) -> None:
        from server.config import settings

        self._enabled: bool = settings.webpush_enabled
        self._private_key: str = settings.vapid_private_key
        self._public_key: str = settings.vapid_public_key
        self._email: str = settings.vapid_email
        self._sub_file: Path = Path(settings.webpush_sub_file)
        self._min_severity: str = settings.webpush_min_severity.lower()
        self._lock = asyncio.Lock()

    # ------------------------------------------------------------------
    # Subscription management
    # ------------------------------------------------------------------

    def _load(self) -> list[dict[str, Any]]:
        if self._sub_file.exists():
            try:
                return json.loads(self._sub_file.read_text(encoding="utf-8"))
            except Exception:
                logger.warning("Could not read subscription file %s — starting empty.", self._sub_file)
        return []

    def _save(self, subs: list[dict[str, Any]]) -> None:
        self._sub_file.write_text(json.dumps(subs, indent=2), encoding="utf-8")

    async def subscribe(self, subscription: dict[str, Any]) -> str:
        """Store a new subscription. Returns its internal id."""
        async with self._lock:
            subs = self._load()
            endpoint = subscription.get("endpoint", "")

            # Replace existing subscription for the same endpoint
            subs = [s for s in subs if s.get("endpoint") != endpoint]

            sub_id = str(uuid.uuid4())
            subs.append({
                "id": sub_id,
                "endpoint": endpoint,
                "expirationTime": subscription.get("expirationTime"),
                "keys": subscription.get("keys", {}),
                "created_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            })
            self._save(subs)
            logger.info(
                "Browser subscribed to push notifications.",
                extra={"action": "webpush_subscribe", "sub_id": sub_id,
                       "total_subs": len(subs)},
            )
            return sub_id

    async def unsubscribe(self, endpoint: str) -> None:
        async with self._lock:
            subs = self._load()
            before = len(subs)
            subs = [s for s in subs if s.get("endpoint") != endpoint]
            self._save(subs)
            if len(subs) < before:
                logger.info(
                    "Browser unsubscribed from push notifications.",
                    extra={"action": "webpush_unsubscribe", "total_subs": len(subs)},
                )

    def subscription_count(self) -> int:
        return len(self._load())

    # ------------------------------------------------------------------
    # Send
    # ------------------------------------------------------------------

    def _severity_passes(self, severity: str) -> bool:
        """Return True if severity >= configured minimum threshold."""
        try:
            return _SEVERITY_ORDER.index(severity) <= _SEVERITY_ORDER.index(self._min_severity)
        except ValueError:
            return True

    async def notify_alert(self, severity: str, message: str, alert_type: str) -> None:
        """
        Send a Web Push notification to all subscribed browsers.
        Called from builtin-alerts after an alert is persisted.
        """
        if not self._enabled:
            return
        if not self._private_key or not self._public_key:
            logger.warning(
                "Web Push enabled but VAPID keys are not configured. "
                "Generate them in the setup wizard.",
                extra={"action": "webpush_no_keys"},
            )
            return
        if not self._severity_passes(severity):
            return

        subs = self._load()
        if not subs:
            return

        payload = json.dumps({
            "title": f"[{severity.upper()}] Discoverykastle",
            "body": message,
            "severity": severity,
            "type": alert_type,
            "url": "/",
        })

        loop = asyncio.get_event_loop()
        failed: list[str] = []

        for sub in subs:
            try:
                await loop.run_in_executor(None, self._send_one, sub, payload)
            except Exception as exc:
                err = str(exc)
                logger.warning(
                    "Push notification failed for subscription %s: %s",
                    sub.get("id"), err,
                    extra={"action": "webpush_send_failed", "sub_id": sub.get("id"),
                           "reason": err},
                )
                # 404/410 = subscription expired/unsubscribed — clean it up
                if "404" in err or "410" in err:
                    failed.append(sub.get("endpoint", ""))

        if failed:
            async with self._lock:
                cleaned = [s for s in self._load() if s.get("endpoint") not in failed]
                self._save(cleaned)
                logger.info(
                    "Removed %d expired push subscriptions.", len(failed),
                    extra={"action": "webpush_cleanup", "removed": len(failed)},
                )

        logger.info(
            "Push notification sent to %d browser(s).",
            len(subs) - len(failed),
            extra={"action": "webpush_sent", "severity": severity,
                   "recipients": len(subs) - len(failed)},
        )

    def _send_one(self, sub: dict[str, Any], payload: str) -> None:
        """Blocking call — must be run in a thread executor."""
        try:
            from pywebpush import webpush  # type: ignore[import-untyped]
        except ImportError as exc:
            raise RuntimeError(
                "pywebpush is not installed. "
                "Run: pip install 'discoverykastle-server[webpush]'"
            ) from exc

        webpush(
            subscription_info={
                "endpoint": sub["endpoint"],
                "keys": sub.get("keys", {}),
            },
            data=payload,
            vapid_private_key=self._private_key,
            vapid_claims={"sub": f"mailto:{self._email}"},
            content_encoding="aes128gcm",
        )


# Module-level singleton — import and use directly
_service: WebPushService | None = None


def get_service() -> WebPushService:
    global _service
    if _service is None:
        _service = WebPushService()
    return _service
