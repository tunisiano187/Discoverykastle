"""
Web Push API — /api/v1/webpush

  GET  /vapid-key         Return the VAPID public key for the browser to subscribe.
  POST /subscribe         Register a push subscription.
  POST /unsubscribe       Remove a push subscription.
  GET  /status            Return subscription count and enabled state.
"""

from __future__ import annotations

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from typing import Any

from server.services.webpush import get_service

router = APIRouter(prefix="/api/v1/webpush", tags=["webpush"])


class SubscribeRequest(BaseModel):
    endpoint: str
    expirationTime: Any = None
    keys: dict[str, str] = {}


class UnsubscribeRequest(BaseModel):
    endpoint: str


@router.get("/vapid-key")
async def vapid_key() -> dict[str, str]:
    """
    Return the VAPID application server public key.
    The browser needs this to create a valid PushSubscription.
    """
    from server.config import settings

    if not settings.webpush_enabled or not settings.vapid_public_key:
        raise HTTPException(
            status_code=503,
            detail="Web Push is not enabled or VAPID keys are not configured.",
        )
    return {"public_key": settings.vapid_public_key}


@router.post("/subscribe", status_code=201)
async def subscribe(body: SubscribeRequest) -> dict[str, str]:
    """Register or refresh a browser push subscription."""
    from server.config import settings

    if not settings.webpush_enabled:
        raise HTTPException(status_code=503, detail="Web Push is not enabled.")

    sub_id = await get_service().subscribe({
        "endpoint": body.endpoint,
        "expirationTime": body.expirationTime,
        "keys": body.keys,
    })
    return {"id": sub_id, "status": "subscribed"}


@router.post("/unsubscribe")
async def unsubscribe(body: UnsubscribeRequest) -> dict[str, str]:
    """Remove a push subscription."""
    await get_service().unsubscribe(body.endpoint)
    return {"status": "unsubscribed"}


@router.get("/status")
async def status() -> dict[str, Any]:
    """Return current Web Push configuration state."""
    from server.config import settings

    svc = get_service()
    return {
        "enabled": settings.webpush_enabled,
        "vapid_public_key": settings.vapid_public_key or None,
        "min_severity": settings.webpush_min_severity,
        "subscription_count": svc.subscription_count() if settings.webpush_enabled else 0,
    }
