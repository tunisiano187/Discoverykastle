"""
NetBox API — /api/v1/netbox

Exposes controls for the NetBox integration module.
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession

from server.database import get_db
from server.modules.registry import registry

router = APIRouter(prefix="/api/v1/netbox", tags=["netbox"])


@router.get("/status")
async def netbox_status() -> dict:
    """Returns whether the NetBox integration is active and reachable."""
    module = registry.get_module("builtin-netbox")
    if module is None:
        return {"enabled": False, "reason": "Module not loaded"}

    enabled = module._ready  # type: ignore[attr-defined]
    return {
        "enabled": enabled,
        "url": module._url if enabled else None,  # type: ignore[attr-defined]
    }


@router.post("/sync")
async def trigger_full_sync(db: AsyncSession = Depends(get_db)) -> dict:
    """
    Trigger a full sync of all discovered inventory to NetBox.
    Returns counts of synced objects per type.
    """
    module = registry.get_module("builtin-netbox")
    if module is None:
        raise HTTPException(status_code=503, detail="NetBox module not loaded")

    result = await module.full_sync(db)  # type: ignore[attr-defined]

    if "error" in result:
        raise HTTPException(status_code=503, detail=result.get("message", "Sync failed"))

    return {"synced": result}
