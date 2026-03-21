"""
NetBox API — /api/v1/netbox

Exposes controls for the NetBox integration module.

  GET  /api/v1/netbox/status   — integration status + last import info
  POST /api/v1/netbox/import   — pull data FROM NetBox into local inventory
  POST /api/v1/netbox/sync     — push local inventory TO NetBox
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession

from server.database import get_db
from server.modules.registry import registry

router = APIRouter(prefix="/api/v1/netbox", tags=["netbox"])


def _get_module():
    module = registry.get_module("builtin-netbox")
    if module is None:
        raise HTTPException(status_code=503, detail="NetBox module not loaded")
    return module


@router.get("/status")
async def netbox_status() -> dict:
    """Returns integration status, connectivity, and last import metadata."""
    module = registry.get_module("builtin-netbox")
    if module is None:
        return {"enabled": False, "reason": "Module not loaded"}

    m = module  # type: ignore[attr-defined]
    enabled = m._ready
    return {
        "enabled": enabled,
        "url": m._url if enabled else None,
        "last_import_at": m.last_import_at.isoformat() if m.last_import_at else None,
        "last_import_counts": m.last_import_counts,
    }


@router.post("/import")
async def trigger_import(db: AsyncSession = Depends(get_db)) -> dict:
    """
    Pull all data FROM NetBox into the local inventory.

    Imports:
      - ipam/prefixes/      → Network records
      - ipam/ip-addresses/  → Host records
      - dcim/devices/       → NetworkDevice records
      - dcim/interfaces/    → NetworkInterface records

    Safe to run multiple times — existing records are updated, not duplicated.
    """
    module = _get_module()

    try:
        result = await module.import_from_netbox(db)  # type: ignore[attr-defined]
    except Exception as exc:
        raise HTTPException(status_code=503, detail=f"Import failed: {exc}") from exc

    if "error" in result:
        raise HTTPException(status_code=503, detail=result.get("message", "Import failed"))

    await db.commit()

    from datetime import datetime
    module.last_import_at = datetime.utcnow()  # type: ignore[attr-defined]
    module.last_import_counts = result  # type: ignore[attr-defined]

    return {"imported": result}


@router.post("/sync")
async def trigger_full_sync(db: AsyncSession = Depends(get_db)) -> dict:
    """
    Push local inventory TO NetBox.
    Returns counts of synced objects per type.
    """
    module = _get_module()

    try:
        result = await module.full_sync(db)  # type: ignore[attr-defined]
    except Exception as exc:
        raise HTTPException(status_code=503, detail=f"Sync failed: {exc}") from exc

    if "error" in result:
        raise HTTPException(status_code=503, detail=result.get("message", "Sync failed"))

    return {"synced": result}
