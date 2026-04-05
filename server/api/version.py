"""
Version API — /api/v1/version

GET  /api/v1/version         — server version + update availability
POST /api/v1/version/check   — force-refresh the update cache (operator JWT)
"""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends
from pydantic import BaseModel

from server.services.auth import require_operator
from server.services.version import MINIMUM_AGENT_VERSION, check_for_updates, current_version

router = APIRouter(prefix="/api/v1/version", tags=["version"])


class VersionOut(BaseModel):
    server_version: str
    latest_version: str | None
    update_available: bool
    minimum_agent_version: str


@router.get("", response_model=VersionOut)
async def get_version() -> VersionOut:
    """
    Return server version information.

    ``update_available`` is True when a newer GitHub release exists.
    This endpoint is unauthenticated so agents can query it before enrolling.
    """
    info = await check_for_updates()
    return VersionOut(
        server_version=info.current,
        latest_version=info.latest,
        update_available=info.update_available,
        minimum_agent_version=MINIMUM_AGENT_VERSION,
    )


@router.post("/check", response_model=VersionOut)
async def force_version_check(
    operator: Annotated[str, Depends(require_operator)],
) -> VersionOut:
    """Force a fresh update check (operator JWT required)."""
    info = await check_for_updates(timeout=10.0)
    return VersionOut(
        server_version=info.current,
        latest_version=info.latest,
        update_available=info.update_available,
        minimum_agent_version=MINIMUM_AGENT_VERSION,
    )
