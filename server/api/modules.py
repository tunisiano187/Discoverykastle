"""
Modules management API — /api/v1/modules

Allows operators to list loaded modules and their metadata.
"""

from __future__ import annotations

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

from server.modules.registry import registry

router = APIRouter(prefix="/api/v1/modules", tags=["modules"])


class ModuleOut(BaseModel):
    name: str
    version: str
    description: str
    author: str
    capabilities: list[str]
    builtin: bool


@router.get("/", response_model=list[ModuleOut])
async def list_modules() -> list[dict]:
    """List all loaded modules with their metadata."""
    return registry.list_modules()


@router.get("/{name}", response_model=ModuleOut)
async def get_module(name: str) -> dict:
    module = registry.get_module(name)
    if module is None:
        raise HTTPException(status_code=404, detail=f"Module '{name}' not found")
    return {
        "name": module.manifest.name,
        "version": module.manifest.version,
        "description": module.manifest.description,
        "author": module.manifest.author,
        "capabilities": [c.value for c in module.manifest.capabilities],
        "builtin": module.manifest.builtin,
    }
