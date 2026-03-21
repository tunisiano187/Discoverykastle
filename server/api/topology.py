"""
Topology API — /api/v1/topology
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, Query, Response
from sqlalchemy.ext.asyncio import AsyncSession

from server.database import get_db
from server.modules.registry import registry

router = APIRouter(prefix="/api/v1/topology", tags=["topology"])


@router.get("/graph")
async def get_topology_graph(db: AsyncSession = Depends(get_db)) -> dict:
    """
    Returns the network topology graph in Cytoscape.js format:
      { "nodes": [...], "target": [...] }
    """
    topology_module = registry.get_module("builtin-topology")
    if topology_module is None:
        return {"nodes": [], "edges": [], "error": "Topology module not loaded"}

    return await topology_module.build_graph(db)  # type: ignore[attr-defined]


@router.get("/export/markdown")
async def export_network_plan_markdown(db: AsyncSession = Depends(get_db)) -> Response:
    """Download the full network plan as a Markdown document."""
    content = await registry.collect_export("markdown", db)
    if content is None:
        content = "_No topology data available yet._"
    return Response(
        content=content,
        media_type="text/markdown",
        headers={"Content-Disposition": "attachment; filename=network-plan.md"},
    )
