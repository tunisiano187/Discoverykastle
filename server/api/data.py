"""
Data ingestion API — /api/v1/data

Endpoints used by agents to push collected data to the server.
All routes require mTLS authentication (certificate fingerprint in header
set by the TLS termination layer or Nginx upstream).

Puppet-specific endpoint:
  POST /api/v1/data/puppet
    Accepts a batch of Puppet node facts and last-run reports collected by
    the DK agent running on the Puppet server host.

    Data flow:
      Puppet agents → Puppet server (writes fact cache + reports to vardir)
      DK agent (on Puppet server) → reads those files → submits here

    The DK agent (agent/collectors/puppet.py) is NOT a Puppet agent.
    It reads the YAML files already written by Puppet agents to the Puppet
    server's vardir, converts them to JSON, and submits them here.
    The server-side Puppet module then upserts each node into the inventory.
"""

from __future__ import annotations

import uuid
import logging
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Header
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession

from server.database import get_db
from server.models.agent import Agent
from sqlalchemy import select

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/data", tags=["data-ingestion"])


# ---------------------------------------------------------------------------
# Auth helper — resolve agent from certificate fingerprint header
# ---------------------------------------------------------------------------

async def _get_agent(
    db: AsyncSession,
    x_agent_fingerprint: str | None,
    x_agent_id: str | None,
) -> Agent:
    """
    Resolve the calling agent.

    The TLS termination layer (Nginx / Uvicorn with mTLS) forwards either:
      X-Agent-Fingerprint: <sha256 of client cert>
      X-Agent-ID:          <agent UUID>

    We accept either header for flexibility during the initial rollout.
    """
    if x_agent_fingerprint:
        result = await db.execute(
            select(Agent).where(Agent.certificate_fingerprint == x_agent_fingerprint)
        )
        agent = result.scalar_one_or_none()
        if agent:
            return agent

    if x_agent_id:
        try:
            agent_uuid = uuid.UUID(x_agent_id)
            agent = await db.get(Agent, agent_uuid)
            if agent:
                return agent
        except ValueError:
            pass

    raise HTTPException(status_code=401, detail="Agent not authenticated")


# ---------------------------------------------------------------------------
# Puppet data ingestion
# ---------------------------------------------------------------------------

class PuppetReport(BaseModel):
    """Last-run report data for a single Puppet node."""
    last_run: str | None = None          # ISO-8601 timestamp
    status: str | None = None            # "changed" | "unchanged" | "failed"
    environment: str | None = None
    puppet_version: str | None = None
    config_version: str | None = None


class PuppetNode(BaseModel):
    """
    Facts + report for a single Puppet-managed node.

    `facts` is a flat or nested dict of Facter values — same structure as
    the YAML files in the Puppet master's fact cache, converted to JSON.
    `report` is optional (present when the agent also collected run reports).
    """
    certname: str
    facts: dict[str, Any] = {}
    report: PuppetReport | None = None


class PuppetBatch(BaseModel):
    """
    Batch of Puppet node data submitted by an agent.
    An agent typically sends one batch per sync cycle.
    """
    nodes: list[PuppetNode]


class PuppetBatchResult(BaseModel):
    received: int
    imported: int
    errors: int


@router.post("/puppet", response_model=PuppetBatchResult)
async def ingest_puppet_data(
    batch: PuppetBatch,
    db: AsyncSession = Depends(get_db),
    x_agent_fingerprint: str | None = Header(None, alias="X-Agent-Fingerprint"),
    x_agent_id: str | None = Header(None, alias="X-Agent-ID"),
) -> PuppetBatchResult:
    """
    Receive a batch of Puppet node facts and reports from a DK agent.

    The DK agent is deployed on the Puppet server host.  After Puppet agents
    have finished their runs and written facts + reports to the Puppet server's
    vardir, the DK agent reads those YAML files, converts them to JSON, and
    POSTs them here.

    Authentication: mTLS — the DK agent certificate fingerprint or UUID must
    match a registered agent in the database.
    """
    agent = await _get_agent(db, x_agent_fingerprint, x_agent_id)

    from server.modules.registry import registry
    puppet_module = registry.get_module("builtin-puppet")

    if puppet_module is None:
        raise HTTPException(
            status_code=503,
            detail="Puppet module is not loaded on this server.",
        )

    imported = 0
    errors = 0
    for node in batch.nodes:
        try:
            facts: dict[str, Any] = dict(node.facts)
            # Merge report metadata into facts under private keys
            if node.report:
                if node.report.last_run:
                    facts["_puppet_last_run"] = node.report.last_run
                if node.report.status:
                    facts["_puppet_status"] = node.report.status
                if node.report.environment:
                    facts["_puppet_environment"] = node.report.environment
                if node.report.puppet_version:
                    facts["_puppet_puppet_version"] = node.report.puppet_version
                if node.report.config_version:
                    facts["_puppet_config_version"] = node.report.config_version

            await puppet_module._upsert_host(node.certname, facts, db)  # type: ignore[attr-defined]
            imported += 1
        except Exception:
            logger.exception(
                "Failed to import Puppet node %s submitted by agent %s",
                node.certname, agent.id,
            )
            errors += 1

    await db.commit()

    logger.info(
        "Puppet batch from agent %s: %d received, %d imported, %d errors",
        agent.id, len(batch.nodes), imported, errors,
    )
    return PuppetBatchResult(
        received=len(batch.nodes),
        imported=imported,
        errors=errors,
    )
