"""
Agent management API — /api/v1/agents

Registration (no JWT — uses one-time enrollment token):
  POST /api/v1/agents/register

Heartbeat (mTLS — agent cert fingerprint in header):
  POST /api/v1/agents/{id}/heartbeat

Operator endpoints (JWT required):
  GET    /api/v1/agents
  GET    /api/v1/agents/{id}
  DELETE /api/v1/agents/{id}
  POST   /api/v1/agents/{id}/tasks
  GET    /api/v1/agents/{id}/tasks
"""

from __future__ import annotations

import logging
import uuid
from datetime import datetime
from typing import Annotated, Any

from fastapi import APIRouter, Depends, Header, HTTPException, status
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from server.database import get_db
from server.models.agent import Agent, AuditLog
from server.services.auth import require_operator
from server.services.ca import ca

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/agents", tags=["agents"])


# ------------------------------------------------------------------
# Schemas
# ------------------------------------------------------------------

class RegisterRequest(BaseModel):
    hostname: str | None = None
    ip_address: str | None = None
    os_platform: str | None = None
    os_version: str | None = None
    agent_version: str | None = None


class RegisterResponse(BaseModel):
    agent_id: str
    certificate: str
    private_key: str
    ca_certificate: str


class AgentOut(BaseModel):
    id: uuid.UUID
    hostname: str | None
    ip_address: str | None
    version: str | None
    status: str
    authorized_cidrs: list[str]
    last_heartbeat: datetime | None
    created_at: datetime

    class Config:
        from_attributes = True


class HeartbeatResponse(BaseModel):
    ok: bool
    # Server version — lets the agent know what version of the server it is talking to
    server_version: str
    # True when the agent's reported version is below MINIMUM_AGENT_VERSION.
    # The agent should call its self-update routine and reconnect.
    agent_update_required: bool
    # Pip install target to use when updating (e.g. "discoverykastle-agent==0.2.0").
    # None means "upgrade to latest".
    agent_update_target: str | None = None


class TaskIn(BaseModel):
    action: str
    params: dict[str, Any] = {}
    timeout_seconds: int = 600
    max_attempts: int = 3


class TaskOut(BaseModel):
    task_id: str
    action: str
    params: dict[str, Any]
    status: str
    attempt: int = 1
    max_attempts: int = 3
    created_at: datetime | None = None


# ------------------------------------------------------------------
# Enrollment token validation
# ------------------------------------------------------------------

def _validate_enrollment_token(authorization: str | None) -> None:
    """
    Validate the enrollment token sent by the agent.

    The agent sends: ``Authorization: Bearer <token>``
    We compare this against ``DKASTLE_ENROLL_TOKEN`` from settings.
    """
    from server.config import settings

    if not settings.enroll_token:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=(
                "No enrollment token configured. "
                "Set DKASTLE_ENROLL_TOKEN in your server configuration."
            ),
        )

    if authorization is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing Authorization header",
        )

    scheme, _, token = authorization.partition(" ")
    if scheme.lower() != "bearer" or token != settings.enroll_token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid enrollment token",
        )


# ------------------------------------------------------------------
# Routes
# ------------------------------------------------------------------

@router.post("/register", response_model=RegisterResponse, status_code=201)
async def register_agent(
    body: RegisterRequest,
    authorization: Annotated[str | None, Header()] = None,
    db: AsyncSession = Depends(get_db),
) -> RegisterResponse:
    """
    Register a new agent with the server.

    The agent must supply a valid enrollment token in the ``Authorization``
    header.  On success the server returns a unique x.509 certificate signed
    by the embedded CA plus the CA certificate itself so the agent can verify
    future server-TLS connections.

    The private key is generated server-side and returned *once* — it is never
    stored on the server.
    """
    _validate_enrollment_token(authorization)

    # Create DB record first to get a stable UUID for the certificate CN
    agent = Agent(
        certificate_fingerprint="pending",  # updated below
        hostname=body.hostname,
        ip_address=body.ip_address,
        version=body.agent_version,
        status="online",
    )
    db.add(agent)
    await db.flush()  # populate agent.id without committing

    # Issue certificate
    issued = ca.issue(str(agent.id))
    fingerprint = ca.fingerprint(issued.cert_pem)

    agent.certificate_fingerprint = fingerprint
    await db.commit()
    await db.refresh(agent)

    # Audit
    audit = AuditLog(
        agent_id=agent.id,
        action="agent_registered",
        target=str(agent.id),
        params={
            "hostname": body.hostname,
            "ip_address": body.ip_address,
            "os_platform": body.os_platform,
            "agent_version": body.agent_version,
        },
        result="success",
    )
    db.add(audit)
    await db.commit()

    logger.info(
        "Agent registered: id=%s hostname=%s ip=%s",
        agent.id, body.hostname, body.ip_address,
    )

    return RegisterResponse(
        agent_id=str(agent.id),
        certificate=issued.cert_pem,
        private_key=issued.key_pem,
        ca_certificate=ca.root_cert_pem,
    )


class HeartbeatRequest(BaseModel):
    """Optional body sent by the agent with its current version."""
    agent_version: str | None = None


@router.post("/{agent_id}/heartbeat", response_model=HeartbeatResponse)
async def heartbeat(
    agent_id: uuid.UUID,
    body: HeartbeatRequest = HeartbeatRequest(),
    x_agent_fingerprint: Annotated[str | None, Header(alias="X-Agent-Fingerprint")] = None,
    x_agent_id: Annotated[str | None, Header(alias="X-Agent-ID")] = None,
    db: AsyncSession = Depends(get_db),
) -> HeartbeatResponse:
    """
    Update the agent's last-heartbeat timestamp and mark it online.

    Authentication is via the mTLS certificate fingerprint forwarded by the
    TLS termination layer (Nginx) in the ``X-Agent-Fingerprint`` header, or
    the ``X-Agent-ID`` header as a fallback during initial rollout.
    """
    agent = await _resolve_agent(db, agent_id, x_agent_fingerprint, x_agent_id)

    # Update stored version if the agent reports it in the heartbeat body.
    if body.agent_version and body.agent_version != agent.version:
        agent.version = body.agent_version

    agent.last_heartbeat = datetime.utcnow()
    agent.status = "online"
    await db.commit()

    from server.services.version import agent_needs_update, current_version

    needs_update = agent_needs_update(agent.version)
    logger.debug("Heartbeat from agent %s (update_required=%s)", agent_id, needs_update)
    return HeartbeatResponse(
        ok=True,
        server_version=current_version(),
        agent_update_required=needs_update,
    )


@router.get("", response_model=list[AgentOut])
async def list_agents(
    operator: Annotated[str, Depends(require_operator)],
    db: AsyncSession = Depends(get_db),
) -> list[Agent]:
    """List all registered agents (operator JWT required)."""
    result = await db.execute(select(Agent).order_by(Agent.created_at.desc()))
    return list(result.scalars())


@router.get("/{agent_id}", response_model=AgentOut)
async def get_agent(
    agent_id: uuid.UUID,
    operator: Annotated[str, Depends(require_operator)],
    db: AsyncSession = Depends(get_db),
) -> Agent:
    """Return a single agent by ID (operator JWT required)."""
    agent = await db.get(Agent, agent_id)
    if not agent:
        raise HTTPException(status_code=404, detail="Agent not found")
    return agent


@router.delete("/{agent_id}", status_code=204)
async def deregister_agent(
    agent_id: uuid.UUID,
    operator: Annotated[str, Depends(require_operator)],
    db: AsyncSession = Depends(get_db),
) -> None:
    """
    Revoke and delete an agent (operator JWT required).

    This marks the agent as revoked in the audit log.  The certificate is
    not added to a CRL in this implementation but can be extended to do so.
    """
    agent = await db.get(Agent, agent_id)
    if not agent:
        raise HTTPException(status_code=404, detail="Agent not found")

    audit = AuditLog(
        agent_id=agent_id,
        user_id=operator,
        action="agent_deregistered",
        target=str(agent_id),
        params={"hostname": agent.hostname},
        result="success",
    )
    db.add(audit)
    await db.delete(agent)
    await db.commit()

    logger.info("Agent %s deregistered by operator %s", agent_id, operator)


@router.post("/{agent_id}/tasks", response_model=TaskOut, status_code=202)
async def dispatch_task(
    agent_id: uuid.UUID,
    body: TaskIn,
    operator: Annotated[str, Depends(require_operator)],
    db: AsyncSession = Depends(get_db),
) -> TaskOut:
    """
    Dispatch a task to an agent (operator JWT required).

    Creates a persistent :class:`~server.models.task.AgentTask` record and
    enqueues the task to the agent's Redis Stream.  The agent picks it up via
    its persistent WebSocket connection and sends back a ``task_result``
    message when done.
    """
    agent = await db.get(Agent, agent_id)
    if not agent:
        raise HTTPException(status_code=404, detail="Agent not found")

    from server.services.task import create_task

    task = await create_task(
        db,
        agent_id,
        body.action,
        body.params,
        operator=operator,
        timeout_seconds=body.timeout_seconds,
        max_attempts=body.max_attempts,
    )

    audit = AuditLog(
        agent_id=agent_id,
        user_id=operator,
        action="task_dispatched",
        target=str(task.id),
        params={"task_id": str(task.id), "action": body.action, "params": body.params},
        result="queued",
    )
    db.add(audit)
    await db.commit()

    logger.info("Task %s dispatched to agent %s by %s", task.id, agent_id, operator)

    return TaskOut(
        task_id=str(task.id),
        action=task.action,
        params=task.params,
        status=task.status,
        attempt=task.attempt,
        max_attempts=task.max_attempts,
        created_at=task.created_at,
    )


@router.get("/{agent_id}/tasks", response_model=list[TaskOut])
async def list_agent_tasks(
    agent_id: uuid.UUID,
    operator: Annotated[str, Depends(require_operator)],
    status_filter: str | None = None,
    limit: int = 50,
    db: AsyncSession = Depends(get_db),
) -> list[TaskOut]:
    """
    List tasks for an agent, ordered newest-first (operator JWT required).

    Query params:
    - ``status``: filter by status (e.g. ``queued``, ``dispatched``, ``completed``)
    - ``limit``: max results (default 50)
    """
    from sqlalchemy import select as sa_select, desc

    agent = await db.get(Agent, agent_id)
    if not agent:
        raise HTTPException(status_code=404, detail="Agent not found")

    from server.models.task import AgentTask

    q = sa_select(AgentTask).where(AgentTask.agent_id == agent_id)
    if status_filter:
        q = q.where(AgentTask.status == status_filter)
    q = q.order_by(desc(AgentTask.created_at)).limit(limit)

    rows = await db.execute(q)
    return [
        TaskOut(
            task_id=str(t.id),
            action=t.action,
            params=t.params,
            status=t.status,
            attempt=t.attempt,
            max_attempts=t.max_attempts,
            created_at=t.created_at,
        )
        for t in rows.scalars()
    ]


# ------------------------------------------------------------------
# Internal helpers
# ------------------------------------------------------------------

async def _resolve_agent(
    db: AsyncSession,
    agent_id: uuid.UUID,
    fingerprint: str | None,
    header_agent_id: str | None,
) -> Agent:
    """
    Resolve and authenticate the calling agent.

    Prefers fingerprint verification; falls back to UUID header match.
    """
    agent = await db.get(Agent, agent_id)
    if not agent:
        raise HTTPException(status_code=404, detail="Agent not found")

    if fingerprint:
        if agent.certificate_fingerprint != fingerprint:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Certificate fingerprint mismatch",
            )
        return agent

    if header_agent_id:
        try:
            if uuid.UUID(header_agent_id) == agent_id:
                return agent
        except ValueError:
            pass

    # No fingerprint or ID header — allow during dev when mTLS is not terminated
    # by Nginx (e.g. direct uvicorn access).  Log a warning.
    logger.warning(
        "Heartbeat from agent %s accepted without cert verification "
        "(no X-Agent-Fingerprint or X-Agent-ID header). "
        "Configure Nginx mTLS termination in production.",
        agent_id,
    )
    return agent
