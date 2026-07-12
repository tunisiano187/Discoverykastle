"""
Authorization Requests API — /api/v1/auth-requests

Agents submit authorization requests when they discover something that requires
operator approval before proceeding (recursive subnet scan, agent deployment on
a new host).  Operators approve or deny via this API.

Request types
-------------
recursive_scan  — agent found a new subnet and wants to scan it
deploy_agent    — agent found a new reachable host and wants to deploy an agent

Agent endpoints (X-Agent-ID or X-Agent-Fingerprint header required):
  POST   /api/v1/auth-requests          — create a new request

Operator endpoints (JWT operator+ required):
  GET    /api/v1/auth-requests          — list requests (filterable by status)
  GET    /api/v1/auth-requests/{id}     — get single request
  POST   /api/v1/auth-requests/{id}/approve — approve (may trigger follow-up task)
  POST   /api/v1/auth-requests/{id}/deny    — deny
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
from server.models.agent import Agent, AuditLog, AuthorizationRequest
from server.services.auth import require_operator

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/auth-requests", tags=["authorization-requests"])

_VALID_REQUEST_TYPES = {"recursive_scan", "deploy_agent"}
_VALID_STATUSES = {"pending", "approved", "denied", "expired"}


# ---------------------------------------------------------------------------
# Schemas
# ---------------------------------------------------------------------------


class AuthRequestIn(BaseModel):
    request_type: str
    details: dict[str, Any] = {}


class AuthRequestOut(BaseModel):
    id: uuid.UUID
    agent_id: uuid.UUID
    request_type: str
    details: dict[str, Any]
    status: str
    requested_at: datetime
    resolved_at: datetime | None = None
    resolved_by: str | None = None
    expires_at: datetime | None = None


class ResolveBody(BaseModel):
    notes: str | None = None


# ---------------------------------------------------------------------------
# Agent authentication helper
# ---------------------------------------------------------------------------


async def _require_agent(
    db: AsyncSession,
    x_agent_fingerprint: str | None,
    x_agent_id: str | None,
) -> Agent:
    if x_agent_fingerprint:
        result = await db.execute(
            select(Agent).where(Agent.certificate_fingerprint == x_agent_fingerprint)
        )
        agent = result.scalar_one_or_none()
        if agent:
            return agent

    if x_agent_id:
        try:
            agent = await db.get(Agent, uuid.UUID(x_agent_id))
            if agent:
                return agent
        except ValueError:
            pass

    raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Agent not authenticated")


# ---------------------------------------------------------------------------
# Agent → submit request
# ---------------------------------------------------------------------------


@router.post("", response_model=AuthRequestOut, status_code=201)
async def create_auth_request(
    body: AuthRequestIn,
    db: AsyncSession = Depends(get_db),
    x_agent_fingerprint: Annotated[str | None, Header(alias="X-Agent-Fingerprint")] = None,
    x_agent_id: Annotated[str | None, Header(alias="X-Agent-ID")] = None,
) -> AuthorizationRequest:
    """Submit an authorization request from an agent.

    The agent calls this when it discovers a new subnet (``recursive_scan``)
    or a new host that could receive an agent (``deploy_agent``).  The request
    stays ``pending`` until an operator approves or denies it.
    """
    agent = await _require_agent(db, x_agent_fingerprint, x_agent_id)

    if body.request_type not in _VALID_REQUEST_TYPES:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=f"request_type must be one of: {sorted(_VALID_REQUEST_TYPES)}",
        )

    req = AuthorizationRequest(
        agent_id=agent.id,
        request_type=body.request_type,
        details=body.details,
        status="pending",
    )
    db.add(req)
    await db.commit()
    await db.refresh(req)

    logger.info(
        "Auth request %s created by agent %s (type=%s)",
        req.id, agent.id, body.request_type,
    )
    return req


# ---------------------------------------------------------------------------
# Operator → list / get
# ---------------------------------------------------------------------------


@router.get("", response_model=list[AuthRequestOut])
async def list_auth_requests(
    operator: Annotated[str, Depends(require_operator)],
    db: AsyncSession = Depends(get_db),
    status_filter: str | None = None,
    limit: int = 100,
) -> list[AuthorizationRequest]:
    """List authorization requests, newest first.

    Query params:
    - ``status_filter``: filter by status (``pending``, ``approved``, ``denied``, ``expired``)
    - ``limit``: max results (default 100)
    """
    if status_filter and status_filter not in _VALID_STATUSES:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=f"status must be one of: {sorted(_VALID_STATUSES)}",
        )

    q = select(AuthorizationRequest).order_by(AuthorizationRequest.requested_at.desc()).limit(limit)
    if status_filter:
        q = q.where(AuthorizationRequest.status == status_filter)

    result = await db.execute(q)
    return list(result.scalars())


@router.get("/{request_id}", response_model=AuthRequestOut)
async def get_auth_request(
    request_id: uuid.UUID,
    operator: Annotated[str, Depends(require_operator)],
    db: AsyncSession = Depends(get_db),
) -> AuthorizationRequest:
    """Retrieve a single authorization request by ID."""
    req = await db.get(AuthorizationRequest, request_id)
    if not req:
        raise HTTPException(status_code=404, detail="Authorization request not found")
    return req


# ---------------------------------------------------------------------------
# Operator → approve
# ---------------------------------------------------------------------------


@router.post("/{request_id}/approve", response_model=AuthRequestOut)
async def approve_auth_request(
    request_id: uuid.UUID,
    body: ResolveBody = ResolveBody(),
    operator: Annotated[str, Depends(require_operator)] = ...,
    db: AsyncSession = Depends(get_db),
) -> AuthorizationRequest:
    """Approve a pending authorization request.

    For ``recursive_scan`` requests the server automatically dispatches a
    ``scan_network`` task to the requesting agent using the CIDR from the
    request details.

    For ``deploy_agent`` requests the server dispatches a ``deploy_agent``
    task with the target host details from the request.
    """
    req = await db.get(AuthorizationRequest, request_id)
    if not req:
        raise HTTPException(status_code=404, detail="Authorization request not found")
    if req.status != "pending":
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"Request is already {req.status}",
        )

    now = datetime.utcnow()
    req.status = "approved"
    req.resolved_at = now
    req.resolved_by = operator

    # Optionally store notes in details
    if body.notes:
        req.details = {**req.details, "_operator_notes": body.notes}

    # Trigger the corresponding task on the requesting agent
    await _dispatch_follow_up_task(db, req, operator)

    audit = AuditLog(
        agent_id=req.agent_id,
        user_id=operator,
        action="auth_request_approved",
        target=str(req.id),
        params={"request_type": req.request_type, "notes": body.notes},
        result="success",
    )
    db.add(audit)
    await db.commit()
    await db.refresh(req)

    logger.info(
        "Auth request %s approved by %s (type=%s)",
        req.id, operator, req.request_type,
    )
    return req


# ---------------------------------------------------------------------------
# Operator → deny
# ---------------------------------------------------------------------------


@router.post("/{request_id}/deny", response_model=AuthRequestOut)
async def deny_auth_request(
    request_id: uuid.UUID,
    body: ResolveBody = ResolveBody(),
    operator: Annotated[str, Depends(require_operator)] = ...,
    db: AsyncSession = Depends(get_db),
) -> AuthorizationRequest:
    """Deny a pending authorization request."""
    req = await db.get(AuthorizationRequest, request_id)
    if not req:
        raise HTTPException(status_code=404, detail="Authorization request not found")
    if req.status != "pending":
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"Request is already {req.status}",
        )

    now = datetime.utcnow()
    req.status = "denied"
    req.resolved_at = now
    req.resolved_by = operator

    if body.notes:
        req.details = {**req.details, "_operator_notes": body.notes}

    audit = AuditLog(
        agent_id=req.agent_id,
        user_id=operator,
        action="auth_request_denied",
        target=str(req.id),
        params={"request_type": req.request_type, "notes": body.notes},
        result="success",
    )
    db.add(audit)
    await db.commit()
    await db.refresh(req)

    logger.info(
        "Auth request %s denied by %s (type=%s)",
        req.id, operator, req.request_type,
    )
    return req


# ---------------------------------------------------------------------------
# Internal: dispatch follow-up task after approval
# ---------------------------------------------------------------------------


async def _dispatch_follow_up_task(
    db: AsyncSession,
    req: AuthorizationRequest,
    operator: str,
) -> None:
    """Queue the appropriate agent task when a request is approved."""
    from server.services.task import create_task

    try:
        if req.request_type == "recursive_scan":
            cidr = req.details.get("cidr")
            if not cidr:
                logger.warning(
                    "Auth request %s approved but details missing 'cidr' — no task queued",
                    req.id,
                )
                return
            depth = req.details.get("depth", 1)
            await create_task(
                db,
                req.agent_id,
                "scan_network",
                {"cidr": cidr, "depth": depth},
                operator=operator,
            )
            logger.info("Queued scan_network task for CIDR %s (auth request %s)", cidr, req.id)

        elif req.request_type == "deploy_agent":
            target_ip = req.details.get("target_ip")
            if not target_ip:
                logger.warning(
                    "Auth request %s approved but details missing 'target_ip' — no task queued",
                    req.id,
                )
                return
            await create_task(
                db,
                req.agent_id,
                "deploy_agent",
                {k: v for k, v in req.details.items() if not k.startswith("_")},
                operator=operator,
            )
            logger.info(
                "Queued deploy_agent task for %s (auth request %s)", target_ip, req.id
            )
    except Exception:
        logger.exception("Failed to dispatch follow-up task for auth request %s", req.id)
