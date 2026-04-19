"""
WebSocket endpoints for real-time agent task dispatch and dashboard updates.

Endpoints
---------
WS /api/v1/ws/agent/{agent_id}
    Persistent connection for an enrolled agent.  The server reads tasks from
    the agent's Redis Stream (``agent:{id}:tasks``) and forwards them over the
    socket.  The agent sends back task-result and heartbeat messages.

    Authentication: ``X-Agent-Fingerprint`` or ``X-Agent-ID`` request header
    (set by the TLS termination layer in production, sent directly in dev).

WS /api/v1/ws/dashboard
    Persistent connection for operator dashboards.  Receives real-time events
    (agent connect/disconnect, task updates).

    Authentication: ``?token=<JWT>`` query parameter or the raw JWT token as
    the first text message (for browsers that cannot set custom WS headers).
"""

from __future__ import annotations

import asyncio
import json
import logging
import uuid
from datetime import datetime
from typing import Any

from fastapi import APIRouter, Query, WebSocket, WebSocketDisconnect

from server.database import AsyncSessionLocal
from server.models.agent import Agent, AuditLog
from server.services.task import mark_dispatched, mark_result

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/ws", tags=["websocket"])


# ---------------------------------------------------------------------------
# Connection registry
# ---------------------------------------------------------------------------


class _ConnectionManager:
    """Asyncio-safe registry of active WebSocket connections."""

    def __init__(self) -> None:
        self._agents: dict[str, WebSocket] = {}
        self._dashboard: list[WebSocket] = []

    # --- Agent connections ---

    def register_agent(self, agent_id: str, ws: WebSocket) -> None:
        """Register a connected agent WebSocket."""
        self._agents[agent_id] = ws
        logger.info("Agent WS connected: %s  (active=%d)", agent_id, len(self._agents))

    def deregister_agent(self, agent_id: str) -> None:
        """Remove a disconnected agent."""
        self._agents.pop(agent_id, None)
        logger.info("Agent WS disconnected: %s  (active=%d)", agent_id, len(self._agents))

    def is_connected(self, agent_id: str) -> bool:
        """Return True if the agent has an active WebSocket connection."""
        return agent_id in self._agents

    def connected_agent_ids(self) -> list[str]:
        """Return IDs of all currently connected agents."""
        return list(self._agents.keys())

    async def send_to_agent(self, agent_id: str, message: dict[str, Any]) -> bool:
        """
        Send a JSON message to a specific agent.

        Returns True on success, False if the agent is not connected or the
        send fails (the agent is removed from the registry on failure).
        """
        ws = self._agents.get(agent_id)
        if ws is None:
            return False
        try:
            await ws.send_json(message)
            return True
        except Exception:
            self.deregister_agent(agent_id)
            return False

    # --- Dashboard connections ---

    def register_dashboard(self, ws: WebSocket) -> None:
        """Register a connected dashboard WebSocket."""
        self._dashboard.append(ws)
        logger.debug("Dashboard WS connected  (active=%d)", len(self._dashboard))

    def deregister_dashboard(self, ws: WebSocket) -> None:
        """Remove a disconnected dashboard client."""
        try:
            self._dashboard.remove(ws)
        except ValueError:
            pass
        logger.debug("Dashboard WS disconnected  (active=%d)", len(self._dashboard))

    async def broadcast(self, event: dict[str, Any]) -> None:
        """
        Broadcast a JSON event to all connected dashboard clients.

        Dead connections are removed from the registry automatically.
        """
        dead: list[WebSocket] = []
        for ws in list(self._dashboard):
            try:
                await ws.send_json(event)
            except Exception:
                dead.append(ws)
        for ws in dead:
            self.deregister_dashboard(ws)


#: Module-level singleton — imported by other modules that need to push events.
manager = _ConnectionManager()


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


async def _verify_agent(
    agent_id: uuid.UUID,
    fingerprint: str | None,
    header_agent_id: str | None,
) -> Agent | None:
    """
    Resolve and authenticate the connecting agent from the database.

    Args:
        agent_id: UUID from the URL path.
        fingerprint: Value of the ``X-Agent-Fingerprint`` header (preferred).
        header_agent_id: Value of the ``X-Agent-ID`` header (fallback).

    Returns:
        The Agent ORM row, or None if authentication fails.
    """
    async with AsyncSessionLocal() as db:
        agent: Agent | None = await db.get(Agent, agent_id)
        if agent is None:
            return None

        if fingerprint:
            if agent.certificate_fingerprint != fingerprint:
                logger.warning(
                    "Agent %s WS auth rejected: fingerprint mismatch", agent_id
                )
                return None
            return agent

        if header_agent_id:
            try:
                if uuid.UUID(header_agent_id) == agent_id:
                    return agent
            except ValueError:
                return None

        # Dev-only fallback — no cert verification available
        logger.warning(
            "Agent %s connected to WS without certificate verification. "
            "Configure Nginx mTLS termination in production.",
            agent_id,
        )
        return agent


async def _mark_agent_status(agent_id: uuid.UUID, status: str) -> None:
    """Update the agent's status and last_heartbeat timestamp in the database."""
    async with AsyncSessionLocal() as db:
        agent = await db.get(Agent, agent_id)
        if agent:
            agent.status = status
            if status == "online":
                agent.last_heartbeat = datetime.utcnow()
            await db.commit()


# ---------------------------------------------------------------------------
# Redis task consumer
# ---------------------------------------------------------------------------


async def _task_consumer(agent_id: str, ws: WebSocket) -> None:
    """
    Read queued tasks from the agent's Redis Stream and forward them via WS.

    Runs as a background asyncio task for the duration of the agent's WS
    session.  Uses ``XREAD BLOCK 2000`` so the loop wakes up at most every
    2 seconds when there are no new messages, allowing prompt cancellation.

    After successful delivery each message is deleted from the stream so it
    is not re-sent on the next connection.  If the agent disconnects before
    delivery the message stays in the stream and will be picked up on the
    next reconnect.
    """
    try:
        import redis.asyncio as aioredis
        from server.config import settings

        r = aioredis.from_url(settings.redis_url, decode_responses=True)
    except Exception as exc:
        logger.warning(
            "Redis unavailable — task consumer disabled for agent %s: %s", agent_id, exc
        )
        return

    stream_key = f"agent:{agent_id}:tasks"
    # Start from the beginning so tasks queued while the agent was offline
    # are delivered immediately on reconnect.
    last_id = "0-0"

    try:
        while True:
            try:
                results = await r.xread({stream_key: last_id}, count=10, block=2000)
            except asyncio.CancelledError:
                raise
            except Exception as exc:
                logger.warning("Redis XREAD error (agent %s): %s", agent_id, exc)
                await asyncio.sleep(2)
                continue

            if not results:
                continue  # block timeout, no messages — loop again

            for _stream_name, messages in results:
                for msg_id, fields in messages:
                    last_id = msg_id
                    try:
                        task_payload: dict[str, Any] = {
                            "type": "task",
                            "task_id": fields.get("task_id", str(uuid.uuid4())),
                            "action": fields.get("action", ""),
                            "params": json.loads(fields.get("params", "{}")),
                        }
                        await ws.send_json(task_payload)
                        # Remove from stream after confirmed delivery
                        await r.xdel(stream_key, msg_id)
                        # Update task state machine: queued → dispatched
                        await mark_dispatched(task_payload["task_id"])
                        logger.info(
                            "Task %s dispatched to agent %s via WS",
                            task_payload["task_id"],
                            agent_id,
                        )
                        await manager.broadcast(
                            {
                                "type": "task_dispatched",
                                "agent_id": agent_id,
                                "task_id": task_payload["task_id"],
                                "action": task_payload["action"],
                            }
                        )
                    except (WebSocketDisconnect, asyncio.CancelledError):
                        raise
                    except Exception as exc:
                        logger.error(
                            "Failed to deliver task to agent %s: %s", agent_id, exc
                        )
                        raise
    except (WebSocketDisconnect, asyncio.CancelledError):
        pass
    finally:
        try:
            await r.aclose()
        except Exception:
            pass


# ---------------------------------------------------------------------------
# Agent WebSocket endpoint
# ---------------------------------------------------------------------------


@router.websocket("/agent/{agent_id}")
async def agent_ws(
    agent_id: uuid.UUID,
    ws: WebSocket,
) -> None:
    """
    Persistent WebSocket connection for an enrolled agent.

    **Authentication** (same options as the REST heartbeat endpoint):

    - ``X-Agent-Fingerprint: <sha256-hex>`` — preferred; set by Nginx mTLS
      termination in production.
    - ``X-Agent-ID: <uuid>`` — acceptable during development.
    - No header — accepted with a warning (dev-only, never use in production).

    **Server → Agent message types**::

        {"type": "task",  "task_id": "...", "action": "...", "params": {...}}
        {"type": "pong"}

    **Agent → Server message types**::

        {"type": "ping"}
        {"type": "heartbeat"}
        {"type": "task_result", "task_id": "...", "status": "completed"|"failed",
         "result": {...}}
    """
    raw_fingerprint = ws.headers.get("x-agent-fingerprint")
    raw_agent_id_hdr = ws.headers.get("x-agent-id")

    agent = await _verify_agent(agent_id, raw_fingerprint, raw_agent_id_hdr)
    if agent is None:
        await ws.close(code=4001, reason="Authentication failed")
        return

    await ws.accept()
    agent_id_str = str(agent_id)

    manager.register_agent(agent_id_str, ws)
    await _mark_agent_status(agent_id, "online")

    await manager.broadcast(
        {
            "type": "agent_connected",
            "agent_id": agent_id_str,
            "hostname": agent.hostname,
        }
    )

    # Background task: read Redis Stream → send tasks to agent
    consumer = asyncio.create_task(_task_consumer(agent_id_str, ws))

    try:
        async with AsyncSessionLocal() as db:
            while True:
                try:
                    data = await ws.receive_json()
                except WebSocketDisconnect:
                    break
                except Exception as exc:
                    logger.warning(
                        "WS receive error (agent %s): %s", agent_id_str, exc
                    )
                    break

                msg_type = data.get("type")

                if msg_type == "ping":
                    try:
                        await ws.send_json({"type": "pong"})
                    except Exception:
                        break

                elif msg_type == "heartbeat":
                    try:
                        row = await db.get(Agent, agent_id)
                        if row:
                            row.last_heartbeat = datetime.utcnow()
                            row.status = "online"
                            await db.commit()
                    except Exception as exc:
                        logger.warning(
                            "Heartbeat DB update failed (agent %s): %s",
                            agent_id_str,
                            exc,
                        )

                elif msg_type == "task_result":
                    task_id = data.get("task_id", "unknown")
                    result_status = data.get("status", "unknown")
                    result_data = data.get("result", {})
                    error_msg = data.get("error")

                    logger.info(
                        "Task result: agent=%s task_id=%s status=%s",
                        agent_id_str,
                        task_id,
                        result_status,
                    )

                    # Persist task state transition
                    await mark_result(
                        task_id,
                        result_status,
                        result=result_data,
                        error=error_msg,
                    )

                    try:
                        audit = AuditLog(
                            agent_id=agent_id,
                            action="task_result",
                            target=task_id,
                            params={"status": result_status, "result": result_data},
                            result=result_status,
                        )
                        db.add(audit)
                        await db.commit()
                    except Exception as exc:
                        logger.warning("Audit log write failed: %s", exc)

                    await manager.broadcast(
                        {
                            "type": "task_update",
                            "agent_id": agent_id_str,
                            "task_id": task_id,
                            "status": result_status,
                            "result": result_data,
                        }
                    )

                else:
                    logger.debug(
                        "Unknown WS message from agent %s: type=%r",
                        agent_id_str,
                        msg_type,
                    )

    finally:
        consumer.cancel()
        try:
            await consumer
        except asyncio.CancelledError:
            pass

        manager.deregister_agent(agent_id_str)
        await _mark_agent_status(agent_id, "offline")

        await manager.broadcast(
            {"type": "agent_disconnected", "agent_id": agent_id_str}
        )
        logger.info("Agent WS session ended: %s", agent_id_str)


# ---------------------------------------------------------------------------
# Dashboard WebSocket endpoint
# ---------------------------------------------------------------------------


@router.websocket("/dashboard")
async def dashboard_ws(
    ws: WebSocket,
    token: str | None = Query(default=None),
) -> None:
    """
    Persistent WebSocket connection for the operator dashboard.

    **Authentication**: JWT access token delivered in one of two ways:

    1. ``?token=<jwt>`` query parameter (simplest, works everywhere).
    2. Raw token as the first text message after the connection is accepted
       (useful when query-string tokens are undesirable, e.g. browser logs).

    **Server → Dashboard event types**::

        {"type": "connected_agents",   "agent_ids": [...]}
        {"type": "agent_connected",    "agent_id": "...", "hostname": "..."}
        {"type": "agent_disconnected", "agent_id": "..."}
        {"type": "task_dispatched",    "agent_id": "...", "task_id": "...", "action": "..."}
        {"type": "task_update",        "agent_id": "...", "task_id": "...",
                                       "status": "...", "result": {...}}
        {"type": "ping"}
    """
    from server.config import settings as _settings
    from server.services.auth import decode_token

    def _authenticate(raw_token: str) -> bool:
        try:
            decode_token(raw_token.strip(), _settings.secret_key)
            return True
        except Exception:
            return False

    if token:
        if not _authenticate(token):
            await ws.close(code=4001, reason="Invalid token")
            return
        await ws.accept()
    else:
        await ws.accept()
        # Wait up to 10 s for the client to send the token as first message
        try:
            raw = await asyncio.wait_for(ws.receive_text(), timeout=10)
        except (asyncio.TimeoutError, WebSocketDisconnect):
            await ws.close(code=4001, reason="Token not received")
            return
        if not _authenticate(raw):
            await ws.close(code=4001, reason="Invalid token")
            return

    manager.register_dashboard(ws)

    # Send initial snapshot: which agents are currently connected
    try:
        await ws.send_json(
            {
                "type": "connected_agents",
                "agent_ids": manager.connected_agent_ids(),
            }
        )
    except Exception:
        manager.deregister_dashboard(ws)
        return

    try:
        while True:
            try:
                # Dashboard is receive-only; just keep the connection alive
                await asyncio.wait_for(ws.receive_text(), timeout=30)
            except asyncio.TimeoutError:
                # Keepalive ping
                try:
                    await ws.send_json({"type": "ping"})
                except Exception:
                    break
            except WebSocketDisconnect:
                break
    finally:
        manager.deregister_dashboard(ws)
