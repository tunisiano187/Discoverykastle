"""
Task engine service — create, dispatch, track, and retry agent tasks.

State machine
-------------
created → queued → dispatched → running → completed
                              ↘ failed   → queued (retry if attempts remain)
                              ↘ timed_out → queued (retry if attempts remain)
          cancelled  (operator-requested, any non-terminal state)

Retry backoff delays (seconds): attempt 2 → 60 s, attempt 3 → 300 s.
After max_attempts the task is permanently failed/timed_out.
"""

from __future__ import annotations

import asyncio
import json
import logging
import uuid
from datetime import datetime, timedelta
from typing import Any

from sqlalchemy import and_, select
from sqlalchemy.ext.asyncio import AsyncSession

from server.database import AsyncSessionLocal
from server.models.task import TERMINAL_STATUSES, AgentTask

logger = logging.getLogger(__name__)

# Seconds to wait before each successive retry attempt (index = attempt-1)
_RETRY_DELAYS: list[int] = [60, 300, 900]

#: How often the background monitor wakes up to scan for timed-out tasks.
TIMEOUT_CHECK_INTERVAL: int = 30


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


async def create_task(
    db: AsyncSession,
    agent_id: uuid.UUID,
    action: str,
    params: dict[str, Any],
    *,
    operator: str | None = None,
    timeout_seconds: int = 600,
    max_attempts: int = 3,
) -> AgentTask:
    """
    Create a new task, persist it, and enqueue it to the agent's Redis Stream.

    Args:
        db: Active async database session (caller must commit).
        agent_id: Target agent.
        action: Task type (e.g. ``scan_network``, ``collect_cves``).
        params: Task parameters forwarded to the agent.
        operator: Username that triggered the task (None for system tasks).
        timeout_seconds: Seconds before a dispatched task is considered timed out.
        max_attempts: Maximum total delivery attempts including retries.

    Returns:
        The newly-created :class:`AgentTask` row (status ``queued``).
    """
    task = AgentTask(
        agent_id=agent_id,
        action=action,
        params=params,
        status="created",
        operator=operator,
        timeout_seconds=timeout_seconds,
        max_attempts=max_attempts,
    )
    db.add(task)
    await db.flush()  # populate task.id without committing

    try:
        await _enqueue(task)
    except Exception as exc:
        logger.warning("Task %s enqueue failed, still persisting record: %s", task.id, exc)

    task.status = "queued"
    task.queued_at = datetime.utcnow()
    await db.commit()
    await db.refresh(task)

    logger.info(
        "Task created: id=%s agent=%s action=%s attempt=%d/%d",
        task.id,
        agent_id,
        action,
        task.attempt,
        task.max_attempts,
    )
    return task


async def mark_dispatched(task_id: str | uuid.UUID) -> None:
    """
    Transition a task from ``queued`` → ``dispatched``.

    Called by the WebSocket task consumer after confirmed WS delivery.
    Silently ignored if the task is already in a non-queued state (e.g. it
    was cancelled while in flight).
    """
    try:
        tid = uuid.UUID(str(task_id))
    except ValueError:
        return

    async with AsyncSessionLocal() as db:
        task = await db.get(AgentTask, tid)
        if task and task.status == "queued":
            task.status = "dispatched"
            task.dispatched_at = datetime.utcnow()
            await db.commit()
            logger.debug("Task %s → dispatched", tid)


async def mark_result(
    task_id: str | uuid.UUID,
    status: str,
    result: dict[str, Any] | None = None,
    error: str | None = None,
) -> None:
    """
    Apply an outcome reported by the agent.

    Args:
        task_id: Task UUID (string or UUID object).
        status: One of ``running``, ``completed``, ``failed``.
        result: Structured result payload (for ``completed``).
        error: Human-readable error description (for ``failed``).
    """
    try:
        tid = uuid.UUID(str(task_id))
    except ValueError:
        return

    async with AsyncSessionLocal() as db:
        task = await db.get(AgentTask, tid)
        if task is None or task.is_terminal:
            return

        now = datetime.utcnow()

        if status == "running":
            task.status = "running"
            task.started_at = task.started_at or now

        elif status == "completed":
            task.status = "completed"
            task.completed_at = now
            task.result = result

        elif status == "failed":
            if task.attempt < task.max_attempts:
                await _schedule_retry(db, task)
                return  # _schedule_retry commits
            else:
                task.status = "failed"
                task.completed_at = now
                task.error = error or "Task failed (no error detail)"

        await db.commit()
        logger.info("Task %s → %s", tid, task.status)


async def cancel_task(task_id: str | uuid.UUID, operator: str) -> bool:
    """
    Cancel a non-terminal task.

    Returns True if the task was cancelled, False if it was already terminal
    or not found.
    """
    try:
        tid = uuid.UUID(str(task_id))
    except ValueError:
        return False

    async with AsyncSessionLocal() as db:
        task = await db.get(AgentTask, tid)
        if task is None or task.is_terminal:
            return False

        task.status = "cancelled"
        task.completed_at = datetime.utcnow()
        task.error = f"Cancelled by {operator}"
        await db.commit()
        logger.info("Task %s cancelled by %s", tid, operator)
        return True


# ---------------------------------------------------------------------------
# Background timeout monitor
# ---------------------------------------------------------------------------


async def run_timeout_monitor() -> None:
    """
    Background coroutine: scan for timed-out tasks and retry or fail them.

    Runs forever (until cancelled).  Wakes up every
    :data:`TIMEOUT_CHECK_INTERVAL` seconds.
    """
    logger.info(
        "Task timeout monitor started (interval=%ds)", TIMEOUT_CHECK_INTERVAL
    )
    while True:
        await asyncio.sleep(TIMEOUT_CHECK_INTERVAL)
        try:
            await _check_timeouts()
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            logger.error("Task timeout monitor error: %s", exc)


async def _check_timeouts() -> None:
    """Find dispatched/running tasks past their deadline and act on them."""
    async with AsyncSessionLocal() as db:
        rows = await db.execute(
            select(AgentTask).where(
                and_(
                    AgentTask.status.in_(["dispatched", "running"]),
                    AgentTask.dispatched_at.isnot(None),
                )
            )
        )
        tasks = list(rows.scalars())

        now = datetime.utcnow()
        for task in tasks:
            deadline = task.dispatched_at + timedelta(seconds=task.timeout_seconds)
            if now < deadline:
                continue

            logger.warning(
                "Task %s timed out (agent=%s action=%s attempt=%d/%d)",
                task.id,
                task.agent_id,
                task.action,
                task.attempt,
                task.max_attempts,
            )

            if task.attempt < task.max_attempts:
                await _schedule_retry(db, task)
            else:
                task.status = "timed_out"
                task.completed_at = now
                task.error = (
                    f"Timed out after {task.timeout_seconds}s "
                    f"({task.max_attempts} attempts exhausted)"
                )

        await db.commit()


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


async def _enqueue(task: AgentTask) -> None:
    """Write the task to the agent's Redis Stream (best-effort)."""
    try:
        import redis.asyncio as aioredis
        from server.config import settings

        r = aioredis.from_url(settings.redis_url, decode_responses=True)
        await r.xadd(
            f"agent:{task.agent_id}:tasks",
            {
                "task_id": str(task.id),
                "action": task.action,
                "params": json.dumps(task.params),
                "operator": task.operator or "",
            },
        )
        await r.aclose()
        logger.debug("Task %s enqueued to Redis (agent=%s)", task.id, task.agent_id)
    except Exception as exc:
        logger.warning(
            "Redis unavailable — task %s not written to stream: %s", task.id, exc
        )


async def _schedule_retry(db: AsyncSession, task: AgentTask) -> None:
    """Increment attempt counter, compute backoff, and re-enqueue the task."""
    delay = _RETRY_DELAYS[min(task.attempt - 1, len(_RETRY_DELAYS) - 1)]
    task.attempt += 1
    task.status = "queued"
    task.queued_at = datetime.utcnow()
    task.next_retry_at = datetime.utcnow() + timedelta(seconds=delay)
    task.dispatched_at = None
    task.started_at = None
    await db.flush()
    await _enqueue(task)
    await db.commit()
    logger.info(
        "Task %s scheduled for retry: attempt %d/%d (delay=%ds)",
        task.id,
        task.attempt,
        task.max_attempts,
        delay,
    )
