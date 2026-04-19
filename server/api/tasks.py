"""
Tasks API — /api/v1/tasks

Cross-agent task management for operators.

GET  /api/v1/tasks              — list all tasks (filterable by agent/status)
GET  /api/v1/tasks/{task_id}    — get a single task with full detail
DELETE /api/v1/tasks/{task_id}  — cancel a non-terminal task
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel
from sqlalchemy import desc, select
from sqlalchemy.ext.asyncio import AsyncSession

from server.database import get_db
from server.models.task import AgentTask
from server.services.auth import require_operator
from server.services.task import cancel_task as svc_cancel

router = APIRouter(prefix="/api/v1/tasks", tags=["tasks"])


# ---------------------------------------------------------------------------
# Schemas
# ---------------------------------------------------------------------------


class TaskDetail(BaseModel):
    task_id: str
    agent_id: str
    action: str
    params: dict[str, Any]
    status: str
    operator: str | None
    attempt: int
    max_attempts: int
    timeout_seconds: int
    queued_at: datetime | None
    dispatched_at: datetime | None
    started_at: datetime | None
    completed_at: datetime | None
    next_retry_at: datetime | None
    result: dict | None
    error: str | None
    created_at: datetime


def _task_detail(t: AgentTask) -> TaskDetail:
    """Convert an AgentTask ORM row to a TaskDetail schema object."""
    return TaskDetail(
        task_id=str(t.id),
        agent_id=str(t.agent_id),
        action=t.action,
        params=t.params or {},
        status=t.status,
        operator=t.operator,
        attempt=t.attempt,
        max_attempts=t.max_attempts,
        timeout_seconds=t.timeout_seconds,
        queued_at=t.queued_at,
        dispatched_at=t.dispatched_at,
        started_at=t.started_at,
        completed_at=t.completed_at,
        next_retry_at=t.next_retry_at,
        result=t.result,
        error=t.error,
        created_at=t.created_at,
    )


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------


@router.get("", response_model=list[TaskDetail])
async def list_tasks(
    operator: Annotated[str, Depends(require_operator)],
    agent_id: uuid.UUID | None = Query(default=None),
    task_status: str | None = Query(default=None, alias="status"),
    limit: int = Query(default=50, le=200),
    db: AsyncSession = Depends(get_db),
) -> list[AgentTask]:
    """
    List tasks across all agents, newest-first (operator JWT required).

    Query params:
    - ``agent_id``: filter by agent UUID
    - ``status``: filter by status (e.g. ``queued``, ``dispatched``, ``completed``)
    - ``limit``: max results (default 50, max 200)
    """
    q = select(AgentTask).order_by(desc(AgentTask.created_at)).limit(limit)
    if agent_id is not None:
        q = q.where(AgentTask.agent_id == agent_id)
    if task_status is not None:
        q = q.where(AgentTask.status == task_status)

    rows = await db.execute(q)
    return [_task_detail(t) for t in rows.scalars()]


@router.get("/{task_id}", response_model=TaskDetail)
async def get_task(
    task_id: uuid.UUID,
    operator: Annotated[str, Depends(require_operator)],
    db: AsyncSession = Depends(get_db),
) -> TaskDetail:
    """Return full detail for a single task (operator JWT required)."""
    task = await db.get(AgentTask, task_id)
    if task is None:
        raise HTTPException(status_code=404, detail="Task not found")
    return _task_detail(task)


@router.delete("/{task_id}", status_code=204)
async def cancel_task(
    task_id: uuid.UUID,
    operator: Annotated[str, Depends(require_operator)],
    db: AsyncSession = Depends(get_db),  # noqa: ARG001 — used indirectly via cancel_task svc
) -> None:
    """
    Cancel a non-terminal task (operator JWT required).

    Returns 404 if the task does not exist, 409 if it is already in a
    terminal state (completed, failed, timed_out, cancelled).
    """
    task = await db.get(AgentTask, task_id)
    if task is None:
        raise HTTPException(status_code=404, detail="Task not found")
    if task.is_terminal:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"Task is already in terminal state '{task.status}'",
        )

    cancelled = await svc_cancel(task_id, operator)
    if not cancelled:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Task could not be cancelled",
        )
