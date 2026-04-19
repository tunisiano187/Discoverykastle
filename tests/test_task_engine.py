"""
Tests for the task engine — server/services/task.py and server/api/tasks.py.

Strategy
--------
* Service-layer tests: mock AsyncSessionLocal and Redis to test state-machine
  logic without external dependencies.
* API-layer tests: TestClient with mocked DB session and task service.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timedelta
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fastapi import FastAPI
from starlette.testclient import TestClient

from server.models.task import AgentTask, TERMINAL_STATUSES


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_task(
    task_id: uuid.UUID | None = None,
    agent_id: uuid.UUID | None = None,
    action: str = "scan_network",
    status: str = "queued",
    attempt: int = 1,
    max_attempts: int = 3,
    timeout_seconds: int = 600,
    dispatched_at: datetime | None = None,
) -> AgentTask:
    t = AgentTask(
        id=task_id or uuid.uuid4(),
        agent_id=agent_id or uuid.uuid4(),
        action=action,
        params={"cidr": "10.0.0.0/24"},
        status=status,
        attempt=attempt,
        max_attempts=max_attempts,
        timeout_seconds=timeout_seconds,
        created_at=datetime.utcnow(),
        dispatched_at=dispatched_at,
    )
    return t


def _mock_db(task: AgentTask | None = None) -> AsyncMock:
    db = AsyncMock()
    db.get = AsyncMock(return_value=task)
    db.add = MagicMock()
    db.flush = AsyncMock()
    db.commit = AsyncMock()
    db.refresh = AsyncMock()
    db.__aenter__ = AsyncMock(return_value=db)
    db.__aexit__ = AsyncMock(return_value=False)
    return db


# ---------------------------------------------------------------------------
# AgentTask model
# ---------------------------------------------------------------------------


class TestAgentTaskModel:
    def test_is_terminal_for_terminal_statuses(self) -> None:
        for s in TERMINAL_STATUSES:
            t = _make_task(status=s)
            assert t.is_terminal is True

    def test_is_not_terminal_for_active_statuses(self) -> None:
        for s in ("created", "queued", "dispatched", "running"):
            t = _make_task(status=s)
            assert t.is_terminal is False


# ---------------------------------------------------------------------------
# create_task
# ---------------------------------------------------------------------------


class TestCreateTask:
    @pytest.mark.asyncio
    async def test_creates_db_record_and_enqueues(self) -> None:
        agent_id = uuid.uuid4()
        db = _mock_db()

        with patch("server.services.task._enqueue", new=AsyncMock()) as mock_enqueue:
            from server.services.task import create_task

            result = await create_task(db, agent_id, "scan_network", {"cidr": "10.0.0.0/24"})

        mock_enqueue.assert_awaited_once()
        db.commit.assert_awaited()
        assert result.status == "queued"
        assert result.queued_at is not None

    @pytest.mark.asyncio
    async def test_enqueue_failure_does_not_raise(self) -> None:
        agent_id = uuid.uuid4()
        db = _mock_db()

        with patch(
            "server.services.task._enqueue",
            new=AsyncMock(side_effect=Exception("redis down")),
        ):
            from server.services.task import create_task

            # Should not raise even if Redis is down
            result = await create_task(db, agent_id, "scan_host", {})

        assert result.status == "queued"
        db.commit.assert_awaited()


# ---------------------------------------------------------------------------
# mark_dispatched
# ---------------------------------------------------------------------------


class TestMarkDispatched:
    @pytest.mark.asyncio
    async def test_transitions_queued_to_dispatched(self) -> None:
        task = _make_task(status="queued")
        db = _mock_db(task)

        with patch("server.services.task.AsyncSessionLocal", return_value=db):
            from server.services.task import mark_dispatched

            await mark_dispatched(str(task.id))

        assert task.status == "dispatched"
        assert task.dispatched_at is not None
        db.commit.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_ignores_non_queued_task(self) -> None:
        task = _make_task(status="dispatched")
        db = _mock_db(task)

        with patch("server.services.task.AsyncSessionLocal", return_value=db):
            from server.services.task import mark_dispatched

            await mark_dispatched(str(task.id))

        # Status unchanged, no commit
        assert task.status == "dispatched"
        db.commit.assert_not_awaited()

    @pytest.mark.asyncio
    async def test_ignores_invalid_uuid(self) -> None:
        from server.services.task import mark_dispatched

        await mark_dispatched("not-a-uuid")  # should not raise

    @pytest.mark.asyncio
    async def test_ignores_missing_task(self) -> None:
        db = _mock_db(None)

        with patch("server.services.task.AsyncSessionLocal", return_value=db):
            from server.services.task import mark_dispatched

            await mark_dispatched(str(uuid.uuid4()))  # should not raise

        db.commit.assert_not_awaited()


# ---------------------------------------------------------------------------
# mark_result
# ---------------------------------------------------------------------------


class TestMarkResult:
    @pytest.mark.asyncio
    async def test_running_updates_status(self) -> None:
        task = _make_task(status="dispatched")
        db = _mock_db(task)

        with patch("server.services.task.AsyncSessionLocal", return_value=db):
            from server.services.task import mark_result

            await mark_result(str(task.id), "running")

        assert task.status == "running"
        assert task.started_at is not None

    @pytest.mark.asyncio
    async def test_completed_sets_result(self) -> None:
        task = _make_task(status="dispatched")
        db = _mock_db(task)

        with patch("server.services.task.AsyncSessionLocal", return_value=db):
            from server.services.task import mark_result

            await mark_result(str(task.id), "completed", result={"hosts_found": 5})

        assert task.status == "completed"
        assert task.completed_at is not None
        assert task.result == {"hosts_found": 5}

    @pytest.mark.asyncio
    async def test_failed_with_retries_remaining_re_queues(self) -> None:
        task = _make_task(status="dispatched", attempt=1, max_attempts=3)
        db = _mock_db(task)

        with (
            patch("server.services.task.AsyncSessionLocal", return_value=db),
            patch("server.services.task._enqueue", new=AsyncMock()),
        ):
            from server.services.task import mark_result

            await mark_result(str(task.id), "failed", error="connection refused")

        assert task.status == "queued"
        assert task.attempt == 2
        assert task.next_retry_at is not None

    @pytest.mark.asyncio
    async def test_failed_at_max_attempts_marks_permanently_failed(self) -> None:
        task = _make_task(status="dispatched", attempt=3, max_attempts=3)
        db = _mock_db(task)

        with patch("server.services.task.AsyncSessionLocal", return_value=db):
            from server.services.task import mark_result

            await mark_result(str(task.id), "failed", error="timeout")

        assert task.status == "failed"
        assert task.error is not None

    @pytest.mark.asyncio
    async def test_ignores_terminal_task(self) -> None:
        task = _make_task(status="completed")
        db = _mock_db(task)

        with patch("server.services.task.AsyncSessionLocal", return_value=db):
            from server.services.task import mark_result

            await mark_result(str(task.id), "completed", result={"new": "data"})

        # result should NOT be overwritten
        assert task.result is None
        db.commit.assert_not_awaited()


# ---------------------------------------------------------------------------
# cancel_task
# ---------------------------------------------------------------------------


class TestCancelTask:
    @pytest.mark.asyncio
    async def test_cancels_queued_task(self) -> None:
        task = _make_task(status="queued")
        db = _mock_db(task)

        with patch("server.services.task.AsyncSessionLocal", return_value=db):
            from server.services.task import cancel_task

            result = await cancel_task(str(task.id), "admin")

        assert result is True
        assert task.status == "cancelled"
        assert "admin" in (task.error or "")

    @pytest.mark.asyncio
    async def test_returns_false_for_terminal_task(self) -> None:
        task = _make_task(status="completed")
        db = _mock_db(task)

        with patch("server.services.task.AsyncSessionLocal", return_value=db):
            from server.services.task import cancel_task

            result = await cancel_task(str(task.id), "admin")

        assert result is False

    @pytest.mark.asyncio
    async def test_returns_false_for_missing_task(self) -> None:
        db = _mock_db(None)

        with patch("server.services.task.AsyncSessionLocal", return_value=db):
            from server.services.task import cancel_task

            result = await cancel_task(str(uuid.uuid4()), "admin")

        assert result is False


# ---------------------------------------------------------------------------
# Timeout monitor
# ---------------------------------------------------------------------------


class TestTimeoutMonitor:
    @pytest.mark.asyncio
    async def test_timed_out_task_retried_when_attempts_remain(self) -> None:
        old_dispatched = datetime.utcnow() - timedelta(seconds=700)
        task = _make_task(
            status="dispatched",
            attempt=1,
            max_attempts=3,
            timeout_seconds=600,
            dispatched_at=old_dispatched,
        )

        db = AsyncMock()
        db.execute = AsyncMock(
            return_value=MagicMock(scalars=MagicMock(return_value=[task]))
        )
        db.get = AsyncMock(return_value=task)
        db.flush = AsyncMock()
        db.commit = AsyncMock()
        db.__aenter__ = AsyncMock(return_value=db)
        db.__aexit__ = AsyncMock(return_value=False)

        with (
            patch("server.services.task.AsyncSessionLocal", return_value=db),
            patch("server.services.task._enqueue", new=AsyncMock()),
        ):
            from server.services.task import _check_timeouts

            await _check_timeouts()

        assert task.status == "queued"
        assert task.attempt == 2

    @pytest.mark.asyncio
    async def test_timed_out_task_permanently_failed_at_max_attempts(self) -> None:
        old_dispatched = datetime.utcnow() - timedelta(seconds=700)
        task = _make_task(
            status="dispatched",
            attempt=3,
            max_attempts=3,
            timeout_seconds=600,
            dispatched_at=old_dispatched,
        )

        db = AsyncMock()
        db.execute = AsyncMock(
            return_value=MagicMock(scalars=MagicMock(return_value=[task]))
        )
        db.commit = AsyncMock()
        db.__aenter__ = AsyncMock(return_value=db)
        db.__aexit__ = AsyncMock(return_value=False)

        with patch("server.services.task.AsyncSessionLocal", return_value=db):
            from server.services.task import _check_timeouts

            await _check_timeouts()

        assert task.status == "timed_out"
        assert task.error is not None

    @pytest.mark.asyncio
    async def test_task_within_timeout_not_affected(self) -> None:
        recent_dispatched = datetime.utcnow() - timedelta(seconds=10)
        task = _make_task(
            status="dispatched",
            timeout_seconds=600,
            dispatched_at=recent_dispatched,
        )

        db = AsyncMock()
        db.execute = AsyncMock(
            return_value=MagicMock(scalars=MagicMock(return_value=[task]))
        )
        db.commit = AsyncMock()
        db.__aenter__ = AsyncMock(return_value=db)
        db.__aexit__ = AsyncMock(return_value=False)

        with patch("server.services.task.AsyncSessionLocal", return_value=db):
            from server.services.task import _check_timeouts

            await _check_timeouts()

        assert task.status == "dispatched"  # unchanged


# ---------------------------------------------------------------------------
# Tasks REST API
# ---------------------------------------------------------------------------


def _make_api_app(mock_db: AsyncMock) -> FastAPI:
    from server.api.tasks import router, require_operator, get_db
    app = FastAPI()
    app.include_router(router)
    app.dependency_overrides[require_operator] = lambda: "admin"
    app.dependency_overrides[get_db] = lambda: mock_db
    return app


def _full_task(task: AgentTask) -> AgentTask:
    """Fill in nullable fields so Pydantic serialisation doesn't fail."""
    task.operator = task.operator or "admin"
    task.queued_at = task.queued_at
    task.dispatched_at = None
    task.started_at = None
    task.completed_at = None
    task.next_retry_at = None
    task.result = None
    task.error = None
    return task


class TestTasksAPI:
    def test_list_tasks_returns_200(self) -> None:
        task = _full_task(_make_task())

        mock_db = AsyncMock()
        mock_rows = MagicMock()
        mock_rows.scalars.return_value = [task]
        mock_db.execute = AsyncMock(return_value=mock_rows)

        with TestClient(_make_api_app(mock_db)) as client:
            resp = client.get("/api/v1/tasks")

        assert resp.status_code == 200
        data = resp.json()
        assert isinstance(data, list)
        assert data[0]["task_id"] == str(task.id)
        assert data[0]["action"] == "scan_network"

    def test_get_task_returns_detail(self) -> None:
        task = _full_task(_make_task())
        task.queued_at = datetime.utcnow()

        mock_db = AsyncMock()
        mock_db.get = AsyncMock(return_value=task)

        with TestClient(_make_api_app(mock_db)) as client:
            resp = client.get(f"/api/v1/tasks/{task.id}")

        assert resp.status_code == 200
        assert resp.json()["task_id"] == str(task.id)

    def test_get_task_404_when_not_found(self) -> None:
        mock_db = AsyncMock()
        mock_db.get = AsyncMock(return_value=None)

        with TestClient(_make_api_app(mock_db)) as client:
            resp = client.delete(f"/api/v1/tasks/{uuid.uuid4()}")

        assert resp.status_code == 404

    def test_cancel_task_204(self) -> None:
        task = _full_task(_make_task(status="queued"))

        mock_db = AsyncMock()
        mock_db.get = AsyncMock(return_value=task)

        with (
            patch("server.api.tasks.svc_cancel", new=AsyncMock(return_value=True)),
        ):
            with TestClient(_make_api_app(mock_db)) as client:
                resp = client.delete(f"/api/v1/tasks/{task.id}")

        assert resp.status_code == 204

    def test_cancel_terminal_task_returns_409(self) -> None:
        task = _full_task(_make_task(status="completed"))

        mock_db = AsyncMock()
        mock_db.get = AsyncMock(return_value=task)

        with TestClient(_make_api_app(mock_db)) as client:
            resp = client.delete(f"/api/v1/tasks/{task.id}")

        assert resp.status_code == 409
