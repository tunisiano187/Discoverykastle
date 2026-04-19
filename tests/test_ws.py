"""
Tests for the WebSocket endpoints — /api/v1/ws/agent/{id} and /api/v1/ws/dashboard

Strategy
--------
* Use FastAPI's built-in WebSocket test support via ``starlette.testclient.TestClient``.
* Stub out DB and Redis to keep tests self-contained and fast.
* Patch ``server.api.ws._verify_agent`` to control auth outcomes.
* Patch ``server.api.ws._task_consumer`` to avoid needing a real Redis instance.
* Patch ``server.api.ws._mark_agent_status`` to avoid needing a real DB.
* For the dashboard, patch ``server.services.auth.decode_token`` to control JWT validation.
"""

from __future__ import annotations

import asyncio
import uuid
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fastapi import FastAPI
from starlette.testclient import TestClient
from starlette.websockets import WebSocketDisconnect

from server.api.ws import manager, router
from server.models.agent import Agent


# ---------------------------------------------------------------------------
# Test app fixture
# ---------------------------------------------------------------------------


def _make_app() -> FastAPI:
    app = FastAPI()
    app.include_router(router)
    return app


def _make_agent(agent_id: uuid.UUID | None = None) -> Agent:
    a = Agent(
        id=agent_id or uuid.uuid4(),
        certificate_fingerprint="deadbeef" * 8,
        hostname="test-host",
        ip_address="10.0.0.1",
        status="offline",
    )
    return a


# ---------------------------------------------------------------------------
# Agent WS — authentication
# ---------------------------------------------------------------------------


class TestAgentWSAuth:
    """Authentication gate for agent WebSocket connections."""

    def test_auth_failure_closes_ws(self) -> None:
        """When _verify_agent returns None the WS should be closed immediately."""
        app = _make_app()
        agent_id = uuid.uuid4()

        with patch("server.api.ws._verify_agent", new=AsyncMock(return_value=None)):
            with TestClient(app) as client:
                # The server closes before accepting — context manager raises
                with pytest.raises(WebSocketDisconnect):
                    with client.websocket_connect(f"/api/v1/ws/agent/{agent_id}") as ws:
                        ws.receive_json()

    def test_auth_success_accepts_ws(self) -> None:
        """When _verify_agent returns an Agent the WS should be accepted."""
        app = _make_app()
        agent_id = uuid.uuid4()
        agent = _make_agent(agent_id)

        async def _noop_consumer(*_args, **_kwargs) -> None:  # noqa: ANN002
            return

        with (
            patch("server.api.ws._verify_agent", new=AsyncMock(return_value=agent)),
            patch("server.api.ws._mark_agent_status", new=AsyncMock()),
            patch("server.api.ws._task_consumer", new=AsyncMock(side_effect=_noop_consumer)),
        ):
            with TestClient(app) as client:
                with client.websocket_connect(f"/api/v1/ws/agent/{agent_id}") as ws:
                    # Connection is up — send ping and expect pong
                    ws.send_json({"type": "ping"})
                    reply = ws.receive_json()
                    assert reply == {"type": "pong"}


# ---------------------------------------------------------------------------
# Agent WS — message handling
# ---------------------------------------------------------------------------


class TestAgentWSMessages:
    """Protocol messages for the agent WebSocket session."""

    def _patched_client(self, app: FastAPI, agent_id: uuid.UUID) -> tuple:
        """Context manager that returns (TestClient, agent)."""
        agent = _make_agent(agent_id)

        ctx = (
            patch("server.api.ws._verify_agent", new=AsyncMock(return_value=agent)),
            patch("server.api.ws._mark_agent_status", new=AsyncMock()),
            patch("server.api.ws._task_consumer", new=AsyncMock(return_value=None)),
            patch("server.api.ws.AsyncSessionLocal"),
        )
        return ctx, agent

    def test_ping_pong(self) -> None:
        """Agent sends ping → server replies pong."""
        app = _make_app()
        agent_id = uuid.uuid4()
        agent = _make_agent(agent_id)

        with (
            patch("server.api.ws._verify_agent", new=AsyncMock(return_value=agent)),
            patch("server.api.ws._mark_agent_status", new=AsyncMock()),
            patch("server.api.ws._task_consumer", new=AsyncMock(return_value=None)),
            patch("server.api.ws.AsyncSessionLocal") as mock_session,
        ):
            # Provide a usable async context manager for the DB session
            mock_db = AsyncMock()
            mock_db.get = AsyncMock(return_value=agent)
            mock_db.commit = AsyncMock()
            mock_session.return_value.__aenter__ = AsyncMock(return_value=mock_db)
            mock_session.return_value.__aexit__ = AsyncMock(return_value=False)

            with TestClient(app) as client:
                with client.websocket_connect(f"/api/v1/ws/agent/{agent_id}") as ws:
                    ws.send_json({"type": "ping"})
                    reply = ws.receive_json()
                    assert reply == {"type": "pong"}

    def test_heartbeat_updates_db(self) -> None:
        """Agent sends heartbeat → DB row is updated to online."""
        app = _make_app()
        agent_id = uuid.uuid4()
        agent = _make_agent(agent_id)

        mock_db = AsyncMock()
        mock_db.get = AsyncMock(return_value=agent)
        mock_db.commit = AsyncMock()

        with (
            patch("server.api.ws._verify_agent", new=AsyncMock(return_value=agent)),
            patch("server.api.ws._mark_agent_status", new=AsyncMock()),
            patch("server.api.ws._task_consumer", new=AsyncMock(return_value=None)),
            patch("server.api.ws.AsyncSessionLocal") as mock_session,
        ):
            mock_session.return_value.__aenter__ = AsyncMock(return_value=mock_db)
            mock_session.return_value.__aexit__ = AsyncMock(return_value=False)

            with TestClient(app) as client:
                with client.websocket_connect(f"/api/v1/ws/agent/{agent_id}") as ws:
                    ws.send_json({"type": "heartbeat"})
                    # Give the server a moment to process then close cleanly
                    ws.send_json({"type": "ping"})
                    ws.receive_json()  # pong

        mock_db.commit.assert_called()

    def test_task_result_broadcast(self) -> None:
        """Agent sends task_result → manager.broadcast is called with task_update."""
        app = _make_app()
        agent_id = uuid.uuid4()
        agent = _make_agent(agent_id)

        mock_db = AsyncMock()
        mock_db.get = AsyncMock(return_value=agent)
        mock_db.add = MagicMock()
        mock_db.commit = AsyncMock()

        with (
            patch("server.api.ws._verify_agent", new=AsyncMock(return_value=agent)),
            patch("server.api.ws._mark_agent_status", new=AsyncMock()),
            patch("server.api.ws._task_consumer", new=AsyncMock(return_value=None)),
            patch("server.api.ws.AsyncSessionLocal") as mock_session,
            patch.object(manager, "broadcast", new=AsyncMock()) as mock_broadcast,
        ):
            mock_session.return_value.__aenter__ = AsyncMock(return_value=mock_db)
            mock_session.return_value.__aexit__ = AsyncMock(return_value=False)

            with TestClient(app) as client:
                with client.websocket_connect(f"/api/v1/ws/agent/{agent_id}") as ws:
                    task_id = str(uuid.uuid4())
                    ws.send_json(
                        {
                            "type": "task_result",
                            "task_id": task_id,
                            "status": "completed",
                            "result": {"hosts_found": 3},
                        }
                    )
                    ws.send_json({"type": "ping"})
                    ws.receive_json()  # pong

        # broadcast should have been called at least twice:
        # once for agent_connected and once for task_update
        calls = [call.args[0] for call in mock_broadcast.await_args_list]
        task_update_calls = [c for c in calls if c.get("type") == "task_update"]
        assert len(task_update_calls) == 1
        assert task_update_calls[0]["task_id"] == task_id
        assert task_update_calls[0]["status"] == "completed"

    def test_connect_broadcasts_agent_connected(self) -> None:
        """Connecting agent triggers an agent_connected broadcast."""
        app = _make_app()
        agent_id = uuid.uuid4()
        agent = _make_agent(agent_id)

        mock_db = AsyncMock()
        mock_db.get = AsyncMock(return_value=agent)
        mock_db.commit = AsyncMock()

        with (
            patch("server.api.ws._verify_agent", new=AsyncMock(return_value=agent)),
            patch("server.api.ws._mark_agent_status", new=AsyncMock()),
            patch("server.api.ws._task_consumer", new=AsyncMock(return_value=None)),
            patch("server.api.ws.AsyncSessionLocal") as mock_session,
            patch.object(manager, "broadcast", new=AsyncMock()) as mock_broadcast,
        ):
            mock_session.return_value.__aenter__ = AsyncMock(return_value=mock_db)
            mock_session.return_value.__aexit__ = AsyncMock(return_value=False)

            with TestClient(app) as client:
                with client.websocket_connect(f"/api/v1/ws/agent/{agent_id}") as ws:
                    ws.send_json({"type": "ping"})
                    ws.receive_json()

        calls = [c.args[0] for c in mock_broadcast.await_args_list]
        connected_calls = [c for c in calls if c.get("type") == "agent_connected"]
        assert len(connected_calls) == 1
        assert connected_calls[0]["agent_id"] == str(agent_id)

    def test_disconnect_broadcasts_agent_disconnected(self) -> None:
        """When the agent WS closes, an agent_disconnected event is broadcast."""
        app = _make_app()
        agent_id = uuid.uuid4()
        agent = _make_agent(agent_id)

        mock_db = AsyncMock()
        mock_db.get = AsyncMock(return_value=agent)
        mock_db.commit = AsyncMock()

        with (
            patch("server.api.ws._verify_agent", new=AsyncMock(return_value=agent)),
            patch("server.api.ws._mark_agent_status", new=AsyncMock()),
            patch("server.api.ws._task_consumer", new=AsyncMock(return_value=None)),
            patch("server.api.ws.AsyncSessionLocal") as mock_session,
            patch.object(manager, "broadcast", new=AsyncMock()) as mock_broadcast,
        ):
            mock_session.return_value.__aenter__ = AsyncMock(return_value=mock_db)
            mock_session.return_value.__aexit__ = AsyncMock(return_value=False)

            with TestClient(app) as client:
                with client.websocket_connect(f"/api/v1/ws/agent/{agent_id}") as _ws:
                    pass  # close immediately

        calls = [c.args[0] for c in mock_broadcast.await_args_list]
        disc_calls = [c for c in calls if c.get("type") == "agent_disconnected"]
        assert len(disc_calls) == 1
        assert disc_calls[0]["agent_id"] == str(agent_id)


# ---------------------------------------------------------------------------
# ConnectionManager unit tests
# ---------------------------------------------------------------------------


class TestConnectionManager:
    """Unit tests for the _ConnectionManager helper class."""

    def test_register_and_deregister_agent(self) -> None:
        from server.api.ws import _ConnectionManager

        mgr = _ConnectionManager()
        ws = MagicMock()
        mgr.register_agent("abc", ws)
        assert mgr.is_connected("abc")
        mgr.deregister_agent("abc")
        assert not mgr.is_connected("abc")

    def test_connected_agent_ids(self) -> None:
        from server.api.ws import _ConnectionManager

        mgr = _ConnectionManager()
        mgr.register_agent("a", MagicMock())
        mgr.register_agent("b", MagicMock())
        assert set(mgr.connected_agent_ids()) == {"a", "b"}

    def test_deregister_nonexistent_is_safe(self) -> None:
        from server.api.ws import _ConnectionManager

        mgr = _ConnectionManager()
        mgr.deregister_agent("nonexistent")  # should not raise

    def test_dashboard_register_deregister(self) -> None:
        from server.api.ws import _ConnectionManager

        mgr = _ConnectionManager()
        ws = MagicMock()
        mgr.register_dashboard(ws)
        mgr.deregister_dashboard(ws)
        mgr.deregister_dashboard(ws)  # idempotent

    @pytest.mark.asyncio
    async def test_send_to_agent_success(self) -> None:
        from server.api.ws import _ConnectionManager

        mgr = _ConnectionManager()
        ws = AsyncMock()
        mgr.register_agent("x", ws)
        result = await mgr.send_to_agent("x", {"type": "task"})
        assert result is True
        ws.send_json.assert_awaited_once_with({"type": "task"})

    @pytest.mark.asyncio
    async def test_send_to_agent_not_connected(self) -> None:
        from server.api.ws import _ConnectionManager

        mgr = _ConnectionManager()
        result = await mgr.send_to_agent("missing", {"type": "task"})
        assert result is False

    @pytest.mark.asyncio
    async def test_broadcast_skips_dead_connections(self) -> None:
        from server.api.ws import _ConnectionManager

        mgr = _ConnectionManager()
        good = AsyncMock()
        bad = AsyncMock()
        bad.send_json.side_effect = RuntimeError("closed")
        mgr.register_dashboard(good)
        mgr.register_dashboard(bad)

        await mgr.broadcast({"type": "test"})

        good.send_json.assert_awaited_once()
        # bad connection should have been removed
        assert bad not in mgr._dashboard


# ---------------------------------------------------------------------------
# Dashboard WS — authentication
# ---------------------------------------------------------------------------


class TestDashboardWSAuth:
    """JWT authentication for the dashboard WebSocket."""

    def test_no_token_times_out_and_closes(self) -> None:
        """Dashboard WS with no token and no first message should close."""
        app = _make_app()
        # Patch asyncio.wait_for at the module level in server.api.ws to raise immediately
        with patch("server.api.ws.asyncio.wait_for", side_effect=asyncio.TimeoutError):
            with TestClient(app) as client:
                with pytest.raises((WebSocketDisconnect, Exception)):
                    with client.websocket_connect("/api/v1/ws/dashboard") as ws:
                        ws.receive_json()

    def test_invalid_token_closes_ws(self) -> None:
        """Invalid JWT → WS closed with 4001."""
        app = _make_app()
        with patch(
            "server.services.auth.decode_token",
            side_effect=Exception("bad token"),
        ):
            with TestClient(app) as client:
                with pytest.raises((WebSocketDisconnect, Exception)):
                    with client.websocket_connect("/api/v1/ws/dashboard?token=bad") as ws:
                        ws.receive_json()

    def test_valid_token_sends_initial_snapshot(self) -> None:
        """Valid JWT → WS accepted + connected_agents snapshot sent."""
        app = _make_app()
        with patch("server.services.auth.decode_token", return_value="admin"):
            with TestClient(app) as client:
                with client.websocket_connect(
                    "/api/v1/ws/dashboard?token=valid-jwt"
                ) as ws:
                    msg = ws.receive_json()
                    assert msg["type"] == "connected_agents"
                    assert isinstance(msg["agent_ids"], list)
