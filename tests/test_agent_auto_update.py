"""
Unit tests for agent auto-update wired into the heartbeat loop.

All tests are fully mocked — no network, no server, no pip required.
"""

from __future__ import annotations

import asyncio
from unittest.mock import AsyncMock, MagicMock, patch

import pytest


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_config(**overrides):
    """Return a minimal AgentConfig-like mock."""
    cfg = MagicMock()
    cfg.server_url = "https://server.local"
    cfg.agent_id = "test-agent-id"
    cfg.is_registered = True
    cfg.agent_cert = "/tmp/agent.crt"
    cfg.agent_key = "/tmp/agent.key"
    cfg.agent_ca = None
    cfg.heartbeat_interval = 0  # don't wait in tests
    cfg.puppet_enabled = False
    cfg.nmap_enabled = False
    cfg.cve_scan_enabled = False
    cfg.ansible_enabled = False
    cfg.netmiko_enabled = False
    for k, v in overrides.items():
        setattr(cfg, k, v)
    return cfg


def _make_heartbeat_response(
    agent_update_required: bool = False,
    agent_update_target: str | None = None,
    server_version: str = "0.1.0",
) -> MagicMock:
    """Return a mock httpx.Response with heartbeat JSON."""
    resp = MagicMock()
    resp.raise_for_status = MagicMock()
    resp.json.return_value = {
        "ok": True,
        "server_version": server_version,
        "agent_update_required": agent_update_required,
        "agent_update_target": agent_update_target,
    }
    return resp


# ---------------------------------------------------------------------------
# Tests — heartbeat sends agent_version
# ---------------------------------------------------------------------------


class TestHeartbeatSendsVersion:
    """The heartbeat POST must include agent_version in the JSON body."""

    @pytest.mark.asyncio
    async def test_heartbeat_includes_agent_version(self) -> None:
        from agent.core import DKAgent

        cfg = _make_config()
        agent = DKAgent(cfg)

        posted_bodies: list[dict] = []

        async def _fake_post(url, **kwargs):
            posted_bodies.append(kwargs.get("json", {}))
            return _make_heartbeat_response()

        mock_client = AsyncMock()
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)
        mock_client.post = AsyncMock(side_effect=_fake_post)

        with patch.object(agent, "_build_client", return_value=mock_client):
            with patch("agent.core._agent_version", return_value="0.1.0"):
                loop_task = asyncio.create_task(agent._heartbeat_loop())
                await asyncio.sleep(0)
                loop_task.cancel()
                try:
                    await loop_task
                except asyncio.CancelledError:
                    pass

        assert len(posted_bodies) >= 1
        assert posted_bodies[0].get("agent_version") == "0.1.0"


# ---------------------------------------------------------------------------
# Tests — no update when agent_update_required is False
# ---------------------------------------------------------------------------


class TestNoUpdateWhenNotRequired:
    """self_update must NOT be called when agent_update_required is False."""

    @pytest.mark.asyncio
    async def test_no_update_called(self) -> None:
        from agent.core import DKAgent

        cfg = _make_config()
        agent = DKAgent(cfg)

        mock_client = AsyncMock()
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)
        mock_client.post = AsyncMock(return_value=_make_heartbeat_response(agent_update_required=False))

        with patch.object(agent, "_build_client", return_value=mock_client):
            with patch("agent.core.self_update") as mock_update:
                loop_task = asyncio.create_task(agent._heartbeat_loop())
                await asyncio.sleep(0)
                loop_task.cancel()
                try:
                    await loop_task
                except asyncio.CancelledError:
                    pass

        mock_update.assert_not_called()


# ---------------------------------------------------------------------------
# Tests — self_update called when required, with correct target
# ---------------------------------------------------------------------------


class TestUpdateCalledWhenRequired:
    """self_update must be called with the correct target when requested."""

    @pytest.mark.asyncio
    async def test_update_called_with_latest(self) -> None:
        from agent.core import DKAgent

        cfg = _make_config()
        agent = DKAgent(cfg)

        update_event = asyncio.Event()

        def _fake_self_update(target):
            update_event.set()

        mock_client = AsyncMock()
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)
        mock_client.post = AsyncMock(
            return_value=_make_heartbeat_response(agent_update_required=True, agent_update_target=None)
        )

        with patch.object(agent, "_build_client", return_value=mock_client):
            with patch("agent.core.self_update", side_effect=_fake_self_update) as mock_update:
                loop_task = asyncio.create_task(agent._heartbeat_loop())
                await asyncio.wait_for(update_event.wait(), timeout=2.0)
                loop_task.cancel()
                try:
                    await loop_task
                except asyncio.CancelledError:
                    pass

        mock_update.assert_called_once_with(None)

    @pytest.mark.asyncio
    async def test_update_called_with_pinned_version(self) -> None:
        from agent.core import DKAgent

        cfg = _make_config()
        agent = DKAgent(cfg)

        update_event = asyncio.Event()

        def _fake_self_update(target):
            update_event.set()

        mock_client = AsyncMock()
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)
        mock_client.post = AsyncMock(
            return_value=_make_heartbeat_response(
                agent_update_required=True,
                agent_update_target="discoverykastle-agent==0.2.0",
            )
        )

        with patch.object(agent, "_build_client", return_value=mock_client):
            with patch("agent.core.self_update", side_effect=_fake_self_update) as mock_update:
                loop_task = asyncio.create_task(agent._heartbeat_loop())
                await asyncio.wait_for(update_event.wait(), timeout=2.0)
                loop_task.cancel()
                try:
                    await loop_task
                except asyncio.CancelledError:
                    pass

        mock_update.assert_called_once_with("discoverykastle-agent==0.2.0")


# ---------------------------------------------------------------------------
# Tests — update failure is non-fatal
# ---------------------------------------------------------------------------


class TestUpdateFailureIsNonFatal:
    """A self_update exception must be logged but not crash the heartbeat loop."""

    @pytest.mark.asyncio
    async def test_update_failure_does_not_stop_loop(self) -> None:
        from agent.core import DKAgent

        cfg = _make_config()
        agent = DKAgent(cfg)

        call_count = 0

        def _failing_update(target):
            raise RuntimeError("pip failed")

        async def _response_sequence(*args, **kwargs):
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                return _make_heartbeat_response(agent_update_required=True)
            return _make_heartbeat_response(agent_update_required=False)

        mock_client = AsyncMock()
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)
        mock_client.post = AsyncMock(side_effect=_response_sequence)

        with patch.object(agent, "_build_client", return_value=mock_client):
            with patch("agent.core.self_update", side_effect=_failing_update):
                loop_task = asyncio.create_task(agent._heartbeat_loop())
                # Wait long enough for two iterations
                await asyncio.sleep(0.05)
                loop_task.cancel()
                try:
                    await loop_task
                except asyncio.CancelledError:
                    pass

        # Loop ran at least twice — it didn't crash after the update failure
        assert call_count >= 2


# ---------------------------------------------------------------------------
# Tests — updater.self_update unit tests (no subprocess)
# ---------------------------------------------------------------------------


class TestSelfUpdateUnit:
    """Unit tests for updater.self_update without actually running pip."""

    def test_calls_pip_with_default_target(self) -> None:
        from agent import updater

        run_result = MagicMock()
        run_result.returncode = 0

        with patch("subprocess.run", return_value=run_result) as mock_run:
            with patch.object(updater, "_restart"):
                updater.self_update()

        call_args = mock_run.call_args[0][0]
        assert "pip" in " ".join(call_args)
        assert "discoverykastle-agent" in call_args

    def test_calls_pip_with_pinned_target(self) -> None:
        from agent import updater

        run_result = MagicMock()
        run_result.returncode = 0

        with patch("subprocess.run", return_value=run_result) as mock_run:
            with patch.object(updater, "_restart"):
                updater.self_update("discoverykastle-agent==0.2.0")

        call_args = mock_run.call_args[0][0]
        assert "discoverykastle-agent==0.2.0" in call_args

    def test_raises_on_pip_failure(self) -> None:
        from agent import updater

        run_result = MagicMock()
        run_result.returncode = 1
        run_result.stdout = ""
        run_result.stderr = "ERROR: No matching distribution"

        with patch("subprocess.run", return_value=run_result):
            with pytest.raises(RuntimeError, match="pip upgrade failed"):
                updater.self_update()
