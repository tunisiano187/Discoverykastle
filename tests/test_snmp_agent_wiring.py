"""
Tests for SNMP config properties in agent/config.py and the SNMP loop wiring
in agent/core.py (DKAgent._snmp_loop / _run_snmp_poll).

All tests are fully mocked — no live SNMP, no network.
"""

from __future__ import annotations

import asyncio
from unittest.mock import MagicMock, patch

import pytest


# ===========================================================================
# AgentConfig — SNMP properties
# ===========================================================================

class TestSNMPConfig:
    """AgentConfig exposes correct SNMP properties with sensible defaults."""

    def _make_config(self, env: dict[str, str] | None = None) -> object:
        from agent.config import AgentConfig
        cfg = AgentConfig.__new__(AgentConfig)
        cfg._file = env or {}
        cfg._env = {}
        return cfg

    def test_snmp_disabled_by_default(self) -> None:
        from agent.config import AgentConfig
        cfg = AgentConfig.__new__(AgentConfig)
        cfg._file = {}
        cfg._env = {}
        assert cfg.snmp_enabled is False

    def test_snmp_enabled_via_env(self) -> None:
        with patch.dict("os.environ", {"SNMP_ENABLED": "true"}):
            from agent.config import AgentConfig
            cfg = AgentConfig.__new__(AgentConfig)
            cfg._file = {}
            cfg._env = {}
            assert cfg.snmp_enabled is True

    def test_snmp_defaults(self) -> None:
        cfg = self._make_config()
        assert cfg.snmp_community == "public"
        assert cfg.snmp_version == "2c"
        assert cfg.snmp_port == 161
        assert cfg.snmp_timeout == 5
        assert cfg.snmp_retries == 2
        assert cfg.snmp_poll_interval == 900

    def test_snmp_v3_defaults_empty(self) -> None:
        cfg = self._make_config()
        assert cfg.snmpv3_username == ""
        assert cfg.snmpv3_auth_protocol == "SHA"
        assert cfg.snmpv3_auth_passphrase == ""
        assert cfg.snmpv3_priv_protocol == "AES"
        assert cfg.snmpv3_priv_passphrase == ""

    def test_snmp_overrides_from_file(self) -> None:
        cfg = self._make_config({
            "SNMP_COMMUNITY": "mysecret",
            "SNMP_VERSION": "3",
            "SNMP_PORT": "1161",
            "SNMP_TIMEOUT": "10",
            "SNMP_RETRIES": "5",
            "SNMP_POLL_INTERVAL": "1800",
        })
        assert cfg.snmp_community == "mysecret"
        assert cfg.snmp_version == "3"
        assert cfg.snmp_port == 1161
        assert cfg.snmp_timeout == 10
        assert cfg.snmp_retries == 5
        assert cfg.snmp_poll_interval == 1800


# ===========================================================================
# DKAgent — _run_snmp_poll instantiates SNMPCollector correctly
# ===========================================================================

class TestRunSNMPPoll:
    """_run_snmp_poll builds an SNMPCollector with config values and calls run_poll_cycle."""

    def _make_cfg(self) -> MagicMock:
        cfg = MagicMock()
        cfg.server_url = "https://server.local"
        cfg.agent_id = "agent-42"
        cfg.agent_cert = "/tmp/agent.crt"
        cfg.agent_key = "/tmp/agent.key"
        cfg.agent_ca = None
        cfg.snmp_community = "testcommunity"
        cfg.snmp_version = "2c"
        cfg.snmp_port = 161
        cfg.snmp_timeout = 5
        cfg.snmp_retries = 2
        cfg.snmpv3_username = ""
        cfg.snmpv3_auth_protocol = "SHA"
        cfg.snmpv3_auth_passphrase = ""
        cfg.snmpv3_priv_protocol = "AES"
        cfg.snmpv3_priv_passphrase = ""
        return cfg

    def test_creates_collector_and_calls_run_poll_cycle(self) -> None:
        from agent.core import DKAgent

        cfg = self._make_cfg()
        agent = DKAgent.__new__(DKAgent)
        agent.config = cfg

        mock_collector_instance = MagicMock()
        mock_collector_cls = MagicMock(return_value=mock_collector_instance)

        # _run_snmp_poll lazy-imports SNMPCollector inside the function body,
        # so patch at the source module, not at agent.core.
        with patch("agent.collectors.snmp_collector.SNMPCollector", mock_collector_cls):
            with patch("agent.core._build_ssl_ctx", return_value=None):
                agent._run_snmp_poll()

        # SNMPCollector was instantiated
        mock_collector_cls.assert_called_once()
        call_kwargs = mock_collector_cls.call_args.kwargs
        assert call_kwargs["community"] == "testcommunity"
        assert call_kwargs["version"] == "2c"
        assert call_kwargs["snmp_port"] == 161
        mock_collector_instance.run_poll_cycle.assert_called_once()

    def test_run_poll_cycle_uses_correct_args(self) -> None:
        """Verify all SNMPv3 kwargs are forwarded from config."""
        from agent.core import DKAgent

        cfg = self._make_cfg()
        cfg.snmpv3_username = "admin"
        cfg.snmpv3_auth_passphrase = "authpass"
        cfg.snmpv3_priv_passphrase = "privpass"

        agent = DKAgent.__new__(DKAgent)
        agent.config = cfg

        mock_collector_instance = MagicMock()
        mock_collector_cls = MagicMock(return_value=mock_collector_instance)

        # _run_snmp_poll lazy-imports SNMPCollector inside the function body,
        # so patch at the source module, not at agent.core.
        with patch("agent.collectors.snmp_collector.SNMPCollector", mock_collector_cls):
            with patch("agent.core._build_ssl_ctx", return_value=None):
                agent._run_snmp_poll()

        call_kwargs = mock_collector_cls.call_args.kwargs
        assert call_kwargs["v3_username"] == "admin"
        assert call_kwargs["v3_auth_passphrase"] == "authpass"
        assert call_kwargs["v3_priv_passphrase"] == "privpass"


# ===========================================================================
# DKAgent — _snmp_loop async behaviour
# ===========================================================================

@pytest.mark.asyncio
class TestSNMPLoop:
    """_snmp_loop calls _run_snmp_poll via to_thread and sleeps between cycles."""

    def _make_cfg(self) -> MagicMock:
        cfg = MagicMock()
        cfg.snmp_poll_interval = 0  # no real sleep in tests
        return cfg

    @staticmethod
    def _make_agent(cfg: MagicMock) -> object:
        from agent.core import DKAgent
        agent = DKAgent.__new__(DKAgent)
        agent.config = cfg
        return agent

    async def test_loop_calls_run_poll_cycle_once(self) -> None:
        cfg = self._make_cfg()
        agent = self._make_agent(cfg)

        poll_called = asyncio.Event()

        def _fake_poll() -> None:
            poll_called.set()

        with patch.object(agent, "_run_snmp_poll", side_effect=_fake_poll):
            loop_task = asyncio.create_task(agent._snmp_loop())
            await asyncio.wait_for(poll_called.wait(), timeout=2.0)
            loop_task.cancel()
            try:
                await loop_task
            except asyncio.CancelledError:
                pass

        assert poll_called.is_set()

    async def test_loop_continues_after_poll_error(self) -> None:
        """A RuntimeError in _run_snmp_poll must not crash the loop."""
        cfg = self._make_cfg()
        agent = self._make_agent(cfg)

        call_count = 0
        second_call = asyncio.Event()

        def _failing_poll() -> None:
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                raise RuntimeError("SNMP timeout")
            second_call.set()

        with patch.object(agent, "_run_snmp_poll", side_effect=_failing_poll):
            loop_task = asyncio.create_task(agent._snmp_loop())
            await asyncio.wait_for(second_call.wait(), timeout=2.0)
            loop_task.cancel()
            try:
                await loop_task
            except asyncio.CancelledError:
                pass

        assert call_count >= 2
