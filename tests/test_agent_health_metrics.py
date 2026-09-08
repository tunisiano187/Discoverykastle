"""
Tests for agent resource-metric collection and heartbeat enrichment.

Covers:
  • _collect_resource_metrics() — with psutil, without psutil, partial failure
  • Heartbeat handler stores metrics on the agent record
  • Heartbeat handler skips None metric values (no overwrite)
  • AgentOut schema exposes cpu/memory/disk_percent fields
"""

from __future__ import annotations

import sys
import uuid
from datetime import datetime
from types import ModuleType
from unittest.mock import AsyncMock, MagicMock, patch

import pytest


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_agent_record(
    agent_id: uuid.UUID | None = None,
    cpu: float | None = None,
    mem: float | None = None,
    disk: float | None = None,
) -> MagicMock:
    rec = MagicMock()
    rec.id = agent_id or uuid.uuid4()
    rec.certificate_fingerprint = "fp"
    rec.hostname = "host1"
    rec.ip_address = "10.0.0.1"
    rec.version = "0.1.0"
    rec.status = "online"
    rec.authorized_cidrs = []
    rec.last_heartbeat = None
    rec.cpu_percent = cpu
    rec.memory_percent = mem
    rec.disk_percent = disk
    rec.created_at = datetime.utcnow()
    return rec


def _make_db(agent: MagicMock | None = None) -> AsyncMock:
    db = AsyncMock()
    db.get = AsyncMock(return_value=agent)
    return db


# ===========================================================================
# _collect_resource_metrics
# ===========================================================================

class TestCollectResourceMetrics:

    def test_returns_metrics_when_psutil_available(self):
        """When psutil is importable, all three metrics must be floats."""
        mock_psutil = ModuleType("psutil")
        mock_psutil.cpu_percent = lambda interval=None: 42.5
        vm = MagicMock()
        vm.percent = 61.0
        mock_psutil.virtual_memory = lambda: vm
        du = MagicMock()
        du.percent = 35.0
        mock_psutil.disk_usage = lambda path: du

        with patch.dict(sys.modules, {"psutil": mock_psutil}):
            from importlib import reload
            import agent.core as core_mod
            reload(core_mod)
            result = core_mod._collect_resource_metrics()

        assert isinstance(result["cpu_percent"], float)
        assert isinstance(result["memory_percent"], float)
        assert isinstance(result["disk_percent"], float)

    def test_returns_none_values_when_psutil_missing(self):
        """When psutil is not available, all values must be None."""
        with patch.dict(sys.modules, {"psutil": None}):
            from agent.core import _collect_resource_metrics
            result = _collect_resource_metrics()

        assert result["cpu_percent"] is None
        assert result["memory_percent"] is None
        assert result["disk_percent"] is None

    def test_returns_none_on_psutil_exception(self):
        """Any psutil error must be caught, returning None values."""
        mock_psutil = ModuleType("psutil")
        mock_psutil.cpu_percent = MagicMock(side_effect=OSError("no data"))

        with patch.dict(sys.modules, {"psutil": mock_psutil}):
            from agent.core import _collect_resource_metrics
            result = _collect_resource_metrics()

        assert result["cpu_percent"] is None

    def test_returns_dict_with_expected_keys(self):
        """Result must always have the three expected keys."""
        with patch.dict(sys.modules, {"psutil": None}):
            from agent.core import _collect_resource_metrics
            result = _collect_resource_metrics()

        assert set(result.keys()) == {"cpu_percent", "memory_percent", "disk_percent"}


# ===========================================================================
# Heartbeat handler stores metrics
# ===========================================================================

@pytest.mark.asyncio
class TestHeartbeatStoresMetrics:

    async def test_stores_all_three_metrics(self):
        from server.api.agents import heartbeat
        from server.api.agents import HeartbeatRequest

        agent_id = uuid.uuid4()
        agent = _make_agent_record(agent_id)
        db = _make_db(agent)

        with patch("server.services.version.agent_needs_update", return_value=False):
            with patch("server.services.version.current_version", return_value="0.1.0"):
                await heartbeat(
                    agent_id=agent_id,
                    body=HeartbeatRequest(
                        agent_version="0.1.0",
                        cpu_percent=55.0,
                        memory_percent=70.0,
                        disk_percent=20.0,
                    ),
                    x_agent_fingerprint="fp",
                    x_agent_id=None,
                    db=db,
                )

        assert agent.cpu_percent == 55.0
        assert agent.memory_percent == 70.0
        assert agent.disk_percent == 20.0

    async def test_skips_none_metrics(self):
        """None metric values must NOT overwrite existing values on the record."""
        from server.api.agents import heartbeat
        from server.api.agents import HeartbeatRequest

        agent_id = uuid.uuid4()
        agent = _make_agent_record(agent_id, cpu=80.0, mem=60.0, disk=40.0)
        db = _make_db(agent)

        with patch("server.services.version.agent_needs_update", return_value=False):
            with patch("server.services.version.current_version", return_value="0.1.0"):
                await heartbeat(
                    agent_id=agent_id,
                    body=HeartbeatRequest(
                        agent_version="0.1.0",
                        cpu_percent=None,
                        memory_percent=None,
                        disk_percent=None,
                    ),
                    x_agent_fingerprint="fp",
                    x_agent_id=None,
                    db=db,
                )

        # Existing values must be preserved when payload sends None
        assert agent.cpu_percent == 80.0
        assert agent.memory_percent == 60.0
        assert agent.disk_percent == 40.0

    async def test_partial_metrics_accepted(self):
        """Only the provided (non-None) metric fields should be updated."""
        from server.api.agents import heartbeat
        from server.api.agents import HeartbeatRequest

        agent_id = uuid.uuid4()
        agent = _make_agent_record(agent_id, cpu=10.0, mem=20.0, disk=30.0)
        db = _make_db(agent)

        with patch("server.services.version.agent_needs_update", return_value=False):
            with patch("server.services.version.current_version", return_value="0.1.0"):
                await heartbeat(
                    agent_id=agent_id,
                    body=HeartbeatRequest(
                        cpu_percent=99.0,
                        memory_percent=None,   # omitted — must not overwrite
                        disk_percent=50.0,
                    ),
                    x_agent_fingerprint="fp",
                    x_agent_id=None,
                    db=db,
                )

        assert agent.cpu_percent == 99.0    # updated
        assert agent.memory_percent == 20.0  # preserved
        assert agent.disk_percent == 50.0   # updated


# ===========================================================================
# AgentOut schema exposes metric fields
# ===========================================================================

class TestAgentOutSchema:

    def test_includes_resource_metric_fields(self):
        from server.api.agents import AgentOut

        fields = AgentOut.model_fields
        assert "cpu_percent" in fields
        assert "memory_percent" in fields
        assert "disk_percent" in fields

    def test_metric_fields_are_optional(self):
        from server.api.agents import AgentOut

        # Must be constructable with metrics absent (None defaults)
        rec = MagicMock()
        rec.id = uuid.uuid4()
        rec.hostname = "h"
        rec.ip_address = "1.2.3.4"
        rec.version = "0.1.0"
        rec.status = "online"
        rec.authorized_cidrs = []
        rec.last_heartbeat = None
        rec.cpu_percent = None
        rec.memory_percent = None
        rec.disk_percent = None
        rec.created_at = datetime.utcnow()

        out = AgentOut.model_validate(rec)
        assert out.cpu_percent is None
        assert out.memory_percent is None
        assert out.disk_percent is None

    def test_metric_values_serialised_correctly(self):
        from server.api.agents import AgentOut

        rec = MagicMock()
        rec.id = uuid.uuid4()
        rec.hostname = "h"
        rec.ip_address = "1.2.3.4"
        rec.version = "0.1.0"
        rec.status = "online"
        rec.authorized_cidrs = []
        rec.last_heartbeat = None
        rec.cpu_percent = 42.5
        rec.memory_percent = 61.0
        rec.disk_percent = 35.0
        rec.created_at = datetime.utcnow()

        out = AgentOut.model_validate(rec)
        assert out.cpu_percent == 42.5
        assert out.memory_percent == 61.0
        assert out.disk_percent == 35.0
