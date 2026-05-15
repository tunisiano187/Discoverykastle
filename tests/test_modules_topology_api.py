"""
Tests for /api/v1/modules and /api/v1/topology endpoints.

Strategy: call endpoint functions directly with mocked registry / DB.
No real DB, HTTP server, or native crypto required.
"""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fastapi import HTTPException


# ---------------------------------------------------------------------------
# Modules API — /api/v1/modules
# ---------------------------------------------------------------------------

class TestListModules:
    @pytest.mark.asyncio
    async def test_returns_empty_list_when_no_modules(self) -> None:
        from server.api.modules import list_modules
        with patch("server.api.modules.registry") as mock_reg:
            mock_reg.list_modules.return_value = []
            result = await list_modules()
        assert result == []

    @pytest.mark.asyncio
    async def test_returns_module_dicts(self) -> None:
        from server.api.modules import list_modules
        modules = [
            {
                "name": "builtin-alerts",
                "version": "0.1.0",
                "description": "Alert management",
                "author": "DK",
                "capabilities": ["alert"],
                "builtin": True,
            }
        ]
        with patch("server.api.modules.registry") as mock_reg:
            mock_reg.list_modules.return_value = modules
            result = await list_modules()
        assert len(result) == 1
        assert result[0]["name"] == "builtin-alerts"

    @pytest.mark.asyncio
    async def test_multiple_modules_returned(self) -> None:
        from server.api.modules import list_modules
        with patch("server.api.modules.registry") as mock_reg:
            mock_reg.list_modules.return_value = [
                {"name": "builtin-dns", "version": "0.1.0", "description": "DNS",
                 "author": "DK", "capabilities": [], "builtin": True},
                {"name": "builtin-alerts", "version": "0.1.0", "description": "Alerts",
                 "author": "DK", "capabilities": [], "builtin": True},
            ]
            result = await list_modules()
        assert len(result) == 2


class TestGetModule:
    def _make_module_mock(self, name: str = "builtin-dns") -> MagicMock:
        m = MagicMock()
        m.manifest.name = name
        m.manifest.version = "0.1.0"
        m.manifest.description = "DNS enrichment"
        m.manifest.author = "DK"
        m.manifest.capabilities = []
        m.manifest.builtin = True
        return m

    @pytest.mark.asyncio
    async def test_returns_module_when_found(self) -> None:
        from server.api.modules import get_module
        mock_module = self._make_module_mock("builtin-dns")
        with patch("server.api.modules.registry") as mock_reg:
            mock_reg.get_module.return_value = mock_module
            result = await get_module("builtin-dns")
        assert result["name"] == "builtin-dns"
        assert result["version"] == "0.1.0"
        assert result["builtin"] is True

    @pytest.mark.asyncio
    async def test_raises_404_when_not_found(self) -> None:
        from server.api.modules import get_module
        with patch("server.api.modules.registry") as mock_reg:
            mock_reg.get_module.return_value = None
            with pytest.raises(HTTPException) as exc_info:
                await get_module("nonexistent-module")
        assert exc_info.value.status_code == 404

    @pytest.mark.asyncio
    async def test_capabilities_serialized_as_strings(self) -> None:
        from server.api.modules import get_module
        mock_cap = MagicMock()
        mock_cap.value = "enrich_host"
        mock_module = self._make_module_mock()
        mock_module.manifest.capabilities = [mock_cap]
        with patch("server.api.modules.registry") as mock_reg:
            mock_reg.get_module.return_value = mock_module
            result = await get_module("builtin-dns")
        assert result["capabilities"] == ["enrich_host"]


# ---------------------------------------------------------------------------
# Topology API — /api/v1/topology
# ---------------------------------------------------------------------------

class TestGetTopologyGraph:
    @pytest.mark.asyncio
    async def test_returns_empty_graph_when_module_not_loaded(self) -> None:
        from server.api.topology import get_topology_graph
        db = AsyncMock()
        with patch("server.api.topology.registry") as mock_reg:
            mock_reg.get_module.return_value = None
            result = await get_topology_graph(db)
        assert result["nodes"] == []
        assert result["edges"] == []
        assert "error" in result

    @pytest.mark.asyncio
    async def test_delegates_to_topology_module(self) -> None:
        from server.api.topology import get_topology_graph
        db = AsyncMock()
        expected = {"nodes": [{"id": "h1"}], "edges": []}
        mock_module = MagicMock()
        mock_module.build_graph = AsyncMock(return_value=expected)
        with patch("server.api.topology.registry") as mock_reg:
            mock_reg.get_module.return_value = mock_module
            result = await get_topology_graph(db)
        assert result == expected
        mock_module.build_graph.assert_awaited_once_with(db)

    @pytest.mark.asyncio
    async def test_get_module_called_with_correct_name(self) -> None:
        from server.api.topology import get_topology_graph
        db = AsyncMock()
        with patch("server.api.topology.registry") as mock_reg:
            mock_reg.get_module.return_value = None
            await get_topology_graph(db)
        mock_reg.get_module.assert_called_once_with("builtin-topology")


class TestExportTopologyMarkdown:
    @pytest.mark.asyncio
    async def test_returns_markdown_when_content_available(self) -> None:
        from server.api.topology import export_network_plan_markdown
        from starlette.responses import Response
        db = AsyncMock()
        with patch("server.api.topology.registry") as mock_reg:
            mock_reg.collect_export = AsyncMock(return_value="# Network Plan\n\nSome content")
            result = await export_network_plan_markdown(db)
        assert isinstance(result, Response)
        assert result.media_type == "text/markdown"
        assert b"# Network Plan" in result.body

    @pytest.mark.asyncio
    async def test_returns_placeholder_when_no_content(self) -> None:
        from server.api.topology import export_network_plan_markdown
        from starlette.responses import Response
        db = AsyncMock()
        with patch("server.api.topology.registry") as mock_reg:
            mock_reg.collect_export = AsyncMock(return_value=None)
            result = await export_network_plan_markdown(db)
        assert isinstance(result, Response)
        assert b"No topology data" in result.body

    @pytest.mark.asyncio
    async def test_content_disposition_header_set(self) -> None:
        from server.api.topology import export_network_plan_markdown
        db = AsyncMock()
        with patch("server.api.topology.registry") as mock_reg:
            mock_reg.collect_export = AsyncMock(return_value="# Plan")
            result = await export_network_plan_markdown(db)
        cd = result.headers.get("content-disposition", "")
        assert "network-plan.md" in cd
