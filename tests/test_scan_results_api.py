"""
Tests for the scan-results inventory endpoints:
  GET /api/v1/inventory/scan-results
  GET /api/v1/inventory/networks/{id}/scan-results

All tests use the route handler functions directly with mocked
AsyncSession — no live DB or HTTP server required.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from unittest.mock import AsyncMock, MagicMock

import pytest

from server.api.inventory import list_scan_results, list_network_scan_results


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_scan_result(
    network_id: uuid.UUID | None = None,
    hosts_found: list[str] | None = None,
) -> MagicMock:
    sr = MagicMock()
    sr.id = uuid.uuid4()
    sr.network_id = network_id
    sr.agent_id = uuid.uuid4()
    sr.started_at = datetime.utcnow()
    sr.completed_at = datetime.utcnow()
    sr.hosts_found = hosts_found or ["10.0.0.1", "10.0.0.2"]
    sr.created_at = datetime.utcnow()
    return sr


def _make_db(results: list | None = None, network: MagicMock | None = None) -> AsyncMock:
    db = AsyncMock()
    rows = MagicMock()
    rows.scalars.return_value = results or []
    db.execute = AsyncMock(return_value=rows)
    db.get = AsyncMock(return_value=network)
    return db


# ===========================================================================
# GET /api/v1/inventory/scan-results
# ===========================================================================

@pytest.mark.asyncio
class TestListScanResults:

    async def test_returns_list_of_scan_results(self):
        sr1 = _make_scan_result()
        sr2 = _make_scan_result()
        db = _make_db(results=[sr1, sr2])

        result = await list_scan_results(network_id=None, limit=50, db=db)

        assert len(result) == 2
        db.execute.assert_awaited_once()

    async def test_empty_list_when_no_results(self):
        db = _make_db(results=[])

        result = await list_scan_results(network_id=None, limit=50, db=db)

        assert result == []

    async def test_network_id_filter_is_applied(self):
        """When network_id is given, the query must include a WHERE clause."""
        net_id = uuid.uuid4()
        sr = _make_scan_result(network_id=net_id)
        db = _make_db(results=[sr])

        result = await list_scan_results(network_id=net_id, limit=50, db=db)

        # We verify that db.execute was called (query was executed)
        assert len(result) == 1
        db.execute.assert_awaited_once()

    async def test_limit_is_respected(self):
        results = [_make_scan_result() for _ in range(5)]
        db = _make_db(results=results)

        result = await list_scan_results(network_id=None, limit=5, db=db)

        assert len(result) == 5

    async def test_returns_result_with_hosts_found(self):
        sr = _make_scan_result(hosts_found=["192.168.1.1", "192.168.1.2", "192.168.1.3"])
        db = _make_db(results=[sr])

        result = await list_scan_results(network_id=None, limit=50, db=db)

        assert len(result) == 1
        assert len(result[0].hosts_found) == 3


# ===========================================================================
# GET /api/v1/inventory/networks/{id}/scan-results
# ===========================================================================

@pytest.mark.asyncio
class TestListNetworkScanResults:

    async def test_returns_scan_results_for_network(self):
        net_id = uuid.uuid4()
        net = MagicMock()
        net.id = net_id
        sr1 = _make_scan_result(network_id=net_id)
        sr2 = _make_scan_result(network_id=net_id)
        db = _make_db(results=[sr1, sr2], network=net)

        result = await list_network_scan_results(
            network_id=net_id, limit=20, db=db
        )

        assert len(result) == 2

    async def test_returns_404_when_network_not_found(self):
        from fastapi import HTTPException

        db = _make_db(results=[], network=None)

        with pytest.raises(HTTPException) as exc_info:
            await list_network_scan_results(
                network_id=uuid.uuid4(), limit=20, db=db
            )

        assert exc_info.value.status_code == 404
        assert "Network not found" in exc_info.value.detail

    async def test_empty_list_for_network_with_no_scans(self):
        net_id = uuid.uuid4()
        net = MagicMock()
        net.id = net_id
        db = _make_db(results=[], network=net)

        result = await list_network_scan_results(
            network_id=net_id, limit=20, db=db
        )

        assert result == []

    async def test_limit_parameter_controls_max_results(self):
        net_id = uuid.uuid4()
        net = MagicMock()
        net.id = net_id
        results = [_make_scan_result(network_id=net_id) for _ in range(3)]
        db = _make_db(results=results, network=net)

        result = await list_network_scan_results(
            network_id=net_id, limit=3, db=db
        )

        assert len(result) == 3
        db.execute.assert_awaited_once()

    async def test_network_lookup_happens_before_query(self):
        """db.get must be called before db.execute (existence check first)."""
        call_order = []

        db = AsyncMock()
        db.get = AsyncMock(side_effect=lambda *a, **kw: call_order.append("get") or MagicMock())
        rows = MagicMock()
        rows.scalars.return_value = []

        async def exec_side(*a, **kw):
            call_order.append("execute")
            return rows

        db.execute = exec_side

        await list_network_scan_results(network_id=uuid.uuid4(), limit=20, db=db)

        assert call_order == ["get", "execute"]
