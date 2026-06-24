"""
Tests for /api/v1/alerts — list, get, acknowledge, delete.

Strategy: call the endpoint functions directly with a mocked AsyncSession.
No real DB or HTTP server required.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from unittest.mock import AsyncMock, MagicMock

import pytest
from fastapi import HTTPException

from server.api.alerts import (
    list_alerts,
    get_alert,
    acknowledge_alert,
    delete_alert,
    AcknowledgeRequest,
)
from server.models.alert import Alert, AlertSeverity, AlertType


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_alert(
    severity: str = "high",
    alert_type: str = "vulnerability",
    acknowledged: bool = False,
    message: str = "Test alert",
) -> Alert:
    return Alert(
        id=uuid.uuid4(),
        severity=severity,
        alert_type=alert_type,
        message=message,
        source="test",
        details={"cve": "CVE-2024-0001"},
        acknowledged=acknowledged,
        acknowledged_at=None,
        acknowledged_by=None,
        created_at=datetime.utcnow(),
        updated_at=datetime.utcnow(),
    )


def _mock_db_with_list(alerts: list[Alert]) -> AsyncMock:
    db = AsyncMock()
    mock_result = MagicMock()
    mock_result.scalars.return_value = alerts
    db.execute = AsyncMock(return_value=mock_result)
    return db


# ---------------------------------------------------------------------------
# list_alerts
# ---------------------------------------------------------------------------

class TestListAlerts:
    @pytest.mark.asyncio
    async def test_returns_empty_list(self) -> None:
        db = _mock_db_with_list([])
        result = await list_alerts(
            severity=None, alert_type=None, acknowledged=None,
            limit=100, offset=0, db=db,
        )
        assert result == []

    @pytest.mark.asyncio
    async def test_returns_all_alerts(self) -> None:
        alerts = [_make_alert("critical"), _make_alert("high")]
        db = _mock_db_with_list(alerts)
        result = await list_alerts(
            severity=None, alert_type=None, acknowledged=None,
            limit=100, offset=0, db=db,
        )
        assert len(result) == 2

    @pytest.mark.asyncio
    async def test_filter_by_severity_builds_query(self) -> None:
        alerts = [_make_alert("critical")]
        db = _mock_db_with_list(alerts)
        result = await list_alerts(
            severity="critical", alert_type=None, acknowledged=None,
            limit=100, offset=0, db=db,
        )
        assert len(result) == 1
        db.execute.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_filter_by_acknowledged_builds_query(self) -> None:
        alerts = [_make_alert(acknowledged=True)]
        db = _mock_db_with_list(alerts)
        result = await list_alerts(
            severity=None, alert_type=None, acknowledged=True,
            limit=100, offset=0, db=db,
        )
        assert len(result) == 1
        db.execute.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_filter_by_alert_type_builds_query(self) -> None:
        db = _mock_db_with_list([])
        await list_alerts(
            severity=None, alert_type="agent_offline", acknowledged=None,
            limit=10, offset=0, db=db,
        )
        db.execute.assert_awaited_once()


# ---------------------------------------------------------------------------
# get_alert
# ---------------------------------------------------------------------------

class TestGetAlert:
    @pytest.mark.asyncio
    async def test_returns_alert_when_found(self) -> None:
        alert = _make_alert("medium")
        db = AsyncMock()
        db.get = AsyncMock(return_value=alert)
        result = await get_alert(alert.id, db)
        assert result is alert

    @pytest.mark.asyncio
    async def test_raises_404_when_not_found(self) -> None:
        db = AsyncMock()
        db.get = AsyncMock(return_value=None)
        with pytest.raises(HTTPException) as exc_info:
            await get_alert(uuid.uuid4(), db)
        assert exc_info.value.status_code == 404

    @pytest.mark.asyncio
    async def test_uses_correct_model_class(self) -> None:
        alert = _make_alert()
        db = AsyncMock()
        db.get = AsyncMock(return_value=alert)
        await get_alert(alert.id, db)
        db.get.assert_awaited_once()
        args = db.get.call_args[0]
        assert args[0] is Alert


# ---------------------------------------------------------------------------
# acknowledge_alert
# ---------------------------------------------------------------------------

class TestAcknowledgeAlert:
    @pytest.mark.asyncio
    async def test_sets_acknowledged_true(self) -> None:
        alert = _make_alert(acknowledged=False)
        db = AsyncMock()
        db.get = AsyncMock(return_value=alert)
        db.refresh = AsyncMock(side_effect=lambda a: None)

        body = AcknowledgeRequest(acknowledged_by="alice")
        await acknowledge_alert(alert.id, body, db)

        assert alert.acknowledged is True
        assert alert.acknowledged_by == "alice"
        assert alert.acknowledged_at is not None
        db.commit.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_raises_404_when_alert_missing(self) -> None:
        db = AsyncMock()
        db.get = AsyncMock(return_value=None)
        with pytest.raises(HTTPException) as exc_info:
            await acknowledge_alert(uuid.uuid4(), AcknowledgeRequest(acknowledged_by="bob"), db)
        assert exc_info.value.status_code == 404

    @pytest.mark.asyncio
    async def test_refresh_called_after_commit(self) -> None:
        alert = _make_alert()
        db = AsyncMock()
        db.get = AsyncMock(return_value=alert)
        db.refresh = AsyncMock(side_effect=lambda a: None)

        await acknowledge_alert(alert.id, AcknowledgeRequest(acknowledged_by="admin"), db)
        db.refresh.assert_awaited_once_with(alert)


# ---------------------------------------------------------------------------
# delete_alert
# ---------------------------------------------------------------------------

class TestDeleteAlert:
    @pytest.mark.asyncio
    async def test_deletes_alert(self) -> None:
        alert = _make_alert()
        db = AsyncMock()
        db.get = AsyncMock(return_value=alert)

        await delete_alert(alert.id, db)

        db.delete.assert_awaited_once_with(alert)
        db.commit.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_raises_404_when_not_found(self) -> None:
        db = AsyncMock()
        db.get = AsyncMock(return_value=None)
        with pytest.raises(HTTPException) as exc_info:
            await delete_alert(uuid.uuid4(), db)
        assert exc_info.value.status_code == 404


# ---------------------------------------------------------------------------
# AlertSeverity / AlertType enums
# ---------------------------------------------------------------------------

class TestAlertEnums:
    def test_severity_values(self) -> None:
        assert AlertSeverity.CRITICAL == "critical"
        assert AlertSeverity.HIGH == "high"
        assert AlertSeverity.MEDIUM == "medium"
        assert AlertSeverity.LOW == "low"
        assert AlertSeverity.INFO == "info"

    def test_alert_type_values(self) -> None:
        assert AlertType.VULNERABILITY == "vulnerability"
        assert AlertType.AGENT_OFFLINE == "agent_offline"
        assert AlertType.NEW_HOST == "new_host"
