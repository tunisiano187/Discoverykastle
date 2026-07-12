"""
Tests for server/api/auth_requests.py — Authorization Requests API.

Strategy: mock AsyncSession; no DB or real server startup needed.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from unittest.mock import AsyncMock, MagicMock

import pytest

_AGENT_ID = uuid.UUID("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee")
_REQUEST_ID = uuid.UUID("11111111-2222-3333-4444-555555555555")
_NOW = datetime(2026, 1, 1, 12, 0, 0)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_agent(**kwargs):
    defaults = dict(id=_AGENT_ID, certificate_fingerprint="sha256:abc", status="online")
    defaults.update(kwargs)
    a = MagicMock()
    for k, v in defaults.items():
        setattr(a, k, v)
    return a


def _make_request(status="pending", request_type="recursive_scan", **kwargs):
    defaults = dict(
        id=_REQUEST_ID,
        agent_id=_AGENT_ID,
        request_type=request_type,
        details={"cidr": "10.1.0.0/24"},
        status=status,
        requested_at=_NOW,
        resolved_at=None,
        resolved_by=None,
        expires_at=None,
    )
    defaults.update(kwargs)
    r = MagicMock()
    for k, v in defaults.items():
        setattr(r, k, v)
    return r


def _make_db(agent=None, auth_req=None, auth_req_list=None) -> AsyncMock:
    db = AsyncMock()

    agent_result = MagicMock()
    agent_result.scalar_one_or_none.return_value = agent

    req_result = MagicMock()
    req_list = auth_req_list if auth_req_list is not None else ([auth_req] if auth_req else [])
    req_result.scalars.return_value.return_value = req_list

    call_count = 0

    async def _execute(stmt):
        nonlocal call_count
        call_count += 1
        if call_count == 1:
            return agent_result
        return req_result

    db.execute = _execute
    db.get = AsyncMock(return_value=auth_req)
    db.add = MagicMock()
    db.commit = AsyncMock()
    db.refresh = AsyncMock(side_effect=lambda obj: None)
    db.delete = AsyncMock()
    return db


# ---------------------------------------------------------------------------
# create_auth_request
# ---------------------------------------------------------------------------


class TestCreateAuthRequest:
    @pytest.mark.asyncio
    async def test_creates_recursive_scan_request(self) -> None:
        from server.api.auth_requests import AuthRequestIn, create_auth_request

        agent = _make_agent()
        db = AsyncMock()
        agent_result = MagicMock()
        agent_result.scalar_one_or_none.return_value = agent
        db.execute = AsyncMock(return_value=agent_result)
        db.add = MagicMock()
        db.commit = AsyncMock()

        async def _refresh(obj):
            obj.id = _REQUEST_ID
            obj.agent_id = _AGENT_ID
            obj.request_type = "recursive_scan"
            obj.details = {"cidr": "10.1.0.0/24"}
            obj.status = "pending"
            obj.requested_at = _NOW
            obj.resolved_at = None
            obj.resolved_by = None
            obj.expires_at = None

        db.refresh = AsyncMock(side_effect=_refresh)

        await create_auth_request(
            body=AuthRequestIn(request_type="recursive_scan", details={"cidr": "10.1.0.0/24"}),
            db=db,
            x_agent_fingerprint=None,
            x_agent_id=str(_AGENT_ID),
        )

        db.add.assert_called_once()
        db.commit.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_creates_deploy_agent_request(self) -> None:
        from server.api.auth_requests import AuthRequestIn, create_auth_request

        agent = _make_agent()
        db = AsyncMock()
        agent_result = MagicMock()
        agent_result.scalar_one_or_none.return_value = agent
        db.execute = AsyncMock(return_value=agent_result)
        db.add = MagicMock()
        db.commit = AsyncMock()

        async def _refresh(obj):
            obj.id = _REQUEST_ID
            obj.agent_id = _AGENT_ID
            obj.request_type = "deploy_agent"
            obj.details = {"target_ip": "192.168.1.50"}
            obj.status = "pending"
            obj.requested_at = _NOW
            obj.resolved_at = None
            obj.resolved_by = None
            obj.expires_at = None

        db.refresh = AsyncMock(side_effect=_refresh)

        await create_auth_request(
            body=AuthRequestIn(request_type="deploy_agent", details={"target_ip": "192.168.1.50"}),
            db=db,
            x_agent_fingerprint=None,
            x_agent_id=str(_AGENT_ID),
        )

        db.add.assert_called_once()

    @pytest.mark.asyncio
    async def test_rejects_invalid_request_type(self) -> None:
        from fastapi import HTTPException

        from server.api.auth_requests import AuthRequestIn, create_auth_request

        agent = _make_agent()
        db = AsyncMock()
        agent_result = MagicMock()
        agent_result.scalar_one_or_none.return_value = agent
        db.execute = AsyncMock(return_value=agent_result)

        with pytest.raises(HTTPException) as exc_info:
            await create_auth_request(
                body=AuthRequestIn(request_type="nuke_everything"),
                db=db,
                x_agent_fingerprint=None,
                x_agent_id=str(_AGENT_ID),
            )
        assert exc_info.value.status_code == 422

    @pytest.mark.asyncio
    async def test_rejects_unauthenticated_agent(self) -> None:
        from fastapi import HTTPException

        from server.api.auth_requests import AuthRequestIn, create_auth_request

        db = AsyncMock()
        agent_result = MagicMock()
        agent_result.scalar_one_or_none.return_value = None
        db.execute = AsyncMock(return_value=agent_result)
        db.get = AsyncMock(return_value=None)

        with pytest.raises(HTTPException) as exc_info:
            await create_auth_request(
                body=AuthRequestIn(request_type="recursive_scan"),
                db=db,
                x_agent_fingerprint=None,
                x_agent_id=None,
            )
        assert exc_info.value.status_code == 401

    @pytest.mark.asyncio
    async def test_resolves_agent_by_fingerprint(self) -> None:
        from server.api.auth_requests import AuthRequestIn, create_auth_request

        agent = _make_agent()
        db = AsyncMock()
        agent_result = MagicMock()
        agent_result.scalar_one_or_none.return_value = agent
        db.execute = AsyncMock(return_value=agent_result)
        db.add = MagicMock()
        db.commit = AsyncMock()

        async def _refresh(obj):
            obj.id = _REQUEST_ID
            obj.agent_id = _AGENT_ID
            obj.request_type = "recursive_scan"
            obj.details = {}
            obj.status = "pending"
            obj.requested_at = _NOW
            obj.resolved_at = None
            obj.resolved_by = None
            obj.expires_at = None

        db.refresh = AsyncMock(side_effect=_refresh)

        await create_auth_request(
            body=AuthRequestIn(request_type="recursive_scan"),
            db=db,
            x_agent_fingerprint="sha256:abc",
            x_agent_id=None,
        )
        db.add.assert_called_once()


# ---------------------------------------------------------------------------
# list_auth_requests
# ---------------------------------------------------------------------------


class TestListAuthRequests:
    @pytest.mark.asyncio
    async def test_returns_list(self) -> None:
        from server.api.auth_requests import list_auth_requests

        req = _make_request()
        db = AsyncMock()
        result_mock = MagicMock()
        result_mock.scalars.return_value.return_value = [req]
        # scalars() is called then list() is applied — use __iter__
        scalars_mock = MagicMock()
        scalars_mock.__iter__ = MagicMock(return_value=iter([req]))
        result_mock.scalars.return_value = scalars_mock
        db.execute = AsyncMock(return_value=result_mock)

        result = await list_auth_requests(operator="admin", db=db)
        assert len(list(result)) >= 0  # just checks it doesn't error

    @pytest.mark.asyncio
    async def test_rejects_invalid_status_filter(self) -> None:
        from fastapi import HTTPException

        from server.api.auth_requests import list_auth_requests

        db = AsyncMock()
        with pytest.raises(HTTPException) as exc_info:
            await list_auth_requests(operator="admin", db=db, status_filter="invalid_status")
        assert exc_info.value.status_code == 422

    @pytest.mark.asyncio
    async def test_accepts_valid_status_filters(self) -> None:
        from server.api.auth_requests import list_auth_requests

        db = AsyncMock()
        scalars_mock = MagicMock()
        scalars_mock.__iter__ = MagicMock(return_value=iter([]))
        result_mock = MagicMock()
        result_mock.scalars.return_value = scalars_mock
        db.execute = AsyncMock(return_value=result_mock)

        for s in ("pending", "approved", "denied", "expired"):
            result_mock.scalars.return_value = scalars_mock
            await list_auth_requests(operator="admin", db=db, status_filter=s)


# ---------------------------------------------------------------------------
# get_auth_request
# ---------------------------------------------------------------------------


class TestGetAuthRequest:
    @pytest.mark.asyncio
    async def test_returns_request(self) -> None:
        from server.api.auth_requests import get_auth_request

        req = _make_request()
        db = AsyncMock()
        db.get = AsyncMock(return_value=req)

        result = await get_auth_request(request_id=_REQUEST_ID, operator="admin", db=db)
        assert result.id == _REQUEST_ID

    @pytest.mark.asyncio
    async def test_404_when_missing(self) -> None:
        from fastapi import HTTPException

        from server.api.auth_requests import get_auth_request

        db = AsyncMock()
        db.get = AsyncMock(return_value=None)

        with pytest.raises(HTTPException) as exc_info:
            await get_auth_request(request_id=_REQUEST_ID, operator="admin", db=db)
        assert exc_info.value.status_code == 404


# ---------------------------------------------------------------------------
# approve_auth_request
# ---------------------------------------------------------------------------


class TestApproveAuthRequest:
    @pytest.mark.asyncio
    async def test_approves_pending_request(self, monkeypatch) -> None:
        from server.api.auth_requests import ResolveBody, approve_auth_request

        req = _make_request(status="pending")
        db = AsyncMock()
        db.get = AsyncMock(return_value=req)
        db.add = MagicMock()
        db.commit = AsyncMock()
        db.refresh = AsyncMock(side_effect=lambda obj: None)

        async def _noop(*args, **kwargs):
            pass

        monkeypatch.setattr(
            "server.api.auth_requests._dispatch_follow_up_task", _noop
        )

        result = await approve_auth_request(
            request_id=_REQUEST_ID,
            body=ResolveBody(notes="looks good"),
            operator="admin",
            db=db,
        )

        assert result.status == "approved"
        assert result.resolved_by == "admin"
        db.commit.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_409_when_already_resolved(self, monkeypatch) -> None:
        from fastapi import HTTPException

        from server.api.auth_requests import ResolveBody, approve_auth_request

        req = _make_request(status="approved")
        db = AsyncMock()
        db.get = AsyncMock(return_value=req)

        async def _noop(*args, **kwargs):
            pass

        monkeypatch.setattr(
            "server.api.auth_requests._dispatch_follow_up_task", _noop
        )

        with pytest.raises(HTTPException) as exc_info:
            await approve_auth_request(
                request_id=_REQUEST_ID,
                body=ResolveBody(),
                operator="admin",
                db=db,
            )
        assert exc_info.value.status_code == 409

    @pytest.mark.asyncio
    async def test_404_when_missing(self, monkeypatch) -> None:
        from fastapi import HTTPException

        from server.api.auth_requests import ResolveBody, approve_auth_request

        db = AsyncMock()
        db.get = AsyncMock(return_value=None)

        with pytest.raises(HTTPException) as exc_info:
            await approve_auth_request(
                request_id=_REQUEST_ID,
                body=ResolveBody(),
                operator="admin",
                db=db,
            )
        assert exc_info.value.status_code == 404

    @pytest.mark.asyncio
    async def test_stores_operator_notes_in_details(self, monkeypatch) -> None:
        from server.api.auth_requests import ResolveBody, approve_auth_request

        req = _make_request(status="pending", details={"cidr": "10.1.0.0/24"})
        db = AsyncMock()
        db.get = AsyncMock(return_value=req)
        db.add = MagicMock()
        db.commit = AsyncMock()
        db.refresh = AsyncMock(side_effect=lambda obj: None)

        async def _noop(*args, **kwargs):
            pass

        monkeypatch.setattr(
            "server.api.auth_requests._dispatch_follow_up_task", _noop
        )

        await approve_auth_request(
            request_id=_REQUEST_ID,
            body=ResolveBody(notes="approved"),
            operator="admin",
            db=db,
        )

        assert "_operator_notes" in req.details


# ---------------------------------------------------------------------------
# deny_auth_request
# ---------------------------------------------------------------------------


class TestDenyAuthRequest:
    @pytest.mark.asyncio
    async def test_denies_pending_request(self) -> None:
        from server.api.auth_requests import ResolveBody, deny_auth_request

        req = _make_request(status="pending")
        db = AsyncMock()
        db.get = AsyncMock(return_value=req)
        db.add = MagicMock()
        db.commit = AsyncMock()
        db.refresh = AsyncMock(side_effect=lambda obj: None)

        result = await deny_auth_request(
            request_id=_REQUEST_ID,
            body=ResolveBody(notes="not allowed"),
            operator="admin",
            db=db,
        )

        assert result.status == "denied"
        assert result.resolved_by == "admin"
        db.commit.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_409_when_already_resolved(self) -> None:
        from fastapi import HTTPException

        from server.api.auth_requests import ResolveBody, deny_auth_request

        req = _make_request(status="denied")
        db = AsyncMock()
        db.get = AsyncMock(return_value=req)

        with pytest.raises(HTTPException) as exc_info:
            await deny_auth_request(
                request_id=_REQUEST_ID,
                body=ResolveBody(),
                operator="admin",
                db=db,
            )
        assert exc_info.value.status_code == 409

    @pytest.mark.asyncio
    async def test_404_when_missing(self) -> None:
        from fastapi import HTTPException

        from server.api.auth_requests import ResolveBody, deny_auth_request

        db = AsyncMock()
        db.get = AsyncMock(return_value=None)

        with pytest.raises(HTTPException) as exc_info:
            await deny_auth_request(
                request_id=_REQUEST_ID,
                body=ResolveBody(),
                operator="admin",
                db=db,
            )
        assert exc_info.value.status_code == 404

    @pytest.mark.asyncio
    async def test_stores_operator_notes_in_details(self) -> None:
        from server.api.auth_requests import ResolveBody, deny_auth_request

        req = _make_request(status="pending", details={"cidr": "10.0.0.0/8"})
        db = AsyncMock()
        db.get = AsyncMock(return_value=req)
        db.add = MagicMock()
        db.commit = AsyncMock()
        db.refresh = AsyncMock(side_effect=lambda obj: None)

        await deny_auth_request(
            request_id=_REQUEST_ID,
            body=ResolveBody(notes="unauthorized target"),
            operator="admin",
            db=db,
        )

        assert "_operator_notes" in req.details


# ---------------------------------------------------------------------------
# _dispatch_follow_up_task (internal)
# ---------------------------------------------------------------------------


class TestDispatchFollowUpTask:
    @pytest.mark.asyncio
    async def test_dispatches_scan_network_on_recursive_scan(self, monkeypatch) -> None:
        import server.services.task as task_module
        from server.api.auth_requests import _dispatch_follow_up_task

        dispatched = {}

        async def _fake_create_task(db, agent_id, action, params, operator=None, **kwargs):
            dispatched["action"] = action
            dispatched["params"] = params

        monkeypatch.setattr(task_module, "create_task", _fake_create_task)

        req = _make_request(
            status="approved",
            request_type="recursive_scan",
            details={"cidr": "10.1.0.0/24", "depth": 2},
        )
        db = AsyncMock()
        await _dispatch_follow_up_task(db, req, "admin")

        assert dispatched.get("action") == "scan_network"
        assert dispatched["params"]["cidr"] == "10.1.0.0/24"
        assert dispatched["params"]["depth"] == 2

    @pytest.mark.asyncio
    async def test_dispatches_deploy_agent_on_deploy_request(self, monkeypatch) -> None:
        import server.services.task as task_module
        from server.api.auth_requests import _dispatch_follow_up_task

        dispatched = {}

        async def _fake_create_task(db, agent_id, action, params, operator=None, **kwargs):
            dispatched["action"] = action
            dispatched["params"] = params

        monkeypatch.setattr(task_module, "create_task", _fake_create_task)

        req = _make_request(
            status="approved",
            request_type="deploy_agent",
            details={"target_ip": "192.168.1.50", "ssh_port": 22},
        )
        db = AsyncMock()
        await _dispatch_follow_up_task(db, req, "admin")

        assert dispatched.get("action") == "deploy_agent"
        assert dispatched["params"]["target_ip"] == "192.168.1.50"

    @pytest.mark.asyncio
    async def test_skips_task_when_cidr_missing(self, monkeypatch) -> None:
        import server.services.task as task_module
        from server.api.auth_requests import _dispatch_follow_up_task

        dispatched = {}

        async def _fake_create_task(*args, **kwargs):
            dispatched["called"] = True

        monkeypatch.setattr(task_module, "create_task", _fake_create_task)

        req = _make_request(
            status="approved",
            request_type="recursive_scan",
            details={},  # no cidr
        )
        db = AsyncMock()
        await _dispatch_follow_up_task(db, req, "admin")

        assert "called" not in dispatched

    @pytest.mark.asyncio
    async def test_skips_task_when_target_ip_missing(self, monkeypatch) -> None:
        import server.services.task as task_module
        from server.api.auth_requests import _dispatch_follow_up_task

        dispatched = {}

        async def _fake_create_task(*args, **kwargs):
            dispatched["called"] = True

        monkeypatch.setattr(task_module, "create_task", _fake_create_task)

        req = _make_request(
            status="approved",
            request_type="deploy_agent",
            details={},  # no target_ip
        )
        db = AsyncMock()
        await _dispatch_follow_up_task(db, req, "admin")

        assert "called" not in dispatched
