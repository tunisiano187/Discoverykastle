"""
Tests for server/api/teams.py — Teams CRUD API.

Strategy: mock AsyncSession and Team/TeamMembership models; no DB or
real server startup needed.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from unittest.mock import AsyncMock, MagicMock

import pytest

_TEAM_ID = uuid.UUID("11111111-2222-3333-4444-555555555555")
_NOW = datetime(2026, 1, 1, 12, 0, 0)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_team(**kwargs):
    defaults = dict(
        id=_TEAM_ID,
        name="it-team",
        description="Integration team",
        created_by="admin",
        created_at=_NOW,
        updated_at=_NOW,
    )
    defaults.update(kwargs)
    t = MagicMock()
    for k, v in defaults.items():
        setattr(t, k, v)
    return t


def _make_membership(username="alice", role="operator"):
    m = MagicMock()
    m.id = uuid.uuid4()
    m.team_id = _TEAM_ID
    m.username = username
    m.role = role
    m.created_at = _NOW
    return m


def _make_db(team=None, members=None) -> AsyncMock:
    db = AsyncMock()

    team_result = MagicMock()
    team_result.scalars.return_value.all.return_value = [team] if team else []
    team_result.scalar_one_or_none.return_value = team

    mem_result = MagicMock()
    mem_result.scalars.return_value.all.return_value = members or []
    mem_result.scalar_one_or_none.return_value = None

    call_count = 0

    async def _execute(stmt):
        nonlocal call_count
        call_count += 1
        if call_count == 1:
            return team_result
        return mem_result

    db.execute = _execute
    db.get = AsyncMock(return_value=team)
    db.add = MagicMock()
    db.commit = AsyncMock()
    db.refresh = AsyncMock(side_effect=lambda obj: None)
    db.delete = AsyncMock()
    return db


# ---------------------------------------------------------------------------
# list_teams
# ---------------------------------------------------------------------------


class TestListTeams:
    @pytest.mark.asyncio
    async def test_returns_list(self) -> None:
        from server.api.teams import list_teams

        team = _make_team()
        db = _make_db(team=team)
        result = await list_teams(_="admin", db=db)
        assert len(result) == 1
        assert result[0].name == "it-team"

    @pytest.mark.asyncio
    async def test_empty_list(self) -> None:
        from server.api.teams import list_teams

        db = _make_db()
        result = await list_teams(_="admin", db=db)
        assert result == []


# ---------------------------------------------------------------------------
# create_team
# ---------------------------------------------------------------------------


class TestCreateTeam:
    @pytest.mark.asyncio
    async def test_creates_team(self) -> None:
        from server.api.teams import TeamCreate, create_team

        db = AsyncMock()
        no_existing = MagicMock()
        no_existing.scalar_one_or_none.return_value = None
        db.execute = AsyncMock(return_value=no_existing)
        db.add = MagicMock()
        db.commit = AsyncMock()

        async def _refresh(obj):
            obj.id = _TEAM_ID
            obj.name = "it-team"
            obj.description = None
            obj.created_by = "admin"

        db.refresh = AsyncMock(side_effect=_refresh)

        result = await create_team(body=TeamCreate(name="it-team"), admin="admin", db=db)

        assert result.name == "it-team"
        db.add.assert_called_once()
        db.commit.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_conflict_if_name_exists(self) -> None:
        from fastapi import HTTPException

        from server.api.teams import TeamCreate, create_team

        existing_team = _make_team()
        db = AsyncMock()
        result_mock = MagicMock()
        result_mock.scalar_one_or_none.return_value = existing_team
        db.execute = AsyncMock(return_value=result_mock)

        with pytest.raises(HTTPException) as exc_info:
            await create_team(body=TeamCreate(name="it-team"), admin="admin", db=db)

        assert exc_info.value.status_code == 409


# ---------------------------------------------------------------------------
# get_team
# ---------------------------------------------------------------------------


class TestGetTeam:
    @pytest.mark.asyncio
    async def test_returns_team_with_members(self) -> None:
        from server.api.teams import get_team

        team = _make_team()
        member = _make_membership("bob", "operator")
        db = AsyncMock()
        mem_result = MagicMock()
        mem_result.scalars.return_value.all.return_value = [member]
        db.get = AsyncMock(return_value=team)
        db.execute = AsyncMock(return_value=mem_result)

        result = await get_team(team_id=_TEAM_ID, _="admin", db=db)
        assert result.id == _TEAM_ID
        assert result.name == "it-team"
        assert len(result.members) == 1
        assert result.members[0].username == "bob"

    @pytest.mark.asyncio
    async def test_404_when_missing(self) -> None:
        from fastapi import HTTPException

        from server.api.teams import get_team

        db = _make_db(team=None)
        with pytest.raises(HTTPException) as exc_info:
            await get_team(team_id=_TEAM_ID, _="admin", db=db)
        assert exc_info.value.status_code == 404


# ---------------------------------------------------------------------------
# delete_team
# ---------------------------------------------------------------------------


class TestDeleteTeam:
    @pytest.mark.asyncio
    async def test_deletes_team(self) -> None:
        from server.api.teams import delete_team

        team = _make_team()
        db = _make_db(team=team)
        await delete_team(team_id=_TEAM_ID, _="admin", db=db)
        db.delete.assert_awaited_once()
        db.commit.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_404_when_missing(self) -> None:
        from fastapi import HTTPException

        from server.api.teams import delete_team

        db = _make_db(team=None)
        with pytest.raises(HTTPException) as exc_info:
            await delete_team(team_id=_TEAM_ID, _="admin", db=db)
        assert exc_info.value.status_code == 404


# ---------------------------------------------------------------------------
# add_member
# ---------------------------------------------------------------------------


class TestAddMember:
    @pytest.mark.asyncio
    async def test_adds_member(self) -> None:
        from server.api.teams import MemberAdd, add_member

        team = _make_team()
        db = AsyncMock()
        no_membership = MagicMock()
        no_membership.scalar_one_or_none.return_value = None

        db.get = AsyncMock(return_value=team)
        db.execute = AsyncMock(return_value=no_membership)
        db.add = MagicMock()
        db.commit = AsyncMock()

        result = await add_member(
            team_id=_TEAM_ID,
            body=MemberAdd(username="alice", role="operator"),
            _="admin",
            db=db,
        )

        assert result.username == "alice"
        assert result.role == "operator"

    @pytest.mark.asyncio
    async def test_invalid_role(self) -> None:
        from fastapi import HTTPException

        from server.api.teams import MemberAdd, add_member

        team = _make_team()
        db = _make_db(team=team)

        with pytest.raises(HTTPException) as exc_info:
            await add_member(
                team_id=_TEAM_ID,
                body=MemberAdd(username="alice", role="superuser"),
                _="admin",
                db=db,
            )
        assert exc_info.value.status_code == 422

    @pytest.mark.asyncio
    async def test_409_if_already_member(self) -> None:
        from fastapi import HTTPException

        from server.api.teams import MemberAdd, add_member

        team = _make_team()
        existing_membership = _make_membership("alice")
        db = AsyncMock()
        result_mock = MagicMock()
        result_mock.scalar_one_or_none.return_value = existing_membership
        db.get = AsyncMock(return_value=team)
        db.execute = AsyncMock(return_value=result_mock)

        with pytest.raises(HTTPException) as exc_info:
            await add_member(
                team_id=_TEAM_ID,
                body=MemberAdd(username="alice", role="viewer"),
                _="admin",
                db=db,
            )
        assert exc_info.value.status_code == 409


# ---------------------------------------------------------------------------
# remove_member
# ---------------------------------------------------------------------------


class TestRemoveMember:
    @pytest.mark.asyncio
    async def test_removes_member(self) -> None:
        from server.api.teams import remove_member

        team = _make_team()
        membership = _make_membership("alice")
        db = AsyncMock()
        result_mock = MagicMock()
        result_mock.scalar_one_or_none.return_value = membership
        db.get = AsyncMock(return_value=team)
        db.execute = AsyncMock(return_value=result_mock)
        db.delete = AsyncMock()
        db.commit = AsyncMock()

        await remove_member(team_id=_TEAM_ID, username="alice", _="admin", db=db)
        db.delete.assert_awaited_once_with(membership)
        db.commit.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_404_if_not_member(self) -> None:
        from fastapi import HTTPException

        from server.api.teams import remove_member

        team = _make_team()
        db = AsyncMock()
        result_mock = MagicMock()
        result_mock.scalar_one_or_none.return_value = None
        db.get = AsyncMock(return_value=team)
        db.execute = AsyncMock(return_value=result_mock)

        with pytest.raises(HTTPException) as exc_info:
            await remove_member(team_id=_TEAM_ID, username="ghost", _="admin", db=db)
        assert exc_info.value.status_code == 404
