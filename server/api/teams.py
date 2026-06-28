"""
Teams API — /api/v1/teams

Multitenancy foundation: create teams, manage memberships.

GET  /api/v1/teams                        — list all teams (viewer+)
POST /api/v1/teams                        — create team (admin)
GET  /api/v1/teams/{id}                   — team detail + member list (viewer+)
DELETE /api/v1/teams/{id}                 — delete team (admin)
POST /api/v1/teams/{id}/members           — add member (admin)
DELETE /api/v1/teams/{id}/members/{user}  — remove member (admin)
"""

from __future__ import annotations

import uuid
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from server.database import get_db
from server.services.auth import require_admin, require_operator

router = APIRouter(prefix="/api/v1/teams", tags=["teams"])

_VALID_ROLES = {"viewer", "analyst", "operator", "admin"}


# ------------------------------------------------------------------
# Schemas
# ------------------------------------------------------------------


class TeamCreate(BaseModel):
    name: str
    description: str | None = None


class MemberAdd(BaseModel):
    username: str
    role: str = "viewer"


class TeamOut(BaseModel):
    id: uuid.UUID
    name: str
    description: str | None
    created_by: str

    model_config = {"from_attributes": True}


class MemberOut(BaseModel):
    username: str
    role: str

    model_config = {"from_attributes": True}


class TeamDetail(BaseModel):
    id: uuid.UUID
    name: str
    description: str | None
    created_by: str
    members: list[MemberOut]

    model_config = {"from_attributes": True}


# ------------------------------------------------------------------
# Routes
# ------------------------------------------------------------------


@router.get("", response_model=list[TeamOut])
async def list_teams(
    _: Annotated[str, Depends(require_operator)],
    db: AsyncSession = Depends(get_db),
) -> list[TeamOut]:
    from server.models.team import Team

    result = await db.execute(select(Team).order_by(Team.name))
    return [TeamOut.model_validate(t) for t in result.scalars().all()]


@router.post("", response_model=TeamOut, status_code=status.HTTP_201_CREATED)
async def create_team(
    body: TeamCreate,
    admin: Annotated[str, Depends(require_admin)],
    db: AsyncSession = Depends(get_db),
) -> TeamOut:
    from server.models.team import Team

    existing = await db.execute(select(Team).where(Team.name == body.name))
    if existing.scalar_one_or_none():
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"Team '{body.name}' already exists",
        )

    team = Team(name=body.name, description=body.description, created_by=admin)
    db.add(team)
    await db.commit()
    await db.refresh(team)
    return TeamOut.model_validate(team)


@router.get("/{team_id}", response_model=TeamDetail)
async def get_team(
    team_id: uuid.UUID,
    _: Annotated[str, Depends(require_operator)],
    db: AsyncSession = Depends(get_db),
) -> TeamDetail:
    from server.models.team import Team, TeamMembership

    team = await db.get(Team, team_id)
    if not team:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Team not found")

    result = await db.execute(
        select(TeamMembership).where(TeamMembership.team_id == team_id)
    )
    members = [MemberOut(username=m.username, role=m.role) for m in result.scalars().all()]

    return TeamDetail(
        id=team.id,
        name=team.name,
        description=team.description,
        created_by=team.created_by,
        members=members,
    )


@router.delete("/{team_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_team(
    team_id: uuid.UUID,
    _: Annotated[str, Depends(require_admin)],
    db: AsyncSession = Depends(get_db),
) -> None:
    from server.models.team import Team

    team = await db.get(Team, team_id)
    if not team:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Team not found")

    await db.delete(team)
    await db.commit()


@router.post("/{team_id}/members", response_model=MemberOut, status_code=status.HTTP_201_CREATED)
async def add_member(
    team_id: uuid.UUID,
    body: MemberAdd,
    _: Annotated[str, Depends(require_admin)],
    db: AsyncSession = Depends(get_db),
) -> MemberOut:
    from server.models.team import Team, TeamMembership

    if body.role not in _VALID_ROLES:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=f"Invalid role '{body.role}'. Must be one of: {sorted(_VALID_ROLES)}",
        )

    team = await db.get(Team, team_id)
    if not team:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Team not found")

    existing = await db.execute(
        select(TeamMembership).where(
            TeamMembership.team_id == team_id,
            TeamMembership.username == body.username,
        )
    )
    if existing.scalar_one_or_none():
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"'{body.username}' is already a member of this team",
        )

    membership = TeamMembership(team_id=team_id, username=body.username, role=body.role)
    db.add(membership)
    await db.commit()
    return MemberOut(username=membership.username, role=membership.role)


@router.delete("/{team_id}/members/{username}", status_code=status.HTTP_204_NO_CONTENT)
async def remove_member(
    team_id: uuid.UUID,
    username: str,
    _: Annotated[str, Depends(require_admin)],
    db: AsyncSession = Depends(get_db),
) -> None:
    from server.models.team import Team, TeamMembership

    team = await db.get(Team, team_id)
    if not team:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Team not found")

    result = await db.execute(
        select(TeamMembership).where(
            TeamMembership.team_id == team_id,
            TeamMembership.username == username,
        )
    )
    membership = result.scalar_one_or_none()
    if not membership:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"'{username}' is not a member of this team",
        )

    await db.delete(membership)
    await db.commit()
