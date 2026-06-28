"""Add teams and team_memberships tables for multitenancy foundation

Revision ID: 0004
Revises: 0003
Create Date: 2026-06-28 00:00:00.000000

Adds the ``teams`` table (name, description, created_by) and the
``team_memberships`` junction table (team_id, username, role) that
form the data layer for multi-team support.  Resource scoping
(adding team_id to hosts/networks/etc.) comes in a later migration.
"""

from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0004"
down_revision: Union[str, None] = "0003"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "teams",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("name", sa.String(100), nullable=False, unique=True),
        sa.Column("description", sa.Text, nullable=True),
        sa.Column("created_by", sa.String(100), nullable=False),
        sa.Column(
            "created_at", sa.DateTime, nullable=False, server_default=sa.func.now()
        ),
        sa.Column(
            "updated_at", sa.DateTime, nullable=False, server_default=sa.func.now()
        ),
    )

    op.create_table(
        "team_memberships",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "team_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("teams.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("username", sa.String(100), nullable=False),
        sa.Column("role", sa.String(20), nullable=False, server_default="viewer"),
        sa.Column(
            "created_at", sa.DateTime, nullable=False, server_default=sa.func.now()
        ),
    )

    op.create_index("ix_team_memberships_team_id", "team_memberships", ["team_id"])
    op.create_index("ix_team_memberships_username", "team_memberships", ["username"])
    op.create_unique_constraint(
        "uq_team_memberships_team_user", "team_memberships", ["team_id", "username"]
    )


def downgrade() -> None:
    op.drop_constraint("uq_team_memberships_team_user", "team_memberships")
    op.drop_index("ix_team_memberships_username", "team_memberships")
    op.drop_index("ix_team_memberships_team_id", "team_memberships")
    op.drop_table("team_memberships")
    op.drop_table("teams")
