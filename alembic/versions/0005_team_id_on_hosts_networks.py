"""Add nullable team_id FK to hosts and networks for team-scoped data isolation

Revision ID: 0005
Revises: 0004
Create Date: 2026-07-26 00:00:00.000000

Adds a nullable ``team_id`` foreign key (→ teams.id) to the ``hosts`` and
``networks`` tables.  Existing rows get NULL (unassigned / global-visible)
which maintains backwards compatibility.  An index is created on both columns
to keep team-filtered list queries fast.
"""

from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0005"
down_revision: Union[str, None] = "0004"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column(
        "hosts",
        sa.Column(
            "team_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("teams.id", ondelete="SET NULL"),
            nullable=True,
        ),
    )
    op.create_index("ix_hosts_team_id", "hosts", ["team_id"])

    op.add_column(
        "networks",
        sa.Column(
            "team_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("teams.id", ondelete="SET NULL"),
            nullable=True,
        ),
    )
    op.create_index("ix_networks_team_id", "networks", ["team_id"])


def downgrade() -> None:
    op.drop_index("ix_networks_team_id", "networks")
    op.drop_column("networks", "team_id")

    op.drop_index("ix_hosts_team_id", "hosts")
    op.drop_column("hosts", "team_id")
