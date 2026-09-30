"""Add team_id to network_devices

Revision ID: 0007
Revises: 0006
Create Date: 2026-09-17

Allows network devices to be scoped to a team for multi-tenant isolation.
"""

from __future__ import annotations

from typing import Union

import sqlalchemy as sa
from alembic import op

revision: str = "0007"
down_revision: Union[str, None] = "0006"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "network_devices",
        sa.Column(
            "team_id",
            sa.dialects.postgresql.UUID(as_uuid=True),
            sa.ForeignKey("teams.id", ondelete="SET NULL"),
            nullable=True,
        ),
    )
    op.create_index("ix_network_devices_team_id", "network_devices", ["team_id"])


def downgrade() -> None:
    op.drop_index("ix_network_devices_team_id", table_name="network_devices")
    op.drop_column("network_devices", "team_id")
