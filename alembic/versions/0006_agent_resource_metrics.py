"""Add resource metric columns to agents table

Revision ID: 0006
Revises: 0005
Create Date: 2026-09-06 00:00:00.000000

Adds three nullable float columns to the ``agents`` table so that resource
metrics reported in heartbeats (CPU %, memory %, disk %) can be stored and
exposed in the API.  All columns are nullable — agents that do not report
metrics (older versions, or psutil not installed) leave them NULL.
"""

from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "0006"
down_revision: Union[str, None] = "0005"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column("agents", sa.Column("cpu_percent", sa.Float, nullable=True))
    op.add_column("agents", sa.Column("memory_percent", sa.Float, nullable=True))
    op.add_column("agents", sa.Column("disk_percent", sa.Float, nullable=True))


def downgrade() -> None:
    op.drop_column("agents", "disk_percent")
    op.drop_column("agents", "memory_percent")
    op.drop_column("agents", "cpu_percent")
