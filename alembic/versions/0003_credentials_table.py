"""Add credentials table for AES-256-GCM encrypted credential vault

Revision ID: 0003
Revises: 0002
Create Date: 2026-06-07 00:00:00.000000

Adds the ``credentials`` table that backs the credential vault.
Credentials are stored encrypted (AES-256-GCM); the master key lives in
DKASTLE_VAULT_KEY and never touches the database.
"""

from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0003"
down_revision: Union[str, None] = "0002"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "credentials",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("label", sa.String(200), nullable=False),
        sa.Column("credential_type", sa.String(50), nullable=False),
        sa.Column("device_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("ciphertext", sa.Text, nullable=False),
        sa.Column("created_by", sa.String(100), nullable=False),
        sa.Column("updated_by", sa.String(100), nullable=True),
        sa.Column(
            "created_at", sa.DateTime, nullable=False, server_default=sa.func.now()
        ),
        sa.Column(
            "updated_at", sa.DateTime, nullable=False, server_default=sa.func.now()
        ),
    )
    op.create_index("ix_credentials_device_id", "credentials", ["device_id"])


def downgrade() -> None:
    op.drop_index("ix_credentials_device_id", "credentials")
    op.drop_table("credentials")
