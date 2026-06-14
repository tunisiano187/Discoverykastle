"""Add vault_credentials table

Revision ID: 0003
Revises: 0002
Create Date: 2026-06-14 00:00:00.000000

Creates the ``vault_credentials`` table that backs the encrypted credential
vault.  Secrets are stored AES-256-GCM encrypted — the server never persists
plaintext credentials.
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
        "vault_credentials",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("device_id", sa.String(255), nullable=False),
        sa.Column("credential_type", sa.String(30), nullable=False),
        sa.Column("label", sa.String(255), nullable=True),
        sa.Column("username_enc", sa.String(4096), nullable=True),
        sa.Column("secret_enc", sa.String(4096), nullable=False),
        sa.Column("notes_enc", sa.String(8192), nullable=True),
        sa.Column("created_by", sa.String(100), nullable=False),
        sa.Column("created_at", sa.DateTime, nullable=False, server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime, nullable=False, server_default=sa.func.now()),
    )
    op.create_index("ix_vault_creds_device_id", "vault_credentials", ["device_id"])


def downgrade() -> None:
    op.drop_index("ix_vault_creds_device_id", "vault_credentials")
    op.drop_table("vault_credentials")
