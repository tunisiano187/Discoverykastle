"""SQLAlchemy model for encrypted device credentials stored in the vault."""

from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import DateTime, String
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column

from server.database import Base

CREDENTIAL_TYPES: list[str] = ["ssh", "snmp", "http_api", "winrm", "api_key"]


class Credential(Base):
    __tablename__ = "vault_credentials"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)

    # Target device (IP address or FQDN)
    device_id: Mapped[str] = mapped_column(String(255), nullable=False, index=True)

    # Type of credential
    credential_type: Mapped[str] = mapped_column(String(30), nullable=False)

    # Human-readable label (e.g. "prod-switch-01 SSH")
    label: Mapped[str | None] = mapped_column(String(255), nullable=True)

    # Encrypted fields — only decrypted inside the server process, never in API responses
    username_enc: Mapped[str | None] = mapped_column(String(4096), nullable=True)
    secret_enc: Mapped[str] = mapped_column(String(4096), nullable=False)
    notes_enc: Mapped[str | None] = mapped_column(String(8192), nullable=True)

    # Audit trail
    created_by: Mapped[str] = mapped_column(String(100), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime, default=datetime.utcnow, onupdate=datetime.utcnow
    )
