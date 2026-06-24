"""
Credential Vault model — AES-256-GCM encrypted storage for device credentials.

The `ciphertext` column stores the AES-256-GCM encrypted credential blob
(nonce + tag + ciphertext, base64-encoded).  The master key lives only in
the DKASTLE_VAULT_KEY environment variable — never in the DB.
"""

from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import DateTime, String, Text
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column

from server.database import Base


class Credential(Base):
    __tablename__ = "credentials"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    # Human-readable label (e.g. "switch-floor-3 SSH")
    label: Mapped[str] = mapped_column(String(200), nullable=False)
    # e.g. "ssh", "snmp_v2", "snmp_v3", "winrm", "api_key"
    credential_type: Mapped[str] = mapped_column(String(50), nullable=False)
    # Optional: link to a network device
    device_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), nullable=True, index=True
    )
    # AES-256-GCM blob: base64(nonce[12] + tag[16] + ciphertext)
    ciphertext: Mapped[str] = mapped_column(Text, nullable=False)
    # Who created/last updated this credential
    created_by: Mapped[str] = mapped_column(String(100), nullable=False)
    updated_by: Mapped[str | None] = mapped_column(String(100), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime, default=datetime.utcnow, onupdate=datetime.utcnow
    )
