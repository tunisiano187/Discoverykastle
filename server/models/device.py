import uuid
from datetime import datetime
from sqlalchemy import String, DateTime, ForeignKey, Text
from sqlalchemy.orm import Mapped, mapped_column
from sqlalchemy.dialects.postgresql import UUID
from server.database import Base


class NetworkDevice(Base):
    __tablename__ = "network_devices"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    host_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True), ForeignKey("hosts.id"), nullable=True)
    ip_address: Mapped[str] = mapped_column(String(50), nullable=False)
    device_type: Mapped[str | None] = mapped_column(String(50), nullable=True)   # router, switch, firewall
    vendor: Mapped[str | None] = mapped_column(String(100), nullable=True)        # cisco, juniper, arista
    model: Mapped[str | None] = mapped_column(String(100), nullable=True)
    firmware_version: Mapped[str | None] = mapped_column(String(100), nullable=True)
    hostname: Mapped[str | None] = mapped_column(String(255), nullable=True)
    # Sanitized running config (passwords removed)
    config_snapshot: Mapped[str | None] = mapped_column(Text, nullable=True)
    # JSON blob with structured data: interfaces, vlans, routes, neighbors
    structured_data: Mapped[str | None] = mapped_column(Text, nullable=True)
    last_seen: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
