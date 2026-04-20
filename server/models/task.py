"""AgentTask — persisted task state for the task engine."""

from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import DateTime, ForeignKey, Integer, JSON, String, Text
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column

from server.database import Base

# Valid status values (ordered by the state machine):
#   created → queued → dispatched → running → completed
#                                           → failed     (→ queued if retries remain)
#                                           → timed_out  (→ queued if retries remain)
#                                 → cancelled  (operator-requested)
TERMINAL_STATUSES = frozenset({"completed", "failed", "timed_out", "cancelled"})


class AgentTask(Base):
    """Persistent record of a single agent task and its lifecycle."""

    __tablename__ = "agent_tasks"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    agent_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("agents.id"), nullable=False, index=True
    )
    action: Mapped[str] = mapped_column(String(100), nullable=False)
    params: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)

    # --- State machine ---
    status: Mapped[str] = mapped_column(
        String(20), nullable=False, default="created", index=True
    )

    # --- Ownership / config ---
    operator: Mapped[str | None] = mapped_column(String(100), nullable=True)
    attempt: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    max_attempts: Mapped[int] = mapped_column(Integer, nullable=False, default=3)
    timeout_seconds: Mapped[int] = mapped_column(Integer, nullable=False, default=600)

    # --- Timestamps ---
    queued_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    dispatched_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    started_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    next_retry_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)

    # --- Outcome ---
    result: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    error: Mapped[str | None] = mapped_column(Text, nullable=True)

    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime, default=datetime.utcnow, onupdate=datetime.utcnow
    )

    @property
    def is_terminal(self) -> bool:
        """Return True if the task is in a terminal state (no further transitions)."""
        return self.status in TERMINAL_STATUSES
