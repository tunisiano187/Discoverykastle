"""
Base class and registry for AI backends.
"""

from __future__ import annotations

import abc
from typing import Any, Callable

# ──────────────────────────────────────────────────────────────────────────────
# Registry
# ──────────────────────────────────────────────────────────────────────────────

REGISTRY: dict[str, type["_Backend"]] = {}


def register(name: str) -> Callable[[type], type]:
    """
    Class decorator — registers a _Backend subclass under `name`.

    Usage:
        @register("mybackend")
        class MyBackend(_Backend):
            ...
    """
    def decorator(cls: type) -> type:
        REGISTRY[name] = cls
        return cls
    return decorator


# ──────────────────────────────────────────────────────────────────────────────
# Abstract base
# ──────────────────────────────────────────────────────────────────────────────

class _Backend(abc.ABC):
    """
    Minimal contract that every AI backend must fulfil.

    Subclass, implement the three abstract members, and decorate with
    @register("your-backend-name") — the module picks it up automatically.
    """

    # Human-readable label shown in logs and the setup UI
    label: str = "Unknown backend"

    # Whether this backend requires an API key to work
    requires_key: bool = False

    # Name of the env var that holds the API key (informational)
    key_env: str = ""

    @abc.abstractmethod
    async def complete(self, system: str, user: str) -> str:
        """
        Send a prompt pair and return the raw text response.

        Both backends must return a string; JSON parsing is handled
        by the caller so the same parsing logic applies everywhere.
        """

    @abc.abstractmethod
    async def probe(self) -> bool:
        """
        Lightweight availability check (should complete in < 5 s).
        Return True if the backend is ready to accept requests.
        """

    async def close(self) -> None:
        """Release held resources (HTTP clients, SDK connections…)."""
