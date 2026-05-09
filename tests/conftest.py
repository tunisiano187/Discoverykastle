"""
Pytest configuration — stubs optional heavy dependencies so tests can run
without a full production environment (no PostgreSQL, no asyncpg, etc.).
"""
from __future__ import annotations

import sys
from types import ModuleType
from unittest.mock import MagicMock


def _stub_module(name: str) -> MagicMock:
    mod = MagicMock(spec=ModuleType(name))
    mod.__name__ = name
    mod.__spec__ = None
    sys.modules[name] = mod
    return mod


# Stub asyncpg and its sub-modules so server.database can be imported
# in unit tests without a real PostgreSQL installation.
for _name in [
    "asyncpg",
    "asyncpg.connection",
    "asyncpg.pool",
]:
    if _name not in sys.modules:
        _stub_module(_name)
