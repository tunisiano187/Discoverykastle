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

# Stub jose so server.services.auth can be imported without the full
# cryptography native stack (which has broken Rust bindings in this env).
# encode round-trips via json so decode_token recovers the original payload.
if "jose" not in sys.modules:
    import json as _json

    _jose = _stub_module("jose")
    _jose.JWTError = Exception

    from datetime import datetime as _datetime

    def _fake_jwt_encode(payload, *args, **kwargs):
        safe = {k: v.isoformat() if isinstance(v, _datetime) else v for k, v in payload.items()}
        return _json.dumps(safe)

    def _fake_jwt_decode(token, *args, **kwargs):
        return _json.loads(token)

    _jose.jwt = MagicMock()
    _jose.jwt.encode = _fake_jwt_encode
    _jose.jwt.decode = _fake_jwt_decode
    _stub_module("jose.jwt")
    _stub_module("jose.exceptions")

# Stub passlib.context so CryptContext imports work.
if "passlib" not in sys.modules:
    _passlib = _stub_module("passlib")
    _passlib_ctx = _stub_module("passlib.context")
    _ctx_cls = MagicMock()
    _ctx_cls.return_value.hash = MagicMock(return_value="hashed")
    _ctx_cls.return_value.verify = MagicMock(return_value=True)
    _passlib_ctx.CryptContext = _ctx_cls
