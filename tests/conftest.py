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

# Stub jose and passlib ONLY when the native cryptography extension is broken.
#
# In CI (GitHub Actions) all packages are properly installed and working.
# In the dev container the `cryptography` Rust extension (loaded via _cffi_backend)
# is broken — importing jose triggers a Rust thread panic (PanicException).
#
# We detect the broken environment by probing _cffi_backend with a plain
# ImportError (not a Rust panic) BEFORE touching jose/cryptography.

def _cffi_available() -> bool:
    """Return True if the _cffi_backend C extension loads cleanly."""
    try:
        import _cffi_backend  # noqa: F401
        return True
    except (ImportError, ModuleNotFoundError):
        return False


if not _cffi_available():
    # Native crypto stack is broken — stub jose and passlib so auth-service
    # imports work without the cryptography native extension.
    import json as _json
    from datetime import datetime as _datetime

    _jose = _stub_module("jose")
    _jose.JWTError = Exception

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

    _passlib = _stub_module("passlib")
    _passlib_ctx = _stub_module("passlib.context")
    _ctx_cls = MagicMock()
    _ctx_cls.return_value.hash = MagicMock(return_value="hashed")
    _ctx_cls.return_value.verify = MagicMock(return_value=True)
    _passlib_ctx.CryptContext = _ctx_cls
