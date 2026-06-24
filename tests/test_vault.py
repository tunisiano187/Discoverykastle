"""
Tests for server/services/vault.py and server/api/vault.py.

Strategy:
- vault service tests: mock _derive_key / os.urandom to avoid real crypto imports
- vault API tests: mock vault.encrypt/decrypt + AsyncSession so no DB or crypto needed
"""

from __future__ import annotations

import base64
import uuid
from datetime import datetime
from unittest.mock import AsyncMock, MagicMock, patch

import pytest


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_FAKE_UUID = uuid.UUID("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee")
_NOW = datetime(2024, 1, 1, 12, 0, 0)


def _make_cred(**kwargs):
    defaults = dict(
        id=_FAKE_UUID,
        label="test-ssh",
        credential_type="ssh",
        device_id=None,
        ciphertext="FAKECIPHERTEXT==",
        created_by="operator1",
        updated_by=None,
        created_at=_NOW,
        updated_at=_NOW,
    )
    defaults.update(kwargs)
    cred = MagicMock()
    for k, v in defaults.items():
        setattr(cred, k, v)
    return cred


def _make_db(cred=None) -> AsyncMock:
    db = AsyncMock()
    result = MagicMock()
    result.scalars.return_value.all.return_value = [cred] if cred else []
    scalars_mock = MagicMock()
    scalars_mock.__iter__ = MagicMock(return_value=iter([cred] if cred else []))
    result.scalars.return_value = scalars_mock
    db.execute = AsyncMock(return_value=result)
    db.get = AsyncMock(return_value=cred)
    db.add = MagicMock()
    db.commit = AsyncMock()
    db.refresh = AsyncMock()
    db.delete = AsyncMock()
    return db


# ---------------------------------------------------------------------------
# vault service: VaultError
# ---------------------------------------------------------------------------


class TestVaultError:
    def test_vault_error_is_exception(self) -> None:
        from server.services.vault import VaultError

        err = VaultError("oops")
        assert isinstance(err, Exception)
        assert str(err) == "oops"


# ---------------------------------------------------------------------------
# vault service: _derive_key
# ---------------------------------------------------------------------------


class TestDeriveKey:
    def test_raises_when_key_not_set(self) -> None:
        from server.services.vault import VaultError, _derive_key

        with patch("server.config.settings") as mock_settings:
            mock_settings.vault_key = None
            with pytest.raises(VaultError, match="DKASTLE_VAULT_KEY is not set"):
                _derive_key()

    def test_raises_when_key_is_placeholder(self) -> None:
        from server.services.vault import VaultError, _derive_key

        with patch("server.config.settings") as mock_settings:
            mock_settings.vault_key = "changeme-base64-32-bytes"
            with pytest.raises(VaultError, match="DKASTLE_VAULT_KEY is not set"):
                _derive_key()

    def test_accepts_valid_base64_key(self) -> None:
        from server.services.vault import _derive_key

        key_bytes = b"A" * 32
        b64_key = base64.b64encode(key_bytes).decode()
        with patch("server.config.settings") as mock_settings:
            mock_settings.vault_key = b64_key
            result = _derive_key()
        assert result == key_bytes
        assert len(result) == 32

    def test_accepts_valid_hex_key(self) -> None:
        from server.services.vault import _derive_key

        key_bytes = bytes(range(32))
        hex_key = key_bytes.hex()
        with patch("server.config.settings") as mock_settings:
            mock_settings.vault_key = hex_key
            result = _derive_key()
        assert result == key_bytes
        assert len(result) == 32

    def test_raises_on_wrong_key_length(self) -> None:
        from server.services.vault import VaultError, _derive_key

        short_key = base64.b64encode(b"too-short").decode()
        with patch("server.config.settings") as mock_settings:
            mock_settings.vault_key = short_key
            with pytest.raises(VaultError, match="32 bytes"):
                _derive_key()

    def test_raises_on_malformed_key(self) -> None:
        from server.services.vault import VaultError, _derive_key

        with patch("server.config.settings") as mock_settings:
            mock_settings.vault_key = "not-valid-base64-or-hex!!!"
            with pytest.raises(VaultError, match="base64 or hex"):
                _derive_key()


# ---------------------------------------------------------------------------
# vault service: decrypt — short blob check (no crypto needed)
# ---------------------------------------------------------------------------


class TestDecryptShortBlob:
    def test_decrypt_raises_vault_error_on_short_blob(self) -> None:
        from server.services.vault import VaultError, decrypt

        key_bytes = b"K" * 32
        short_blob = base64.b64encode(b"\x00" * 10).decode()
        with patch("server.services.vault._derive_key", return_value=key_bytes):
            with pytest.raises(VaultError, match="too short"):
                decrypt(short_blob)


# ---------------------------------------------------------------------------
# Vault API tests
# ---------------------------------------------------------------------------


class TestVaultAPI:
    """Test vault API endpoints with mocked DB and vault service."""

    def _auth_headers(self):
        return {"Authorization": "Bearer fake-token"}

    def _make_app(self, db: AsyncMock):
        from fastapi import FastAPI
        from server.api.vault import router

        app = FastAPI()

        async def _fake_db():
            yield db

        app.include_router(router)
        # Override get_db
        from server.database import get_db
        app.dependency_overrides[get_db] = _fake_db
        return app

    @pytest.mark.asyncio
    async def test_create_credential_returns_201(self) -> None:
        import httpx
        from fastapi import FastAPI
        from server.api.vault import router, _require_operator
        from server.database import get_db

        db = _make_db()

        async def _refresh_side_effect(obj):
            # Simulate DB filling auto-generated fields after flush
            obj.id = _FAKE_UUID
            obj.created_at = _NOW
            obj.updated_at = _NOW

        db.refresh = AsyncMock(side_effect=_refresh_side_effect)

        app = FastAPI()

        async def _fake_db():
            yield db

        app.dependency_overrides[get_db] = _fake_db
        app.dependency_overrides[_require_operator] = lambda: "operator1"
        app.include_router(router)

        with patch("server.api.vault.encrypt", return_value="FAKECIPHERTEXT=="):
            async with httpx.AsyncClient(
                transport=httpx.ASGITransport(app=app), base_url="http://test"
            ) as client:
                resp = await client.post(
                    "/api/v1/vault/credentials",
                    json={
                        "label": "test-ssh",
                        "credential_type": "ssh",
                        "data": {"user": "alice", "password": "secret"},
                    },
                )
        assert resp.status_code == 201

    @pytest.mark.asyncio
    async def test_list_credentials_returns_200(self) -> None:
        import httpx
        from fastapi import FastAPI
        from server.api.vault import router, _require_operator
        from server.database import get_db

        cred = _make_cred()
        db = _make_db(cred)

        app = FastAPI()

        async def _fake_db():
            yield db

        app.dependency_overrides[get_db] = _fake_db
        app.dependency_overrides[_require_operator] = lambda: "operator1"
        app.include_router(router)

        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="http://test"
        ) as client:
            resp = await client.get("/api/v1/vault/credentials")
        assert resp.status_code == 200
        assert isinstance(resp.json(), list)

    @pytest.mark.asyncio
    async def test_get_credential_returns_200(self) -> None:
        import httpx
        from fastapi import FastAPI
        from server.api.vault import router, _require_operator
        from server.database import get_db

        cred = _make_cred()
        db = _make_db(cred)

        app = FastAPI()

        async def _fake_db():
            yield db

        app.dependency_overrides[get_db] = _fake_db
        app.dependency_overrides[_require_operator] = lambda: "operator1"
        app.include_router(router)

        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="http://test"
        ) as client:
            resp = await client.get(f"/api/v1/vault/credentials/{_FAKE_UUID}")
        assert resp.status_code == 200
        assert resp.json()["label"] == "test-ssh"

    @pytest.mark.asyncio
    async def test_get_credential_404_when_not_found(self) -> None:
        import httpx
        from fastapi import FastAPI
        from server.api.vault import router, _require_operator
        from server.database import get_db

        db = _make_db(None)  # no credential found

        app = FastAPI()

        async def _fake_db():
            yield db

        app.dependency_overrides[get_db] = _fake_db
        app.dependency_overrides[_require_operator] = lambda: "operator1"
        app.include_router(router)

        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="http://test"
        ) as client:
            resp = await client.get(f"/api/v1/vault/credentials/{_FAKE_UUID}")
        assert resp.status_code == 404

    @pytest.mark.asyncio
    async def test_delete_credential_returns_204(self) -> None:
        import httpx
        from fastapi import FastAPI
        from server.api.vault import router, _require_admin
        from server.database import get_db

        cred = _make_cred()
        db = _make_db(cred)

        app = FastAPI()

        async def _fake_db():
            yield db

        app.dependency_overrides[get_db] = _fake_db
        app.dependency_overrides[_require_admin] = lambda: "admin1"
        app.include_router(router)

        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="http://test"
        ) as client:
            resp = await client.delete(f"/api/v1/vault/credentials/{_FAKE_UUID}")
        assert resp.status_code == 204

    @pytest.mark.asyncio
    async def test_delete_credential_404_when_not_found(self) -> None:
        import httpx
        from fastapi import FastAPI
        from server.api.vault import router, _require_admin
        from server.database import get_db

        db = _make_db(None)

        app = FastAPI()

        async def _fake_db():
            yield db

        app.dependency_overrides[get_db] = _fake_db
        app.dependency_overrides[_require_admin] = lambda: "admin1"
        app.include_router(router)

        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="http://test"
        ) as client:
            resp = await client.delete(f"/api/v1/vault/credentials/{_FAKE_UUID}")
        assert resp.status_code == 404

    @pytest.mark.asyncio
    async def test_decrypt_credential_returns_plaintext(self) -> None:
        import httpx
        from fastapi import FastAPI
        from server.api.vault import router, _require_operator
        from server.database import get_db

        cred = _make_cred()
        db = _make_db(cred)

        app = FastAPI()

        async def _fake_db():
            yield db

        app.dependency_overrides[get_db] = _fake_db
        app.dependency_overrides[_require_operator] = lambda: "operator1"
        app.include_router(router)

        with patch("server.api.vault.decrypt", return_value={"user": "alice", "password": "s3cr3t"}):  # gitguardian:ignore
            async with httpx.AsyncClient(
                transport=httpx.ASGITransport(app=app), base_url="http://test"
            ) as client:
                resp = await client.post(f"/api/v1/vault/credentials/{_FAKE_UUID}/decrypt")
        assert resp.status_code == 200
        body = resp.json()
        assert body["data"]["user"] == "alice"
        assert body["data"]["password"] == "s3cr3t"

    @pytest.mark.asyncio
    async def test_decrypt_credential_404_when_not_found(self) -> None:
        import httpx
        from fastapi import FastAPI
        from server.api.vault import router, _require_operator
        from server.database import get_db

        db = _make_db(None)

        app = FastAPI()

        async def _fake_db():
            yield db

        app.dependency_overrides[get_db] = _fake_db
        app.dependency_overrides[_require_operator] = lambda: "operator1"
        app.include_router(router)

        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="http://test"
        ) as client:
            resp = await client.post(f"/api/v1/vault/credentials/{_FAKE_UUID}/decrypt")
        assert resp.status_code == 404

    @pytest.mark.asyncio
    async def test_create_credential_500_on_vault_error(self) -> None:
        import httpx
        from fastapi import FastAPI
        from server.api.vault import router, _require_operator
        from server.database import get_db
        from server.services.vault import VaultError

        db = _make_db()

        app = FastAPI()

        async def _fake_db():
            yield db

        app.dependency_overrides[get_db] = _fake_db
        app.dependency_overrides[_require_operator] = lambda: "operator1"
        app.include_router(router)

        with patch("server.api.vault.encrypt", side_effect=VaultError("key not set")):
            async with httpx.AsyncClient(
                transport=httpx.ASGITransport(app=app), base_url="http://test"
            ) as client:
                resp = await client.post(
                    "/api/v1/vault/credentials",
                    json={"label": "x", "credential_type": "ssh", "data": {"k": "v"}},
                )
        assert resp.status_code == 500

    @pytest.mark.asyncio
    async def test_decrypt_credential_500_on_vault_error(self) -> None:
        import httpx
        from fastapi import FastAPI
        from server.api.vault import router, _require_operator
        from server.database import get_db
        from server.services.vault import VaultError

        cred = _make_cred()
        db = _make_db(cred)

        app = FastAPI()

        async def _fake_db():
            yield db

        app.dependency_overrides[get_db] = _fake_db
        app.dependency_overrides[_require_operator] = lambda: "operator1"
        app.include_router(router)

        with patch("server.api.vault.decrypt", side_effect=VaultError("wrong key")):
            async with httpx.AsyncClient(
                transport=httpx.ASGITransport(app=app), base_url="http://test"
            ) as client:
                resp = await client.post(f"/api/v1/vault/credentials/{_FAKE_UUID}/decrypt")
        assert resp.status_code == 500

    @pytest.mark.asyncio
    async def test_update_credential_returns_200(self) -> None:
        import httpx
        from fastapi import FastAPI
        from server.api.vault import router, _require_operator
        from server.database import get_db

        cred = _make_cred()
        db = _make_db(cred)

        async def _refresh_side_effect(obj):
            obj.label = "updated-label"
            obj.updated_by = "operator1"

        db.refresh = AsyncMock(side_effect=_refresh_side_effect)

        app = FastAPI()

        async def _fake_db():
            yield db

        app.dependency_overrides[get_db] = _fake_db
        app.dependency_overrides[_require_operator] = lambda: "operator1"
        app.include_router(router)

        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="http://test"
        ) as client:
            resp = await client.patch(
                f"/api/v1/vault/credentials/{_FAKE_UUID}",
                json={"label": "updated-label"},
            )
        assert resp.status_code == 200

    @pytest.mark.asyncio
    async def test_update_credential_404_when_not_found(self) -> None:
        import httpx
        from fastapi import FastAPI
        from server.api.vault import router, _require_operator
        from server.database import get_db

        db = _make_db(None)

        app = FastAPI()

        async def _fake_db():
            yield db

        app.dependency_overrides[get_db] = _fake_db
        app.dependency_overrides[_require_operator] = lambda: "operator1"
        app.include_router(router)

        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="http://test"
        ) as client:
            resp = await client.patch(
                f"/api/v1/vault/credentials/{_FAKE_UUID}",
                json={"label": "new"},
            )
        assert resp.status_code == 404

    @pytest.mark.asyncio
    async def test_update_credential_reencrypts_when_data_provided(self) -> None:
        import httpx
        from fastapi import FastAPI
        from server.api.vault import router, _require_operator
        from server.database import get_db

        cred = _make_cred()
        db = _make_db(cred)
        db.refresh = AsyncMock(side_effect=lambda obj: None)

        app = FastAPI()

        async def _fake_db():
            yield db

        app.dependency_overrides[get_db] = _fake_db
        app.dependency_overrides[_require_operator] = lambda: "operator1"
        app.include_router(router)

        with patch("server.api.vault.encrypt", return_value="NEWCIPHERTEXT==") as mock_enc:
            async with httpx.AsyncClient(
                transport=httpx.ASGITransport(app=app), base_url="http://test"
            ) as client:
                resp = await client.patch(
                    f"/api/v1/vault/credentials/{_FAKE_UUID}",
                    json={"data": {"user": "bob", "password": "new-pw"}},  # gitguardian:ignore
                )
        mock_enc.assert_called_once()
        assert resp.status_code == 200

    @pytest.mark.asyncio
    async def test_list_credentials_with_query_params(self) -> None:
        import httpx
        from fastapi import FastAPI
        from server.api.vault import router, _require_operator
        from server.database import get_db

        cred = _make_cred()
        db = _make_db(cred)

        app = FastAPI()

        async def _fake_db():
            yield db

        app.dependency_overrides[get_db] = _fake_db
        app.dependency_overrides[_require_operator] = lambda: "operator1"
        app.include_router(router)

        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="http://test"
        ) as client:
            resp = await client.get(
                "/api/v1/vault/credentials",
                params={"credential_type": "ssh", "skip": 0, "limit": 10},
            )
        assert resp.status_code == 200
