"""
Unit tests for the credential vault service and API.

VaultService tests: use pytest.importorskip so they skip gracefully when the
cryptography package is unavailable (broken install), but pass in CI where
a proper wheel is installed.

API tests: mock DB + vault using the same pattern as test_inventory.py.
No real database or encryption required.
"""

from __future__ import annotations

import base64
import uuid
from datetime import datetime
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from server.models.credential import CREDENTIAL_TYPES, Credential
from server.api.vault import router

_TEST_VAULT_KEY = base64.b64encode(b"A" * 32).decode()
_SECRET = "vault-test-jwt-secret"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_token(username: str = "alice", role: str = "operator") -> str:
    from server.services.auth import create_access_token

    return create_access_token(username, role, _SECRET, expire_minutes=60)


def _auth(role: str = "operator") -> dict[str, str]:
    return {"Authorization": f"Bearer {_make_token('alice', role)}"}


def _make_app() -> FastAPI:
    app = FastAPI()
    app.include_router(router)
    return app


def _make_cred(**kwargs) -> MagicMock:
    c = MagicMock(spec=Credential)
    c.id = kwargs.get("id", uuid.uuid4())
    c.device_id = kwargs.get("device_id", "192.168.1.1")
    c.credential_type = kwargs.get("credential_type", "ssh")
    c.label = kwargs.get("label", "my-label")
    c.username_enc = kwargs.get("username_enc", "enc-user")
    c.secret_enc = kwargs.get("secret_enc", "enc-secret")
    c.notes_enc = kwargs.get("notes_enc", None)
    c.created_by = kwargs.get("created_by", "alice")
    c.created_at = kwargs.get("created_at", datetime(2026, 1, 1))
    c.updated_at = kwargs.get("updated_at", datetime(2026, 1, 1))
    return c


# ---------------------------------------------------------------------------
# VaultService unit tests
# Skip if cryptography is not properly installed.
# ---------------------------------------------------------------------------

cryptography_aead = pytest.importorskip(
    "cryptography.hazmat.primitives.ciphers.aead",
    reason="cryptography package not available or broken",
)


class TestVaultService:
    def _make_vault(self):
        from server.services.vault import VaultService

        return VaultService(_TEST_VAULT_KEY)

    def test_encrypt_decrypt_roundtrip(self) -> None:
        vault = self._make_vault()
        plain = "super-secret-password-123!"
        token = vault.encrypt(plain)
        assert token != plain
        assert vault.decrypt(token) == plain

    def test_encrypt_produces_different_tokens(self) -> None:
        vault = self._make_vault()
        t1 = vault.encrypt("abc")
        t2 = vault.encrypt("abc")
        assert t1 != t2

    def test_decrypt_tampered_raises(self) -> None:
        from cryptography.exceptions import InvalidTag

        vault = self._make_vault()
        token = vault.encrypt("secret")
        raw = base64.b64decode(token + "==")
        tampered = raw[:-1] + bytes([raw[-1] ^ 0xFF])
        with pytest.raises(InvalidTag):
            vault.decrypt(base64.b64encode(tampered).decode())

    def test_non_base64_key_still_works(self) -> None:
        from server.services.vault import VaultService

        vault = VaultService("not-base64!!!")
        assert vault.decrypt(vault.encrypt("hello")) == "hello"

    def test_unicode_plaintext(self) -> None:
        vault = self._make_vault()
        plain = "pàssw0rd — ñoño 🔐"
        assert vault.decrypt(vault.encrypt(plain)) == plain

    def test_empty_string(self) -> None:
        vault = self._make_vault()
        assert vault.decrypt(vault.encrypt("")) == ""

    def test_key_derivation_consistent(self) -> None:
        from server.services.vault import VaultService

        v1 = VaultService("same-key")
        v2 = VaultService("same-key")
        token = v1.encrypt("data")
        assert v2.decrypt(token) == "data"


# ---------------------------------------------------------------------------
# Credential model
# ---------------------------------------------------------------------------


class TestCredentialTypes:
    def test_all_required_types_present(self) -> None:
        for t in ("ssh", "snmp", "http_api", "winrm", "api_key"):
            assert t in CREDENTIAL_TYPES


# ---------------------------------------------------------------------------
# Vault API — role enforcement
# ---------------------------------------------------------------------------


class TestVaultAPIRoles:
    def setup_method(self) -> None:
        with patch("server.config.settings") as ms:
            ms.secret_key = _SECRET
            self.app = _make_app()

    def _client(self) -> TestClient:
        with patch("server.config.settings") as ms:
            ms.secret_key = _SECRET
            return TestClient(self.app)

    def test_viewer_cannot_list(self) -> None:
        with patch("server.config.settings") as ms:
            ms.secret_key = _SECRET
            app = _make_app()
            client = TestClient(app)
            resp = client.get("/credentials", headers=_auth("viewer"))
            assert resp.status_code == 403

    def test_analyst_cannot_list(self) -> None:
        with patch("server.config.settings") as ms:
            ms.secret_key = _SECRET
            app = _make_app()
            client = TestClient(app)
            resp = client.get("/credentials", headers=_auth("analyst"))
            assert resp.status_code == 403

    def test_operator_can_list(self) -> None:
        async def fake_db():
            db = AsyncMock()
            res = MagicMock()
            res.scalars.return_value = iter([])
            db.execute = AsyncMock(return_value=res)
            yield db

        with (
            patch("server.config.settings") as ms,
            patch("server.api.vault.get_db", fake_db),
        ):
            ms.secret_key = _SECRET
            app = _make_app()
            client = TestClient(app)
            resp = client.get("/credentials", headers=_auth("operator"))
            assert resp.status_code == 200

    def test_admin_can_list(self) -> None:
        async def fake_db():
            db = AsyncMock()
            res = MagicMock()
            res.scalars.return_value = iter([])
            db.execute = AsyncMock(return_value=res)
            yield db

        with (
            patch("server.config.settings") as ms,
            patch("server.api.vault.get_db", fake_db),
        ):
            ms.secret_key = _SECRET
            app = _make_app()
            client = TestClient(app)
            resp = client.get("/credentials", headers=_auth("admin"))
            assert resp.status_code == 200

    def test_analyst_cannot_create(self) -> None:
        with patch("server.config.settings") as ms:
            ms.secret_key = _SECRET
            app = _make_app()
            client = TestClient(app)
            resp = client.post(
                "/credentials",
                json={"device_id": "10.0.0.1", "credential_type": "ssh", "secret": "pass"},
                headers=_auth("analyst"),
            )
            assert resp.status_code == 403

    def test_unauthenticated_rejected(self) -> None:
        app = _make_app()
        client = TestClient(app)
        resp = client.get("/credentials")
        assert resp.status_code == 401


# ---------------------------------------------------------------------------
# Vault API — CRUD behaviour
# ---------------------------------------------------------------------------


class TestVaultAPICRUD:
    def test_list_returns_metadata_only(self) -> None:
        creds = [_make_cred(device_id="10.0.0.1"), _make_cred(device_id="10.0.0.2")]

        async def fake_db():
            db = AsyncMock()
            res = MagicMock()
            res.scalars.return_value = iter(creds)
            db.execute = AsyncMock(return_value=res)
            yield db

        with (
            patch("server.config.settings") as ms,
            patch("server.api.vault.get_db", fake_db),
        ):
            ms.secret_key = _SECRET
            client = TestClient(_make_app())
            resp = client.get("/credentials", headers=_auth("operator"))

        assert resp.status_code == 200
        items = resp.json()
        assert len(items) == 2
        for item in items:
            # These fields must NEVER appear in the response
            assert "secret" not in item
            assert "secret_enc" not in item
            assert "username_enc" not in item
            assert "notes_enc" not in item
            # These metadata fields must be present
            assert "device_id" in item
            assert "credential_type" in item
            assert "has_username" in item

    def test_get_single_credential(self) -> None:
        cred_id = uuid.uuid4()
        cred = _make_cred(id=cred_id, device_id="10.0.0.99")

        async def fake_db():
            db = AsyncMock()
            res = MagicMock()
            res.scalar_one_or_none.return_value = cred
            db.execute = AsyncMock(return_value=res)
            yield db

        with (
            patch("server.config.settings") as ms,
            patch("server.api.vault.get_db", fake_db),
        ):
            ms.secret_key = _SECRET
            client = TestClient(_make_app())
            resp = client.get(f"/credentials/{cred_id}", headers=_auth("operator"))

        assert resp.status_code == 200
        body = resp.json()
        assert body["device_id"] == "10.0.0.99"
        assert "secret" not in body
        assert "secret_enc" not in body

    def test_get_nonexistent_returns_404(self) -> None:
        async def fake_db():
            db = AsyncMock()
            res = MagicMock()
            res.scalar_one_or_none.return_value = None
            db.execute = AsyncMock(return_value=res)
            yield db

        with (
            patch("server.config.settings") as ms,
            patch("server.api.vault.get_db", fake_db),
        ):
            ms.secret_key = _SECRET
            client = TestClient(_make_app())
            resp = client.get(f"/credentials/{uuid.uuid4()}", headers=_auth("operator"))

        assert resp.status_code == 404

    def test_create_encrypts_secret(self) -> None:
        """Verify that create calls vault.encrypt and never stores plaintext."""
        cred_id = uuid.uuid4()

        async def fake_db():
            db = AsyncMock()
            db.add = MagicMock()
            db.commit = AsyncMock()

            async def _refresh(obj):
                obj.id = cred_id
                obj.device_id = "10.0.0.1"
                obj.credential_type = "ssh"
                obj.label = None
                obj.username_enc = "enc-user"
                obj.secret_enc = "enc-secret"
                obj.notes_enc = None
                obj.created_by = "alice"
                obj.created_at = datetime(2026, 1, 1)
                obj.updated_at = datetime(2026, 1, 1)

            db.refresh = _refresh
            yield db

        mock_vault = MagicMock()
        mock_vault.encrypt.return_value = "encrypted-value"

        with (
            patch("server.config.settings") as ms,
            patch("server.api.vault.get_db", fake_db),
            patch("server.api.vault.get_vault", return_value=mock_vault),
        ):
            ms.secret_key = _SECRET
            client = TestClient(_make_app())
            resp = client.post(
                "/credentials",
                json={
                    "device_id": "10.0.0.1",
                    "credential_type": "ssh",
                    "username": "admin",
                    "secret": "s3cr3t",
                },
                headers=_auth("operator"),
            )

        assert resp.status_code == 201
        # vault.encrypt must have been called (at least once for secret)
        assert mock_vault.encrypt.called
        body = resp.json()
        assert "secret" not in body
        assert "secret_enc" not in body
        assert body["has_username"] is True

    def test_create_invalid_type_rejected(self) -> None:
        with patch("server.config.settings") as ms:
            ms.secret_key = _SECRET
            client = TestClient(_make_app())
            resp = client.post(
                "/credentials",
                json={"device_id": "10.0.0.1", "credential_type": "telnet", "secret": "x"},
                headers=_auth("operator"),
            )
        assert resp.status_code == 422

    def test_create_empty_secret_rejected(self) -> None:
        with patch("server.config.settings") as ms:
            ms.secret_key = _SECRET
            client = TestClient(_make_app())
            resp = client.post(
                "/credentials",
                json={"device_id": "10.0.0.1", "credential_type": "ssh", "secret": "   "},
                headers=_auth("operator"),
            )
        assert resp.status_code == 422

    def test_delete_credential(self) -> None:
        cred_id = uuid.uuid4()
        cred = _make_cred(id=cred_id)

        async def fake_db():
            db = AsyncMock()
            res = MagicMock()
            res.scalar_one_or_none.return_value = cred
            db.execute = AsyncMock(return_value=res)
            db.delete = AsyncMock()
            db.commit = AsyncMock()
            yield db

        with (
            patch("server.config.settings") as ms,
            patch("server.api.vault.get_db", fake_db),
        ):
            ms.secret_key = _SECRET
            client = TestClient(_make_app())
            resp = client.delete(f"/credentials/{cred_id}", headers=_auth("operator"))

        assert resp.status_code == 204

    def test_delete_nonexistent_returns_404(self) -> None:
        async def fake_db():
            db = AsyncMock()
            res = MagicMock()
            res.scalar_one_or_none.return_value = None
            db.execute = AsyncMock(return_value=res)
            yield db

        with (
            patch("server.config.settings") as ms,
            patch("server.api.vault.get_db", fake_db),
        ):
            ms.secret_key = _SECRET
            client = TestClient(_make_app())
            resp = client.delete(f"/credentials/{uuid.uuid4()}", headers=_auth("admin"))

        assert resp.status_code == 404

    def test_patch_credential(self) -> None:
        cred_id = uuid.uuid4()
        cred = _make_cred(id=cred_id, label="old-label")

        async def fake_db():
            db = AsyncMock()
            res = MagicMock()
            res.scalar_one_or_none.return_value = cred
            db.execute = AsyncMock(return_value=res)
            db.commit = AsyncMock()

            async def _refresh(obj):
                pass

            db.refresh = _refresh
            yield db

        mock_vault = MagicMock()
        mock_vault.encrypt.return_value = "new-enc"

        with (
            patch("server.config.settings") as ms,
            patch("server.api.vault.get_db", fake_db),
            patch("server.api.vault.get_vault", return_value=mock_vault),
        ):
            ms.secret_key = _SECRET
            client = TestClient(_make_app())
            resp = client.patch(
                f"/credentials/{cred_id}",
                json={"label": "new-label", "secret": "new-pass"},
                headers=_auth("operator"),
            )

        assert resp.status_code == 200
        mock_vault.encrypt.assert_called_once_with("new-pass")

    def test_filter_by_device_id(self) -> None:
        async def fake_db():
            db = AsyncMock()
            res = MagicMock()
            res.scalars.return_value = iter([])
            db.execute = AsyncMock(return_value=res)
            yield db

        with (
            patch("server.config.settings") as ms,
            patch("server.api.vault.get_db", fake_db),
        ):
            ms.secret_key = _SECRET
            client = TestClient(_make_app())
            resp = client.get(
                "/credentials?device_id=10.0.0.1", headers=_auth("operator")
            )
        assert resp.status_code == 200
