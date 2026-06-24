"""
Integration tests — credential vault flows.

Tests cover full CRUD through the vault REST API against a real database,
verifying that secrets are never returned in responses.
"""
from __future__ import annotations

import uuid

import pytest


CRED_PAYLOAD = {
    "label": "it-test-cred",
    "credential_type": "ssh",
    "data": {"user": "root", "ssh_key": "mock-key-for-integration-test"},
}


class TestVaultCRUD:
    @pytest.mark.asyncio
    async def test_create_credential_returns_201(self, client, auth_headers):
        resp = await client.post(
            "/api/v1/vault/credentials",
            json=CRED_PAYLOAD,
            headers=auth_headers,
        )
        assert resp.status_code == 201
        body = resp.json()
        assert "id" in body
        assert body["label"] == "it-test-cred"
        assert body["credential_type"] == "ssh"
        # Secret data must never appear in the response
        assert "ciphertext" not in body
        assert "data" not in body

    @pytest.mark.asyncio
    async def test_list_credentials_returns_metadata_only(self, client, auth_headers, engine):
        from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker
        from sqlalchemy import text
        from server.models.credential import Credential
        from server.services.vault import encrypt
        import json

        # Seed a credential directly in the DB
        cred_id = uuid.uuid4()
        Session = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
        async with Session() as session:
            cred = Credential(
                id=cred_id,
                label="it-list-cred",
                credential_type="snmp",
                ciphertext=encrypt(json.dumps({"community": "public"})),
                created_by="it-operator",
            )
            session.add(cred)
            await session.commit()

        try:
            resp = await client.get("/api/v1/vault/credentials", headers=auth_headers)
            assert resp.status_code == 200
            items = resp.json()
            ids = [item["id"] for item in items]
            assert str(cred_id) in ids

            # Verify no secret data in any response item
            for item in items:
                assert "ciphertext" not in item
                assert "data" not in item
        finally:
            async with Session() as session:
                await session.execute(
                    text(f"DELETE FROM vault_credentials WHERE id = '{cred_id}'")
                )
                await session.commit()

    @pytest.mark.asyncio
    async def test_get_single_credential(self, client, auth_headers, engine):
        from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker
        from sqlalchemy import text
        from server.models.credential import Credential
        from server.services.vault import encrypt
        import json

        cred_id = uuid.uuid4()
        Session = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
        async with Session() as session:
            cred = Credential(
                id=cred_id,
                label="it-get-cred",
                credential_type="api_key",
                ciphertext=encrypt(json.dumps({"token": "mock-api-token"})),
                created_by="it-operator",
            )
            session.add(cred)
            await session.commit()

        try:
            resp = await client.get(
                f"/api/v1/vault/credentials/{cred_id}", headers=auth_headers
            )
            assert resp.status_code == 200
            body = resp.json()
            assert body["id"] == str(cred_id)
            assert body["label"] == "it-get-cred"
            assert "ciphertext" not in body
            assert "data" not in body
        finally:
            async with Session() as session:
                await session.execute(
                    text(f"DELETE FROM vault_credentials WHERE id = '{cred_id}'")
                )
                await session.commit()

    @pytest.mark.asyncio
    async def test_get_nonexistent_credential_returns_404(self, client, auth_headers):
        resp = await client.get(
            f"/api/v1/vault/credentials/{uuid.uuid4()}", headers=auth_headers
        )
        assert resp.status_code == 404

    @pytest.mark.asyncio
    async def test_delete_credential(self, client, auth_headers, engine):
        from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker
        from server.models.credential import Credential
        from server.services.vault import encrypt
        import json

        cred_id = uuid.uuid4()
        Session = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
        async with Session() as session:
            cred = Credential(
                id=cred_id,
                label="it-delete-cred",
                credential_type="winrm",
                ciphertext=encrypt(json.dumps({"user": "Administrator", "token": "mock"})),
                created_by="it-operator",
            )
            session.add(cred)
            await session.commit()

        resp = await client.delete(
            f"/api/v1/vault/credentials/{cred_id}", headers=auth_headers
        )
        assert resp.status_code == 204

        # Verify it's gone
        resp2 = await client.get(
            f"/api/v1/vault/credentials/{cred_id}", headers=auth_headers
        )
        assert resp2.status_code == 404

    @pytest.mark.asyncio
    async def test_delete_nonexistent_returns_404(self, client, auth_headers):
        resp = await client.delete(
            f"/api/v1/vault/credentials/{uuid.uuid4()}", headers=auth_headers
        )
        assert resp.status_code == 404


class TestVaultRBAC:
    @pytest.mark.asyncio
    async def test_viewer_cannot_create_credential(self, client, viewer_token):
        resp = await client.post(
            "/api/v1/vault/credentials",
            json=CRED_PAYLOAD,
            headers={"Authorization": f"Bearer {viewer_token}"},
        )
        assert resp.status_code == 403

    @pytest.mark.asyncio
    async def test_unauthenticated_cannot_list(self, client):
        resp = await client.get("/api/v1/vault/credentials")
        assert resp.status_code == 401
