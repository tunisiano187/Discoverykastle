"""
Integration tests — inventory API flows.

Tests cover host and network listing through the REST API against a real
PostgreSQL database.
"""
from __future__ import annotations

import uuid

import pytest


class TestHostInventory:
    @pytest.mark.asyncio
    async def test_list_hosts_returns_200(self, client, auth_headers):
        resp = await client.get("/api/v1/inventory/hosts", headers=auth_headers)
        assert resp.status_code == 200
        assert isinstance(resp.json(), list)

    @pytest.mark.asyncio
    async def test_list_hosts_unauthenticated_returns_401(self, client):
        resp = await client.get("/api/v1/inventory/hosts")
        assert resp.status_code == 401

    @pytest.mark.asyncio
    async def test_get_seeded_host(self, client, auth_headers, engine):
        from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker
        from sqlalchemy import text
        from server.models.host import Host

        host_id = uuid.uuid4()
        Session = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
        async with Session() as session:
            host = Host(
                id=host_id,
                fqdn="it-host.test.local",
                ip_addresses=["192.0.2.1"],
                os="Linux",
                os_version="Ubuntu 22.04",
            )
            session.add(host)
            await session.commit()

        try:
            resp = await client.get(
                f"/api/v1/inventory/hosts/{host_id}", headers=auth_headers
            )
            assert resp.status_code == 200
            body = resp.json()
            assert body["fqdn"] == "it-host.test.local"
            assert "192.0.2.1" in body["ip_addresses"]
        finally:
            async with Session() as session:
                await session.execute(
                    text(f"DELETE FROM hosts WHERE id = '{host_id}'")
                )
                await session.commit()

    @pytest.mark.asyncio
    async def test_get_nonexistent_host_returns_404(self, client, auth_headers):
        resp = await client.get(
            f"/api/v1/inventory/hosts/{uuid.uuid4()}", headers=auth_headers
        )
        assert resp.status_code == 404

    @pytest.mark.asyncio
    async def test_inventory_stats_endpoint(self, client, auth_headers):
        resp = await client.get("/api/v1/inventory/stats", headers=auth_headers)
        assert resp.status_code == 200
        body = resp.json()
        assert "total_hosts" in body


class TestNetworkInventory:
    @pytest.mark.asyncio
    async def test_list_networks_returns_200(self, client, auth_headers):
        resp = await client.get("/api/v1/inventory/networks", headers=auth_headers)
        assert resp.status_code == 200
        assert isinstance(resp.json(), list)
