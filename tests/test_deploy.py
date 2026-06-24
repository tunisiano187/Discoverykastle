"""
Tests for server/services/deploy.py and server/api/deploy.py.

Strategy:
- Service tests: mock db.get, vault.decrypt, and _ssh_deploy
- API tests: override auth + DB, mock deploy_agent
- No real SSH or crypto required.
"""

from __future__ import annotations

import uuid
from unittest.mock import AsyncMock, MagicMock, patch

import pytest


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_HOST_ID = uuid.UUID("11111111-2222-3333-4444-555555555555")
_CRED_ID = uuid.UUID("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee")


def _make_host(ip_addresses=None, fqdn="server1.office.local"):
    host = MagicMock()
    host.id = _HOST_ID
    host.fqdn = fqdn
    host.ip_addresses = ip_addresses if ip_addresses is not None else ["192.168.1.10"]
    return host


def _make_credential(cred_type="ssh"):
    cred = MagicMock()
    cred.id = _CRED_ID
    cred.credential_type = cred_type
    cred.ciphertext = "FAKECIPHERTEXT=="
    return cred


def _make_db(host=None, cred=None):
    db = AsyncMock()

    async def _get(model_class, obj_id):
        if "Host" in model_class.__name__:
            return host
        if "Credential" in model_class.__name__:
            return cred
        return None

    db.get = AsyncMock(side_effect=_get)
    return db


# ---------------------------------------------------------------------------
# DeployResult / DeployError
# ---------------------------------------------------------------------------


class TestDeployResult:
    def test_dataclass_defaults(self) -> None:
        from server.services.deploy import DeployResult

        r = DeployResult(host_id=_HOST_ID, success=True, message="ok")
        assert r.stdout == ""
        assert r.stderr == ""
        assert r.exit_code == -1
        assert r.errors == []

    def test_deploy_error_is_exception(self) -> None:
        from server.services.deploy import DeployError

        err = DeployError("host not found")
        assert isinstance(err, Exception)
        assert "host not found" in str(err)


# ---------------------------------------------------------------------------
# _pick_ip
# ---------------------------------------------------------------------------


class TestPickIp:
    def test_returns_first_non_loopback(self) -> None:
        from server.services.deploy import _pick_ip

        host = _make_host(ip_addresses=["127.0.0.1", "10.0.0.5"])
        assert _pick_ip(host) == "10.0.0.5"

    def test_returns_none_when_only_loopback(self) -> None:
        from server.services.deploy import _pick_ip

        host = _make_host(ip_addresses=["127.0.0.1"])
        assert _pick_ip(host) is None

    def test_returns_none_when_empty(self) -> None:
        from server.services.deploy import _pick_ip

        host = _make_host(ip_addresses=[])
        assert _pick_ip(host) is None

    def test_returns_first_ip_when_single_public(self) -> None:
        from server.services.deploy import _pick_ip

        host = _make_host(ip_addresses=["192.168.1.10"])
        assert _pick_ip(host) == "192.168.1.10"


# ---------------------------------------------------------------------------
# _shell_quote
# ---------------------------------------------------------------------------


class TestShellQuote:
    def test_wraps_in_single_quotes(self) -> None:
        from server.services.deploy import _shell_quote

        result = _shell_quote("echo hello")
        assert result == "'echo hello'"

    def test_escapes_embedded_single_quotes(self) -> None:
        from server.services.deploy import _shell_quote

        result = _shell_quote("echo 'hi'")
        assert "'\\''" in result


# ---------------------------------------------------------------------------
# deploy_agent (service)
# ---------------------------------------------------------------------------


class TestDeployAgent:
    @pytest.mark.asyncio
    async def test_raises_deploy_error_when_host_not_found(self) -> None:
        from server.services.deploy import DeployError, deploy_agent

        db = AsyncMock()
        db.get = AsyncMock(return_value=None)

        with pytest.raises(DeployError, match="not found"):
            await deploy_agent(db, _HOST_ID, _CRED_ID)

    @pytest.mark.asyncio
    async def test_raises_deploy_error_when_no_usable_ip(self) -> None:
        from server.services.deploy import DeployError, deploy_agent

        host = _make_host(ip_addresses=["127.0.0.1"])
        cred = _make_credential()

        db = AsyncMock()

        async def _get(cls, oid):
            if "Host" in cls.__name__:
                return host
            return cred

        db.get = AsyncMock(side_effect=_get)

        with pytest.raises(DeployError, match="no usable IP"):
            await deploy_agent(db, _HOST_ID, _CRED_ID)

    @pytest.mark.asyncio
    async def test_raises_deploy_error_when_credential_not_found(self) -> None:
        from server.services.deploy import DeployError, deploy_agent

        host = _make_host()

        db = AsyncMock()

        async def _get(cls, oid):
            if "Host" in cls.__name__:
                return host
            return None  # credential not found

        db.get = AsyncMock(side_effect=_get)

        with pytest.raises(DeployError, match="Credential .* not found"):
            await deploy_agent(db, _HOST_ID, _CRED_ID)

    @pytest.mark.asyncio
    async def test_raises_deploy_error_when_credential_wrong_type(self) -> None:
        from server.services.deploy import DeployError, deploy_agent

        host = _make_host()
        cred = _make_credential(cred_type="snmp_v2")

        db = AsyncMock()

        async def _get(cls, oid):
            if "Host" in cls.__name__:
                return host
            return cred

        db.get = AsyncMock(side_effect=_get)

        with pytest.raises(DeployError, match="not supported for SSH"):
            await deploy_agent(db, _HOST_ID, _CRED_ID)

    @pytest.mark.asyncio
    async def test_returns_success_result_on_exit_code_0(self) -> None:
        from server.services.deploy import DeployResult, deploy_agent

        host = _make_host()
        cred = _make_credential()

        db = AsyncMock()

        async def _get(cls, oid):
            if "Host" in cls.__name__:
                return host
            return cred

        db.get = AsyncMock(side_effect=_get)

        with patch("server.services.deploy.decrypt", return_value={"username": "root", "password": "secret"}), \
             patch("server.services.deploy._ssh_deploy", return_value=("installed\n", "", 0)):
            result = await deploy_agent(db, _HOST_ID, _CRED_ID, server_url="https://dkastle.local")

        assert isinstance(result, DeployResult)
        assert result.success is True
        assert result.exit_code == 0
        assert "installed" in result.stdout

    @pytest.mark.asyncio
    async def test_returns_failure_result_on_nonzero_exit_code(self) -> None:
        from server.services.deploy import deploy_agent

        host = _make_host()
        cred = _make_credential()

        db = AsyncMock()

        async def _get(cls, oid):
            if "Host" in cls.__name__:
                return host
            return cred

        db.get = AsyncMock(side_effect=_get)

        with patch("server.services.deploy.decrypt", return_value={"username": "root", "password": "pw"}), \
             patch("server.services.deploy._ssh_deploy", return_value=("", "error: curl failed", 1)):
            result = await deploy_agent(db, _HOST_ID, _CRED_ID)

        assert result.success is False
        assert result.exit_code == 1

    @pytest.mark.asyncio
    async def test_returns_failure_result_on_ssh_exception(self) -> None:
        from server.services.deploy import deploy_agent

        host = _make_host()
        cred = _make_credential()

        db = AsyncMock()

        async def _get(cls, oid):
            if "Host" in cls.__name__:
                return host
            return cred

        db.get = AsyncMock(side_effect=_get)

        with patch("server.services.deploy.decrypt", return_value={"username": "ubuntu", "password": "pw"}), \
             patch("server.services.deploy._ssh_deploy", side_effect=ConnectionRefusedError("Connection refused")):
            result = await deploy_agent(db, _HOST_ID, _CRED_ID)

        assert result.success is False
        assert "Connection refused" in result.message

    @pytest.mark.asyncio
    async def test_raises_deploy_error_on_vault_error(self) -> None:
        from server.services.deploy import DeployError, deploy_agent
        from server.services.vault import VaultError

        host = _make_host()
        cred = _make_credential()

        db = AsyncMock()

        async def _get(cls, oid):
            if "Host" in cls.__name__:
                return host
            return cred

        db.get = AsyncMock(side_effect=_get)

        with patch("server.services.deploy.decrypt", side_effect=VaultError("wrong key")):
            with pytest.raises(DeployError, match="Failed to decrypt"):
                await deploy_agent(db, _HOST_ID, _CRED_ID)


# ---------------------------------------------------------------------------
# deploy API tests
# ---------------------------------------------------------------------------


class TestDeployAPI:
    @pytest.mark.asyncio
    async def test_trigger_deploy_success_returns_200(self) -> None:
        import httpx
        from fastapi import FastAPI
        from server.api.deploy import router, _require_operator
        from server.database import get_db
        from server.services.deploy import DeployResult

        db = AsyncMock()

        app = FastAPI()

        async def _fake_db():
            yield db

        app.dependency_overrides[get_db] = _fake_db
        app.dependency_overrides[_require_operator] = lambda: "operator1"
        app.include_router(router)

        fake_result = DeployResult(
            host_id=_HOST_ID,
            success=True,
            message="Agent installed successfully",
            stdout="Done.\n",
            stderr="",
            exit_code=0,
        )

        with patch("server.api.deploy.deploy_agent", return_value=fake_result):
            async with httpx.AsyncClient(
                transport=httpx.ASGITransport(app=app), base_url="http://test"
            ) as client:
                resp = await client.post(
                    f"/api/v1/deploy/{_HOST_ID}",
                    json={"credential_id": str(_CRED_ID)},
                )
        assert resp.status_code == 200
        body = resp.json()
        assert body["success"] is True
        assert body["exit_code"] == 0

    @pytest.mark.asyncio
    async def test_trigger_deploy_returns_422_on_deploy_error(self) -> None:
        import httpx
        from fastapi import FastAPI
        from server.api.deploy import router, _require_operator
        from server.database import get_db
        from server.services.deploy import DeployError

        db = AsyncMock()

        app = FastAPI()

        async def _fake_db():
            yield db

        app.dependency_overrides[get_db] = _fake_db
        app.dependency_overrides[_require_operator] = lambda: "operator1"
        app.include_router(router)

        with patch("server.api.deploy.deploy_agent", side_effect=DeployError("Host not found")):
            async with httpx.AsyncClient(
                transport=httpx.ASGITransport(app=app), base_url="http://test"
            ) as client:
                resp = await client.post(
                    f"/api/v1/deploy/{_HOST_ID}",
                    json={"credential_id": str(_CRED_ID)},
                )
        assert resp.status_code == 422
        assert "Host not found" in resp.json()["detail"]

    @pytest.mark.asyncio
    async def test_trigger_deploy_failure_still_returns_200(self) -> None:
        import httpx
        from fastapi import FastAPI
        from server.api.deploy import router, _require_operator
        from server.database import get_db
        from server.services.deploy import DeployResult

        db = AsyncMock()

        app = FastAPI()

        async def _fake_db():
            yield db

        app.dependency_overrides[get_db] = _fake_db
        app.dependency_overrides[_require_operator] = lambda: "operator1"
        app.include_router(router)

        fake_result = DeployResult(
            host_id=_HOST_ID,
            success=False,
            message="Installer exited with code 1",
            stdout="",
            stderr="curl: not found",
            exit_code=1,
        )

        with patch("server.api.deploy.deploy_agent", return_value=fake_result):
            async with httpx.AsyncClient(
                transport=httpx.ASGITransport(app=app), base_url="http://test"
            ) as client:
                resp = await client.post(
                    f"/api/v1/deploy/{_HOST_ID}",
                    json={"credential_id": str(_CRED_ID)},
                )
        assert resp.status_code == 200
        body = resp.json()
        assert body["success"] is False
        assert body["exit_code"] == 1
