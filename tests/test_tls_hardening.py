"""
Tests for TLS hardening:
  - POST /api/v1/agents/{id}/cert/renew (server — mocked DB)
  - _cert_days_remaining() helper (agent)
  - _build_ssl_ctx() helper (agent)
  - DKAgent._renew_cert_if_needed() (agent)
"""
from __future__ import annotations

import datetime
import ssl
import uuid
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from agent.core import _cert_days_remaining, _build_ssl_ctx, _CERT_RENEW_DAYS


# ---------------------------------------------------------------------------
# Cert-generation helpers
# ---------------------------------------------------------------------------

def _make_key():
    return ec.generate_private_key(ec.SECP256R1())


def _make_cert_pem(days_valid: int = 90) -> bytes:
    """Generate a minimal self-signed PEM cert valid for *days_valid* days."""
    key = _make_key()
    now = datetime.datetime.utcnow()
    cert = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "test-agent")]))
        .issuer_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "test-ca")]))
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=days_valid))
        .sign(key, hashes.SHA256())
    )
    return cert.public_bytes(serialization.Encoding.PEM)


def _make_key_pem() -> bytes:
    key = _make_key()
    return key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.TraditionalOpenSSL,
        serialization.NoEncryption(),
    )


def _write_cert(tmp_dir: Path, days_valid: int = 90) -> Path:
    p = tmp_dir / "agent.crt"
    p.write_bytes(_make_cert_pem(days_valid))
    return p


# ===========================================================================
# _cert_days_remaining
# ===========================================================================

class TestCertDaysRemaining:
    def test_returns_roughly_correct_days(self, tmp_path):
        cert_path = _write_cert(tmp_path, days_valid=30)
        days = _cert_days_remaining(cert_path)
        assert days is not None
        assert 28 <= days <= 30

    def test_long_lived_cert(self, tmp_path):
        cert_path = _write_cert(tmp_path, days_valid=365)
        days = _cert_days_remaining(cert_path)
        assert days is not None
        assert days >= 363

    def test_returns_zero_for_nearly_expired(self, tmp_path):
        """A cert expiring today (day 0) returns 0, not negative."""
        cert_path = _write_cert(tmp_path, days_valid=1)
        days = _cert_days_remaining(cert_path)
        assert days is not None
        assert days >= 0

    def test_returns_none_for_missing_file(self, tmp_path):
        days = _cert_days_remaining(tmp_path / "nonexistent.crt")
        assert days is None

    def test_returns_none_for_invalid_pem(self, tmp_path):
        p = tmp_path / "bad.crt"
        p.write_text("not a certificate")
        days = _cert_days_remaining(p)
        assert days is None

    def test_accepts_string_path(self, tmp_path):
        cert_path = _write_cert(tmp_path, days_valid=60)
        days = _cert_days_remaining(str(cert_path))
        assert days is not None
        assert days >= 58

    def test_expiring_soon_is_below_renew_threshold(self, tmp_path):
        cert_path = _write_cert(tmp_path, days_valid=5)
        days = _cert_days_remaining(cert_path)
        assert days is not None
        assert days < _CERT_RENEW_DAYS


# ===========================================================================
# _build_ssl_ctx
# ===========================================================================

class TestBuildSslCtx:
    def test_returns_none_when_no_cert(self):
        assert _build_ssl_ctx(None, None, None) is None

    def test_returns_none_when_only_cert_no_key(self, tmp_path):
        cert = tmp_path / "a.crt"
        cert.write_bytes(_make_cert_pem())
        assert _build_ssl_ctx(str(cert), None, None) is None

    def test_insecure_mode_logged_when_no_ca(self, tmp_path):
        """When no CA file is given, CERT_NONE is set and a warning is emitted."""
        key = _make_key()
        key_pem = key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.NoEncryption(),
        )
        now = datetime.datetime.utcnow()
        cert = (
            x509.CertificateBuilder()
            .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "a")]))
            .issuer_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "a")]))
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now)
            .not_valid_after(now + datetime.timedelta(days=90))
            .sign(key, hashes.SHA256())
        )
        cert_pem = cert.public_bytes(serialization.Encoding.PEM)

        cert_path = tmp_path / "a.crt"
        key_path  = tmp_path / "a.key"
        cert_path.write_bytes(cert_pem)
        key_path.write_bytes(key_pem)

        with patch("agent.core.logger") as mock_log:
            ctx = _build_ssl_ctx(str(cert_path), str(key_path), None)

        assert ctx is not None
        assert ctx.verify_mode == ssl.CERT_NONE
        mock_log.warning.assert_called_once()

    def test_no_ca_check_hostname_disabled(self, tmp_path):
        key = _make_key()
        key_pem = key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.NoEncryption(),
        )
        now = datetime.datetime.utcnow()
        cert = (
            x509.CertificateBuilder()
            .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "b")]))
            .issuer_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "b")]))
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now)
            .not_valid_after(now + datetime.timedelta(days=90))
            .sign(key, hashes.SHA256())
        )
        cert_pem = cert.public_bytes(serialization.Encoding.PEM)
        cert_path = tmp_path / "b.crt"
        key_path  = tmp_path / "b.key"
        cert_path.write_bytes(cert_pem)
        key_path.write_bytes(key_pem)

        with patch("agent.core.logger"):
            ctx = _build_ssl_ctx(str(cert_path), str(key_path), None)

        assert ctx is not None
        assert ctx.check_hostname is False


# ===========================================================================
# POST /api/v1/agents/{id}/cert/renew — server route (mocked DB + CA)
# ===========================================================================

@pytest.mark.asyncio
class TestCertRenewEndpoint:
    """
    Tests for the /cert/renew endpoint.  The DB and CA are mocked so that
    no real database or TLS is required.
    """

    def _make_agent_record(self, agent_id: uuid.UUID, fingerprint: str) -> MagicMock:
        agent = MagicMock()
        agent.id = agent_id
        agent.certificate_fingerprint = fingerprint
        return agent

    async def test_renew_issues_new_cert(self):
        from server.api.agents import renew_agent_cert
        from server.services.ca import CertificateAuthority

        agent_id = uuid.uuid4()
        cert_pem = _make_cert_pem(90).decode()
        key_pem = _make_key_pem().decode()
        old_fp = "oldfp1234"

        agent = self._make_agent_record(agent_id, old_fp)

        mock_db = AsyncMock()
        mock_db.get = AsyncMock(return_value=agent)

        issued = MagicMock()
        issued.cert_pem = cert_pem
        issued.key_pem = key_pem

        mock_ca = MagicMock(spec=CertificateAuthority)
        mock_ca.issue.return_value = issued
        mock_ca.fingerprint.return_value = "newfingerprint567"
        mock_ca.root_cert_pem = "fake-ca-cert"

        with patch("server.api.agents.ca", mock_ca):
            result = await renew_agent_cert(
                agent_id=agent_id,
                x_agent_fingerprint=old_fp,
                x_agent_id=None,
                db=mock_db,
            )

        assert result.certificate == cert_pem
        assert result.private_key == key_pem
        assert result.ca_certificate == "fake-ca-cert"
        assert agent.certificate_fingerprint == "newfingerprint567"
        mock_db.commit.assert_awaited_once()

    async def test_renew_wrong_fingerprint_raises_403(self):
        from fastapi import HTTPException
        from server.api.agents import renew_agent_cert

        agent_id = uuid.uuid4()
        agent = self._make_agent_record(agent_id, "correct-fp")

        mock_db = AsyncMock()
        mock_db.get = AsyncMock(return_value=agent)

        with pytest.raises(HTTPException) as exc_info:
            await renew_agent_cert(
                agent_id=agent_id,
                x_agent_fingerprint="wrong-fp",
                x_agent_id=None,
                db=mock_db,
            )
        assert exc_info.value.status_code == 403

    async def test_renew_unknown_agent_raises_404(self):
        from fastapi import HTTPException
        from server.api.agents import renew_agent_cert

        mock_db = AsyncMock()
        mock_db.get = AsyncMock(return_value=None)  # agent not found

        with pytest.raises(HTTPException) as exc_info:
            await renew_agent_cert(
                agent_id=uuid.uuid4(),
                x_agent_fingerprint="any-fp",
                x_agent_id=None,
                db=mock_db,
            )
        assert exc_info.value.status_code == 404

    async def test_renew_fallback_to_agent_id_header(self):
        """X-Agent-ID header (no fingerprint) is accepted as fallback."""
        from server.api.agents import renew_agent_cert
        from server.services.ca import CertificateAuthority

        agent_id = uuid.uuid4()
        agent = self._make_agent_record(agent_id, "some-fp")

        mock_db = AsyncMock()
        mock_db.get = AsyncMock(return_value=agent)

        issued = MagicMock()
        issued.cert_pem = _make_cert_pem().decode()
        issued.key_pem = _make_key_pem().decode()

        mock_ca = MagicMock(spec=CertificateAuthority)
        mock_ca.issue.return_value = issued
        mock_ca.fingerprint.return_value = "new-fp"
        mock_ca.root_cert_pem = "ca-pem"

        with patch("server.api.agents.ca", mock_ca):
            result = await renew_agent_cert(
                agent_id=agent_id,
                x_agent_fingerprint=None,
                x_agent_id=str(agent_id),  # fallback path
                db=mock_db,
            )
        assert result.certificate == issued.cert_pem


# ===========================================================================
# DKAgent._renew_cert_if_needed
# ===========================================================================

@pytest.mark.asyncio
class TestRenewCertIfNeeded:

    def _make_agent(self, cert_path: str | None = None) -> tuple:
        from agent.core import DKAgent
        from agent.config import AgentConfig

        cfg = MagicMock(spec=AgentConfig)
        cfg.is_registered = True
        cfg.agent_id = "test-agent-uuid"
        cfg.agent_cert = cert_path
        cfg.agent_key = "/fake/agent.key"
        cfg.agent_ca = None
        cfg.server_url = "https://server:8443"
        return DKAgent(cfg), cfg

    async def test_no_op_when_not_registered(self):
        from agent.core import DKAgent
        from agent.config import AgentConfig

        cfg = MagicMock(spec=AgentConfig)
        cfg.is_registered = False
        agent = DKAgent(cfg)
        # Must not raise
        await agent._renew_cert_if_needed()

    async def test_no_op_when_cert_has_plenty_of_time(self, tmp_path):
        cert_path = _write_cert(tmp_path, days_valid=60)
        agent, _ = self._make_agent(str(cert_path))

        with patch.object(agent, "_build_client") as mock_client:
            await agent._renew_cert_if_needed()
        mock_client.assert_not_called()

    async def test_renews_when_cert_expiring_soon(self, tmp_path):
        cert_path = _write_cert(tmp_path, days_valid=5)  # < _CERT_RENEW_DAYS
        key_path = tmp_path / "agent.key"
        key_path.write_text("fake-key")

        agent, cfg = self._make_agent(str(cert_path))
        cfg.agent_key = str(key_path)
        cfg.agent_ca = None

        new_cert_content = _make_cert_pem(90).decode()

        mock_resp = MagicMock()
        mock_resp.raise_for_status = MagicMock()
        mock_resp.json.return_value = {
            "certificate": new_cert_content,
            "private_key": "new-private-key",
            "ca_certificate": "",
        }

        mock_client_cm = AsyncMock()
        mock_client_cm.__aenter__ = AsyncMock(return_value=mock_client_cm)
        mock_client_cm.__aexit__ = AsyncMock(return_value=False)
        mock_client_cm.post = AsyncMock(return_value=mock_resp)

        with patch.object(agent, "_build_client", return_value=mock_client_cm):
            await agent._renew_cert_if_needed()

        written = cert_path.read_text()
        assert written == new_cert_content
        mock_client_cm.post.assert_awaited_once()
        call_url = mock_client_cm.post.call_args[0][0]
        assert "cert/renew" in call_url

    async def test_renewal_failure_is_caught(self, tmp_path):
        cert_path = _write_cert(tmp_path, days_valid=3)
        agent, cfg = self._make_agent(str(cert_path))
        cfg.agent_key = str(tmp_path / "agent.key")

        mock_client_cm = AsyncMock()
        mock_client_cm.__aenter__ = AsyncMock(return_value=mock_client_cm)
        mock_client_cm.__aexit__ = AsyncMock(return_value=False)
        mock_client_cm.post = AsyncMock(side_effect=ConnectionError("server down"))

        with patch.object(agent, "_build_client", return_value=mock_client_cm):
            # Must not raise — just log a warning
            await agent._renew_cert_if_needed()

    async def test_no_op_when_no_cert_path(self):
        agent, cfg = self._make_agent(cert_path=None)
        with patch.object(agent, "_build_client") as mock_client:
            await agent._renew_cert_if_needed()
        mock_client.assert_not_called()
