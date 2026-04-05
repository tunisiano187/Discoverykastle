"""Tests for the embedded Certificate Authority."""

from __future__ import annotations

import tempfile
from pathlib import Path

import pytest

from server.services.ca import CertificateAuthority


@pytest.fixture()
def ca_instance(tmp_path: Path) -> CertificateAuthority:
    """Return a fresh, initialized CA backed by a temp directory."""
    instance = CertificateAuthority()
    instance.init(tmp_path / "ca")
    return instance


class TestCARootGeneration:
    def test_init_creates_files(self, tmp_path: Path) -> None:
        ca = CertificateAuthority()
        ca_dir = tmp_path / "ca"
        ca.init(ca_dir)
        assert (ca_dir / "ca.key").exists()
        assert (ca_dir / "ca.crt").exists()

    def test_init_idempotent(self, tmp_path: Path) -> None:
        """Calling init() twice with same dir loads the existing CA."""
        ca1 = CertificateAuthority()
        ca1.init(tmp_path / "ca")
        pem1 = ca1.root_cert_pem

        ca2 = CertificateAuthority()
        ca2.init(tmp_path / "ca")
        pem2 = ca2.root_cert_pem

        assert pem1 == pem2

    def test_root_cert_pem_is_valid(self, ca_instance: CertificateAuthority) -> None:
        pem = ca_instance.root_cert_pem
        assert pem.startswith("-----BEGIN CERTIFICATE-----")

    def test_key_file_permissions(self, tmp_path: Path) -> None:
        import sys
        if sys.platform == "win32":
            pytest.skip("Permission check not applicable on Windows")
        ca = CertificateAuthority()
        ca.init(tmp_path / "ca")
        key_path = tmp_path / "ca" / "ca.key"
        mode = oct(key_path.stat().st_mode)[-3:]
        assert mode == "600", f"Expected 600, got {mode}"


class TestCertIssuance:
    def test_issue_returns_cert_and_key(self, ca_instance: CertificateAuthority) -> None:
        issued = ca_instance.issue("test-agent-id")
        assert issued.cert_pem.startswith("-----BEGIN CERTIFICATE-----")
        assert "PRIVATE KEY" in issued.key_pem

    def test_issued_cert_has_correct_cn(self, ca_instance: CertificateAuthority) -> None:
        from cryptography import x509

        agent_id = "my-agent-uuid"
        issued = ca_instance.issue(agent_id)
        cert = x509.load_pem_x509_certificate(issued.cert_pem.encode())
        cn = cert.subject.get_attributes_for_oid(
            x509.NameOID.COMMON_NAME  # type: ignore[attr-defined]
        )[0].value
        assert cn == agent_id

    def test_different_agents_get_different_certs(
        self, ca_instance: CertificateAuthority
    ) -> None:
        a = ca_instance.issue("agent-a")
        b = ca_instance.issue("agent-b")
        assert a.cert_pem != b.cert_pem
        assert a.key_pem != b.key_pem


class TestFingerprint:
    def test_fingerprint_is_hex(self, ca_instance: CertificateAuthority) -> None:
        issued = ca_instance.issue("agent-fp-test")
        fp = CertificateAuthority.fingerprint(issued.cert_pem)
        assert len(fp) == 64  # SHA-256 = 32 bytes = 64 hex chars
        int(fp, 16)  # should not raise

    def test_same_cert_same_fingerprint(self, ca_instance: CertificateAuthority) -> None:
        issued = ca_instance.issue("stable-agent")
        fp1 = CertificateAuthority.fingerprint(issued.cert_pem)
        fp2 = CertificateAuthority.fingerprint(issued.cert_pem)
        assert fp1 == fp2

    def test_different_certs_different_fingerprints(
        self, ca_instance: CertificateAuthority
    ) -> None:
        a = ca_instance.issue("agent-x")
        b = ca_instance.issue("agent-y")
        assert CertificateAuthority.fingerprint(a.cert_pem) != CertificateAuthority.fingerprint(
            b.cert_pem
        )
