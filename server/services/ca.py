"""
Embedded Certificate Authority for DK agent mTLS.

The CA root certificate and key are generated once at first startup and stored
on disk under ``ca_dir`` (default: ``./data/ca/``).  All agent certificates are
signed by this CA with a 90-day validity period.

Public API
----------
``ca`` — module-level singleton (call ``ca.init()`` inside the FastAPI lifespan).

``ca.root_cert_pem``  — PEM bytes of the root CA certificate (sent to agents
                         so they can verify the server's TLS cert).
``ca.issue(agent_id)`` — generate a new key-pair, sign a cert, return PEMs.
``ca.fingerprint(pem)`` — SHA-256 fingerprint of a PEM certificate.
"""

from __future__ import annotations

import datetime
import hashlib
import logging
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

logger = logging.getLogger(__name__)

_CERT_VALIDITY_DAYS = 90
_CA_VALIDITY_YEARS = 10


class _IssuedCert:
    """Holds PEM strings for a freshly-issued agent certificate."""

    def __init__(self, cert_pem: str, key_pem: str) -> None:
        self.cert_pem = cert_pem
        self.key_pem = key_pem


class CertificateAuthority:
    """Simple embedded CA backed by a file on disk."""

    def __init__(self) -> None:
        self._root_key: ec.EllipticCurvePrivateKey | None = None
        self._root_cert: x509.Certificate | None = None
        self._ca_dir: Path | None = None

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    def init(self, ca_dir: str | Path = "data/ca") -> None:
        """
        Load or generate the root CA.  Call once inside FastAPI lifespan.

        Args:
            ca_dir: Directory where ``ca.key`` and ``ca.crt`` are stored.
        """
        self._ca_dir = Path(ca_dir)
        self._ca_dir.mkdir(parents=True, exist_ok=True)

        key_path = self._ca_dir / "ca.key"
        cert_path = self._ca_dir / "ca.crt"

        if key_path.exists() and cert_path.exists():
            self._root_key = self._load_key(key_path)
            self._root_cert = self._load_cert(cert_path)
            logger.info("CA loaded from %s", self._ca_dir)
        else:
            self._root_key, self._root_cert = self._generate_root_ca()
            key_path.write_bytes(
                self._root_key.private_bytes(
                    serialization.Encoding.PEM,
                    serialization.PrivateFormat.TraditionalOpenSSL,
                    serialization.NoEncryption(),
                )
            )
            key_path.chmod(0o600)
            cert_path.write_bytes(self._root_cert.public_bytes(serialization.Encoding.PEM))
            logger.info("Root CA generated and stored in %s", self._ca_dir)

    # ------------------------------------------------------------------
    # Properties
    # ------------------------------------------------------------------

    @property
    def root_cert_pem(self) -> str:
        """PEM-encoded root CA certificate (sent to agents at enrollment)."""
        self._assert_init()
        return self._root_cert.public_bytes(serialization.Encoding.PEM).decode()  # type: ignore[union-attr]

    # ------------------------------------------------------------------
    # Certificate issuance
    # ------------------------------------------------------------------

    def issue(self, agent_id: str) -> _IssuedCert:
        """
        Generate a new EC key-pair and sign an agent certificate.

        Args:
            agent_id: UUID string used as the certificate CN and stored in the
                      Subject so the server can verify which agent is connecting.

        Returns:
            _IssuedCert with ``cert_pem`` and ``key_pem`` as PEM strings.
        """
        self._assert_init()

        # Generate a new ECDSA P-256 key for the agent
        agent_key = ec.generate_private_key(ec.SECP256R1())

        now = datetime.datetime.utcnow()
        cert = (
            x509.CertificateBuilder()
            .subject_name(x509.Name([
                x509.NameAttribute(NameOID.COMMON_NAME, agent_id),
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Discoverykastle Agent"),
            ]))
            .issuer_name(self._root_cert.subject)  # type: ignore[union-attr]
            .public_key(agent_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now)
            .not_valid_after(now + datetime.timedelta(days=_CERT_VALIDITY_DAYS))
            .add_extension(
                x509.BasicConstraints(ca=False, path_length=None),
                critical=True,
            )
            .add_extension(
                x509.SubjectAlternativeName([x509.DNSName(agent_id)]),
                critical=False,
            )
            .sign(self._root_key, hashes.SHA256())  # type: ignore[arg-type]
        )

        cert_pem = cert.public_bytes(serialization.Encoding.PEM).decode()
        key_pem = agent_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.NoEncryption(),
        ).decode()

        logger.info("Issued certificate for agent %s", agent_id)
        return _IssuedCert(cert_pem=cert_pem, key_pem=key_pem)

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def fingerprint(pem: str) -> str:
        """Return the SHA-256 fingerprint of a PEM certificate as a hex string."""
        cert = x509.load_pem_x509_certificate(pem.encode())
        raw = cert.fingerprint(hashes.SHA256())
        return raw.hex()

    @staticmethod
    def fingerprint_from_bytes(der: bytes) -> str:
        """Return SHA-256 fingerprint of a DER-encoded certificate."""
        return hashlib.sha256(der).hexdigest()

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    def _assert_init(self) -> None:
        if self._root_key is None or self._root_cert is None:
            raise RuntimeError("CertificateAuthority.init() has not been called")

    @staticmethod
    def _generate_root_ca() -> tuple[ec.EllipticCurvePrivateKey, x509.Certificate]:
        key = ec.generate_private_key(ec.SECP256R1())
        name = x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, "Discoverykastle Root CA"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Discoverykastle"),
        ])
        now = datetime.datetime.utcnow()
        cert = (
            x509.CertificateBuilder()
            .subject_name(name)
            .issuer_name(name)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now)
            .not_valid_after(now + datetime.timedelta(days=_CA_VALIDITY_YEARS * 365))
            .add_extension(
                x509.BasicConstraints(ca=True, path_length=0),
                critical=True,
            )
            .add_extension(
                x509.KeyUsage(
                    key_cert_sign=True,
                    crl_sign=True,
                    digital_signature=False,
                    content_commitment=False,
                    key_encipherment=False,
                    data_encipherment=False,
                    key_agreement=False,
                    encipher_only=False,
                    decipher_only=False,
                ),
                critical=True,
            )
            .sign(key, hashes.SHA256())
        )
        return key, cert

    @staticmethod
    def _load_key(path: Path) -> ec.EllipticCurvePrivateKey:
        raw = path.read_bytes()
        key = serialization.load_pem_private_key(raw, password=None)
        if not isinstance(key, ec.EllipticCurvePrivateKey):
            raise TypeError(f"Expected EC private key, got {type(key)}")
        return key

    @staticmethod
    def _load_cert(path: Path) -> x509.Certificate:
        return x509.load_pem_x509_certificate(path.read_bytes())


# Module-level singleton
ca = CertificateAuthority()
