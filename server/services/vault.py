"""
AES-256-GCM credential vault service.

Provides symmetric encryption for sensitive values (passwords, API keys,
SNMP community strings) stored in the ``vault_credentials`` table.

The master key is sourced from ``DKASTLE_VAULT_KEY`` (32-byte base64 string).
If the value is not valid base64 or not exactly 32 bytes when decoded, a
deterministic 32-byte key is derived via SHA-256 so any string works.

Wire format: base64(nonce[12] || ciphertext+tag)
"""

from __future__ import annotations

import base64
import hashlib
import logging
import os

logger = logging.getLogger(__name__)


def _key_bytes(vault_key: str) -> bytes:
    """Return a 32-byte AES key derived from the vault_key config string."""
    try:
        raw = base64.b64decode(vault_key + "==")
        if len(raw) == 32:
            return raw
    except Exception:
        pass
    return hashlib.sha256(vault_key.encode()).digest()


class VaultService:
    """AES-256-GCM encrypt / decrypt for credential secrets."""

    def __init__(self, vault_key: str) -> None:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM

        self._aesgcm = AESGCM(_key_bytes(vault_key))

    def encrypt(self, plaintext: str) -> str:
        """Encrypt *plaintext* and return a base64-encoded token (nonce + ciphertext)."""
        nonce = os.urandom(12)
        ct = self._aesgcm.encrypt(nonce, plaintext.encode(), None)
        return base64.b64encode(nonce + ct).decode()

    def decrypt(self, token: str) -> str:
        """Decrypt a token produced by :meth:`encrypt` and return plaintext."""
        data = base64.b64decode(token + "==")
        nonce, ct = data[:12], data[12:]
        return self._aesgcm.decrypt(nonce, ct, None).decode()


_vault: VaultService | None = None


def get_vault() -> VaultService:
    """Return the module-level VaultService singleton (lazy-initialised)."""
    global _vault
    if _vault is None:
        from server.config import settings

        _vault = VaultService(settings.vault_key)
        logger.debug("VaultService initialised.", extra={"event": "vault_init"})
    return _vault
