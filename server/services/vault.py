"""
Credential Vault — AES-256-GCM encrypt/decrypt for stored credentials.

Encryption:
  - Key: DKASTLE_VAULT_KEY (base64-encoded 32-byte key, generated at first run)
  - Algorithm: AES-256-GCM (authenticated encryption)
  - Nonce: random 12 bytes per encryption operation
  - Stored blob: base64(nonce[12] + tag[16] + ciphertext)

The key is never stored in the DB.  Rotating the key requires re-encrypting
all stored credentials (out of scope for this module — use a migration script).
"""

from __future__ import annotations

import base64
import json
import os


class VaultError(Exception):
    """Raised when vault encryption/decryption fails."""


def _derive_key() -> bytes:
    """
    Return the 32-byte AES-256 key from the DKASTLE_VAULT_KEY setting.

    Accepts both raw base64 and hex-encoded keys.
    Raises VaultError if the key is missing or malformed.
    """
    from server.config import settings

    raw = settings.vault_key
    if not raw or raw == "changeme-base64-32-bytes":
        raise VaultError(
            "DKASTLE_VAULT_KEY is not set. "
            "Generate a key with: python -c \"import secrets,base64; "
            "print(base64.b64encode(secrets.token_bytes(32)).decode())\""
        )
    # Try base64 first; fall back to hex if base64 gives the wrong length
    # (a 64-char hex string is valid base64 but decodes to 48 bytes, not 32).
    key: bytes | None = None
    try:
        candidate = base64.b64decode(raw)
        if len(candidate) == 32:
            key = candidate
    except Exception:
        pass

    if key is None:
        try:
            candidate = bytes.fromhex(raw)
            if len(candidate) == 32:
                key = candidate
        except Exception:
            pass

    if key is None:
        raise VaultError("DKASTLE_VAULT_KEY must be base64 or hex-encoded 32 bytes")
    return key


def encrypt(plaintext: dict) -> str:
    """
    Encrypt a credential dict and return a base64-encoded ciphertext blob.

    Args:
        plaintext: Dict containing the credential fields (e.g. username, password).

    Returns:
        base64(nonce[12] + tag[16] + ciphertext)
    """
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    key = _derive_key()
    nonce = os.urandom(12)
    data = json.dumps(plaintext).encode()
    aesgcm = AESGCM(key)
    # AESGCM.encrypt returns ciphertext + tag (tag is appended)
    ct_with_tag = aesgcm.encrypt(nonce, data, None)
    blob = nonce + ct_with_tag
    return base64.b64encode(blob).decode()


def decrypt(ciphertext_b64: str) -> dict:
    """
    Decrypt a ciphertext blob and return the original credential dict.

    Args:
        ciphertext_b64: base64(nonce[12] + tag[16] + ciphertext)

    Returns:
        The decrypted credential dict.

    Raises:
        VaultError: If decryption fails (wrong key, tampered data, etc.)
    """
    key = _derive_key()
    try:
        blob = base64.b64decode(ciphertext_b64)
    except Exception as exc:
        raise VaultError(f"Decryption failed: {exc}") from exc

    if len(blob) < 28:  # nonce(12) + tag(16) minimum
        raise VaultError("Ciphertext blob is too short")

    nonce = blob[:12]
    ct_with_tag = blob[12:]

    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.exceptions import InvalidTag

    try:
        aesgcm = AESGCM(key)
        plaintext = aesgcm.decrypt(nonce, ct_with_tag, None)
        return json.loads(plaintext)
    except InvalidTag:
        raise VaultError("Decryption failed: invalid tag (wrong key or tampered data)")
    except Exception as exc:
        raise VaultError(f"Decryption failed: {exc}") from exc
