"""
Agent auto-deployment — SSH into a discovered host and install the Discoverykastle agent.

Deployment flow:
  1. Fetch the host from the DB.
  2. Look up an SSH credential for the host from the vault.
  3. Open an SSH connection (paramiko).
  4. Upload or download the agent installer and run it.
  5. Return a DeployResult with success/failure details.

The actual SSH I/O is isolated in _ssh_deploy() so tests can mock it cleanly.
paramiko is imported lazily so the module loads without it installed.
"""

from __future__ import annotations

import logging
import uuid
from dataclasses import dataclass, field
from typing import Any

from server.models.credential import Credential
from server.models.host import Host
from server.services.vault import VaultError, decrypt

logger = logging.getLogger(__name__)

# Default agent installer URL (overridable via settings)
_DEFAULT_INSTALLER_URL = (
    "https://raw.githubusercontent.com/tunisiano187/Discoverykastle/main/agent/install.sh"
)

# Shell script that downloads and runs the installer
_INSTALL_SCRIPT = """\
set -e
curl -fsSL {url} -o /tmp/dkastle_install.sh
chmod +x /tmp/dkastle_install.sh
DKASTLE_SERVER={server_url} /tmp/dkastle_install.sh
"""


@dataclass
class DeployResult:
    host_id: uuid.UUID
    success: bool
    message: str
    stdout: str = ""
    stderr: str = ""
    exit_code: int = -1
    errors: list[str] = field(default_factory=list)


class DeployError(Exception):
    """Raised when deployment fails before the SSH command runs."""


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------


async def deploy_agent(
    db: Any,
    host_id: uuid.UUID,
    credential_id: uuid.UUID,
    *,
    server_url: str = "",
    installer_url: str = _DEFAULT_INSTALLER_URL,
    port: int = 22,
    timeout: int = 60,
) -> DeployResult:
    """
    Deploy the Discoverykastle agent on *host_id* via SSH.

    Args:
        db: Active async SQLAlchemy session.
        host_id: UUID of the Host record to deploy onto.
        credential_id: UUID of the Credential (must be type ``ssh``) to use.
        server_url: URL the installed agent should use to reach this server.
        installer_url: URL of the install script (default: GitHub main branch).
        port: SSH port (default 22).
        timeout: SSH connection timeout in seconds.

    Returns:
        DeployResult with success/failure details.
    """
    # Fetch host
    host = await db.get(Host, host_id)
    if host is None:
        raise DeployError(f"Host {host_id} not found")

    target_ip = _pick_ip(host)
    if not target_ip:
        raise DeployError(f"Host {host_id} has no usable IP address")

    # Fetch credential
    cred_row = await db.get(Credential, credential_id)
    if cred_row is None:
        raise DeployError(f"Credential {credential_id} not found")
    if cred_row.credential_type not in ("ssh", "ssh_key"):
        raise DeployError(
            f"Credential type '{cred_row.credential_type}' is not supported for SSH deployment"
        )

    try:
        secret = decrypt(cred_row.ciphertext)
    except VaultError as exc:
        raise DeployError(f"Failed to decrypt credential: {exc}") from exc

    username = secret.get("username", "root")
    password = secret.get("password")
    private_key_pem = secret.get("private_key")

    script = _INSTALL_SCRIPT.format(url=installer_url, server_url=server_url or target_ip)

    try:
        stdout, stderr, exit_code = _ssh_deploy(
            host=target_ip,
            port=port,
            username=username,
            password=password,
            private_key_pem=private_key_pem,
            script=script,
            timeout=timeout,
        )
    except Exception as exc:
        logger.warning("SSH deploy failed on %s: %s", target_ip, exc)
        return DeployResult(
            host_id=host_id,
            success=False,
            message=f"SSH error: {exc}",
            errors=[str(exc)],
        )

    success = exit_code == 0
    message = "Agent installed successfully" if success else f"Installer exited with code {exit_code}"
    logger.info(
        "Deploy on %s finished: success=%s exit_code=%d",
        target_ip,
        success,
        exit_code,
    )
    return DeployResult(
        host_id=host_id,
        success=success,
        message=message,
        stdout=stdout,
        stderr=stderr,
        exit_code=exit_code,
    )


# ---------------------------------------------------------------------------
# SSH execution (isolated for easy mocking)
# ---------------------------------------------------------------------------


def _ssh_deploy(
    *,
    host: str,
    port: int,
    username: str,
    password: str | None,
    private_key_pem: str | None,
    script: str,
    timeout: int,
) -> tuple[str, str, int]:
    """
    Open an SSH connection and run *script*.

    Returns:
        (stdout, stderr, exit_code)

    Raises:
        Exception: Any paramiko / network error.
    """
    import io

    import paramiko

    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    connect_kwargs: dict[str, Any] = {
        "hostname": host,
        "port": port,
        "username": username,
        "timeout": timeout,
        "allow_agent": False,
        "look_for_keys": False,
    }
    if private_key_pem:
        pkey = paramiko.RSAKey.from_private_key(io.StringIO(private_key_pem))
        connect_kwargs["pkey"] = pkey
    elif password:
        connect_kwargs["password"] = password
    else:
        raise ValueError("Either password or private_key must be provided in the credential")

    client.connect(**connect_kwargs)
    try:
        _stdin, _stdout, _stderr = client.exec_command(f"bash -c {_shell_quote(script)}")
        exit_code = _stdout.channel.recv_exit_status()
        stdout = _stdout.read().decode(errors="replace")
        stderr = _stderr.read().decode(errors="replace")
        return stdout, stderr, exit_code
    finally:
        client.close()


def _pick_ip(host: Any) -> str | None:
    """Return the first non-loopback IP from the host record."""
    ips = getattr(host, "ip_addresses", None) or []
    for ip in ips:
        if not ip.startswith("127."):
            return ip
    return None


def _shell_quote(s: str) -> str:
    """Wrap a multi-line script in single quotes for safe exec_command usage."""
    return "'" + s.replace("'", "'\\''") + "'"
