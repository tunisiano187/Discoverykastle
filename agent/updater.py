"""
DK Agent — self-update logic.

Called when the server signals ``agent_update_required: true`` in the
heartbeat response.  Runs the pip upgrade in a subprocess so it can replace
the running package's files while the agent is still alive, then restarts
the agent process to load the new code.

Supported scenarios
-------------------
* Installed via ``pip install discoverykastle-agent`` (PyPI / local wheel)
* Installed via the install.sh / install.ps1 scripts (venv in install dir)

The update target defaults to "discoverykastle-agent" (latest on PyPI).
A specific pinned version can be supplied by the server via the heartbeat
response field ``agent_update_target`` (e.g. ``"discoverykastle-agent==0.2.0"``).
"""

from __future__ import annotations

import logging
import os
import subprocess
import sys

logger = logging.getLogger(__name__)


def self_update(update_target: str | None = None) -> None:
    """
    Upgrade the agent package and restart the process.

    Args:
        update_target: Pip install target string.  Defaults to ``"discoverykastle-agent"``,
                       which installs the latest published version.

    Raises:
        RuntimeError: If the pip upgrade subprocess exits with a non-zero code.
    """
    target = update_target or "discoverykastle-agent"
    logger.info("Starting self-update — pip install --upgrade %s", target)

    result = subprocess.run(
        [sys.executable, "-m", "pip", "install", "--upgrade", target],
        capture_output=True,
        text=True,
    )

    if result.returncode != 0:
        logger.error(
            "Self-update failed (exit %d):\nstdout: %s\nstderr: %s",
            result.returncode,
            result.stdout,
            result.stderr,
        )
        raise RuntimeError(f"pip upgrade failed with exit code {result.returncode}")

    logger.info("Package upgrade complete. Restarting agent process…")
    _restart()


def _restart() -> None:
    """
    Re-exec the current process to load the updated code.

    Uses ``os.execv`` on POSIX so the PID is preserved (systemd / Windows SCM
    are watching the original PID).  Falls back to subprocess.Popen + sys.exit
    on Windows where os.execv is not available.
    """
    args = [sys.executable] + sys.argv
    logger.info("Re-exec: %s", " ".join(args))
    try:
        os.execv(sys.executable, args)
    except AttributeError:
        # Windows — execv not available; start a new process and exit cleanly
        import subprocess as sp
        sp.Popen(args)
        sys.exit(0)
