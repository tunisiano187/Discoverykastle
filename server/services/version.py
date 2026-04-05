"""
Version management — server version info and update checking.

Provides:
  - current_version()     → version string from package metadata
  - check_for_updates()   → query GitHub releases for a newer tag
  - minimum_agent_version → the oldest agent version the server accepts
                            before demanding an update
"""

from __future__ import annotations

import logging
from typing import NamedTuple

import httpx

logger = logging.getLogger(__name__)

# Bump this when a breaking change requires all agents to update.
MINIMUM_AGENT_VERSION: str = "0.1.0"

# GitHub releases API endpoint for the project
_GITHUB_RELEASES_URL = (
    "https://api.github.com/repos/tunisiano187/Discoverykastle/releases/latest"
)


class VersionInfo(NamedTuple):
    current: str
    latest: str | None
    update_available: bool


def current_version() -> str:
    """Return the installed server package version."""
    try:
        from importlib.metadata import version
        return version("discoverykastle-server")
    except Exception:
        return "0.1.0-dev"


async def check_for_updates(timeout: float = 5.0) -> VersionInfo:
    """
    Query GitHub releases for the latest tag and compare to the installed version.

    Args:
        timeout: HTTP request timeout in seconds.

    Returns:
        VersionInfo with ``current``, ``latest``, and ``update_available`` fields.
        ``latest`` is None when the check fails (e.g. no network).
    """
    cur = current_version()
    try:
        async with httpx.AsyncClient(timeout=timeout) as client:
            resp = await client.get(
                _GITHUB_RELEASES_URL,
                headers={"Accept": "application/vnd.github.v3+json"},
                follow_redirects=True,
            )
            resp.raise_for_status()
            data = resp.json()
            tag: str = data.get("tag_name", "").lstrip("v")
            if not tag:
                return VersionInfo(current=cur, latest=None, update_available=False)
            newer = _is_newer(tag, cur)
            return VersionInfo(current=cur, latest=tag, update_available=newer)
    except Exception as exc:
        logger.debug("Version check failed: %s", exc)
        return VersionInfo(current=cur, latest=None, update_available=False)


def agent_needs_update(agent_version: str | None) -> bool:
    """
    Return True if ``agent_version`` is older than ``MINIMUM_AGENT_VERSION``.

    Args:
        agent_version: Version string reported by the agent (may be None if unknown).

    Returns:
        True if the agent should update before proceeding.
    """
    if not agent_version:
        return False  # unknown version — don't force update
    try:
        return _is_newer(MINIMUM_AGENT_VERSION, agent_version)
    except Exception:
        return False


# ------------------------------------------------------------------
# Internal
# ------------------------------------------------------------------

def _is_newer(candidate: str, current: str) -> bool:
    """Return True if ``candidate`` version is strictly newer than ``current``."""
    try:
        # Strip leading 'v' and any pre-release suffix for comparison
        def _parse(v: str) -> tuple[int, ...]:
            clean = v.lstrip("v").split("-")[0]
            return tuple(int(x) for x in clean.split("."))

        return _parse(candidate) > _parse(current)
    except Exception:
        return False
