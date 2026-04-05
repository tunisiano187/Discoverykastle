"""Tests for the version service."""

from __future__ import annotations

import pytest

from server.services.version import (
    MINIMUM_AGENT_VERSION,
    _is_newer,
    agent_needs_update,
    current_version,
)


class TestIsNewer:
    def test_newer_major(self) -> None:
        assert _is_newer("2.0.0", "1.0.0") is True

    def test_newer_minor(self) -> None:
        assert _is_newer("1.1.0", "1.0.0") is True

    def test_newer_patch(self) -> None:
        assert _is_newer("1.0.1", "1.0.0") is True

    def test_same_version(self) -> None:
        assert _is_newer("1.0.0", "1.0.0") is False

    def test_older_version(self) -> None:
        assert _is_newer("0.9.0", "1.0.0") is False

    def test_v_prefix_stripped(self) -> None:
        assert _is_newer("v2.0.0", "1.0.0") is True

    def test_prerelease_suffix_stripped(self) -> None:
        assert _is_newer("1.0.1-beta", "1.0.0") is True


class TestAgentNeedsUpdate:
    def test_none_version_no_update(self) -> None:
        assert agent_needs_update(None) is False

    def test_empty_version_no_update(self) -> None:
        assert agent_needs_update("") is False

    def test_old_agent_needs_update(self) -> None:
        # If minimum is "0.1.0" and agent reports "0.0.1", it needs update
        # Force minimum to something higher than "0.0.1"
        import server.services.version as vsvc
        original = vsvc.MINIMUM_AGENT_VERSION
        vsvc.MINIMUM_AGENT_VERSION = "0.2.0"  # type: ignore[attr-defined]
        try:
            assert agent_needs_update("0.1.0") is True
        finally:
            vsvc.MINIMUM_AGENT_VERSION = original  # type: ignore[attr-defined]

    def test_current_version_no_update(self) -> None:
        assert agent_needs_update(MINIMUM_AGENT_VERSION) is False

    def test_newer_agent_no_update(self) -> None:
        assert agent_needs_update("99.0.0") is False


class TestCurrentVersion:
    def test_returns_string(self) -> None:
        v = current_version()
        assert isinstance(v, str)
        assert len(v) > 0
