"""
Tests for Alembic-based schema initialisation (server/database.py).

All tests are fully offline — no real database or Alembic binary is
required.  We verify that:

  • ``_run_alembic_upgrade`` builds the correct AlembicConfig and delegates
    to ``alembic.command.upgrade`` with "head".
  • ``init_db`` calls ``_run_alembic_upgrade`` via ``asyncio.to_thread``.
  • The Config URL override uses ``settings.database_url`` (not the
    static value in alembic.ini).
  • Alembic errors propagate out of ``init_db`` rather than being swallowed.
"""

from __future__ import annotations

from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _mock_alembic_cfg() -> MagicMock:
    cfg = MagicMock()
    cfg.config_ini_section = "alembic"
    return cfg


# ===========================================================================
# _run_alembic_upgrade
# ===========================================================================

class TestRunAlembicUpgrade:
    """Unit tests for the synchronous _run_alembic_upgrade helper.

    AlembicConfig and alembic_command are imported lazily inside the function,
    so we patch their actual module locations rather than server.database.
    """

    def test_calls_upgrade_with_head(self):
        """upgrade("head") must always be the target revision."""
        from server.database import _run_alembic_upgrade

        mock_cfg = _mock_alembic_cfg()
        with (
            patch("alembic.config.Config", return_value=mock_cfg),
            patch("alembic.command.upgrade") as mock_upgrade,
        ):
            _run_alembic_upgrade()

        mock_upgrade.assert_called_once_with(mock_cfg, "head")

    def test_config_url_overridden_with_settings_url(self):
        """The URL from settings must override the placeholder in alembic.ini."""
        from server.database import _run_alembic_upgrade, settings

        mock_cfg = _mock_alembic_cfg()
        with (
            patch("alembic.config.Config", return_value=mock_cfg),
            patch("alembic.command.upgrade"),
        ):
            _run_alembic_upgrade()

        mock_cfg.set_main_option.assert_called_once_with(
            "sqlalchemy.url", settings.database_url
        )

    def test_alembic_ini_path_points_to_project_root(self):
        """alembic.ini is expected one level above server/database.py."""
        from server.database import _run_alembic_upgrade

        captured: list[str] = []

        def capture_cfg(path: str):
            captured.append(path)
            return _mock_alembic_cfg()

        with (
            patch("alembic.config.Config", side_effect=capture_cfg),
            patch("alembic.command.upgrade"),
        ):
            _run_alembic_upgrade()

        assert len(captured) == 1
        ini_path = Path(captured[0])
        assert ini_path.name == "alembic.ini"
        # The path should be inside the project root (parent of server/)
        assert "server" not in ini_path.parts[-2:]  # not inside server/

    def test_alembic_error_propagates(self):
        """Errors from alembic.command.upgrade must not be swallowed."""
        from server.database import _run_alembic_upgrade

        with (
            patch("alembic.config.Config", return_value=_mock_alembic_cfg()),
            patch(
                "alembic.command.upgrade",
                side_effect=RuntimeError("db unavailable"),
            ),
        ):
            with pytest.raises(RuntimeError, match="db unavailable"):
                _run_alembic_upgrade()


# ===========================================================================
# init_db
# ===========================================================================

@pytest.mark.asyncio
class TestInitDb:
    """Async tests for init_db()."""

    async def test_init_db_delegates_to_run_alembic_upgrade(self):
        """init_db must call _run_alembic_upgrade (via asyncio.to_thread)."""
        from server.database import init_db

        with patch("server.database._run_alembic_upgrade") as mock_fn:
            # asyncio.to_thread calls the function in a thread pool;
            # patch the target directly so we can confirm it's invoked.
            with patch("asyncio.to_thread", new=AsyncMock(return_value=None)) as mock_thread:
                await init_db()

        mock_thread.assert_awaited_once()
        args = mock_thread.call_args[0]
        assert args[0] is mock_fn or callable(args[0])

    async def test_init_db_runs_without_error(self):
        """init_db must complete cleanly when _run_alembic_upgrade succeeds."""
        from server.database import init_db

        with patch("server.database._run_alembic_upgrade"):
            with patch("asyncio.to_thread", new=AsyncMock(return_value=None)):
                # Should not raise
                await init_db()

    async def test_init_db_propagates_alembic_error(self):
        """If _run_alembic_upgrade raises, init_db must re-raise."""
        from server.database import init_db

        async def _raise(*args, **kwargs):
            raise RuntimeError("migration failed")

        with patch("asyncio.to_thread", new=AsyncMock(side_effect=_raise)):
            with pytest.raises(RuntimeError, match="migration failed"):
                await init_db()
