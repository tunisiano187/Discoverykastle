"""
Unit tests for server/cli/main.py (dkctl).

Tests the pure-logic helpers — no live server required.
"""
from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest


# ---------------------------------------------------------------------------
# _resolve — config priority chain
# ---------------------------------------------------------------------------

class TestResolve:
    def _resolve(self, cli_val, env_var, file_key, file_cfg):
        from server.cli.main import _resolve
        return _resolve(cli_val, env_var, file_key, file_cfg)

    def test_cli_takes_priority_over_env(self) -> None:
        with patch.dict("os.environ", {"MY_VAR": "from-env"}):
            assert self._resolve("from-cli", "MY_VAR", "key", {}) == "from-cli"

    def test_env_takes_priority_over_file(self) -> None:
        with patch.dict("os.environ", {"MY_VAR": "from-env"}):
            assert self._resolve(None, "MY_VAR", "key", {"key": "from-file"}) == "from-env"

    def test_file_used_when_no_cli_no_env(self) -> None:
        with patch.dict("os.environ", {}, clear=False):
            # make sure the env var is absent
            env = {k: v for k, v in __import__("os").environ.items() if k != "MY_VAR"}
            with patch.dict("os.environ", env, clear=True):
                assert self._resolve(None, "MY_VAR", "key", {"key": "from-file"}) == "from-file"

    def test_empty_string_when_nothing_set(self) -> None:
        with patch.dict("os.environ", {}, clear=True):
            assert self._resolve(None, "NONEXISTENT_VAR_XYZ", "key", {}) == ""


# ---------------------------------------------------------------------------
# APIClient._request — error handling
# ---------------------------------------------------------------------------

class TestAPIClient:
    def _client(self):
        from server.cli.main import APIClient
        return APIClient("https://dk.example.com", "test-token", verify_tls=False)

    def test_http_error_calls_die(self) -> None:
        import urllib.error
        from server.cli.main import APIClient

        client = APIClient("https://dk.example.com", "tok", verify_tls=False)
        http_err = urllib.error.HTTPError(
            url="https://dk.example.com/api/v1/version",
            code=401,
            msg="Unauthorized",
            hdrs=MagicMock(),
            fp=MagicMock(read=lambda: b'{"detail": "Not authenticated"}'),
        )
        with patch("urllib.request.urlopen", side_effect=http_err), \
             pytest.raises(SystemExit):
            client.get("/api/v1/version")

    def test_url_error_calls_die(self) -> None:
        import urllib.error
        from server.cli.main import APIClient

        client = APIClient("https://unreachable.invalid", "tok", verify_tls=False)
        with patch("urllib.request.urlopen", side_effect=urllib.error.URLError("Name not resolved")), \
             pytest.raises(SystemExit):
            client.get("/api/v1/version")

    def test_bearer_token_in_headers(self) -> None:
        from server.cli.main import APIClient
        import urllib.request as ur

        client = APIClient("https://dk.example.com", "my-secret-token", verify_tls=False)
        captured: list[ur.Request] = []

        def fake_urlopen(req, context=None, timeout=None):
            captured.append(req)
            resp = MagicMock()
            resp.__enter__ = lambda s: s
            resp.__exit__ = MagicMock(return_value=False)
            resp.read.return_value = b'{"version": "0.1.0"}'
            return resp

        with patch("urllib.request.urlopen", side_effect=fake_urlopen):
            client.get("/api/v1/version")

        assert captured[0].get_header("Authorization") == "Bearer my-secret-token"


# ---------------------------------------------------------------------------
# _print_table
# ---------------------------------------------------------------------------

class TestPrintTable:
    def test_empty_rows(self, capsys) -> None:
        from server.cli.main import _print_table
        _print_table([], ["id", "name"])
        out, _ = capsys.readouterr()
        assert "no results" in out

    def test_single_row(self, capsys) -> None:
        from server.cli.main import _print_table
        _print_table([{"id": "abc", "name": "web01"}], ["id", "name"])
        out, _ = capsys.readouterr()
        assert "abc" in out
        assert "web01" in out

    def test_header_row_present(self, capsys) -> None:
        from server.cli.main import _print_table
        _print_table([{"cidr": "10.0.0.0/8", "ip_class": "private"}], ["cidr", "ip_class"])
        out, _ = capsys.readouterr()
        lines = out.strip().splitlines()
        assert "CIDR" in lines[0]
        assert "IP_CLASS" in lines[0]

    def test_missing_column_value_defaults_to_empty(self, capsys) -> None:
        from server.cli.main import _print_table
        _print_table([{"id": "1"}], ["id", "missing_col"])
        out, _ = capsys.readouterr()
        assert "1" in out  # should not raise


# ---------------------------------------------------------------------------
# Argument parser — basic smoke tests
# ---------------------------------------------------------------------------

class TestParser:
    def _parse(self, *args):
        from server.cli.main import _build_parser
        return _build_parser().parse_args(list(args))

    def test_status_command(self) -> None:
        args = self._parse("status")
        assert args.command == "status"

    def test_agents_list(self) -> None:
        args = self._parse("agents", "list")
        assert args.command == "agents"
        assert args.agents_cmd == "list"

    def test_agents_token(self) -> None:
        args = self._parse("agents", "token")
        assert args.agents_cmd == "token"

    def test_vulns_list_with_severity(self) -> None:
        args = self._parse("vulns", "list", "--severity", "critical")
        assert args.vulns_cmd == "list"
        assert args.severity == "critical"

    def test_json_flag(self) -> None:
        args = self._parse("--json", "status")
        assert args.json is True

    def test_no_verify_tls_flag(self) -> None:
        args = self._parse("--no-verify-tls", "status")
        assert args.no_verify_tls is True

    def test_hosts_list_default_limit(self) -> None:
        args = self._parse("hosts", "list")
        assert args.limit == 50

    def test_hosts_list_custom_limit(self) -> None:
        args = self._parse("hosts", "list", "--limit", "10")
        assert args.limit == 10

    def test_missing_command_exits(self) -> None:
        from server.cli.main import _build_parser
        with pytest.raises(SystemExit):
            _build_parser().parse_args([])


# ---------------------------------------------------------------------------
# main() — missing config exits
# ---------------------------------------------------------------------------

class TestMainConfigValidation:
    def test_missing_url_exits(self) -> None:
        from server.cli.main import main
        with patch("sys.argv", ["dkctl", "status"]), \
             patch.dict("os.environ", {}, clear=True), \
             patch("server.cli.main._load_file_config", return_value={}), \
             pytest.raises(SystemExit):
            main()

    def test_missing_token_exits(self) -> None:
        from server.cli.main import main
        with patch("sys.argv", ["dkctl", "--url", "https://dk.example.com", "status"]), \
             patch.dict("os.environ", {}, clear=True), \
             patch("server.cli.main._load_file_config", return_value={}), \
             pytest.raises(SystemExit):
            main()
