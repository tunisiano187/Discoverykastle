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


# ---------------------------------------------------------------------------
# Report generator
# ---------------------------------------------------------------------------

class TestReportGenerator:
    def _make_client(self, data_map: dict):
        from server.cli.main import APIClient
        client = APIClient("https://dk.example.com", "tok", verify_tls=False)

        def fake_get(path: str):
            for key, val in data_map.items():
                if key in path:
                    return val
            return []

        client.get = fake_get  # type: ignore[method-assign]
        return client

    def _run_report(self, client, **kwargs):
        import argparse
        from server.cli.main import cmd_report
        args = argparse.Namespace(output=None, limit=200, **kwargs)
        return cmd_report(client, args)

    def test_report_contains_section_headers(self, capsys) -> None:
        client = self._make_client({
            "/api/v1/version": {"version": "0.1.0"},
            "hosts": [{"ip_address": "10.0.0.1", "fqdn": "web01", "os": "Ubuntu", "last_seen": "2024-01-15"}],
            "networks": [{"cidr": "10.0.0.0/8", "ip_class": "private", "domain_name": None, "scan_authorized": True}],
            "vulns/summary": {"total": 3, "by_severity": {"critical": 1, "high": 2, "medium": 0, "low": 0}},
            "vulns": [],
            "agents": [],
            "alerts": [],
            "devices": [],
        })
        self._run_report(client)
        out, _ = capsys.readouterr()
        assert "# Infrastructure Report" in out
        assert "## Networks" in out
        assert "## Hosts" in out
        assert "## Critical & High Vulnerabilities" in out
        assert "## Agents" in out

    def test_report_summary_counts(self, capsys) -> None:
        client = self._make_client({
            "/api/v1/version": {"version": "0.1.0"},
            "hosts": [{"ip_address": "10.0.0.1"}, {"ip_address": "10.0.0.2"}],
            "networks": [{"cidr": "10.0.0.0/8", "ip_class": "private"}],
            "vulns/summary": {"total": 5, "by_severity": {"critical": 2, "high": 3}},
            "vulns": [],
            "agents": [{"status": "online"}, {"status": "offline"}],
            "alerts": [],
            "devices": [],
        })
        self._run_report(client)
        out, _ = capsys.readouterr()
        assert "| Hosts discovered | 2 |" in out
        assert "| Networks | 1 |" in out
        assert "| &nbsp;&nbsp;Critical | 2 |" in out

    def test_report_writes_to_file(self, tmp_path) -> None:
        from server.cli.main import cmd_report
        import argparse

        outfile = tmp_path / "report.md"
        client = self._make_client({
            "/api/v1/version": {"version": "0.1.0"},
            "hosts": [],
            "networks": [],
            "vulns/summary": {},
            "vulns": [],
            "agents": [],
            "alerts": [],
            "devices": [],
        })
        args = argparse.Namespace(output=str(outfile), limit=200)
        cmd_report(client, args)
        assert outfile.exists()
        content = outfile.read_text()
        assert "# Infrastructure Report" in content

    def test_md_table_empty(self) -> None:
        from server.cli.main import _md_table
        assert "_None_" in _md_table([], ["a", "b"])

    def test_md_table_header_formatted(self) -> None:
        from server.cli.main import _md_table
        result = _md_table([{"ip_address": "1.2.3.4"}], ["ip_address"])
        assert "Ip Address" in result
        assert "1.2.3.4" in result

    def test_report_command_in_parser(self) -> None:
        from server.cli.main import _build_parser
        args = _build_parser().parse_args(["report"])
        assert args.command == "report"
        assert args.limit == 200

    def test_report_output_flag(self) -> None:
        from server.cli.main import _build_parser
        args = _build_parser().parse_args(["report", "--output", "out.md"])
        assert args.output == "out.md"
