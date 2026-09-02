"""
Tests for VS Code Copilot `mcp_<server>_<tool>` resolution + sanctioning in
copilot/hooks/unbound.py. Tool names are real ones from VS Code chat transcripts;
server keys mirror a real VS Code mcp.json.
"""

import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from tests.conftest import tool_module

unbound = tool_module("copilot/hooks")
# Real VS Code mcp.json server keys + minimal configs.
CONFIG = {
    "servers": {
        "github": {"url": "https://api.githubcopilot.com/mcp/"},
        "io.github.github/github-mcp-server": {"url": "https://api.githubcopilot.com/mcp/"},
        "microsoft/markitdown": {"command": "uvx", "args": ["markitdown-mcp@0.0.1a4"]},
        "oraios/serena": {"command": "uvx", "args": ["serena@latest"]},
        "io.github.upstash/context7": {"command": "npx", "args": ["@upstash/context7-mcp"]},
        "playwright": {"command": "npx", "args": ["@playwright/mcp@latest"]},
        "postgres": {"command": "npx", "args": ["pg-mcp"]},
    }
}

GH_GROUP = "https://api.githubcopilot.com/mcp/"


def _read_fixture_servers():
    # Build the same shape read_copilot_mcp_servers() returns, from CONFIG.
    out = {}
    for name, srv in CONFIG["servers"].items():
        out[name] = unbound._extract_mcp_server_fields(srv) or {}
    return out


class TestResolveVscodeMcp(unittest.TestCase):
    def setUp(self):
        self.servers = _read_fixture_servers()

    def test_truncated_server_name_resolves(self):
        # io.github.github/github-mcp-server surfaces as the truncated
        # `github_mcp_se`; must still map back to the full server key.
        srv, tool, cfg = unbound._resolve_vscode_mcp(
            "mcp_github_mcp_se_search_repositories", self.servers)
        self.assertEqual(srv, "io.github.github/github-mcp-server")
        self.assertEqual(tool, "search_repositories")
        self.assertEqual(cfg.get("url"), GH_GROUP)

    def test_last_path_segment_servers_resolve(self):
        cases = {
            "mcp_markitdown_convert_to_markdown": ("microsoft/markitdown", "convert_to_markdown"),
            "mcp_serena_find_declaration": ("oraios/serena", "find_declaration"),
            "mcp_context7_resolve_library_id": ("io.github.upstash/context7", "resolve_library_id"),
            "mcp_playwright_browser_navigate": ("playwright", "browser_navigate"),
        }
        for raw, (exp_srv, exp_tool) in cases.items():
            srv, tool, _cfg = unbound._resolve_vscode_mcp(raw, self.servers)
            self.assertEqual(srv, exp_srv, raw)
            self.assertEqual(tool, exp_tool, raw)

    def test_longer_server_portion_wins_over_short_prefix(self):
        # Both `github` and `github-mcp-server` are configured. A github-mcp-server
        # call must not be mis-attributed to the bare `github` server.
        srv, _tool, _cfg = unbound._resolve_vscode_mcp(
            "mcp_github_mcp_se_list_commits", self.servers)
        self.assertEqual(srv, "io.github.github/github-mcp-server")

    def test_bare_github_resolves_to_bare_server(self):
        srv, tool, _cfg = unbound._resolve_vscode_mcp(
            "mcp_github_get_me", self.servers)
        self.assertEqual(srv, "github")
        self.assertEqual(tool, "get_me")

    def test_prefix_matching_is_case_insensitive(self):
        srv, tool, _cfg = unbound._resolve_vscode_mcp(
            "MCP_GITHUB_GET_ME", self.servers)
        self.assertEqual(srv, "github")
        self.assertEqual(tool, "GET_ME")

    def test_claude_double_underscore_form_is_not_handled_here(self):
        # mcp__ is the Claude/CLI form (gateway parses it); resolver ignores it.
        self.assertEqual(
            unbound._resolve_vscode_mcp("mcp__github__search", self.servers),
            (None, None, None))

    def test_ambiguous_truncated_prefix_is_unresolved(self):
        # Two configured servers whose names both start with the truncated token
        # `sup` and that have OPPOSITE sanction outcomes: the resolver must not
        # silently guess one — it returns unresolved so the call fails open/secure.
        servers = {"supabase": {"url": "https://safe/mcp"},
                   "superdanger": {"url": "https://danger/mcp"}}
        self.assertEqual(
            unbound._resolve_vscode_mcp("mcp_sup_run", servers),
            (None, None, None))

    def test_short_prefix_cannot_borrow_a_configured_server(self):
        self.assertEqual(
            unbound._resolve_vscode_mcp(
                "mcp_git_read_issue",
                {"github": {"url": "https://github.example/mcp"}},
            ),
            (None, None, None),
        )

    def test_full_name_disambiguates_overlapping_servers(self):
        # When the token carries the full server name, the overlap is resolved.
        servers = {"supabase": {"url": "https://safe/mcp"},
                   "superdanger": {"url": "https://danger/mcp"}}
        srv, tool, _cfg = unbound._resolve_vscode_mcp("mcp_supabase_run_query", servers)
        self.assertEqual(srv, "supabase")
        self.assertEqual(tool, "run_query")

    def test_overlapping_sibling_different_config_is_unresolved(self):
        # `linear` (exact) vs `linear_create_safe` (longer fuzzy) with DIFFERENT
        # configs: the longer fuzzy match for the wrong server must NOT out-rank the
        # exact match for the right one -> ambiguous -> unresolved (no mis-attribution,
        # so no sanction bypass and no false deny).
        servers = {"linear": {"url": "https://danger/mcp"},
                   "linear_create_safe": {"url": "https://safe/mcp"}}
        self.assertEqual(
            unbound._resolve_vscode_mcp("mcp_linear_create_issue", servers),
            (None, None, None))

    def test_same_config_overlap_still_resolves(self):
        # Two keys for the SAME underlying server (identical config) must NOT be
        # treated as ambiguous — resolution still works (github + hosted github).
        servers = {"github": {"url": "https://api.githubcopilot.com/mcp"},
                   "io.github.github/github-mcp-server": {"url": "https://api.githubcopilot.com/mcp"}}
        srv, tool, _cfg = unbound._resolve_vscode_mcp("mcp_github_mcp_se_search_repos", servers)
        self.assertEqual(srv, "io.github.github/github-mcp-server")
        self.assertEqual(tool, "search_repos")

    def test_non_mcp_and_unknown_return_none(self):
        self.assertEqual(
            unbound._resolve_vscode_mcp("run_in_terminal", self.servers),
            (None, None, None))
        self.assertEqual(
            unbound._resolve_vscode_mcp("mcp_unknownserver_do_thing", self.servers),
            (None, None, None))
        self.assertEqual(unbound.canonical_tool_name("mcpWithoutSeparator"), "")

    def test_configured_server_name_without_a_tool_is_not_an_mcp_call(self):
        self.assertEqual(
            unbound.detect_mcp_call("github", self.servers),
            (None, None, None))

    def test_double_separator_does_not_become_part_of_tool_name(self):
        servers = {
            "azure_devops": {"command": "npx", "args": ["azure-devops-mcp"]},
        }

        server, tool, config = unbound._resolve_vscode_mcp(
            "mcp_azure_devops__wit_work_item_link_write", servers
        )

        self.assertEqual(server, "azure_devops")
        self.assertEqual(tool, "wit_work_item_link_write")
        self.assertEqual(config, servers["azure_devops"])

    def test_builtin_github_resolves_without_local_config(self):
        self.assertEqual(
            unbound.resolve_copilot_mcp(
                "github-mcp-server-search_code", {}
            ),
            ("github-mcp-server", "search_code", {'additional_data': {'scope': 'copilot-builtin'}}),
        )

    def test_builtin_github_tagged_when_explicit_identity_matches(self):
        self.assertEqual(
            unbound.resolve_copilot_mcp(
                "github-mcp-server-search_code", {},
                server_name="github-mcp-server", tool_name="search_code",
            ),
            ("github-mcp-server", "search_code",
             {"additional_data": {"scope": "copilot-builtin"}}),
        )

    def test_fetch_and_time_are_not_builtins(self):
        for raw in ("fetch-fetch_url", "time-get_current_time"):
            with self.subTest(raw=raw):
                self.assertEqual(
                    unbound.resolve_copilot_mcp(raw, {}),
                    (None, None, None),
                )

    def test_configured_github_wins_over_builtin_shortcut(self):
        servers = {
            "github-mcp-server": {"url": "https://company.example/mcp"},
        }
        self.assertEqual(
            unbound.resolve_copilot_mcp(
                "github-mcp-server-search_code", servers
            ),
            (
                "github-mcp-server",
                "search_code",
                {"url": "https://company.example/mcp"},
            ),
        )

    def test_short_configured_prefix_does_not_steal_builtin_github(self):
        servers = {"github": {"url": "https://company.example/mcp"}}
        for explicit in (
            {},
            {"server_name": "github", "tool_name": "mcp-server-search_code"},
        ):
            with self.subTest(explicit=explicit):
                self.assertEqual(
                    unbound.resolve_copilot_mcp(
                        "github-mcp-server-search_code", servers, **explicit
                    ),
                    ("github-mcp-server", "search_code", {'additional_data': {'scope': 'copilot-builtin'}}),
                )

    def test_longer_configured_server_wins_over_builtin_prefix(self):
        config = {"command": "evil-mcp"}
        self.assertEqual(
            unbound.resolve_copilot_mcp(
                "github-mcp-server-evil-steal",
                {"github-mcp-server-evil": config},
            ),
            ("github-mcp-server-evil", "steal", config),
        )


def _gateway(sanctioned_groups):
    """Mirror preToolUseHandler: read mcp_server/mcp_tool, fingerprint the forwarded
    config (url or command+args), apply the org allow-list."""
    def gw(request_body, api_key):
        ptd = request_body.get("pre_tool_use_data", {}) or {}
        md = ptd.get("metadata", {}) or {}
        tn = ptd.get("tool_name", "") or ""
        srv, tool = md.get("mcp_server"), md.get("mcp_tool")
        if not (srv and tool):
            for pfx in ("mcp__", "MCP:"):
                if tn.startswith(pfx):
                    parts = tn[len(pfx):].split("__", 1)
                    srv = parts[0]
                    tool = parts[1] if len(parts) > 1 else ""
                    break
        if srv and tool:
            cfg = md.get("mcp_server_config") or {}
            cmd = cfg.get("command")
            # group by command + args (not bare command) so npx servers don't collapse
            grp = cfg.get("url") or (cmd and " ".join([cmd, *(cfg.get("args") or [])])) or srv
            applies = len(sanctioned_groups) > 0
            if applies and grp not in sanctioned_groups:
                return {"decision": "deny", "reason": "not sanctioned", "additionalContext": "x"}
            return {"decision": "allow"}
        return {"decision": "allow"}  # no MCP resolved -> no_policy -> allow
    return gw


class ProcessPreToolUseBase(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        cfg_path = Path(self._tmp.name) / ".vscode" / "mcp.json"
        cfg_path.parent.mkdir(parents=True, exist_ok=True)
        cfg_path.write_text(json.dumps(CONFIG))
        self._patchers = [
            patch.object(unbound, "_copilot_mcp_config_paths", lambda cwd=None, plugins=None: [cfg_path]),
            patch.object(unbound, "_plugin_mcp_config_paths", lambda home=None: []),
            patch.object(unbound, "load_policy_cache", lambda: None),
            patch.object(unbound, "get_recent_user_prompts_for_session", lambda *a, **k: []),
            patch.object(unbound, "get_session_start_model", lambda *a, **k: "auto"),
            patch.object(unbound, "_is_approval_retry", lambda *a, **k: False),
            patch.object(unbound, "report_error_to_gateway", lambda *a, **k: None),
        ]
        for p in self._patchers:
            p.start()
        self.cwd = self._tmp.name

    def tearDown(self):
        for p in self._patchers:
            p.stop()
        self._tmp.cleanup()

    def run_tool(self, raw_tool, sanctioned_groups, failure_action="allow"):
        event = {
            "hook_event_name": "PreToolUse",
            "tool_name": raw_tool,
            "tool_input": {"q": "x"},
            "cwd": self.cwd,
            "session_id": "sess",
        }
        with patch.object(unbound, "send_to_hook_api", _gateway(sanctioned_groups)), \
             patch.object(unbound, "_read_policy_cache_raw",
                          lambda: {"policy_check_failure_action": failure_action}):
            return unbound.process_pre_tool_use(event, "API_KEY")

    @staticmethod
    def is_block(ret):
        if not ret:
            return False
        pd = ret.get("permissionDecision") or (ret.get("hookSpecificOutput") or {}).get("permissionDecision")
        return pd == "deny"


class TestProcessPreToolUseVscode(ProcessPreToolUseBase):
    def test_unsanctioned_vscode_mcp_is_blocked(self):
        # GitHub MCP sanctioned; a serena call (unsanctioned) must be blocked.
        ret = self.run_tool("mcp_serena_find_declaration", {GH_GROUP})
        self.assertTrue(self.is_block(ret))

    def test_sanctioned_vscode_mcp_is_allowed(self):
        ret = self.run_tool("mcp_github_mcp_se_search_repositories", {GH_GROUP})
        self.assertFalse(self.is_block(ret))

    def test_empty_sanction_list_allows_all(self):
        # Default state (nothing sanctioned) must not over-block.
        ret = self.run_tool("mcp_serena_find_declaration", set())
        self.assertFalse(self.is_block(ret))

    def test_resolved_call_forwards_server_and_config_to_gateway(self):
        captured = {}

        def capturing_gw(request_body, api_key):
            captured["md"] = request_body["pre_tool_use_data"]["metadata"]
            return {"decision": "allow"}

        event = {
            "hook_event_name": "PreToolUse",
            "tool_name": "mcp_markitdown_convert_to_markdown",
            "tool_input": {}, "cwd": self.cwd, "session_id": "s",
        }
        with patch.object(unbound, "send_to_hook_api", capturing_gw):
            unbound.process_pre_tool_use(event, "K")
        self.assertEqual(captured["md"].get("mcp_server"), "microsoft/markitdown")
        self.assertEqual(captured["md"].get("mcp_tool"), "convert_to_markdown")
        self.assertEqual(captured["md"]["mcp_server_config"], {
            "command": "uvx",
            "args": ["markitdown-mcp@0.0.1a4"],
        })

    def test_explicit_mcp_identity_cannot_relabel_a_native_tool_name(self):
        captured = {}

        def capturing_gw(request_body, api_key):
            captured["pretool"] = request_body["pre_tool_use_data"]
            return {"decision": "allow"}

        event = {
            "hook_event_name": "PreToolUse",
            "tool_name": "read_file",
            "tool_input": {"path": "document"},
            "mcpServerName": "documents",
            "mcpToolName": "read_file",
            "cwd": self.cwd,
            "session_id": "s",
        }
        with patch.object(
            unbound,
            "read_copilot_mcp_servers",
            return_value={"documents": {"command": "documents-mcp"}},
        ), patch.object(unbound, "send_to_hook_api", capturing_gw):
            unbound.process_pre_tool_use(event, "K")

        self.assertEqual(captured["pretool"]["tool_name"], "Read")
        self.assertNotIn("mcp_server", captured["pretool"]["metadata"])

    def test_builtin_github_forwards_identity_without_local_config(self):
        captured = {}

        def capturing_gw(request_body, api_key):
            captured["request"] = request_body
            return {"decision": "allow"}

        event = {
            "hook_event_name": "PreToolUse",
            "tool_name": "github-mcp-server-search_code",
            "tool_input": {"query": "mcp"},
            "cwd": self.cwd,
            "session_id": "s",
        }
        with patch.object(unbound, "read_copilot_mcp_servers", return_value={}), \
             patch.object(unbound, "send_to_hook_api", capturing_gw):
            unbound.process_pre_tool_use(event, "K")

        pretool = captured["request"]["pre_tool_use_data"]
        self.assertEqual(pretool["tool_name"], "mcp__github-mcp-server__search_code")
        self.assertEqual(pretool["metadata"]["mcp_server"], "github-mcp-server")
        self.assertEqual(pretool["metadata"]["mcp_tool"], "search_code")
        self.assertEqual(
            pretool["metadata"]["mcp_server_config"],
            {"additional_data": {"scope": "copilot-builtin"}},
        )

    def test_unknown_server_dispatches_targeted_scan(self):
        event = {
            "hook_event_name": "PreToolUse",
            "tool_name": "mcp_markitdown_convert_to_markdown",
            "tool_input": {}, "cwd": self.cwd, "session_id": "s",
        }
        gateway = unittest.mock.Mock(return_value={
            "decision": "allow",
            "unknown_mcp_server": True,
        })
        with patch.object(unbound, "send_to_hook_api", gateway), patch.object(
            unbound, "_dispatch_mcp_server_scan"
        ) as dispatch:
            unbound.process_pre_tool_use(event, "K")

        dispatch.assert_called_once()
        self.assertEqual(dispatch.call_args.args[0], "microsoft/markitdown")
        self.assertEqual(dispatch.call_args.args[1]["command"], "uvx")

    def test_denied_unknown_server_does_not_dispatch_targeted_scan(self):
        event = {
            "hook_event_name": "PreToolUse",
            "tool_name": "mcp_markitdown_convert_to_markdown",
            "tool_input": {}, "cwd": self.cwd, "session_id": "s",
        }
        gateway = unittest.mock.Mock(return_value={
            "decision": "deny",
            "unknown_mcp_server": True,
        })
        with patch.object(unbound, "send_to_hook_api", gateway), patch.object(
            unbound, "_dispatch_mcp_server_scan"
        ) as dispatch:
            unbound.process_pre_tool_use(event, "K")

        dispatch.assert_not_called()

    def test_targeted_scan_uses_resolved_config(self):
        config_path = Path(self._tmp.name) / "unbound.json"
        config_path.write_text(json.dumps({
            "api_key": "secret-api-key",
            "base_url": "https://backend.example.com",
        }))
        with patch.object(unbound, "UNBOUND_CONFIG_PATH", config_path), patch.object(
            unbound, "RUNNING_FROZEN", True
        ), patch.object(unbound.os.path, "isfile", return_value=True), patch.object(
            unbound.subprocess, "Popen"
        ) as popen:
            unbound._dispatch_mcp_server_scan(
                "microsoft/markitdown", {"command": "uvx", "args": ["markitdown-mcp"]}
            )

        command = popen.call_args.args[0]
        environment = popen.call_args.kwargs["env"]
        self.assertEqual(command[:2], [unbound.FROZEN_DISCOVERY_BIN, "mcp-scan"])
        self.assertNotIn("secret-api-key", command)
        self.assertEqual(environment["UNBOUND_API_KEY"], "secret-api-key")
        self.assertEqual(json.loads(environment["UNBOUND_MCP_SERVER_JSON"]), {
            "command": "uvx",
            "args": ["markitdown-mcp"],
        })

    def test_non_frozen_targeted_scan_uses_direct_command(self):
        config_path = Path(self._tmp.name) / "unbound.json"
        install_path = Path(self._tmp.name) / "install.sh"
        config_path.write_text(json.dumps({
            "api_key": "secret-api-key",
            "base_url": "https://backend.example.com",
        }))
        with patch.object(unbound, "UNBOUND_CONFIG_PATH", config_path), patch.object(
            unbound, "DISCOVERY_INSTALL_SH", install_path
        ), patch.object(unbound, "RUNNING_FROZEN", False), patch.object(
            unbound, "_ensure_discovery_installer", return_value=True
        ), patch.object(unbound.subprocess, "Popen") as popen:
            unbound._dispatch_mcp_server_scan(
                "microsoft/markitdown", {"command": "uvx", "args": ["markitdown-mcp"]}
            )

        self.assertEqual(popen.call_args.args[0], [
            "bash", str(install_path), "mcp-scan", "--name", "microsoft/markitdown",
            "--domain", "https://backend.example.com",
        ])
        self.assertNotIn("-c", popen.call_args.args[0])

    def test_discovery_installer_is_published_after_download(self):
        install_dir = Path(self._tmp.name) / "discovery"
        install_path = install_dir / "install.sh"

        def download(command, **_kwargs):
            destination = Path(command[command.index("-o") + 1])
            self.assertNotEqual(destination, install_path)
            destination.write_text("installer", encoding="utf-8")
            return unittest.mock.Mock(returncode=0, stderr=b"")

        with patch.object(unbound, "DISCOVERY_INSTALL_DIR", install_dir), patch.object(
            unbound, "DISCOVERY_INSTALL_SH", install_path
        ), patch.object(unbound.subprocess, "run", side_effect=download):
            self.assertTrue(unbound._ensure_discovery_installer())

        self.assertEqual(install_path.read_text(encoding="utf-8"), "installer")
        self.assertEqual(list(install_dir.glob("*.tmp")), [])

    def test_non_mcp_tool_not_treated_as_mcp(self):
        captured = {}

        def capturing_gw(request_body, api_key):
            captured["md"] = request_body["pre_tool_use_data"]["metadata"]
            return {"decision": "allow"}

        event = {
            "hook_event_name": "PreToolUse",
            "tool_name": "run_in_terminal",
            "tool_input": {"command": "ls"}, "cwd": self.cwd, "session_id": "s",
        }
        with patch.object(unbound, "send_to_hook_api", capturing_gw):
            ret = unbound.process_pre_tool_use(event, "K")
        self.assertNotIn("mcp_server", captured.get("md", {}))
        self.assertFalse(self.is_block(ret))

    def test_unmapped_native_tool_is_ignored(self):
        event = {
            "hook_event_name": "PreToolUse",
            "tool_name": "install_python_packages",
            "tool_input": {"packageNames": ["requests"]},
            "cwd": self.cwd,
            "session_id": "s",
        }
        gateway = unittest.mock.Mock(return_value={"decision": "deny"})
        with patch.object(unbound, "send_to_hook_api", gateway):
            ret = unbound.process_pre_tool_use(event, "K")

        self.assertEqual(ret, {})
        gateway.assert_not_called()

    def test_server_name_without_tool_does_not_claim_native_tool(self):
        event = {
            "hook_event_name": "PreToolUse",
            "tool_name": "install_python_packages",
            "tool_input": {"packageNames": ["requests"]},
            "cwd": self.cwd,
            "session_id": "s",
        }
        colliding_config = {
            "install_python_packages": {"command": "untrusted-workspace-server"},
        }
        gateway = unittest.mock.Mock(return_value={"decision": "deny"})
        with patch.object(
            unbound, "read_copilot_mcp_servers", return_value=colliding_config
        ), patch.object(unbound, "send_to_hook_api", gateway):
            ret = unbound.process_pre_tool_use(event, "K")

        self.assertEqual(ret, {})
        gateway.assert_not_called()

    def test_workspace_mcp_config_cannot_relabel_terminal_like_native_tool(self):
        gateway = unittest.mock.Mock(return_value={"decision": "allow"})
        event = {
            "hook_event_name": "PreToolUse",
            "tool_name": "grep_search",
            "tool_input": {"query": "needle"},
            "cwd": self.cwd,
            "session_id": "s",
        }
        colliding_config = {
            "grep_search": {"command": "untrusted-workspace-server"},
        }
        with patch.object(
            unbound, "read_copilot_mcp_servers", return_value=colliding_config
        ), patch.object(unbound, "send_to_hook_api", gateway):
            ret = unbound.process_pre_tool_use(event, "K")

        self.assertEqual(ret, {})
        gateway.assert_not_called()

class TestStringToolArgs(ProcessPreToolUseBase):
    """VS Code sends toolArgs as a JSON string. The command must still reach the policy
    check — a hook that raises fails open, so the tool would run unchecked."""

    def _command_sent(self, tool_args, raw_tool="run_in_terminal"):
        captured = {}

        def capturing_gw(request_body, api_key):
            captured["cmd"] = request_body["pre_tool_use_data"]["command"]
            return {"decision": "allow"}

        event = {
            "hook_event_name": "PreToolUse",
            "tool_name": raw_tool,
            "toolArgs": tool_args, "cwd": self.cwd, "session_id": "s",
        }
        with patch.object(unbound, "send_to_hook_api", capturing_gw):
            unbound.process_pre_tool_use(event, "K")
        return captured.get("cmd")

    def test_json_string_toolargs_command_reaches_gateway(self):
        self.assertEqual(
            self._command_sent('{"command": "rm -rf /tmp/x"}'), "rm -rf /tmp/x")

    def test_non_json_string_toolargs_command_reaches_gateway(self):
        # Unparseable payload is preserved verbatim, not dropped for want of a dict.
        self.assertEqual(self._command_sent('rm -rf /tmp/x'), "rm -rf /tmp/x")

    def test_deeply_nested_toolargs_does_not_fail_open(self):
        # json.loads raises RecursionError (not a ValueError) well before 2000 levels.
        nested = '{"command": "ls", "pad": ' + '[' * 2000 + ']' * 2000 + '}'
        self.assertIn("ls", self._command_sent(nested))

    def test_json_array_toolargs_does_not_crash(self):
        self.assertEqual(self._command_sent('["ls", "-la"]'), '["ls", "-la"]')


class TestUnresolvedForwarding(ProcessPreToolUseBase):
    def test_unresolved_mcp_is_forwarded_to_gateway_not_short_circuited(self):
        # An unmappable mcp_ call must still reach the gateway, not return {} early.
        called = {}

        def capturing_gw(request_body, api_key):
            called["body"] = request_body
            return {"decision": "allow"}

        event = {
            "hook_event_name": "PreToolUse",
            "tool_name": "mcp_unknownserver_do_thing",
            "tool_input": {"q": "x"}, "cwd": self.cwd, "session_id": "s",
        }
        with patch.object(unbound, "send_to_hook_api", capturing_gw):
            unbound.process_pre_tool_use(event, "K")
        self.assertIn("body", called)  # gateway WAS called (not short-circuited)
        md = called["body"]["pre_tool_use_data"]["metadata"]
        self.assertNotIn("mcp_server", md)  # nothing resolved to forward

    def test_unresolved_mcp_not_sanction_blocked(self):
        # No resolved server -> allow-list not evaluated (fail-open) for unresolved.
        ret = self.run_tool("mcp_unknownserver_do_thing", {GH_GROUP})
        self.assertFalse(self.is_block(ret))


_PLUGIN_TOOLCHAIN_URL = (
    "https://mcp.example.com/mcp/v1/rpc?tool_filter=gdrive*,gdocs*"
)


class TestAgentPluginConfigPaths(unittest.TestCase):
    """Exercise the real agentPlugins glob (no mocking) against a temp HOME."""

    def _run(self, write_user_gdrive=None):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        with patch.object(unbound.Path, "home", return_value=Path(tmp.name)):
            user_dir = unbound._vscode_user_dirs()[0]
            user_dir.mkdir(parents=True, exist_ok=True)
            plugin_dir = (
                user_dir.parent
                / "agentPlugins" / "github.com" / "forter" / "datastores-core"
            )
            plugin_dir.mkdir(parents=True, exist_ok=True)
            (plugin_dir / ".mcp.json").write_text(
                json.dumps({"mcpServers": {
                    "gdrive": {"type": "http", "url": _PLUGIN_TOOLCHAIN_URL}}})
            )
            if write_user_gdrive:
                (user_dir / "mcp.json").write_text(
                    json.dumps({"servers": {"gdrive": {"command": write_user_gdrive}}})
                )
            return unbound.read_copilot_mcp_servers(None)

    def test_plugin_bundled_server_resolves(self):
        servers = self._run()
        server, tool, cfg = unbound._resolve_vscode_mcp(
            "mcp_gdrive_gdrive-search", servers
        )
        self.assertEqual(server, "gdrive")
        self.assertEqual(tool, "gdrive-search")
        self.assertEqual(cfg["url"], _PLUGIN_TOOLCHAIN_URL)

    def test_plugin_and_user_name_collision_is_ambiguous(self):
        servers = self._run(write_user_gdrive="/usr/local/bin/my-real-gdrive")
        self.assertIsNone(servers["gdrive"])

    def test_no_plugins_is_noop(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        with patch.object(unbound.Path, "home", return_value=Path(tmp.name)):
            unbound._vscode_user_dirs()[0].mkdir(parents=True, exist_ok=True)
            self.assertEqual(unbound.read_copilot_mcp_servers(None), {})

    def test_bare_package_config_reaches_the_gateway(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        with patch.object(unbound.Path, "home", return_value=Path(tmp.name)):
            user_dir = unbound._vscode_user_dirs()[0]
            user_dir.mkdir(parents=True, exist_ok=True)
            (user_dir / "mcp.json").write_text(json.dumps({"servers": {
                "postgres": {"command": "npx", "args": ["-y", "pg-mcp"]},
            }}))
            servers = unbound.read_copilot_mcp_servers(None)
        self.assertEqual(servers["postgres"], {
            "command": "npx",
            "args": ["-y", "pg-mcp"],
        })

    def test_config_is_forwarded_unchanged(self):
        config = unbound._extract_mcp_server_fields({
            "command": "npx",
            "args": ["-y", "pg-mcp", "--token", "ghp_abcdefghijklmnopqrst", "API_KEY=secret"],
        })

        metadata = {
            "mcp_server": "postgres",
            "mcp_tool": "query",
            "mcp_server_config": config,
        }
        unbound._attach_tool_content_hash(metadata)
        self.assertEqual(metadata["mcp_server_config"], config)

    def test_bespoke_command_config_is_forwarded(self):
        config = unbound._extract_mcp_server_fields({
            "command": "server",
            "args": [
                "--header", "Authorization: Bearer opaque-value",
                "--env", "SESSION=opaque-value",
                "--header=X-Key: opaque-value",
            ],
        })

        self.assertEqual(config["command"], "server")
        self.assertEqual(len(config["args"]), 5)

    def test_config_survives_tool_hash_lookup_failure(self):
        metadata = {
            "mcp_server": "private",
            "mcp_tool": "read",
            "mcp_server_config": {
                "command": "private-mcp",
                "args": ["--token", "secret"],
            },
        }
        with patch.object(
            unbound, "_lookup_tool_content_hash", side_effect=RuntimeError("failed")
        ):
            unbound._attach_tool_content_hash(metadata)

        self.assertEqual(metadata["mcp_server_config"], {
            "command": "private-mcp",
            "args": ["--token", "secret"],
        })

    def test_plugin_relative_command_is_forwarded_without_hook_fingerprint(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        with patch.object(unbound.Path, "home", return_value=Path(tmp.name)):
            user_dir = unbound._vscode_user_dirs()[0]
            user_dir.mkdir(parents=True, exist_ok=True)
            plugin_dir = (
                user_dir.parent / "agentPlugins" / "github.com" / "acme" / "local-mcp"
            )
            plugin_dir.mkdir(parents=True, exist_ok=True)
            (plugin_dir / "server.py").write_text("print('hi')\n")
            (plugin_dir / ".mcp.json").write_text(
                json.dumps({"mcpServers": {"local": {"command": "./server.py"}}})
            )
            # cwd points at a dir that does NOT contain the script.
            servers = unbound.read_copilot_mcp_servers(str(user_dir.parent))
        self.assertIn("local", servers)
        self.assertEqual(servers["local"], {"command": "./server.py"})


class TestCopilotProjectConfigPaths(unittest.TestCase):
    def test_copilot_home_contains_cli_config_and_plugins(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            custom_home = Path(tmpdir) / "copilot-home"
            plugin = custom_home / "installed-plugins" / "docs"
            plugin.mkdir(parents=True)
            custom_home.mkdir(exist_ok=True)
            (custom_home / "mcp-config.json").write_text(json.dumps({
                "mcpServers": {"linear": {"url": "https://mcp.linear.app/mcp"}},
            }))
            (plugin / ".mcp.json").write_text(json.dumps({
                "mcpServers": {"docs": {"command": "docs-mcp"}},
            }))

            with patch.dict(os.environ, {"COPILOT_HOME": str(custom_home)}):
                servers = unbound.read_copilot_mcp_servers(None)

        self.assertEqual(servers["linear"]["url"], "https://mcp.linear.app/mcp")
        self.assertEqual(servers["docs"]["command"], "docs-mcp")

    def test_cli_github_config_is_read_from_git_root(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            home = Path(tmpdir) / "home"
            repo = Path(tmpdir) / "repo"
            nested = repo / "packages" / "app"
            (repo / ".git").mkdir(parents=True)
            (repo / ".github").mkdir()
            nested.mkdir(parents=True)
            (repo / ".github" / "mcp.json").write_text(json.dumps({
                "mcpServers": {
                    "github": {"command": "npx", "args": ["github-mcp-server"]},
                },
            }))

            with patch.object(unbound.Path, "home", return_value=home):
                servers = unbound.read_copilot_mcp_servers(str(nested))

        self.assertEqual(servers["github"], {
            "command": "npx",
            "args": ["github-mcp-server"],
        })

    def test_bare_project_config_is_read(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            home = Path(tmpdir) / "home"
            repo = Path(tmpdir) / "repo"
            (repo / ".git").mkdir(parents=True)
            (repo / ".mcp.json").write_text(json.dumps({
                "linear": {"type": "http", "url": "https://mcp.linear.app/mcp"},
            }))

            with patch.object(unbound.Path, "home", return_value=home):
                servers = unbound.read_copilot_mcp_servers(str(repo))

        self.assertEqual(servers["linear"]["url"], "https://mcp.linear.app/mcp")

    def test_nearest_portable_config_wins(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            home = Path(tmpdir) / "home"
            repo = Path(tmpdir) / "repo"
            nested = repo / "packages" / "app"
            (repo / ".git").mkdir(parents=True)
            (repo / ".github").mkdir()
            nested.mkdir(parents=True)
            (repo / ".github" / "mcp.json").write_text(json.dumps({
                "mcpServers": {"github": {"command": "root-server"}},
            }))
            (nested / ".mcp.json").write_text(json.dumps({
                "mcpServers": {"github": {"command": "nested-server"}},
            }))

            with patch.object(unbound.Path, "home", return_value=home):
                servers = unbound.read_copilot_mcp_servers(str(nested))

        self.assertEqual(servers["github"]["command"], "nested-server")

    def test_dot_mcp_overrides_only_conflicting_github_servers(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            home = Path(tmpdir) / "home"
            repo = Path(tmpdir) / "repo"
            (repo / ".git").mkdir(parents=True)
            (repo / ".github").mkdir()
            (repo / ".github" / "mcp.json").write_text(json.dumps({
                "mcpServers": {
                    "shared": {"command": "github-value"},
                    "github-only": {"command": "loaded"},
                },
            }))
            (repo / ".mcp.json").write_text(json.dumps({
                "mcpServers": {
                    "shared": {"command": "portable-value"},
                    "portable": {"command": "loaded"},
                },
            }))

            with patch.object(unbound.Path, "home", return_value=home):
                servers = unbound.read_copilot_mcp_servers(str(repo))

        self.assertEqual(servers["portable"]["command"], "loaded")
        self.assertEqual(servers["github-only"]["command"], "loaded")
        self.assertEqual(servers["shared"]["command"], "portable-value")

    def test_vscode_workspace_config_is_read(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            home = Path(tmpdir) / "home"
            repo = Path(tmpdir) / "repo"
            (repo / ".git").mkdir(parents=True)
            (repo / ".vscode").mkdir()
            (repo / ".vscode" / "mcp.json").write_text(json.dumps({
                "servers": {"context7": {"command": "npx", "args": ["context7-mcp"]}},
            }))

            with patch.object(unbound.Path, "home", return_value=home):
                servers = unbound.read_copilot_mcp_servers(str(repo))

        self.assertEqual(servers["context7"]["args"], ["context7-mcp"])

    def test_conflicting_user_and_workspace_configs_are_ambiguous(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            home = Path(tmpdir) / "home"
            repo = Path(tmpdir) / "repo"
            user_dir = home / "Library" / "Application Support" / "Code" / "User"
            user_dir.mkdir(parents=True)
            repo.mkdir()
            (repo / ".git").mkdir()
            (repo / ".mcp.json").write_text(json.dumps({
                "shared": {"command": "workspace-server"},
            }))
            (user_dir / "mcp.json").write_text(json.dumps({
                "servers": {"shared": {"command": "user-server"}},
            }))

            with patch.object(unbound.Path, "home", return_value=home), patch.object(
                unbound.platform, "system", return_value="Darwin"
            ):
                servers = unbound.read_copilot_mcp_servers(str(repo))

        self.assertIn("shared", servers)
        self.assertIsNone(servers["shared"])

if __name__ == "__main__":
    unittest.main()
