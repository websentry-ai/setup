"""
Tests for VS Code Copilot `mcp_<server>_<tool>` resolution + sanctioning in
copilot/hooks/unbound.py. Tool names are real ones from VS Code chat transcripts;
server keys mirror a real VS Code mcp.json.
"""

import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import unbound

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
        out[name] = unbound._sanitize_mcp_server_fields(srv) or {}
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
            patch.object(unbound, "_copilot_mcp_config_paths", lambda cwd=None: [cfg_path]),
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
        self.assertIn("mcp_server_config", captured["md"])

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


# Query string is stripped by the hook + gateway, so the fingerprint is host+path.
_PLUGIN_TOOLCHAIN_URL = (
    "https://toolchain-internal.frdstr.com/mcp/v1/rpc?tool_filter=gdrive*,gdocs*"
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
        self.assertEqual(
            cfg.get("url"), "https://toolchain-internal.frdstr.com/mcp/v1/rpc"
        )

    def test_user_mcp_json_wins_over_plugin(self):
        # A plugin must not override the user's own same-named server.
        servers = self._run(write_user_gdrive="/usr/local/bin/my-real-gdrive")
        self.assertEqual(servers["gdrive"].get("command"), "/usr/local/bin/my-real-gdrive")
        self.assertNotIn("url", servers["gdrive"])

    def test_no_plugins_is_noop(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        with patch.object(unbound.Path, "home", return_value=Path(tmp.name)):
            unbound._vscode_user_dirs()[0].mkdir(parents=True, exist_ok=True)
            self.assertEqual(unbound.read_copilot_mcp_servers(None), {})


if __name__ == "__main__":
    unittest.main()
