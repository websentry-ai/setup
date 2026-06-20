"""
Tests for VS Code Copilot MCP-server resolution + sanctioning in
copilot/hooks/unbound.py.

VS Code Copilot emits MCP tools as `mcp_<server>_<tool>` (single underscore),
which canonical_tool_name() treats as already-resolved and the gateway (which
only parses the Claude-style `mcp__` form) cannot decode — so without the
resolver the server is never identified and sanctioning is silently bypassed.

Covers:
  - _resolve_vscode_mcp           (reverse-map sanitized/truncated server token)
  - process_pre_tool_use          (end-to-end: resolve -> forward config -> deny)

Tool names below are the real ones harvested from VS Code Copilot chat
transcripts; server keys mirror a real VS Code mcp.json (registry-style keys).
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

    def test_non_mcp_and_unknown_return_none(self):
        self.assertEqual(
            unbound._resolve_vscode_mcp("run_in_terminal", self.servers),
            (None, None, None))
        self.assertEqual(
            unbound._resolve_vscode_mcp("mcp_unknownserver_do_thing", self.servers),
            (None, None, None))


def _gateway(sanctioned_groups):
    """Mirror preToolUseHandler: read mcp_server/mcp_tool (+ config fingerprint),
    apply the org allow-list. group == forwarded config url/command."""
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
            grp = cfg.get("url") or cfg.get("command") or srv
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


class TestUnresolvedFailSecure(ProcessPreToolUseBase):
    def test_unresolved_mcp_fails_open_by_default(self):
        ret = self.run_tool("mcp_unknownserver_do_thing", {GH_GROUP}, failure_action="allow")
        self.assertFalse(self.is_block(ret))

    def test_unresolved_mcp_fails_secure_in_strict_org(self):
        ret = self.run_tool("mcp_unknownserver_do_thing", {GH_GROUP}, failure_action="block")
        self.assertTrue(self.is_block(ret))


if __name__ == "__main__":
    unittest.main()
