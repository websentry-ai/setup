"""
Tests for Claude Code plugin-MCP + claude.ai connector resolution in
claude-code/hooks/unbound.py. Plugin servers surface as
`mcp__plugin_<plugin>_<server>__<tool>` (name `plugin_slack_slack`) and
claude.ai connectors as `mcp__claude_ai_<Name>__<tool>` (name `claude_ai_Slack`);
neither has a config-file `mcpServers` entry, so the hook must rebuild a config
to give the gateway a non-null fingerprint.
"""

import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import unbound


def _write_json(path: Path, data):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data))


def _make_plugin(cache_dir, marketplace, plugin, version, files, in_use=False):
    """files: {".mcp.json": {...}, ".claude-plugin/plugin.json": {...}, "rel.json": {...}}"""
    ver_dir = cache_dir / marketplace / plugin / version
    ver_dir.mkdir(parents=True, exist_ok=True)
    for rel, data in files.items():
        _write_json(ver_dir / rel, data)
    if in_use:
        (ver_dir / ".in_use").write_text("")
    return ver_dir


class TestResolvePluginMcpConfig(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.cache = Path(self._tmp.name)

    def tearDown(self):
        self._tmp.cleanup()

    def test_mangle_token(self):
        self.assertEqual(unbound._mangle_mcp_token("monday.com"), "monday_com")
        self.assertEqual(unbound._mangle_mcp_token("my-plugin"), "my-plugin")
        self.assertEqual(unbound._mangle_mcp_token(None), "")

    def test_mcp_json_hit(self):
        _make_plugin(
            self.cache, "anthropics", "slack", "1.0.0",
            {".mcp.json": {"mcpServers": {"slack": {"url": "https://mcp.slack.com/mcp", "type": "http"}}}},
        )
        cfg = unbound._resolve_plugin_mcp_config("plugin_slack_slack", cache_dir=self.cache)
        self.assertEqual(cfg, {"url": "https://mcp.slack.com/mcp", "type": "http"})

    def test_inline_plugin_json_hit(self):
        _make_plugin(
            self.cache, "mkt", "stripe", "2.1.0",
            {".claude-plugin/plugin.json": {
                "mcpServers": {"stripe": {"command": "npx", "args": ["@stripe/mcp"]}}}},
        )
        cfg = unbound._resolve_plugin_mcp_config("plugin_stripe_stripe", cache_dir=self.cache)
        self.assertEqual(cfg, {"command": "npx", "args": ["@stripe/mcp"]})

    def test_unwrapped_root_map_mcp_json_hit(self):
        # Playwright ships {"playwright": {...}} at the root, no mcpServers wrapper.
        _make_plugin(
            self.cache, "claude-plugins-official", "playwright", "1.0.0",
            {".mcp.json": {"playwright": {"command": "npx", "args": ["@playwright/mcp@latest"]}}},
        )
        cfg = unbound._resolve_plugin_mcp_config("plugin_playwright_playwright", cache_dir=self.cache)
        self.assertEqual(cfg, {"command": "npx", "args": ["@playwright/mcp@latest"]})

    def test_unwrapped_root_ignores_non_server_entries(self):
        # A plugin.json-style root (no command/url) must not be read as servers.
        _make_plugin(
            self.cache, "mkt", "noserver", "1.0.0",
            {".mcp.json": {"name": "noserver", "author": {"name": "acme"}}},
        )
        cfg = unbound._resolve_plugin_mcp_config("plugin_noserver_name", cache_dir=self.cache)
        self.assertIsNone(cfg)

    def test_string_form_relative_path_hit(self):
        _make_plugin(
            self.cache, "mkt", "vercel", "3.0.0",
            {
                ".claude-plugin/plugin.json": {"mcpServers": ".mcp.json"},
                ".mcp.json": {"mcpServers": {"vercel": {"url": "https://mcp.vercel.com"}}},
            },
        )
        cfg = unbound._resolve_plugin_mcp_config("plugin_vercel_vercel", cache_dir=self.cache)
        self.assertEqual(cfg, {"url": "https://mcp.vercel.com"})

    def test_multiple_in_use_picks_newest_deterministically(self):
        import os
        _make_plugin(
            self.cache, "mkt", "demo", "1.0.0",
            {".mcp.json": {"mcpServers": {"demo": {"url": "https://old.example/mcp", "type": "http"}}}},
            in_use=True,
        )
        _make_plugin(
            self.cache, "mkt", "demo", "2.0.0",
            {".mcp.json": {"mcpServers": {"demo": {"url": "https://new.example/mcp", "type": "http"}}}},
            in_use=True,
        )
        base = self.cache / "mkt" / "demo"
        os.utime(base / "1.0.0", (1000, 1000))
        os.utime(base / "2.0.0", (2000, 2000))
        cfg = unbound._resolve_plugin_mcp_config("plugin_demo_demo", cache_dir=self.cache)
        self.assertEqual(cfg, {"url": "https://new.example/mcp", "type": "http"})

    def test_string_form_within_version_dir_hit(self):
        # A relative path that stays inside the version dir resolves normally.
        _make_plugin(
            self.cache, "mkt", "linear", "1.0.0",
            {
                ".claude-plugin/plugin.json": {"mcpServers": "servers.json"},
                "servers.json": {"mcpServers": {"linear": {"url": "https://mcp.linear.app"}}},
            },
        )
        cfg = unbound._resolve_plugin_mcp_config("plugin_linear_linear", cache_dir=self.cache)
        self.assertEqual(cfg, {"url": "https://mcp.linear.app"})

    def test_string_form_traversal_escape_rejected(self):
        # `../` traversal must not read a file outside the version dir.
        ver_dir = _make_plugin(
            self.cache, "mkt", "evilplug", "1.0.0",
            {".claude-plugin/plugin.json": {"mcpServers": "../../../evil.json"}},
        )
        # The escape target exists and would resolve to a real file if uncontained.
        outside = ver_dir.parent.parent.parent / "evil.json"
        _write_json(outside, {"mcpServers": {"evil": {"url": "https://evil.example/mcp"}}})
        cfg = unbound._resolve_plugin_mcp_config("plugin_evilplug_evil", cache_dir=self.cache)
        self.assertIsNone(cfg)

    def test_string_form_absolute_path_rejected(self):
        # An absolute path must be rejected (pathlib would otherwise replace the
        # base, reading an arbitrary file). Point it at a real file to prove the
        # containment check, not a missing file, is what stops the read.
        outside = Path(self._tmp.name) / "abs_evil.json"
        _write_json(outside, {"mcpServers": {"evil": {"url": "https://abs.example/mcp"}}})
        _make_plugin(
            self.cache, "mkt", "absplug", "1.0.0",
            {".claude-plugin/plugin.json": {"mcpServers": str(outside)}},
        )
        cfg = unbound._resolve_plugin_mcp_config("plugin_absplug_evil", cache_dir=self.cache)
        self.assertIsNone(cfg)

    def test_identical_config_collision_resolves(self):
        # Two distinct (plugin, server) pairs mangle to the same candidate AND
        # share the SAME config -> one distinct entry -> resolves (benign).
        _make_plugin(
            self.cache, "mkt", "a_b", "1.0.0",
            {".mcp.json": {"mcpServers": {"c": {"url": "https://same.example/mcp"}}}},
        )
        _make_plugin(
            self.cache, "mkt", "a", "1.0.0",
            {".mcp.json": {"mcpServers": {"b_c": {"url": "https://same.example/mcp"}}}},
        )
        # both -> plugin_a_b_c
        cfg = unbound._resolve_plugin_mcp_config("plugin_a_b_c", cache_dir=self.cache)
        self.assertEqual(cfg, {"url": "https://same.example/mcp"})

    def test_multi_version_prefers_in_use(self):
        _make_plugin(
            self.cache, "mkt", "slack", "1.0.0",
            {".mcp.json": {"mcpServers": {"slack": {"url": "https://old.example/mcp"}}}},
        )
        _make_plugin(
            self.cache, "mkt", "slack", "2.0.0",
            {".mcp.json": {"mcpServers": {"slack": {"url": "https://current.example/mcp"}}}},
            in_use=True,
        )
        cfg = unbound._resolve_plugin_mcp_config("plugin_slack_slack", cache_dir=self.cache)
        self.assertEqual(cfg, {"url": "https://current.example/mcp"})

    def test_multi_version_prefers_newest_when_no_in_use(self):
        old = _make_plugin(
            self.cache, "mkt", "slack", "1.0.0",
            {".mcp.json": {"mcpServers": {"slack": {"url": "https://old.example/mcp"}}}},
        )
        new = _make_plugin(
            self.cache, "mkt", "slack", "2.0.0",
            {".mcp.json": {"mcpServers": {"slack": {"url": "https://newest.example/mcp"}}}},
        )
        import os
        os.utime(old, (1000, 1000))
        os.utime(new, (2000, 2000))
        cfg = unbound._resolve_plugin_mcp_config("plugin_slack_slack", cache_dir=self.cache)
        self.assertEqual(cfg, {"url": "https://newest.example/mcp"})

    def test_underscore_in_names_disambiguates(self):
        # plugin dir `my_plugin`, server key `my_server` => plugin_my_plugin_my_server
        _make_plugin(
            self.cache, "mkt", "my_plugin", "1.0.0",
            {".mcp.json": {"mcpServers": {"my_server": {"url": "https://my.example/mcp"}}}},
        )
        cfg = unbound._resolve_plugin_mcp_config("plugin_my_plugin_my_server", cache_dir=self.cache)
        self.assertEqual(cfg, {"url": "https://my.example/mcp"})

    def test_ambiguous_different_configs_returns_none(self):
        # Two distinct (plugin, server) pairs both mangle to the same candidate
        # name but carry DIFFERENT configs -> ambiguous -> None (no guessing).
        _make_plugin(
            self.cache, "mkt", "a_b", "1.0.0",
            {".mcp.json": {"mcpServers": {"c": {"url": "https://a.example/mcp"}}}},
        )
        _make_plugin(
            self.cache, "mkt", "a", "1.0.0",
            {".mcp.json": {"mcpServers": {"b_c": {"url": "https://b.example/mcp"}}}},
        )
        # both -> plugin_a_b_c
        cfg = unbound._resolve_plugin_mcp_config("plugin_a_b_c", cache_dir=self.cache)
        self.assertIsNone(cfg)

    def test_secret_stripping(self):
        _make_plugin(
            self.cache, "mkt", "slack", "1.0.0",
            {".mcp.json": {"mcpServers": {"slack": {
                "url": "https://mcp.slack.com/mcp",
                "type": "http",
                "oauth": {"client_secret": "shh"},
                "env": {"TOKEN": "xoxb-secret"},
                "headers": {"Authorization": "Bearer secret"},
            }}}},
        )
        cfg = unbound._resolve_plugin_mcp_config("plugin_slack_slack", cache_dir=self.cache)
        self.assertEqual(set(cfg.keys()), {"url", "type"})
        self.assertNotIn("oauth", cfg)
        self.assertNotIn("env", cfg)
        self.assertNotIn("headers", cfg)

    def test_missing_cache_dir_returns_none_no_raise(self):
        missing = Path(self._tmp.name) / "does" / "not" / "exist"
        self.assertIsNone(unbound._resolve_plugin_mcp_config("plugin_slack_slack", cache_dir=missing))

    def test_non_plugin_name_returns_none(self):
        self.assertIsNone(unbound._resolve_plugin_mcp_config("slack", cache_dir=self.cache))

    def test_miss_returns_none(self):
        _make_plugin(
            self.cache, "mkt", "slack", "1.0.0",
            {".mcp.json": {"mcpServers": {"slack": {"url": "https://mcp.slack.com/mcp"}}}},
        )
        self.assertIsNone(
            unbound._resolve_plugin_mcp_config("plugin_other_other", cache_dir=self.cache))

    def test_corrupt_sibling_plugin_does_not_abort_scan(self):
        # A plugin with a corrupt .mcp.json must not deny every plugin call:
        # the valid sibling still resolves, and the corrupt plugin's own name
        # misses (returns None) without raising.
        corrupt_dir = _make_plugin(self.cache, "mkt", "broken", "1.0.0", {})
        (corrupt_dir / ".mcp.json").write_text("{ broken")
        _make_plugin(
            self.cache, "mkt", "slack", "1.0.0",
            {".mcp.json": {"mcpServers": {"slack": {"url": "https://mcp.slack.com/mcp", "type": "http"}}}},
        )
        cfg = unbound._resolve_plugin_mcp_config("plugin_slack_slack", cache_dir=self.cache)
        self.assertEqual(cfg, {"url": "https://mcp.slack.com/mcp", "type": "http"})
        self.assertIsNone(
            unbound._resolve_plugin_mcp_config("plugin_broken_broken", cache_dir=self.cache))


class TestResolveClaudeAiConnector(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.cfg_path = Path(self._tmp.name) / ".claude.json"

    def tearDown(self):
        self._tmp.cleanup()

    def test_connector_hit(self):
        _write_json(self.cfg_path, {"claudeAiMcpEverConnected": ["claude.ai Slack", "claude.ai Notion"]})
        result = unbound._resolve_claude_ai_connector("claude_ai_Slack", config_path=self.cfg_path)
        self.assertEqual(result, ("claude.ai Slack", {"additional_data": {"scope": "claudeai"}}))

    def test_connector_dotted_mangle(self):
        _write_json(self.cfg_path, {"claudeAiMcpEverConnected": ["claude.ai monday.com"]})
        result = unbound._resolve_claude_ai_connector("claude_ai_monday_com", config_path=self.cfg_path)
        self.assertEqual(result, ("claude.ai monday.com", {"additional_data": {"scope": "claudeai"}}))

    def test_connector_not_in_list_returns_none(self):
        _write_json(self.cfg_path, {"claudeAiMcpEverConnected": ["claude.ai Notion"]})
        self.assertIsNone(
            unbound._resolve_claude_ai_connector("claude_ai_Slack", config_path=self.cfg_path))

    def test_missing_config_returns_none_no_raise(self):
        missing = Path(self._tmp.name) / "nope.json"
        self.assertIsNone(
            unbound._resolve_claude_ai_connector("claude_ai_Slack", config_path=missing))

    def test_corrupt_config_returns_none_no_raise(self):
        self.cfg_path.write_text("{ this is not json")
        self.assertIsNone(
            unbound._resolve_claude_ai_connector("claude_ai_Slack", config_path=self.cfg_path))

    def test_non_connector_name_returns_none(self):
        _write_json(self.cfg_path, {"claudeAiMcpEverConnected": ["claude.ai Slack"]})
        self.assertIsNone(
            unbound._resolve_claude_ai_connector("plugin_slack_slack", config_path=self.cfg_path))

    def test_never_copies_other_fields(self):
        _write_json(self.cfg_path, {
            "claudeAiMcpEverConnected": ["claude.ai Slack"],
            "oauthAccount": {"accessToken": "secret"},
        })
        result = unbound._resolve_claude_ai_connector("claude_ai_Slack", config_path=self.cfg_path)
        self.assertEqual(result[1], {"additional_data": {"scope": "claudeai"}})

    def test_ambiguous_distinct_displays_returns_none(self):
        # Two distinct display names mangle to the same server_name -> fail-secure
        # (no guessing which dotted identity to inject).
        _write_json(self.cfg_path, {
            "claudeAiMcpEverConnected": ["claude.ai monday.com", "claude.ai monday_com"]})
        self.assertIsNone(
            unbound._resolve_claude_ai_connector("claude_ai_monday_com", config_path=self.cfg_path))

    def test_single_match_resolves(self):
        # Control: a single matching display resolves to its dotted identity.
        _write_json(self.cfg_path, {"claudeAiMcpEverConnected": ["claude.ai monday.com"]})
        result = unbound._resolve_claude_ai_connector("claude_ai_monday_com", config_path=self.cfg_path)
        self.assertEqual(result, ("claude.ai monday.com", {"additional_data": {"scope": "claudeai"}}))


class ProcessPreToolUseBase(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name)
        # Empty config so _read_mcp_server_config finds nothing -> resolvers run.
        self.claude_json = self.root / ".claude.json"
        _write_json(self.claude_json, {"mcpServers": {}})
        self.plugin_cache = self.root / "plugins" / "cache"
        self.plugin_cache.mkdir(parents=True, exist_ok=True)
        self._patchers = [
            patch.object(unbound, "CLAUDE_MCP_CONFIG_PATH", self.claude_json),
            patch.object(unbound, "CLAUDE_PLUGIN_CACHE_DIR", self.plugin_cache),
            patch.object(unbound, "load_policy_cache", lambda: {"tools_to_check": [], "ts": 0}),
            patch.object(unbound, "is_cache_stale", lambda c: False),
            patch.object(unbound, "get_recent_user_prompts_for_session", lambda *a, **k: []),
            patch.object(unbound, "_get_session_model", lambda *a, **k: "auto"),
            patch.object(unbound, "_is_approval_retry", lambda *a, **k: False),
            patch.object(unbound, "build_account_identity", lambda *a, **k: {}),
            patch.object(unbound, "report_error_to_gateway", lambda *a, **k: None),
            patch.object(unbound, "_dispatch_mcp_server_scan", lambda *a, **k: None),
        ]
        for p in self._patchers:
            p.start()
        self.cwd = str(self.root)

    def tearDown(self):
        for p in self._patchers:
            p.stop()
        self._tmp.cleanup()

    def run_capture(self, raw_tool):
        captured = {}

        def capturing_gw(request_body, api_key):
            captured["md"] = request_body["pre_tool_use_data"]["metadata"]
            return {"decision": "allow"}

        event = {
            "hook_event_name": "PreToolUse",
            "tool_name": raw_tool,
            "tool_input": {"q": "x"},
            "cwd": self.cwd,
            "session_id": "sess",
        }
        with patch.object(unbound, "send_to_hook_api", capturing_gw):
            unbound.process_pre_tool_use(event, "API_KEY")
        return captured.get("md", {})


class TestProcessPreToolUseEndToEnd(ProcessPreToolUseBase):
    def test_plugin_call_forwards_slack_url(self):
        _make_plugin(
            self.plugin_cache, "anthropics", "slack", "1.0.0",
            {".mcp.json": {"mcpServers": {"slack": {"url": "https://mcp.slack.com/mcp", "type": "http"}}}},
        )
        md = self.run_capture("mcp__plugin_slack_slack__post_message")
        self.assertEqual(md.get("mcp_server"), "plugin_slack_slack")  # unchanged for plugins
        self.assertEqual(md.get("mcp_tool"), "post_message")  # tool half preserved
        self.assertEqual(
            md.get("mcp_server_config"),
            {"url": "https://mcp.slack.com/mcp", "type": "http"},
        )

    def test_connector_call_rewrites_server_name(self):
        _write_json(self.claude_json, {
            "mcpServers": {},
            "claudeAiMcpEverConnected": ["claude.ai Slack"],
        })
        md = self.run_capture("mcp__claude_ai_Slack__send_message")
        self.assertEqual(md.get("mcp_server"), "claude.ai Slack")
        self.assertEqual(md.get("mcp_tool"), "send_message")  # tool half preserved through rewrite
        self.assertEqual(md.get("mcp_server_config"), {"additional_data": {"scope": "claudeai"}})

    def test_unresolved_mcp_carries_no_config(self):
        md = self.run_capture("mcp__plugin_unknown_unknown__do_thing")
        self.assertEqual(md.get("mcp_server"), "plugin_unknown_unknown")  # unchanged
        self.assertNotIn("mcp_server_config", md)

    def test_config_file_server_takes_precedence_over_resolvers(self):
        # A real config-file entry must win; resolvers must not run/override it.
        _write_json(self.claude_json, {
            "mcpServers": {"plugin_slack_slack": {"url": "https://configfile.example/mcp"}},
        })
        _make_plugin(
            self.plugin_cache, "mkt", "slack", "1.0.0",
            {".mcp.json": {"mcpServers": {"slack": {"url": "https://mcp.slack.com/mcp"}}}},
        )
        md = self.run_capture("mcp__plugin_slack_slack__post_message")
        self.assertEqual(md.get("mcp_server_config"), {"url": "https://configfile.example/mcp"})


class TestUnboundAppLabel(unittest.TestCase):
    """_unbound_app_label reports Cowork via the desktop env markers, with the
    local-agent-mode-sessions sandbox path as a fallback; everything else is
    claude-code. Verified against real captured events from all three surfaces."""

    def setUp(self):
        # neutralize any ambient Cowork env so path-based cases are deterministic
        self._env = patch.dict("os.environ", {}, clear=True)
        self._env.start()
        self.addCleanup(self._env.stop)

    def test_claude_code_cli(self):
        ev = {"cwd": "/Users/x/Documents/proj",
              "transcript_path": "/Users/x/.claude/projects/-Users-x-Documents-proj/s.jsonl"}
        self.assertEqual(unbound._unbound_app_label(ev), "claude-code")

    def test_claude_code_desktop(self):
        ev = {"cwd": "/Users/x/Downloads",
              "transcript_path": "/Users/x/.claude/projects/-Users-x-Downloads/s.jsonl"}
        self.assertEqual(unbound._unbound_app_label(ev), "claude-code")

    def test_cowork_env_is_cowork_flag(self):
        # env wins even when the path looks like plain Claude Code
        with patch.dict("os.environ", {"CLAUDE_CODE_IS_COWORK": "1"}):
            self.assertEqual(unbound._unbound_app_label({"cwd": "/Users/x/proj"}), "cowork")

    def test_cowork_env_entrypoint_values(self):
        for val in ("local-agent", "local_agent", "remote_cowork"):
            with patch.dict("os.environ", {"CLAUDE_CODE_ENTRYPOINT": val}):
                self.assertEqual(unbound._unbound_app_label({}), "cowork")

    def test_unrecognized_entrypoint_is_claude_code(self):
        for val in ("cli", "desktop", "vscode", ""):
            with patch.dict("os.environ", {"CLAUDE_CODE_ENTRYPOINT": val}):
                self.assertEqual(unbound._unbound_app_label({}), "claude-code")

    def test_is_cowork_flag_non_1_is_claude_code(self):
        for val in ("0", "true", ""):
            with patch.dict("os.environ", {"CLAUDE_CODE_IS_COWORK": val}):
                self.assertEqual(unbound._unbound_app_label({}), "claude-code")

    def test_cowork_path_fallback_cwd(self):
        ev = {"cwd": "/Users/x/Library/Application Support/Claude/local-agent-mode-sessions/a/b/local_c/outputs"}
        self.assertEqual(unbound._unbound_app_label(ev), "cowork")

    def test_cowork_path_fallback_transcript_only(self):
        # cowork transcript lives in a tmpdir but the sanitized project name keeps the marker
        ev = {"cwd": "/private/tmp",
              "transcript_path": "/var/folders/x/T/claude-hostloop-plugins/h/projects/-Users-x-Library-Application-Support-Claude-local-agent-mode-sessions-a-b-local-c-outputs/s.jsonl"}
        self.assertEqual(unbound._unbound_app_label(ev), "cowork")

    def test_missing_fields_default_to_claude_code(self):
        self.assertEqual(unbound._unbound_app_label({}), "claude-code")
        self.assertEqual(unbound._unbound_app_label({"cwd": None, "transcript_path": None}), "claude-code")


class TestResolvePluginMcpConfigRegistry(unittest.TestCase):
    """Registry-driven resolution: the hook must read a plugin's .mcp.json from
    where Claude loads it (installed_plugins.json + known_marketplaces.json), which
    for a `directory` marketplace is the live clone -- not the lagging cache snapshot.
    """

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name)
        self.plugins_root = self.root / "plugins"
        self.cache = self.plugins_root / "cache"
        self.cache.mkdir(parents=True)

    def tearDown(self):
        self._tmp.cleanup()

    def _registries(self, installed, marketplaces):
        _write_json(self.plugins_root / "installed_plugins.json", {"version": 2, "plugins": installed})
        _write_json(self.plugins_root / "known_marketplaces.json", marketplaces)

    @staticmethod
    def _http(url):
        return {"type": "http", "url": url}

    def test_directory_marketplace_resolves_server_absent_from_cache(self):
        # The exact reported scenario, structurally: installPath -> a stale cache
        # snapshot missing a server; the live source (installLocation/plugins/<plugin>)
        # has it. Resolves via the conventional layout, no marketplace.json needed.
        _make_plugin(
            self.cache, "localmkt", "toolkit", "0.1.0",
            {".mcp.json": {"mcpServers": {"alpha-mcp": self._http("https://proxy.example.com/rpc?f=alpha")}}},
            in_use=True,
        )
        install_path = self.cache / "localmkt" / "toolkit" / "0.1.0"
        clone = self.root / "clone"
        _write_json(clone / "plugins" / "toolkit" / ".mcp.json", {"mcpServers": {
            "alpha-mcp": self._http("https://proxy.example.com/rpc?f=alpha"),
            "beta-mcp": self._http("https://proxy.example.com/rpc?f=beta"),
        }})
        self._registries(
            {"toolkit@localmkt": [{"scope": "user", "installPath": str(install_path)}]},
            {"localmkt": {"source": {"source": "directory", "path": str(clone)}, "installLocation": str(clone)}},
        )
        cfg = unbound._resolve_plugin_mcp_config("plugin_toolkit_beta-mcp", cache_dir=self.cache)
        self.assertEqual(cfg, self._http("https://proxy.example.com/rpc?f=beta"))
        # legacy cache-only path still misses it (proves the fix is what closed the gap)
        self.assertIsNone(unbound._resolve_plugin_mcp_config_from_cache(
            "plugin_toolkit_beta-mcp", cache_dir=self.cache))

    def test_directory_marketplace_multiple_plugins_selects_correct_one(self):
        # Mirrors a real directory marketplace with several sibling plugins (as in
        # the reported case). Cache snapshots are stale; the live clone is complete.
        clone = self.root / "clone"
        installed = {}
        for name, servers in (("coding", {"c1-mcp": "coding/c1"}),
                              ("toolkit", {"alpha-mcp": "toolkit/alpha"}),
                              ("search", {"s1-mcp": "search/s1"})):
            _make_plugin(self.cache, "localmkt", name, "0.1.0",
                         {".mcp.json": {"mcpServers": {k: self._http("https://x/%s" % v) for k, v in servers.items()}}},
                         in_use=True)
            installed["%s@localmkt" % name] = [{"installPath": str(self.cache / "localmkt" / name / "0.1.0")}]
        # live clone: toolkit gains a beta-mcp that never made it into the cache
        _write_json(clone / "plugins" / "coding" / ".mcp.json", {"mcpServers": {"c1-mcp": self._http("https://x/coding/c1")}})
        _write_json(clone / "plugins" / "toolkit" / ".mcp.json", {"mcpServers": {
            "alpha-mcp": self._http("https://x/toolkit/alpha"), "beta-mcp": self._http("https://x/toolkit/beta")}})
        _write_json(clone / "plugins" / "search" / ".mcp.json", {"mcpServers": {"s1-mcp": self._http("https://x/search/s1")}})
        self._registries(installed,
                         {"localmkt": {"source": {"source": "directory", "path": str(clone)}, "installLocation": str(clone)}})
        # the cache-absent server resolves to the RIGHT plugin
        self.assertEqual(unbound._resolve_plugin_mcp_config("plugin_toolkit_beta-mcp", cache_dir=self.cache),
                         self._http("https://x/toolkit/beta"))
        # a sibling plugin's server still resolves (no cross-contamination)
        self.assertEqual(unbound._resolve_plugin_mcp_config("plugin_search_s1-mcp", cache_dir=self.cache),
                         self._http("https://x/search/s1"))

    def test_directory_marketplace_manifest_declared_path(self):
        # Non-standard layout: plugin source is declared in marketplace.json, and
        # there is NO conventional plugins/<plugin> dir -> the manifest path resolves.
        clone = self.root / "clone"
        _write_json(clone / "custom" / "loc" / ".mcp.json",
                    {"mcpServers": {"s": self._http("https://declared.example/mcp")}})
        _write_json(clone / ".claude-plugin" / "marketplace.json", {"name": "mk", "plugins": [
            {"name": "p", "source": {"source": "directory", "path": "custom/loc"}}]})
        self._registries({"p@mk": [{"installPath": str(self.cache / "mk" / "p" / "0.1.0")}]},
                         {"mk": {"source": {"source": "directory", "path": str(clone)}, "installLocation": str(clone)}})
        self.assertEqual(unbound._resolve_plugin_mcp_config("plugin_p_s", cache_dir=self.cache),
                         self._http("https://declared.example/mcp"))

    def test_conventional_dir_missing_server_does_not_stop_search(self):
        # The conventional plugins/<plugin> dir exists but holds OTHER servers, not
        # the requested one; the manifest-declared path defines it and the cache
        # lacks it. Resolution must not stop at the first populated dir.
        _make_plugin(self.cache, "mk", "p", "1.0.0",
                     {".mcp.json": {"mcpServers": {"other": self._http("https://other.example/mcp")}}}, in_use=True)
        install_path = self.cache / "mk" / "p" / "1.0.0"
        clone = self.root / "clone"
        _write_json(clone / "plugins" / "p" / ".mcp.json",
                    {"mcpServers": {"other": self._http("https://other.example/mcp")}})
        _write_json(clone / "custom" / "loc" / ".mcp.json",
                    {"mcpServers": {"wanted": self._http("https://wanted.example/mcp")}})
        _write_json(clone / ".claude-plugin" / "marketplace.json", {"name": "mk", "plugins": [
            {"name": "p", "source": {"source": "directory", "path": "custom/loc"}}]})
        self._registries({"p@mk": [{"installPath": str(install_path)}]},
                         {"mk": {"source": {"source": "directory", "path": str(clone)}, "installLocation": str(clone)}})
        self.assertEqual(unbound._resolve_plugin_mcp_config("plugin_p_wanted", cache_dir=self.cache),
                         self._http("https://wanted.example/mcp"))

    def test_entry_with_no_forwardable_fields_does_not_stop_search(self):
        # An earlier candidate has the server key but nothing to forward
        # (`_extract_mcp_server_fields` returns None). A later candidate (manifest-
        # declared) defines it and the cache lacks it, so resolution keeps looking.
        _make_plugin(self.cache, "mk", "p", "1.0.0",
                     {".mcp.json": {"mcpServers": {"s": {"headers": {"x": "y"}}}}}, in_use=True)
        install_path = self.cache / "mk" / "p" / "1.0.0"
        clone = self.root / "clone"
        _write_json(clone / "plugins" / "p" / ".mcp.json", {"mcpServers": {"s": {"headers": {"x": "y"}}}})
        _write_json(clone / "custom" / "loc" / ".mcp.json",
                    {"mcpServers": {"s": self._http("https://declared.example/mcp")}})
        _write_json(clone / ".claude-plugin" / "marketplace.json", {"name": "mk", "plugins": [
            {"name": "p", "source": {"source": "directory", "path": "custom/loc"}}]})
        self._registries({"p@mk": [{"installPath": str(install_path)}]},
                         {"mk": {"source": {"source": "directory", "path": str(clone)}, "installLocation": str(clone)}})
        self.assertEqual(unbound._resolve_plugin_mcp_config("plugin_p_s", cache_dir=self.cache),
                         self._http("https://declared.example/mcp"))

    def test_colliding_keys_in_one_dir_is_ambiguous(self):
        # Two server keys in ONE .mcp.json mangle to the same candidate with different
        # configs. All keys are considered (like the cache path) -> ambiguous -> None.
        clone = self.root / "clone"
        _write_json(clone / "plugins" / "p" / ".mcp.json", {"mcpServers": {
            "s.x": self._http("https://a.example/mcp"),  # -> plugin_p_s_x
            "s_x": self._http("https://b.example/mcp"),  # -> plugin_p_s_x
        }})
        self._registries({"p@mk": [{"installPath": str(self.cache / "none")}]},
                         {"mk": {"source": {"source": "directory", "path": str(clone)}, "installLocation": str(clone)}})
        self.assertIsNone(unbound._resolve_plugin_mcp_config("plugin_p_s_x", cache_dir=self.cache))

    def test_registry_ambiguous_candidate_returns_none(self):
        # Two (plugin, server) pairs mangle to the same candidate with DIFFERENT
        # configs -> ambiguous -> None (never guess).
        clone = self.root / "clone"
        _write_json(clone / "plugins" / "a_b" / ".mcp.json", {"mcpServers": {"c": self._http("https://a.example/mcp")}})
        _write_json(clone / "plugins" / "a" / ".mcp.json", {"mcpServers": {"b_c": self._http("https://b.example/mcp")}})
        self._registries(
            {"a_b@mk": [{"installPath": str(self.cache / "z1")}], "a@mk": [{"installPath": str(self.cache / "z2")}]},
            {"mk": {"source": {"source": "directory", "path": str(clone)}, "installLocation": str(clone)}})
        self.assertIsNone(unbound._resolve_plugin_mcp_config("plugin_a_b_c", cache_dir=self.cache))

    def test_prefers_live_source_over_stale_cache_same_key(self):
        # No manifest -> exercises the conventional plugins/<plugin> fallback layout.
        _make_plugin(self.cache, "mk", "p", "1.0.0",
                     {".mcp.json": {"mcpServers": {"s": self._http("https://old.example/mcp")}}}, in_use=True)
        install_path = self.cache / "mk" / "p" / "1.0.0"
        clone = self.root / "clone"
        _write_json(clone / "plugins" / "p" / ".mcp.json", {"mcpServers": {"s": self._http("https://new.example/mcp")}})
        self._registries({"p@mk": [{"installPath": str(install_path)}]},
                         {"mk": {"source": {"source": "directory", "path": str(clone)}, "installLocation": str(clone)}})
        self.assertEqual(unbound._resolve_plugin_mcp_config("plugin_p_s", cache_dir=self.cache),
                         self._http("https://new.example/mcp"))

    def test_github_marketplace_reads_installpath(self):
        _make_plugin(self.cache, "official", "ghp", "unknown",
                     {".mcp.json": {"mcpServers": {"ghp": self._http("https://gh.example/mcp")}}})
        install_path = self.cache / "official" / "ghp" / "unknown"
        self._registries({"ghp@official": [{"installPath": str(install_path)}]},
                         {"official": {"source": {"source": "github", "repo": "x/y"},
                                       "installLocation": str(self.plugins_root / "marketplaces" / "official")}})
        self.assertEqual(unbound._resolve_plugin_mcp_config("plugin_ghp_ghp", cache_dir=self.cache),
                         self._http("https://gh.example/mcp"))

    def test_manifest_source_path_traversal_rejected(self):
        # marketplace.json points the plugin source outside installLocation: reject
        # the escape and fall back to the safe installPath copy, never read evil.
        _make_plugin(self.cache, "mk", "p", "1.0.0",
                     {".mcp.json": {"mcpServers": {"s": self._http("https://safe.example/mcp")}}}, in_use=True)
        install_path = self.cache / "mk" / "p" / "1.0.0"
        clone = self.root / "clone"
        clone.mkdir(parents=True)
        _write_json(self.root / "evil" / "plugins" / "p" / ".mcp.json",
                    {"mcpServers": {"s": self._http("https://evil.example/mcp")}})
        _write_json(clone / ".claude-plugin" / "marketplace.json", {"name": "mk", "plugins": [
            {"name": "p", "source": {"source": "directory", "path": "../evil/plugins/p"}}]})
        self._registries({"p@mk": [{"installPath": str(install_path)}]},
                         {"mk": {"source": {"source": "directory", "path": str(clone)}, "installLocation": str(clone)}})
        self.assertEqual(unbound._resolve_plugin_mcp_config("plugin_p_s", cache_dir=self.cache),
                         self._http("https://safe.example/mcp"))

    def test_plugin_in_cache_but_not_registry_falls_back(self):
        _make_plugin(self.cache, "mk", "orphan", "1.0.0",
                     {".mcp.json": {"mcpServers": {"orphan": self._http("https://orphan.example/mcp")}}}, in_use=True)
        self._registries({"other@mk": [{"installPath": str(self.cache / "mk" / "other" / "1.0.0")}]},
                         {"mk": {"source": {"source": "github", "repo": "x/y"}, "installLocation": "/x"}})
        self.assertEqual(unbound._resolve_plugin_mcp_config("plugin_orphan_orphan", cache_dir=self.cache),
                         self._http("https://orphan.example/mcp"))

    def test_registries_absent_uses_cache(self):
        _make_plugin(self.cache, "mk", "p", "1.0.0",
                     {".mcp.json": {"mcpServers": {"p": self._http("https://c.example/mcp")}}}, in_use=True)
        self.assertEqual(unbound._resolve_plugin_mcp_config("plugin_p_p", cache_dir=self.cache),
                         self._http("https://c.example/mcp"))


if __name__ == "__main__":
    unittest.main()
