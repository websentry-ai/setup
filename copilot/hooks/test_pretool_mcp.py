"""
Integration tests for Copilot PreToolUse MCP identification + telemetry.

Driven through process_pre_tool_use / main() (the outermost layer) — assertions
are on the RETURNED dict, never on internal helpers. No network: send_to_hook_api
and report_error_to_gateway are patched. Mirrors the harness in
claude-code/hooks/test_identity.py (sibling `unbound` module, unittest, tmpdir +
patch.object for LOG_DIR / POLICY_CACHE_FILE / config paths).

Covers:
  - both surfaces (VS Code camelCase + CLI snake_case) resolve identically
  - cwd resolution via event cwd AND via the SessionStart-cwd fallback
  - COPILOT_HOME override
  - flat top-level server form
  - unresolved bare tool is allowed (return {}) while still emitting telemetry
  - infra fail-open (resolved call, gateway {}) honors policy_check_failure_action
  - never-crash on garbage/oversized/missing input
  - telemetry categories on each path + resolution-budget isolation
"""

import json
import os
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import patch

import unbound


def _fresh_cache():
    """A present, non-stale policy cache so resolved tools reach the API and
    native-file tools aren't force-pulled."""
    return {
        'last_synced': datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ'),
        'tools_to_check': ['Read', 'Write', 'Edit', 'Bash'],
        'policy_check_failure_action': 'allow',
    }


class _Base(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())

        # Redirect all hook state into the tmpdir.
        self.audit_log = self.tmp / "agent-audit.log"
        self.policy_cache = self.tmp / ".policy_cache.json"
        self._patchers = [
            patch.object(unbound, "LOG_DIR", self.tmp),
            patch.object(unbound, "AUDIT_LOG", self.audit_log),
            patch.object(unbound, "ERROR_LOG", self.tmp / "error.log"),
            patch.object(unbound, "POLICY_CACHE_FILE", self.policy_cache),
            patch.object(unbound, "LAST_REPORT_FILE", self.tmp / ".last_error_report"),
            # No network, ever.
            patch.object(unbound, "send_to_hook_api", return_value={}),
            patch.object(unbound, "report_error_to_gateway"),
        ]
        for p in self._patchers:
            p.start()
            self.addCleanup(p.stop)

        self.policy_cache.write_text(json.dumps(_fresh_cache()), encoding="utf-8")

        # MCP config the hook will read. Tests point _copilot_mcp_config_paths
        # here unless they specifically exercise path resolution.
        self.mcp_config = self.tmp / "mcp-config.json"

    def _point_config_paths_at(self, *paths):
        return patch.object(unbound, "_copilot_mcp_config_paths", lambda cwd=None: list(paths))

    def _write_mcp(self, data):
        self.mcp_config.write_text(json.dumps(data), encoding="utf-8")

    @property
    def mock_api(self):
        return unbound.send_to_hook_api

    @property
    def mock_telemetry(self):
        return unbound.report_error_to_gateway

    def _telemetry_categories(self):
        return [kw.get('category') for _, kw in self.mock_telemetry.call_args_list]


class TestResolutionBothSurfaces(_Base):
    """A configured `github` server resolves `github-create_issue` identically on
    both surfaces, and the resolved MCP tool reaches the gateway as
    mcp__github__create_issue."""

    def setUp(self):
        super().setUp()
        self._write_mcp({"servers": {"github": {"command": "github-mcp"}}})
        self._cp = self._point_config_paths_at(self.mcp_config)
        self._cp.start()
        self.addCleanup(self._cp.stop)

    def _run(self, event):
        with patch.object(unbound, "send_to_hook_api", return_value={}) as api:
            result = unbound.process_pre_tool_use(event, "api-key")
        return result, api

    def test_cli_snake_case_resolves(self):
        event = {
            "hook_event_name": "PreToolUse",
            "session_id": "s1",
            "tool_name": "github-create_issue",
            "tool_input": {"title": "x"},
        }
        result, api = self._run(event)
        sent = api.call_args[0][0]
        self.assertEqual(sent['pre_tool_use_data']['tool_name'], 'mcp__github__create_issue')
        self.assertEqual(result, {})  # gateway returned {} → allow

    def test_vscode_camel_case_resolves(self):
        event = {
            "hookEventName": "PreToolUse",
            "sessionId": "s1",
            "toolName": "github-create_issue",
            "toolArgs": {"title": "x"},
        }
        result, api = self._run(event)
        sent = api.call_args[0][0]
        self.assertEqual(sent['pre_tool_use_data']['tool_name'], 'mcp__github__create_issue')
        self.assertEqual(result, {})

    def test_both_surfaces_emit_same_canonical(self):
        cli = {"tool_name": "github-create_issue", "session_id": "s1"}
        vs = {"toolName": "github-create_issue", "sessionId": "s1"}
        with patch.object(unbound, "send_to_hook_api", return_value={}) as api:
            unbound.process_pre_tool_use(cli, "k")
            cli_sent = api.call_args[0][0]['pre_tool_use_data']['tool_name']
        with patch.object(unbound, "send_to_hook_api", return_value={}) as api:
            unbound.process_pre_tool_use(vs, "k")
            vs_sent = api.call_args[0][0]['pre_tool_use_data']['tool_name']
        self.assertEqual(cli_sent, vs_sent)
        self.assertEqual(cli_sent, 'mcp__github__create_issue')

    def test_resolved_emits_resolved_telemetry(self):
        self.mock_telemetry.reset_mock()
        unbound.process_pre_tool_use(
            {"tool_name": "github-create_issue", "session_id": "s1"}, "k"
        )
        self.assertIn('copilot_mcp_resolved', self._telemetry_categories())

    def test_mcp_double_underscore_form_resolves(self):
        # The self-delimiting mcp__ form short-circuits before config lookup.
        event = {"tool_name": "mcp__github__create_issue", "session_id": "s1"}
        with patch.object(unbound, "send_to_hook_api", return_value={}) as api:
            unbound.process_pre_tool_use(event, "k")
            sent = api.call_args[0][0]
        self.assertEqual(sent['pre_tool_use_data']['tool_name'], 'mcp__github__create_issue')


class TestCwdFallback(_Base):
    """Workspace-scoped server resolves via event cwd, and via the SessionStart
    cwd fallback when PreToolUse omits cwd."""

    def setUp(self):
        super().setUp()
        # Workspace config under a project dir; resolution must find it via cwd.
        self.project = self.tmp / "project"
        (self.project).mkdir()
        (self.project / ".mcp.json").write_text(
            json.dumps({"mcpServers": {"ws": {"command": "ws-mcp"}}}), encoding="utf-8"
        )

    def test_resolves_via_event_cwd(self):
        event = {"tool_name": "ws-do_thing", "session_id": "s1", "cwd": str(self.project)}
        with patch.object(unbound, "send_to_hook_api", return_value={}) as api:
            unbound.process_pre_tool_use(event, "k")
            sent = api.call_args[0][0]
        self.assertEqual(sent['pre_tool_use_data']['tool_name'], 'mcp__ws__do_thing')

    def test_resolves_via_session_start_cwd_when_pretool_omits_cwd(self):
        # Log a SessionStart carrying cwd (via main()), then a PreToolUse with NO cwd.
        with patch("sys.stdin") as stdin:
            stdin.read.return_value = json.dumps({
                "hook_event_name": "SessionStart",
                "session_id": "s1",
                "cwd": str(self.project),
            })
            with patch.object(unbound, "_check_self_update"), \
                 patch.object(unbound, "_dispatch_discovery"), \
                 patch("builtins.print"):
                unbound.main()

        # Sanity: the helper recovers it.
        self.assertEqual(unbound.get_session_start_cwd("s1"), str(self.project))

        event = {"tool_name": "ws-do_thing", "session_id": "s1"}  # no cwd
        with patch.object(unbound, "send_to_hook_api", return_value={}) as api:
            unbound.process_pre_tool_use(event, "k")
            sent = api.call_args[0][0]
        self.assertEqual(sent['pre_tool_use_data']['tool_name'], 'mcp__ws__do_thing')


class TestCopilotHomeOverride(_Base):
    """COPILOT_HOME relocates the CLI config dir; the server there resolves."""

    def test_copilot_home_override_resolves(self):
        reloc = self.tmp / "relocated-copilot"
        reloc.mkdir()
        (reloc / "mcp-config.json").write_text(
            json.dumps({"mcpServers": {"relo": {"command": "relo-mcp"}}}), encoding="utf-8"
        )
        # Do NOT patch _copilot_mcp_config_paths — exercise real resolution.
        # Pin home to tmp and set COPILOT_HOME so _copilot_cli_config_dir wins.
        with patch.object(unbound.Path, "home", staticmethod(lambda: self.tmp)), \
             patch.dict(os.environ, {"COPILOT_HOME": str(reloc)}), \
             patch.object(unbound, "send_to_hook_api", return_value={}) as api:
            event = {"tool_name": "relo-go", "session_id": "s1"}
            unbound.process_pre_tool_use(event, "k")
            sent = api.call_args[0][0]
        self.assertEqual(sent['pre_tool_use_data']['tool_name'], 'mcp__relo__go')


class TestFlatTopLevelForm(_Base):
    """Flat (unwrapped) top-level server form resolves."""

    def test_flat_form_resolves(self):
        self._write_mcp({"github": {"command": "github-mcp"}})
        with self._point_config_paths_at(self.mcp_config), \
             patch.object(unbound, "send_to_hook_api", return_value={}) as api:
            event = {"tool_name": "github-create_issue", "session_id": "s1"}
            unbound.process_pre_tool_use(event, "k")
            sent = api.call_args[0][0]
        self.assertEqual(sent['pre_tool_use_data']['tool_name'], 'mcp__github__create_issue')

    def test_flat_form_ignores_scalar_and_non_server_objects(self):
        # `inputs` (VS Code block) and a scalar must NOT be treated as servers,
        # so a tool named after them stays unresolved (allow when flag OFF).
        self._write_mcp({"inputs": {"foo": "bar"}, "version": "1", "github": {"command": "c"}})
        with self._point_config_paths_at(self.mcp_config), \
             patch.object(unbound, "send_to_hook_api", return_value={}) as api:
            # `inputs-x` shares the `inputs` prefix but inputs isn't a server.
            unbound.process_pre_tool_use({"tool_name": "inputs-x", "session_id": "s1"}, "k")
            # Unresolved → no API call.
            self.assertFalse(api.called)

    def test_flat_form_inputs_block_with_command_is_not_a_server(self):
        # A VS Code `inputs` metadata block can itself carry a `command` key; it
        # must NOT mint a phantom `inputs` server, while a real sibling server
        # alongside it still resolves.
        self._write_mcp({
            "inputs": {"command": "echo", "args": ["${input:token}"]},
            "$schema": "https://example/schema.json",
            "github": {"command": "github-mcp"},
        })
        # The `inputs` block must not appear as a parsed server.
        with self._point_config_paths_at(self.mcp_config):
            servers = unbound.read_copilot_mcp_servers()
        self.assertNotIn("inputs", servers)
        self.assertIn("github", servers)

        # A tool named after the phantom `inputs` server stays unresolved (no
        # API call); the real `github` server still resolves to canonical form.
        with self._point_config_paths_at(self.mcp_config), \
             patch.object(unbound, "send_to_hook_api", return_value={}) as api:
            unbound.process_pre_tool_use({"tool_name": "inputs-do_thing", "session_id": "s1"}, "k")
            self.assertFalse(api.called)  # phantom server not minted → unresolved

        with self._point_config_paths_at(self.mcp_config), \
             patch.object(unbound, "send_to_hook_api", return_value={}) as api:
            unbound.process_pre_tool_use({"tool_name": "github-create_issue", "session_id": "s1"}, "k")
            sent = api.call_args[0][0]
        self.assertEqual(sent['pre_tool_use_data']['tool_name'], 'mcp__github__create_issue')


class TestUnresolvedIsAllowed(_Base):
    """An unresolved bare tool is ALLOWED (return {}) — identical to pre-PR
    behavior. Identification + telemetry are observe-only; no deny is issued.
    Known built-ins stay out of the unresolved telemetry (noise reduction)."""

    def _run(self, event, config):
        if config is not None:
            self._write_mcp(config)
        paths = (self.mcp_config,) if config is not None else ()
        with self._point_config_paths_at(*paths), \
             patch.object(unbound, "send_to_hook_api", return_value={}) as api:
            return unbound.process_pre_tool_use(event, "k"), api

    def test_unresolved_with_config_allows(self):
        # A genuinely-unknown tool on an MCP-configured machine is NOT denied.
        result, api = self._run(
            {"tool_name": "totally-unknown-mcp-tool", "session_id": "s1"},
            {"servers": {"github": {"command": "c"}}},
        )
        self.assertEqual(result, {})
        self.assertFalse(api.called)  # unresolved → no gateway call

    def test_unresolved_no_config_allows(self):
        # No MCP configured at all → cannot be an MCP call → allow.
        result, _ = self._run({"tool_name": "weird-thing", "session_id": "s1"}, None)
        self.assertEqual(result, {})

    def test_known_builtin_allows_with_config(self):
        # `read_file` is a known built-in; allowed even when MCP configured.
        result, _ = self._run(
            {"tool_name": "read_file", "session_id": "s1", "tool_input": {"filePath": "/x"}},
            {"servers": {"github": {"command": "c"}}},
        )
        self.assertEqual(result, {})

    def test_vscode_agent_builtins_allow_with_config(self):
        # The expanded VS Code agent-mode built-in set (read-only search, test
        # running, notebook editing, repo/task meta — both camel & snake
        # variants) is allowed when MCP is configured.
        builtins = [
            "fetch", "fetch_webpage", "semantic_search", "codebase", "usages",
            "findTestFiles", "runTests", "run_tests", "get_errors",
            "test_search", "test_failure", "githubRepo", "runTasks",
            "runCommands", "open_simple_browser", "editNotebook",
            "runNotebookCell", "edit_notebook", "run_notebook_cell",
        ]
        for tool in builtins:
            result, _ = self._run(
                {"tool_name": tool, "session_id": "s1"},
                {"servers": {"github": {"command": "c"}}},
            )
            self.assertEqual(result, {}, f"{tool} should be allowed")

    def test_known_builtin_emits_no_unresolved_telemetry(self):
        # A known built-in must not register as unresolved-with-config (noise).
        self.mock_telemetry.reset_mock()
        self._run(
            {"tool_name": "semantic_search", "session_id": "s1"},
            {"servers": {"github": {"command": "c"}}},
        )
        self.assertNotIn('copilot_mcp_unresolved_with_config', self._telemetry_categories())

    def test_unresolved_with_config_still_emits_telemetry(self):
        # Identification telemetry ships regardless: the unresolved (allowed)
        # case still emits copilot_mcp_unresolved_with_config for the soak.
        self.mock_telemetry.reset_mock()
        self._run(
            {"tool_name": "totally-unknown-mcp-tool", "session_id": "s1"},
            {"servers": {"github": {"command": "c"}}},
        )
        self.assertIn('copilot_mcp_unresolved_with_config', self._telemetry_categories())


class TestInfraVsIdentity(_Base):
    """A RESOLVED MCP call where the gateway is unreachable ({}) must honor
    policy_check_failure_action — the infra fail-open/closed path, distinct from
    the identification path (an unresolved tool, which simply allows)."""

    def setUp(self):
        super().setUp()
        self._write_mcp({"servers": {"github": {"command": "c"}}})
        self._cp = self._point_config_paths_at(self.mcp_config)
        self._cp.start()
        self.addCleanup(self._cp.stop)

    def test_resolved_gateway_down_block_action_blocks_with_infra_reason(self):
        # failure-action = block → infra fail-CLOSED with the infra reason.
        self.policy_cache.write_text(json.dumps({
            **_fresh_cache(), 'policy_check_failure_action': 'block',
        }), encoding="utf-8")
        with patch.object(unbound, "send_to_hook_api", return_value={}):
            result = unbound.process_pre_tool_use(
                {"tool_name": "github-create_issue", "session_id": "s1"}, "k"
            )
        self.assertEqual(result.get('permissionDecision'), 'deny')
        self.assertEqual(
            result['permissionDecisionReason'], unbound.POLICY_CHECK_FAILURE_BLOCK_REASON
        )

    def test_resolved_gateway_down_allow_action_allows(self):
        # failure-action = allow (default) → infra fail-OPEN.
        with patch.object(unbound, "send_to_hook_api", return_value={}):
            result = unbound.process_pre_tool_use(
                {"tool_name": "github-create_issue", "session_id": "s1"}, "k"
            )
        self.assertEqual(result, {})


class TestNeverCrash(_Base):
    """The hook must never raise on customer machines."""

    def test_oversized_config_does_not_crash(self):
        # Real resolution path (no _copilot_mcp_config_paths patch) over a >1MB file.
        big = self.tmp / "huge-mcp-config.json"
        big.write_text("{" + '"x":1,' * 200000 + '"github":{"command":"c"}}', encoding="utf-8")
        with self._point_config_paths_at(big), \
             patch.object(unbound, "send_to_hook_api", return_value={}):
            result = unbound.process_pre_tool_use(
                {"tool_name": "github-create_issue", "session_id": "s1"}, "k"
            )
        self.assertIsInstance(result, dict)  # skipped (too big) → unresolved → {}

    def test_garbage_config_does_not_crash(self):
        self.mcp_config.write_text("{ this is not json ::: ", encoding="utf-8")
        with self._point_config_paths_at(self.mcp_config), \
             patch.object(unbound, "send_to_hook_api", return_value={}):
            result = unbound.process_pre_tool_use(
                {"tool_name": "github-create_issue", "session_id": "s1"}, "k"
            )
        self.assertIsInstance(result, dict)

    def test_missing_cwd_and_no_config_does_not_crash(self):
        with self._point_config_paths_at(), \
             patch.object(unbound, "send_to_hook_api", return_value={}):
            result = unbound.process_pre_tool_use({"tool_name": "whatever"}, "k")
        self.assertIsInstance(result, dict)

    def test_malformed_event_does_not_crash(self):
        with self._point_config_paths_at():
            result = unbound.process_pre_tool_use({}, "k")
        self.assertIsInstance(result, dict)

    def test_main_session_start_garbage_does_not_crash(self):
        with patch("sys.stdin") as stdin:
            stdin.read.return_value = "not json at all"
            with patch("builtins.print") as pr:
                unbound.main()
            pr.assert_called()  # emitted {} and returned


class TestTelemetryCategories(_Base):
    """Each resolution outcome emits its stable category (names only)."""

    def test_unresolved_no_config_category(self):
        self.mock_telemetry.reset_mock()
        with self._point_config_paths_at(), \
             patch.object(unbound, "send_to_hook_api", return_value={}):
            unbound.process_pre_tool_use({"tool_name": "weird-thing", "session_id": "s1"}, "k")
        self.assertIn('copilot_mcp_unresolved_no_config', self._telemetry_categories())

    def test_unresolved_with_config_category(self):
        self.mock_telemetry.reset_mock()
        self._write_mcp({"servers": {"github": {"command": "c"}}})
        with self._point_config_paths_at(self.mcp_config), \
             patch.object(unbound, "send_to_hook_api", return_value={}):
            unbound.process_pre_tool_use({"tool_name": "unknown-xyz", "session_id": "s1"}, "k")
        self.assertIn('copilot_mcp_unresolved_with_config', self._telemetry_categories())

    def test_resolved_category(self):
        self.mock_telemetry.reset_mock()
        self._write_mcp({"servers": {"github": {"command": "c"}}})
        with self._point_config_paths_at(self.mcp_config), \
             patch.object(unbound, "send_to_hook_api", return_value={}):
            unbound.process_pre_tool_use({"tool_name": "github-x", "session_id": "s1"}, "k")
        self.assertIn('copilot_mcp_resolved', self._telemetry_categories())

    def test_telemetry_payload_contains_only_names_not_args(self):
        # The redaction discipline: the telemetry message must not carry args.
        self.mock_telemetry.reset_mock()
        self._write_mcp({"servers": {"github": {"command": "c"}}})
        with self._point_config_paths_at(self.mcp_config), \
             patch.object(unbound, "send_to_hook_api", return_value={}):
            unbound.process_pre_tool_use(
                {"tool_name": "github-x", "session_id": "s1",
                 "tool_input": {"secret_token": "sk-shouldnotappear"}},
                "k",
            )
        for args, _ in self.mock_telemetry.call_args_list:
            self.assertNotIn("sk-shouldnotappear", args[0])


class TestResolutionTelemetryBudgetIsolation(unittest.TestCase):
    """Resolution telemetry must use a SEPARATE rate-limit budget so it can never
    suppress a genuine error/bypass report. Exercises the REAL
    report_error_to_gateway + _should_report against real (tmpdir) throttle
    files; only the network POST is stubbed (counted, never sent)."""

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self._patchers = [
            patch.object(unbound, "LOG_DIR", self.tmp),
            patch.object(unbound, "ERROR_LOG", self.tmp / "error.log"),
            patch.object(unbound, "LAST_REPORT_FILE", self.tmp / ".last_error_report"),
            patch.object(unbound, "LAST_RESOLUTION_REPORT_FILE", self.tmp / ".last_resolution_report"),
            # Stub only the actual network POST so we count sends without curl.
            # report_error_to_gateway / _should_report run for real.
            patch.object(unbound, "_post_error_payload"),
        ]
        for p in self._patchers:
            p.start()
            self.addCleanup(p.stop)

    @property
    def _post(self):
        return unbound._post_error_payload

    def test_resolution_telemetry_does_not_consume_error_budget(self):
        # 1) Routine resolution telemetry fires (consuming ONLY its own budget).
        unbound._report_mcp_resolution(
            "copilot_mcp_resolved", "github-x", {"tool_name": "github-x"}, "k"
        )
        self.assertEqual(self._post.call_count, 1)

        # 2) A genuine error/bypass report — issued immediately after, well
        #    within the 60s window — must STILL go out. If resolution telemetry
        #    shared the error budget, this would be throttled (regression).
        unbound.report_error_to_gateway(
            "Hook bypassed_due_to_failure: gateway unreachable",
            category="bypassed_due_to_failure",
            api_key="k",
        )
        self.assertEqual(
            self._post.call_count, 2,
            "real error report was suppressed by resolution telemetry's budget",
        )

    def test_resolution_budget_self_throttles_independently(self):
        # Resolution telemetry still rate-limits itself at 1/60s on its own file.
        for _ in range(3):
            unbound._report_mcp_resolution(
                "copilot_mcp_resolved", "github-x", {"tool_name": "github-x"}, "k"
            )
        self.assertEqual(self._post.call_count, 1)

    def test_error_budget_does_not_consume_resolution_budget(self):
        # Symmetric: a real error report must not starve resolution telemetry.
        unbound.report_error_to_gateway("real error", category="general", api_key="k")
        self.assertEqual(self._post.call_count, 1)
        unbound._report_mcp_resolution(
            "copilot_mcp_resolved", "github-x", {"tool_name": "github-x"}, "k"
        )
        self.assertEqual(
            self._post.call_count, 2,
            "resolution telemetry was suppressed by the error budget",
        )


class TestCleanupPreservesSessionStart(unittest.TestCase):
    """cleanup_old_logs must preserve the current session's SessionStart record
    so the cwd/model fallback survives a very long single session."""

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self._patchers = [
            patch.object(unbound, "AUDIT_LOG", self.tmp / "agent-audit.log"),
            patch.object(unbound, "ERROR_LOG", self.tmp / "error.log"),
            patch.object(unbound, "AUDIT_LOG_TOTAL_LIMIT", 100),
        ]
        for p in self._patchers:
            p.start()
            self.addCleanup(p.stop)

    def test_long_single_session_keeps_session_start_cwd_and_model(self):
        unbound.append_to_audit_log({"event": {
            "hook_event_name": "SessionStart", "session_id": "s1",
            "cwd": "/proj", "model": "gpt-x",
        }})
        for i in range(150):
            unbound.append_to_audit_log({"event": {
                "hook_event_name": "PreToolUse", "session_id": "s1", "seq": i,
            }})

        unbound.cleanup_old_logs()

        # The SessionStart-derived fallbacks must still resolve.
        self.assertEqual(unbound.get_session_start_cwd("s1"), "/proj")
        self.assertEqual(unbound.get_session_start_model("s1"), "gpt-x")
        # Still bounded: the tail window plus the preserved SessionStart.
        self.assertEqual(len(unbound.load_existing_logs()), 101)

    def test_long_session_with_session_start_in_tail_is_unchanged(self):
        # If SessionStart already falls inside the tail window, no duplication.
        for i in range(150):
            unbound.append_to_audit_log({"event": {
                "hook_event_name": "PreToolUse", "session_id": "s1", "seq": i,
            }})
        unbound.append_to_audit_log({"event": {
            "hook_event_name": "SessionStart", "session_id": "s1",
            "cwd": "/late", "model": "m",
        }})

        unbound.cleanup_old_logs()

        logs = unbound.load_existing_logs()
        self.assertEqual(len(logs), 100)
        starts = [
            l for l in logs
            if l.get("event", {}).get("hook_event_name") == "SessionStart"
        ]
        self.assertEqual(len(starts), 1)


if __name__ == "__main__":
    unittest.main()
