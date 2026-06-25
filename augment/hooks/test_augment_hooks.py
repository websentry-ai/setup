"""End-to-end behavior tests for the Augment hook integration.

Tested at the outermost boundaries:
  - PreToolUse decision mapping (process_pre_tool_use) — the load-bearing
    fail-open + deny-only contract.
  - Stop audit exchange (process_stop_event / build_llm_exchange).
  - Settings merge (setup.configure_augment_settings) and clear.
  - MDM managed settings (mdm/setup.setup_managed_hooks / clear / detect).

Gateway/network is mocked at the curl boundary (send_to_hook_api / send_to_api /
notify_setup_complete) so no real HTTP is made.
"""

import importlib.util
import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock
from unittest.mock import patch

import unbound
import setup


def _load_mdm():
    spec = importlib.util.spec_from_file_location(
        "augment_mdm_setup", str(Path(__file__).parent / "mdm" / "setup.py")
    )
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


class _HomeTmp(unittest.TestCase):
    """Base: redirect Path.home() to a temp dir so hook/audit/cache files are
    isolated, and reset unbound's cached api key."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.home = Path(self._tmp.name)
        self.addCleanup(self._tmp.cleanup)
        self._home_patch = patch.object(Path, "home", return_value=self.home)
        self._home_patch.start()
        self.addCleanup(self._home_patch.stop)
        # Re-point module-level path constants that were bound at import time.
        self._consts = patch.multiple(
            unbound,
            AUDIT_LOG=self.home / ".augment" / "hooks" / "agent-audit.log",
            ERROR_LOG=self.home / ".augment" / "hooks" / "error.log",
            LAST_REPORT_FILE=self.home / ".augment" / "hooks" / ".last_error_report",
            POLICY_CACHE_FILE=self.home / ".augment" / "hooks" / ".policy_cache.json",
            _APPROVAL_MARKER_FILE=self.home / ".augment" / "hooks" / ".approval_pending",
            IDENTITY_CACHE_PATH=self.home / ".unbound" / "identity.json",
        )
        self._consts.start()
        self.addCleanup(self._consts.stop)
        unbound._cached_api_key = "sk-test"
        # Never probe the real device serial in tests.
        self._serial = patch.object(unbound, "_device_serial", return_value=None)
        self._serial.start()
        self.addCleanup(self._serial.stop)


# --------------------------------------------------------------------------- #
# PreToolUse decision mapping + fail-open                                      #
# --------------------------------------------------------------------------- #
class TestPreToolDecisionMapping(_HomeTmp):
    def _pre(self, gateway_response, event=None, failure_action="allow"):
        """Run process_pre_tool_use with the gateway returning gateway_response.
        A None gateway_response simulates an unreachable/empty gateway."""
        event = event or {
            "hook_event_name": "PreToolUse",
            "session_id": "conv-1",
            "tool_name": "launch-process",
            "tool_input": {"command": "ls -la"},
            "is_mcp_tool": False,
            "context": {"userEmail": "a@b.com", "modelName": "augment-default"},
        }
        # Seed a fresh policy cache so the fast path doesn't suppress the call,
        # and so the failure-action is what we set.
        unbound.save_policy_cache(tools_to_check=["launch-process"],
                                  policy_check_failure_action=failure_action)
        with patch.object(unbound, "send_to_hook_api", return_value=(gateway_response or {})), \
             patch.object(unbound, "report_error_to_gateway"):
            return unbound.process_pre_tool_use(event, "sk-test")

    def test_allow_returns_empty(self):
        """allow -> {} (never force-allow)."""
        out = self._pre({"decision": "allow"})
        self.assertEqual(out, {})

    def test_allow_with_additional_context_has_no_permission_decision(self):
        """Even with additionalContext, allow emits no permissionDecision."""
        out = self._pre({"decision": "allow", "additionalContext": "fyi"})
        self.assertNotIn("hookSpecificOutput", out)
        self.assertEqual(out, {})

    def test_deny_emits_permission_decision_deny(self):
        out = self._pre({"decision": "deny", "reason": "blocked by policy"})
        hso = out["hookSpecificOutput"]
        self.assertEqual(hso["hookEventName"], "PreToolUse")
        self.assertEqual(hso["permissionDecision"], "deny")
        self.assertEqual(hso["permissionDecisionReason"], "blocked by policy")

    def test_warn_is_delegated_returns_empty(self):
        """WARN -> {} (delegated to native toolPermissions ask-user)."""
        out = self._pre({"decision": "warn", "reason": "careful"})
        self.assertEqual(out, {})

    def test_ask_returns_empty(self):
        out = self._pre({"decision": "ask", "reason": "?"})
        self.assertEqual(out, {})

    def test_unexpected_decision_does_not_deny(self):
        """Any non-deny, non-allow decision returns empty (only true BLOCK denies)."""
        out = self._pre({"decision": "something-new", "reason": "x"})
        self.assertEqual(out, {})

    def test_gateway_unreachable_fails_open(self):
        """Empty/unreachable gateway with default failure-action -> allow ({})."""
        out = self._pre(None, failure_action="allow")
        self.assertEqual(out, {})

    def test_gateway_unreachable_block_policy_denies(self):
        """The ONLY non-fail-open path: cached policy_check_failure_action=block."""
        out = self._pre(None, failure_action="block")
        self.assertEqual(out["hookSpecificOutput"]["permissionDecision"], "deny")

    def test_block_policy_only_fires_when_cache_says_so(self):
        """D5: gateway down + a BLOCK *policy decision* is still allowed unless the
        cached failure-action is 'block'. A gateway that returns deny is a real
        block; a gateway that returns nothing with failure-action allow is not."""
        out = self._pre(None, failure_action="allow")
        self.assertEqual(out, {})

    def test_app_label_is_byte_exact_augment(self):
        captured = {}

        def _capture(body, key):
            captured["body"] = body
            return {"decision": "allow"}

        event = {
            "hook_event_name": "PreToolUse", "session_id": "c",
            "tool_name": "launch-process", "tool_input": {"command": "ls"},
            "is_mcp_tool": False,
        }
        unbound.save_policy_cache(tools_to_check=["launch-process"])
        with patch.object(unbound, "send_to_hook_api", side_effect=_capture):
            unbound.process_pre_tool_use(event, "sk-test")
        self.assertEqual(captured["body"]["unbound_app_label"], "augment")
        # byte-exact
        self.assertEqual(
            json.dumps(captured["body"]["unbound_app_label"]), '"augment"'
        )

    def test_model_from_context_model_name(self):
        captured = {}

        def _capture(body, key):
            captured["body"] = body
            return {"decision": "allow"}

        event = {
            "hook_event_name": "PreToolUse", "session_id": "c",
            "tool_name": "launch-process", "tool_input": {"command": "ls"},
            "is_mcp_tool": False, "context": {"modelName": "gpt-X"},
        }
        unbound.save_policy_cache(tools_to_check=["launch-process"])
        with patch.object(unbound, "send_to_hook_api", side_effect=_capture):
            unbound.process_pre_tool_use(event, "sk-test")
        self.assertEqual(captured["body"]["model"], "gpt-X")

    def test_model_defaults_to_auto(self):
        captured = {}

        def _capture(body, key):
            captured["body"] = body
            return {"decision": "allow"}

        event = {
            "hook_event_name": "PreToolUse", "session_id": "c",
            "tool_name": "launch-process", "tool_input": {"command": "ls"},
            "is_mcp_tool": False,
        }
        unbound.save_policy_cache(tools_to_check=["launch-process"])
        with patch.object(unbound, "send_to_hook_api", side_effect=_capture):
            unbound.process_pre_tool_use(event, "sk-test")
        self.assertEqual(captured["body"]["model"], "auto")

    def test_user_prompts_empty(self):
        captured = {}

        def _capture(body, key):
            captured["body"] = body
            return {"decision": "allow"}

        event = {
            "hook_event_name": "PreToolUse", "session_id": "c",
            "tool_name": "launch-process", "tool_input": {"command": "ls"},
            "is_mcp_tool": False,
        }
        unbound.save_policy_cache(tools_to_check=["launch-process"])
        with patch.object(unbound, "send_to_hook_api", side_effect=_capture):
            unbound.process_pre_tool_use(event, "sk-test")
        self.assertEqual(captured["body"]["user_prompts"], [])
        self.assertEqual(captured["body"]["messages"], [])

    def test_tool_use_id_forwarded(self):
        captured = {}

        def _capture(body, key):
            captured["body"] = body
            return {"decision": "allow"}

        event = {
            "hook_event_name": "PreToolUse", "session_id": "c",
            "tool_name": "launch-process", "tool_input": {"command": "ls"},
            "is_mcp_tool": False, "tool_use_id": "tuid-42",
        }
        unbound.save_policy_cache(tools_to_check=["launch-process"])
        with patch.object(unbound, "send_to_hook_api", side_effect=_capture):
            unbound.process_pre_tool_use(event, "sk-test")
        self.assertEqual(captured["body"]["pre_tool_use_data"]["tool_use_id"], "tuid-42")

    def test_mcp_detected_via_flag_and_metadata(self):
        captured = {}

        def _capture(body, key):
            captured["body"] = body
            return {"decision": "allow"}

        event = {
            "hook_event_name": "PreToolUse", "session_id": "c",
            "tool_name": "some-mcp-call", "tool_input": {"q": 1},
            "is_mcp_tool": True,
            "mcp_metadata": {
                "mcpExecutedToolServerName": "github",
                "mcpExecutedToolName": "create_issue",
            },
        }
        with patch.object(unbound, "send_to_hook_api", side_effect=_capture):
            unbound.process_pre_tool_use(event, "sk-test")
        meta = captured["body"]["pre_tool_use_data"]["metadata"]
        self.assertEqual(meta["mcp_server"], "github")
        self.assertEqual(meta["mcp_tool"], "create_issue")
        # MCP command is the stringified tool_input.
        self.assertEqual(captured["body"]["pre_tool_use_data"]["command"],
                         json.dumps({"q": 1}))

    def test_mcp_without_mcp_metadata_still_sent_to_gateway(self):
        """Auggie 0.30.0 ships NO mcp_metadata (the includeMCPMetadata flag is
        intentionally unseeded). An MCP tool (is_mcp_tool: true) with no
        mcp_metadata is STILL evaluated by the gateway — sent with is_mcp_tool +
        the raw tool_name, just without server/tool resolution. Must not crash."""
        captured = {}

        def _capture(body, key):
            captured["body"] = body
            return {"decision": "allow"}

        event = {
            "hook_event_name": "PreToolUse", "session_id": "c",
            "tool_name": "some-mcp-call", "tool_input": {"q": 1},
            "is_mcp_tool": True,
            # no mcp_metadata key at all
        }
        with patch.object(unbound, "send_to_hook_api", side_effect=_capture):
            out = unbound.process_pre_tool_use(event, "sk-test")  # must not raise
        # The gateway WAS called (the request body was captured).
        self.assertIn("body", captured)
        pre = captured["body"]["pre_tool_use_data"]
        # Raw tool_name forwarded; is_mcp_tool flag preserved in metadata.
        self.assertEqual(pre["tool_name"], "some-mcp-call")
        self.assertTrue(pre["metadata"]["is_mcp_tool"])
        # No server/tool resolution happened (no mcp_metadata to read).
        self.assertNotIn("mcp_server", pre["metadata"])
        self.assertNotIn("mcp_tool", pre["metadata"])
        # Command is still the stringified tool_input.
        self.assertEqual(pre["command"], json.dumps({"q": 1}))
        # Allow decision -> empty hook output (fail-open / non-blocking).
        self.assertEqual(out, {})
        self.assertEqual(captured["body"]["unbound_app_label"], "augment")

    def test_corrupted_stdin_is_noop(self):
        """A non-JSON stdin must not blow up main(); it prints suppressOutput."""
        with patch("sys.stdin") as stdin, \
             patch("builtins.print") as pr, \
             patch.object(unbound, "get_api_key", return_value="sk-test"):
            stdin.read.return_value = "{not json"
            unbound.main()
        out = pr.call_args[0][0]
        self.assertIn("suppressOutput", out)

    def test_missing_api_key_pretool_fails_open(self):
        """No API key -> send_to_hook_api returns {} -> fail-open allow."""
        event = {
            "hook_event_name": "PreToolUse", "session_id": "c",
            "tool_name": "launch-process", "tool_input": {"command": "ls"},
            "is_mcp_tool": False,
        }
        unbound.save_policy_cache(tools_to_check=["launch-process"],
                                  policy_check_failure_action="allow")
        out = unbound.process_pre_tool_use(event, "")  # empty key
        self.assertEqual(out, {})


# --------------------------------------------------------------------------- #
# extract_command_for_pretool                                                 #
# --------------------------------------------------------------------------- #
class TestExtractCommand(unittest.TestCase):
    def test_launch_process_command(self):
        ev = {"tool_name": "launch-process", "tool_input": {"command": "echo hi"}}
        self.assertEqual(unbound.extract_command_for_pretool(ev), "echo hi")

    def test_launch_process_command_line_fallback(self):
        ev = {"tool_name": "launch-process", "tool_input": {"commandLine": "echo hi"}}
        self.assertEqual(unbound.extract_command_for_pretool(ev), "echo hi")

    def test_file_tool_path(self):
        ev = {"tool_name": "save-file", "tool_input": {"path": "/tmp/x"}}
        self.assertEqual(unbound.extract_command_for_pretool(ev), "/tmp/x")

    def test_file_tool_file_path_fallback(self):
        ev = {"tool_name": "str-replace-editor", "tool_input": {"filePath": "/tmp/y"}}
        self.assertEqual(unbound.extract_command_for_pretool(ev), "/tmp/y")

    def test_mcp_tool_stringifies_input(self):
        ev = {"tool_name": "x", "is_mcp_tool": True, "tool_input": {"a": 1}}
        self.assertEqual(unbound.extract_command_for_pretool(ev), json.dumps({"a": 1}))

    def test_unknown_tool_falls_back_to_json(self):
        ev = {"tool_name": "novel-tool", "tool_input": {"k": "v"}}
        self.assertEqual(unbound.extract_command_for_pretool(ev), json.dumps({"k": "v"}))

    def test_non_dict_tool_input_does_not_raise(self):
        ev = {"tool_name": "launch-process", "tool_input": "oops"}
        out = unbound.extract_command_for_pretool(ev)
        self.assertIsInstance(out, str)


# --------------------------------------------------------------------------- #
# Stop audit exchange                                                         #
# --------------------------------------------------------------------------- #
class TestStopExchange(_HomeTmp):
    def test_build_exchange_from_conversation_and_post_log(self):
        # Seed one PostToolUse entry in the audit log for the session.
        unbound.append_to_audit_log({
            "timestamp": "2026-01-01T00:00:00Z",
            "session_id": "conv-9",
            "event": {
                "hook_event_name": "PostToolUse",
                "session_id": "conv-9",
                "tool_name": "launch-process",
                "tool_input": {"command": "ls"},
                "tool_output": "file1\nfile2",
                "tool_error": None,
                "file_changes": [],
                "tool_use_id": "tuid-9",
            },
        })
        stop_event = {
            "hook_event_name": "Stop",
            "session_id": "conv-9",
            "conversation": {
                "userPrompt": "list files",
                "agentTextResponse": "Here are the files.",
                "agentCodeResponse": ["print('done')"],
            },
        }
        captured = {}
        with patch.object(unbound, "send_to_api", side_effect=lambda ex, key: captured.update(ex) or True):
            unbound.process_stop_event(stop_event, "sk-test")

        self.assertEqual(captured["conversation_id"], "conv-9")
        self.assertEqual(captured["messages"][0], {"role": "user", "content": "list files"})
        assistant = captured["messages"][1]
        self.assertEqual(assistant["role"], "assistant")
        self.assertIn("Here are the files.", assistant["content"])
        self.assertIn("print('done')", assistant["content"])
        tu = assistant["tool_use"][0]
        self.assertEqual(tu["tool_name"], "launch-process")
        self.assertEqual(tu["tool_output"], "file1\nfile2")
        self.assertEqual(tu["tool_use_id"], "tuid-9")

    def test_audit_endpoint_is_augment(self):
        captured = {}

        def fake_run(cmd, **kw):
            # The auth header is now passed off-argv as `-H @<tmpfile>`, so the
            # URL is no longer guaranteed to be the last argv element. Find the
            # gateway URL among the args by prefix instead of by position.
            captured["cmd"] = cmd
            captured["url"] = next(
                a for a in cmd
                if isinstance(a, str) and a.startswith("http")
            )

            class R:
                returncode = 0
                stdout = b""
                stderr = b""
            return R()

        with patch.object(subprocess, "run", side_effect=fake_run):
            unbound.send_to_api({"conversation_id": "c", "messages": []}, "sk-test")
        self.assertTrue(captured["url"].endswith("/v1/hooks/augment"))

    def test_audit_404_is_noop_stop_never_blocks(self):
        """A 404 audit endpoint (Phase 1) -> send_to_api False -> Stop no-ops and
        process_stop_event does not raise."""
        def fake_run(cmd, **kw):
            class R:
                returncode = 22  # curl -f on HTTP 404
                stdout = b""
                stderr = b"404"
            return R()

        stop_event = {
            "hook_event_name": "Stop", "session_id": "c",
            "conversation": {"userPrompt": "hi", "agentTextResponse": "hello"},
        }
        with patch.object(subprocess, "run", side_effect=fake_run):
            # Must not raise.
            unbound.process_stop_event(stop_event, "sk-test")

    def test_exchange_none_when_no_assistant_content(self):
        """Fewer than 2 messages -> no exchange -> send_to_api not called."""
        stop_event = {
            "hook_event_name": "Stop", "session_id": "lonely",
            "conversation": {"userPrompt": "hi"},  # no assistant response, no tools
        }
        with patch.object(unbound, "send_to_api") as send:
            unbound.process_stop_event(stop_event, "sk-test")
            send.assert_not_called()

    def test_stop_with_no_conversation_emits_dropped_turn_signal(self):
        """Auggie 0.30.0 ships NO `conversation` on Stop (the includeConversationData
        metadata flag is intentionally unseeded). With accumulated PostToolUse
        records but no conversation, build_llm_exchange returns None (messages < 2),
        so the audit is a no-op AND the visible `dropped_turn` signal fires — the
        turn is never silently lost. Must not crash."""
        unbound.append_to_audit_log({
            "timestamp": "2026-01-01T00:00:00Z",
            "session_id": "no-conv",
            "event": {
                "hook_event_name": "PostToolUse",
                "session_id": "no-conv",
                "tool_name": "launch-process",
                "tool_input": {"command": "ls"},
                "tool_output": "out",
            },
        })
        stop_event = {"hook_event_name": "Stop", "session_id": "no-conv"}  # no conversation
        with patch.object(unbound, "send_to_api") as send, \
             patch.object(unbound, "log_error") as log_err:
            unbound.process_stop_event(stop_event, "sk-test")  # must not raise
            send.assert_not_called()
        # The dropped_turn signal fired with the right category.
        self.assertTrue(log_err.called)
        category = log_err.call_args[0][1] if len(log_err.call_args[0]) > 1 else log_err.call_args[1].get("category")
        self.assertEqual(category, "dropped_turn")


# --------------------------------------------------------------------------- #
# main() dispatch (session_id alias, no UserPromptSubmit)                      #
# --------------------------------------------------------------------------- #
class TestMainDispatch(_HomeTmp):
    def _run_main(self, event):
        with patch("sys.stdin") as stdin, \
             patch("builtins.print") as pr, \
             patch.object(unbound, "get_api_key", return_value="sk-test"):
            stdin.read.return_value = json.dumps(event)
            unbound.main()
        return pr

    def test_conversation_id_aliased_to_session_id(self):
        captured = {}
        event = {
            "hook_event_name": "PreToolUse",
            "conversation_id": "abc-123",
            "tool_name": "launch-process",
            "tool_input": {"command": "ls"},
            "is_mcp_tool": False,
        }
        unbound.save_policy_cache(tools_to_check=["launch-process"])

        def _capture(body, key):
            captured["body"] = body
            return {"decision": "allow"}

        with patch("sys.stdin") as stdin, patch("builtins.print"), \
             patch.object(unbound, "get_api_key", return_value="sk-test"), \
             patch.object(unbound, "send_to_hook_api", side_effect=_capture):
            stdin.read.return_value = json.dumps(event)
            unbound.main()
        self.assertEqual(captured["body"]["conversation_id"], "abc-123")

    def test_session_start_returns_empty_object(self):
        pr = None
        with patch.object(unbound, "_check_self_update"), \
             patch.object(unbound, "_dispatch_discovery"):
            pr = self._run_main({"hook_event_name": "SessionStart", "conversation_id": "s"})
        self.assertEqual(pr.call_args[0][0], "{}")


# --------------------------------------------------------------------------- #
# setup.configure_augment_settings — merge + idempotency + preservation       #
# --------------------------------------------------------------------------- #
class TestSettingsMerge(_HomeTmp):
    def setUp(self):
        super().setUp()
        self.settings_path = self.home / ".augment" / "settings.json"
        # Force POSIX command form (not windows) deterministically.
        self._plat = patch.object(setup.platform, "system", return_value="Darwin")
        self._plat.start()
        self.addCleanup(self._plat.stop)

    def _read(self):
        return json.loads(self.settings_path.read_text())

    def test_writes_hooks_and_tool_permissions(self):
        self.assertTrue(setup.configure_augment_settings())
        data = self._read()
        # All five Augment events, no UserPromptSubmit.
        self.assertEqual(
            set(data["hooks"].keys()),
            {"PreToolUse", "PostToolUse", "Stop", "SessionStart", "SessionEnd"},
        )
        self.assertNotIn("UserPromptSubmit", data["hooks"])
        # No per-hook metadata is seeded — Auggie 0.30.0 warns on any metadata
        # flag and the data is unused until Phase 2 (deferral note in setup.py).
        pre = data["hooks"]["PreToolUse"][0]["hooks"][0]
        self.assertEqual(pre["timeout"], 15000)
        self.assertNotIn("metadata", pre)
        # Every seeded hook entry (all five events) is metadata-free and matches
        # the minimal {type, command, timeout} shape.
        for event, items in data["hooks"].items():
            for item in items:
                for hook in item["hooks"]:
                    self.assertNotIn("metadata", hook, f"{event} hook carries metadata")
                    self.assertEqual(
                        set(hook.keys()), {"type", "command", "timeout"},
                        f"{event} hook has unexpected keys: {hook}",
                    )
        # PreToolUse/PostToolUse keep their ".*" matcher; Stop/SessionStart/
        # SessionEnd carry no matcher.
        self.assertEqual(data["hooks"]["PreToolUse"][0]["matcher"], ".*")
        self.assertEqual(data["hooks"]["PostToolUse"][0]["matcher"], ".*")
        self.assertNotIn("matcher", data["hooks"]["Stop"][0])
        self.assertNotIn("matcher", data["hooks"]["SessionStart"][0])
        self.assertNotIn("matcher", data["hooks"]["SessionEnd"][0])
        # toolPermissions seeded.
        names = {r["toolName"] for r in data["toolPermissions"]}
        self.assertEqual(names, {"launch-process", "mcp:.*"})
        for r in data["toolPermissions"]:
            self.assertEqual(r["permission"], {"type": "ask-user"})

    def test_idempotent_three_runs(self):
        for _ in range(3):
            self.assertTrue(setup.configure_augment_settings())
        data = self._read()
        # Exactly one of our hook entries per event.
        for event in data["hooks"]:
            cmds = [
                h.get("command")
                for item in data["hooks"][event]
                for h in item.get("hooks", [])
            ]
            our = [c for c in cmds if c == str(self.home / ".augment" / "hooks" / "unbound.py")]
            self.assertEqual(len(our), 1, f"{event}: {our}")
        # Exactly one of each of our rules.
        ids = [(r.get("toolName"), r.get("shellInputRegex")) for r in data["toolPermissions"]]
        self.assertEqual(len(ids), len(set(ids)))
        self.assertEqual(len(data["toolPermissions"]), 2)

    def test_preserves_foreign_hooks_and_permissions(self):
        self.settings_path.parent.mkdir(parents=True, exist_ok=True)
        self.settings_path.write_text(json.dumps({
            "hooks": {
                "PreToolUse": [
                    {"matcher": ".*", "hooks": [{"type": "command", "command": "/usr/bin/other-hook"}]}
                ]
            },
            "toolPermissions": [
                {"toolName": "custom-tool", "eventType": "tool-call", "permission": {"type": "allow"}}
            ],
            "someForeignTopLevelKey": {"keep": True},
        }))
        self.assertTrue(setup.configure_augment_settings())
        data = self._read()
        cmds = [
            h.get("command")
            for item in data["hooks"]["PreToolUse"]
            for h in item.get("hooks", [])
        ]
        self.assertIn("/usr/bin/other-hook", cmds)
        self.assertIn(str(self.home / ".augment" / "hooks" / "unbound.py"), cmds)
        perm_names = {r["toolName"] for r in data["toolPermissions"]}
        self.assertIn("custom-tool", perm_names)
        self.assertIn("launch-process", perm_names)
        self.assertEqual(data["someForeignTopLevelKey"], {"keep": True})

    def test_corrupted_settings_not_clobbered(self):
        self.settings_path.parent.mkdir(parents=True, exist_ok=True)
        self.settings_path.write_text("{ this is not json")
        ok = setup.configure_augment_settings()
        self.assertFalse(ok)
        # The corrupt file is left untouched (not truncated to {}).
        self.assertEqual(self.settings_path.read_text(), "{ this is not json")

    def test_no_augment_dir_is_created(self):
        self.assertFalse((self.home / ".augment").exists())
        self.assertTrue(setup.configure_augment_settings())
        self.assertTrue(self.settings_path.exists())

    def test_clear_removes_our_hooks_and_rules_preserves_foreign(self):
        # Install, then add a foreign hook + rule, then clear.
        setup.configure_augment_settings()
        data = self._read()
        data["hooks"]["PreToolUse"].append(
            {"matcher": ".*", "hooks": [{"type": "command", "command": "/usr/bin/keep"}]}
        )
        data["toolPermissions"].append(
            {"toolName": "keep-tool", "eventType": "tool-call", "permission": {"type": "allow"}}
        )
        self.settings_path.write_text(json.dumps(data))

        status = setup.remove_hooks_from_settings()
        self.assertEqual(status, "cleared")
        data = self._read()
        # Our unbound.py hook gone, foreign kept.
        all_cmds = [
            h.get("command")
            for ev in data.get("hooks", {}).values()
            for item in ev
            for h in item.get("hooks", [])
        ]
        self.assertNotIn(str(self.home / ".augment" / "hooks" / "unbound.py"), all_cmds)
        self.assertIn("/usr/bin/keep", all_cmds)
        # Our rules gone, foreign kept.
        perm_names = {r["toolName"] for r in data.get("toolPermissions", [])}
        self.assertNotIn("mcp:.*", perm_names)
        self.assertIn("keep-tool", perm_names)


# --------------------------------------------------------------------------- #
# setup metrics / labels                                                      #
# --------------------------------------------------------------------------- #
class TestSetupMetrics(unittest.TestCase):
    def test_notify_setup_complete_posts_augment_tool_type(self):
        captured = {}

        def fake_run(cmd, **kw):
            captured["body"] = json.loads(kw["input"].decode())

            class R:
                returncode = 0
                stdout = b""
                stderr = b""
            return R()

        with patch.object(setup.subprocess, "run", side_effect=fake_run):
            setup.notify_setup_complete("k", "augment", backend_url="https://b")
        self.assertEqual(captured["body"]["tool_type"], "augment")
        self.assertNotIn("managed", captured["body"])

    def test_mdm_notify_includes_managed_true(self):
        mdm = _load_mdm()
        captured = {}

        def fake_run(cmd, **kw):
            captured["body"] = json.loads(kw["input"].decode())

            class R:
                returncode = 0
                stdout = b""
                stderr = b""
            return R()

        with patch.object(mdm.subprocess, "run", side_effect=fake_run):
            mdm.notify_setup_complete("k", "augment", backend_url="https://b")
        self.assertEqual(captured["body"]["tool_type"], "augment")
        self.assertTrue(captured["body"]["managed"])


# --------------------------------------------------------------------------- #
# FIX 3 (security): setup.py / mdm/setup.py keep keys OFF the curl argv        #
# --------------------------------------------------------------------------- #
class TestSetupAuthHeaderOffArgv(unittest.TestCase):
    SECRET = "sk-setup-secret-key-0987654321"

    def _assert_off_argv(self, module, run_call):
        captured = {"argv": None, "mode": None, "contents": None}

        def fake_run(cmd, **kw):
            captured["argv"] = list(cmd)
            for i, a in enumerate(cmd):
                if isinstance(a, str) and a.startswith("@") and i > 0 and cmd[i - 1] == "-H":
                    p = a[1:]
                    captured["mode"] = oct(os.stat(p).st_mode & 0o777)
                    captured["contents"] = Path(p).read_text()

            class R:
                returncode = 0
                stdout = "{}\n200" if kw.get("text") else b""
                stderr = "" if kw.get("text") else b""
            return R()

        with patch.object(module.subprocess, "run", side_effect=fake_run):
            run_call()

        for a in captured["argv"]:
            self.assertNotIn("Authorization", str(a))
            self.assertNotIn("X-API-KEY", str(a))
            self.assertNotIn(self.SECRET, str(a))
        self.assertEqual(captured["mode"], oct(0o600))
        self.assertIn(self.SECRET, captured["contents"])

    def test_setup_notify_complete_key_off_argv(self):
        self._assert_off_argv(
            setup,
            lambda: setup.notify_setup_complete(self.SECRET, "augment", backend_url="https://b"),
        )

    def test_mdm_notify_complete_key_off_argv(self):
        mdm = _load_mdm()
        self._assert_off_argv(
            mdm,
            lambda: mdm.notify_setup_complete(self.SECRET, "augment", backend_url="https://b"),
        )

    def test_mdm_fetch_api_key_privileged_key_off_argv(self):
        """The privileged admin key passed to fetch_api_key_from_mdm must never
        appear on the curl argv."""
        mdm = _load_mdm()
        self._assert_off_argv(
            mdm,
            lambda: mdm.fetch_api_key_from_mdm("https://b", None, self.SECRET, "dev-1"),
        )

    def test_mdm_fetch_api_key_url_encodes_query_params(self):
        """FIX C: device_id / app_name with reserved chars ('&', ' ', '=') must
        be percent-encoded in the query string, never injected raw."""
        mdm = _load_mdm()
        captured = {"url": None}

        def fake_run(cmd, **kw):
            # The request URL is the curl arg immediately before the `-H @<file>`
            # auth header that curl_with_auth appends last.
            for i, a in enumerate(cmd):
                if isinstance(a, str) and a.startswith("http"):
                    captured["url"] = a

            class R:
                returncode = 0
                stdout = "{}\n200"
                stderr = ""
            return R()

        with patch.object(mdm.subprocess, "run", side_effect=fake_run):
            mdm.fetch_api_key_from_mdm("https://b", "App & Co", self.SECRET, "dev=1 &2")

        url = captured["url"]
        self.assertIsNotNone(url, "curl was never invoked with a URL")
        # Raw reserved chars from the inputs must NOT appear in the query.
        query = url.split("?", 1)[1]
        self.assertNotIn("dev=1 &2", query)
        self.assertNotIn("App & Co", query)
        # Properly encoded forms are present instead.
        self.assertIn("serial_number=dev%3D1+%262", query)
        self.assertIn("app_name=App+%26+Co", query)
        self.assertIn("app_type=augment", query)

    def test_setup_backfill_http_request_bearer_off_argv(self):
        """FIX A: the backfill HTTP path (setup.py _backfill_http_request) must
        route the Authorization: Bearer <key> header off-argv via the 0600 temp
        header file — never on the curl argv."""
        headers = {
            'User-Agent': 'Unbound-Setup/test-backfill',
            'X-Unbound-Operation': 'backfill',
            'Authorization': f'Bearer {self.SECRET}',
            'Content-Type': 'application/json',
        }
        self._assert_off_argv(
            setup,
            lambda: setup._backfill_http_request("https://b/upload-url/", "POST",
                                                 headers, body=b"{}"),
        )

    def test_mdm_backfill_http_request_bearer_off_argv(self):
        """FIX A: mdm/setup.py _backfill_http_request (the privileged backfill
        path) must also keep the Bearer key off the curl argv."""
        mdm = _load_mdm()
        headers = {
            'User-Agent': 'Unbound-Setup/test-backfill',
            'X-Unbound-Operation': 'backfill',
            'Authorization': f'Bearer {self.SECRET}',
            'Content-Type': 'application/json',
        }
        self._assert_off_argv(
            mdm,
            lambda: mdm._backfill_http_request("https://b/upload-url/", "POST",
                                               headers, body=b"{}"),
        )

    def test_backfill_s3_put_no_auth_header_file(self):
        """FIX A (guardrail): a presigned S3 PUT carries NO auth header, so no
        temp header file is created and no Authorization lands on the argv."""
        captured = {"argv": None, "header_file_seen": False}

        def fake_run(cmd, **kw):
            captured["argv"] = list(cmd)
            for i, a in enumerate(cmd):
                if isinstance(a, str) and a.startswith("@") and i > 0 and cmd[i - 1] == "-H":
                    captured["header_file_seen"] = True

            class R:
                returncode = 0
                stdout = b""
                stderr = b""
            return R()

        with patch.object(setup.subprocess, "run", side_effect=fake_run):
            setup._backfill_http_request(
                "https://s3.example.com/presigned", "PUT",
                {'Content-Type': 'application/json'}, body=b"{}")
        for a in captured["argv"]:
            self.assertNotIn("Authorization", str(a))
        self.assertFalse(captured["header_file_seen"])


# --------------------------------------------------------------------------- #
# MDM managed settings + per-user gating                                       #
# --------------------------------------------------------------------------- #
class TestMdmManagedSettings(unittest.TestCase):
    def setUp(self):
        self.mdm = _load_mdm()
        self._tmp = tempfile.TemporaryDirectory()
        self.managed = Path(self._tmp.name) / "etc-augment"
        self.addCleanup(self._tmp.cleanup)
        self._dir_patch = patch.object(self.mdm, "get_managed_settings_dir", return_value=self.managed)
        self._dir_patch.start()
        self.addCleanup(self._dir_patch.stop)
        self._plat = patch.object(self.mdm.platform, "system", return_value="Linux")
        self._plat.start()
        self.addCleanup(self._plat.stop)

    def _settings(self):
        return json.loads((self.managed / "settings.json").read_text())

    def test_setup_managed_writes_hooks_and_permissions(self):
        with patch.object(self.mdm, "download_file", return_value=True):
            # The hook script is downloaded (mocked); create it so chmod succeeds.
            (self.managed / "hooks").mkdir(parents=True, exist_ok=True)
            (self.managed / "hooks" / "unbound.py").write_text("# stub")
            self.assertTrue(self.mdm.setup_managed_hooks())
        data = self._settings()
        self.assertEqual(
            set(data["hooks"].keys()),
            {"PreToolUse", "PostToolUse", "Stop", "SessionStart", "SessionEnd"},
        )
        # Managed command quotes the /etc/augment path.
        cmd = data["hooks"]["PreToolUse"][0]["hooks"][0]["command"]
        self.assertIn(str(self.managed / "hooks" / "unbound.py"), cmd)
        # No per-hook metadata is seeded (Auggie 0.30.0 warns on any flag;
        # deferred to Phase 2). Every entry is just {type, command, timeout}.
        for event, items in data["hooks"].items():
            for item in items:
                for hook in item["hooks"]:
                    self.assertNotIn("metadata", hook, f"{event} hook carries metadata")
                    self.assertEqual(
                        set(hook.keys()), {"type", "command", "timeout"},
                        f"{event} hook has unexpected keys: {hook}",
                    )
        # PreToolUse/PostToolUse keep ".*"; Stop/SessionStart/SessionEnd have none.
        self.assertEqual(data["hooks"]["PreToolUse"][0]["matcher"], ".*")
        self.assertEqual(data["hooks"]["PostToolUse"][0]["matcher"], ".*")
        self.assertNotIn("matcher", data["hooks"]["Stop"][0])
        names = {r["toolName"] for r in data["toolPermissions"]}
        self.assertEqual(names, {"launch-process", "mcp:.*"})

    def test_managed_merges_hooks_preserves_foreign(self):
        """FIX 1: settings.json is shared with the org's own Augment config, so
        setup MERGES per-entry — a foreign PreToolUse hook is preserved and ours
        is appended once alongside it; other top-level keys survive."""
        self.managed.mkdir(parents=True, exist_ok=True)
        (self.managed / "settings.json").write_text(json.dumps({
            "hooks": {"PreToolUse": [{"matcher": "x", "hooks": [{"command": "/usr/bin/foreign-hook"}]}]},
            "foreignKey": 7,
        }))
        with patch.object(self.mdm, "download_file", return_value=True):
            (self.managed / "hooks").mkdir(parents=True, exist_ok=True)
            (self.managed / "hooks" / "unbound.py").write_text("# stub")
            self.assertTrue(self.mdm.setup_managed_hooks())
        data = self._settings()
        cmds = [h.get("command") for item in data["hooks"]["PreToolUse"] for h in item["hooks"]]
        # Foreign hook preserved (NOT clobbered).
        self.assertIn("/usr/bin/foreign-hook", cmds)
        # Ours added alongside it.
        ours = f'"{self.managed / "hooks" / "unbound.py"}"'
        self.assertIn(ours, cmds)
        # Other top-level key preserved.
        self.assertEqual(data["foreignKey"], 7)

    def test_setup_managed_idempotent(self):
        with patch.object(self.mdm, "download_file", return_value=True):
            (self.managed / "hooks").mkdir(parents=True, exist_ok=True)
            (self.managed / "hooks" / "unbound.py").write_text("# stub")
            self.mdm.setup_managed_hooks()
            self.mdm.setup_managed_hooks()
        data = self._settings()
        # Single hook per event, single set of rules.
        self.assertEqual(len(data["hooks"]["PreToolUse"]), 1)
        self.assertEqual(len(data["toolPermissions"]), 2)

    def test_detect_install_state(self):
        # fresh: no settings.json
        self.assertEqual(self.mdm.detect_install_state(), "fresh")
        # persisted: settings + hook script
        (self.managed / "hooks").mkdir(parents=True, exist_ok=True)
        (self.managed / "settings.json").write_text("{}")
        (self.managed / "hooks" / "unbound.py").write_text("x")
        self.assertEqual(self.mdm.detect_install_state(), "persisted")
        # tampered: settings present, hook script missing
        (self.managed / "hooks" / "unbound.py").unlink()
        self.assertEqual(self.mdm.detect_install_state(), "tampered")

    def test_clear_managed_removes_hooks_and_permissions(self):
        with patch.object(self.mdm, "download_file", return_value=True):
            (self.managed / "hooks").mkdir(parents=True, exist_ok=True)
            (self.managed / "hooks" / "unbound.py").write_text("# stub")
            self.mdm.setup_managed_hooks()
        # Add a foreign top-level key to verify it survives clear.
        data = self._settings()
        data["foreign"] = 1
        (self.managed / "settings.json").write_text(json.dumps(data))

        self.assertEqual(self.mdm.clear_managed_hooks(), "cleared")
        data = self._settings()
        self.assertNotIn("hooks", data)
        self.assertNotIn("toolPermissions", data)
        self.assertEqual(data["foreign"], 1)

    def _seed_foreign_settings(self):
        """Write a settings.json carrying foreign content of all three kinds:
        a foreign PreToolUse hook, a foreign toolPermissions rule, and a foreign
        top-level key."""
        self.managed.mkdir(parents=True, exist_ok=True)
        (self.managed / "settings.json").write_text(json.dumps({
            "hooks": {
                "PreToolUse": [
                    {"matcher": ".*", "hooks": [{"type": "command", "command": "/usr/bin/foreign-hook"}]}
                ]
            },
            "toolPermissions": [
                {"toolName": "foreign-tool", "eventType": "tool-call", "permission": {"type": "allow"}}
            ],
            "foreignTopLevel": {"keep": True},
        }))

    def test_install_onto_foreign_config_preserves_all_three(self):
        """FIX 1 (critical): MDM install onto a shared settings.json with a
        foreign PreToolUse hook + foreign toolPermissions rule + foreign
        top-level key preserves all three; ours is added exactly once."""
        self._seed_foreign_settings()
        ours_cmd = f'"{self.managed / "hooks" / "unbound.py"}"'
        with patch.object(self.mdm, "download_file", return_value=True):
            (self.managed / "hooks").mkdir(parents=True, exist_ok=True)
            (self.managed / "hooks" / "unbound.py").write_text("# stub")
            # Run twice to also prove the merge is idempotent (ours once).
            self.assertTrue(self.mdm.setup_managed_hooks())
            self.assertTrue(self.mdm.setup_managed_hooks())
        data = self._settings()

        pre_cmds = [h.get("command") for item in data["hooks"]["PreToolUse"] for h in item["hooks"]]
        self.assertIn("/usr/bin/foreign-hook", pre_cmds)          # foreign hook preserved
        self.assertEqual(pre_cmds.count(ours_cmd), 1)             # ours added exactly once

        perm_names = [r["toolName"] for r in data["toolPermissions"]]
        self.assertIn("foreign-tool", perm_names)                 # foreign rule preserved
        self.assertEqual(perm_names.count("launch-process"), 1)   # ours added once
        self.assertEqual(perm_names.count("mcp:.*"), 1)

        self.assertEqual(data["foreignTopLevel"], {"keep": True})  # foreign top-level preserved

    def test_clear_strips_ours_preserves_foreign_does_not_unlink(self):
        """FIX 1 (critical): MDM --clear removes only our hook/permission, leaves
        every foreign item, and does NOT unlink settings.json while foreign
        content remains."""
        self._seed_foreign_settings()
        ours_cmd = f'"{self.managed / "hooks" / "unbound.py"}"'
        with patch.object(self.mdm, "download_file", return_value=True):
            (self.managed / "hooks").mkdir(parents=True, exist_ok=True)
            (self.managed / "hooks" / "unbound.py").write_text("# stub")
            self.assertTrue(self.mdm.setup_managed_hooks())

        self.assertEqual(self.mdm.clear_managed_hooks(), "cleared")

        # File still exists (foreign content remained) — NOT unlinked.
        self.assertTrue((self.managed / "settings.json").exists())
        data = self._settings()

        pre_cmds = [h.get("command") for item in data.get("hooks", {}).get("PreToolUse", []) for h in item["hooks"]]
        self.assertNotIn(ours_cmd, pre_cmds)                       # ours gone
        self.assertIn("/usr/bin/foreign-hook", pre_cmds)          # foreign hook survives

        perm_names = {r["toolName"] for r in data.get("toolPermissions", [])}
        self.assertNotIn("launch-process", perm_names)            # ours gone
        self.assertNotIn("mcp:.*", perm_names)
        self.assertIn("foreign-tool", perm_names)                 # foreign rule survives

        self.assertEqual(data["foreignTopLevel"], {"keep": True})  # foreign top-level survives


class TestMdmRemoveUserLevelHooks(unittest.TestCase):
    """MDM strips user-level leftovers but preserves foreign hooks/rules."""

    def setUp(self):
        self.mdm = _load_mdm()
        self._tmp = tempfile.TemporaryDirectory()
        self.home = Path(self._tmp.name)
        self.addCleanup(self._tmp.cleanup)
        self._plat = patch.object(self.mdm.platform, "system", return_value="Linux")
        self._plat.start()
        self.addCleanup(self._plat.stop)
        # Run the privilege-dropped closure in-process.
        self._rau = patch.object(self.mdm, "_run_as_user", side_effect=lambda u, fn, *a, **k: fn(*a, **k))
        self._rau.start()
        self.addCleanup(self._rau.stop)

    def test_strips_unbound_preserves_foreign(self):
        settings_path = self.home / ".augment" / "settings.json"
        script_path = self.home / ".augment" / "hooks" / "unbound.py"
        script_path.parent.mkdir(parents=True, exist_ok=True)
        script_path.write_text("# our hook")
        settings_path.write_text(json.dumps({
            "hooks": {
                "PreToolUse": [
                    {"matcher": ".*", "hooks": [
                        {"type": "command", "command": str(script_path)},
                        {"type": "command", "command": "/usr/bin/foreign"},
                    ]}
                ]
            },
            "toolPermissions": [
                {"toolName": "launch-process",
                 "shellInputRegex": self.mdm._HIGH_RISK_SHELL_REGEX,
                 "eventType": "tool-call", "permission": {"type": "ask-user"}},
                {"toolName": "keep", "permission": {"type": "allow"}},
            ],
        }))

        self.mdm.remove_user_level_hooks_for_user("u", self.home)

        data = json.loads(settings_path.read_text())
        cmds = [h["command"] for item in data["hooks"]["PreToolUse"] for h in item["hooks"]]
        self.assertNotIn(str(script_path), cmds)
        self.assertIn("/usr/bin/foreign", cmds)
        perm_names = {r["toolName"] for r in data["toolPermissions"]}
        self.assertNotIn("launch-process", perm_names)
        self.assertIn("keep", perm_names)
        # Our hook script removed (JSON no longer references it).
        self.assertFalse(script_path.exists())


# --------------------------------------------------------------------------- #
# FIX D: MDM install ordering — never strip user-level hooks before managed    #
# hooks are written AND verified present                                       #
# --------------------------------------------------------------------------- #
class TestMdmInstallOrdering(unittest.TestCase):
    def setUp(self):
        self.mdm = _load_mdm()
        self._tmp = tempfile.TemporaryDirectory()
        self.home = Path(self._tmp.name)
        self.addCleanup(self._tmp.cleanup)

    def _run_main(self, managed_ok: bool, verify_ok: bool):
        """Drive mdm.main() far enough to reach the install ordering, recording
        whether remove_user_level_hooks_for_user is called. managed_ok controls
        setup_managed_hooks; verify_ok controls verify_managed_hooks_installed."""
        removed = []
        with patch.object(self.mdm, "check_admin_privileges", return_value=True), \
             patch.object(self.mdm.platform, "system", return_value="Linux"), \
             patch("sys.argv", ["setup.py", "--api-key", "admin-key"]), \
             patch.object(self.mdm, "get_device_identifier", return_value="dev-1"), \
             patch.object(self.mdm, "fetch_api_key_from_mdm", return_value="app-key"), \
             patch.object(self.mdm, "set_env_var_system_wide", return_value=(True, False)), \
             patch.object(self.mdm, "get_all_user_homes", return_value=[("u", self.home)]), \
             patch.object(self.mdm, "write_unbound_config_for_user"), \
             patch.object(self.mdm, "detect_install_state", return_value="fresh"), \
             patch.object(self.mdm, "notify_setup_complete"), \
             patch.object(self.mdm, "setup_managed_hooks", return_value=managed_ok), \
             patch.object(self.mdm, "verify_managed_hooks_installed", return_value=verify_ok), \
             patch.object(self.mdm, "remove_user_level_hooks_for_user",
                          side_effect=lambda u, h: removed.append(u)):
            self.mdm.main()
        return removed

    def test_managed_write_failure_does_not_remove_user_hooks(self):
        """FIX D: if the managed hook write FAILS, user-level hooks must NOT be
        stripped — the user stays covered by their existing hooks."""
        removed = self._run_main(managed_ok=False, verify_ok=False)
        self.assertEqual(removed, [],
                         "user-level hooks were stripped despite managed write failure")

    def test_managed_verify_failure_does_not_remove_user_hooks(self):
        """FIX D: even if setup_managed_hooks returns True, an unverifiable
        managed install (verify False) must NOT strip user-level hooks."""
        removed = self._run_main(managed_ok=True, verify_ok=False)
        self.assertEqual(removed, [],
                         "user-level hooks were stripped despite unverified managed install")

    def test_managed_written_and_verified_strips_user_hooks(self):
        """FIX D (happy path): managed hooks written AND verified present → only
        THEN are user-level hooks removed."""
        removed = self._run_main(managed_ok=True, verify_ok=True)
        self.assertEqual(removed, ["u"])


# --------------------------------------------------------------------------- #
# user-level MDM conflict gate (SystemExit(3))                                 #
# --------------------------------------------------------------------------- #
class TestUserLevelMdmGate(_HomeTmp):
    def test_managed_present_user_main_exits_3(self):
        import sys
        managed = self.home / "etc-augment"
        (managed / "hooks").mkdir(parents=True, exist_ok=True)
        (managed / "hooks" / "unbound.py").write_text("x")
        with patch.object(setup, "get_managed_settings_dir", return_value=managed), \
             patch("sys.argv", ["setup.py", "--api-key", "k"]), \
             patch.object(setup, "install_macos_certificates"):
            with self.assertRaises(SystemExit) as cm:
                setup.main()
        self.assertEqual(cm.exception.code, 3)

    def test_foreign_settings_without_our_marker_not_a_conflict(self):
        """FIX B: a machine carrying the org's OWN Augment managed config
        (a /etc/augment/settings.json that does NOT reference our unbound.py)
        must NOT be treated as an Unbound MDM install — the user-level install
        proceeds."""
        managed = self.home / "etc-augment"
        managed.mkdir(parents=True, exist_ok=True)
        # Foreign config: real hooks block, but no Unbound marker anywhere.
        (managed / "settings.json").write_text(json.dumps({
            "hooks": {"PreToolUse": [{"matcher": ".*", "hooks": [
                {"type": "command", "command": "/opt/acme/their-hook.sh"}
            ]}]}
        }))
        with patch.object(setup, "get_managed_settings_dir", return_value=managed):
            self.assertFalse(setup.check_enterprise_hooks_conflict())

    def test_our_marker_in_settings_is_a_conflict(self):
        """FIX B: when our hook command (referencing the managed unbound.py)
        appears in /etc/augment/settings.json, that IS our MDM install → skip."""
        managed = self.home / "etc-augment"
        managed.mkdir(parents=True, exist_ok=True)
        our_script = str(managed / "hooks" / "unbound.py")
        (managed / "settings.json").write_text(json.dumps({
            "hooks": {"PreToolUse": [{"matcher": ".*", "hooks": [
                {"type": "command", "command": f'"{our_script}"'}
            ]}]}
        }))
        with patch.object(setup, "get_managed_settings_dir", return_value=managed):
            self.assertTrue(setup.check_enterprise_hooks_conflict())

    def test_managed_script_file_alone_is_a_conflict(self):
        """FIX B: the managed hook script existing on disk is our marker too —
        conflict even before settings.json is consulted."""
        managed = self.home / "etc-augment"
        (managed / "hooks").mkdir(parents=True, exist_ok=True)
        (managed / "hooks" / "unbound.py").write_text("x")
        with patch.object(setup, "get_managed_settings_dir", return_value=managed):
            self.assertTrue(setup.check_enterprise_hooks_conflict())

    def test_conflict_gate_fails_closed_on_settings_read_error(self):
        """FIX B: a read/parse EXCEPTION on settings.json fails CLOSED (assume
        managed → skip), preserving the earlier hardening."""
        managed = self.home / "etc-augment"
        managed.mkdir(parents=True, exist_ok=True)
        (managed / "settings.json").write_text("{}")
        # No managed script file, so the gate falls through to reading
        # settings.json; force that read to raise.
        real_open = open

        def _boom(path, *a, **k):
            if str(path).endswith("settings.json"):
                raise OSError("read boom")
            return real_open(path, *a, **k)

        with patch.object(setup, "get_managed_settings_dir", return_value=managed), \
             patch("builtins.open", side_effect=_boom):
            self.assertTrue(setup.check_enterprise_hooks_conflict())

    def test_conflict_gate_fails_closed_on_stat_error(self):
        """FIX 4 (INFO-2): when the managed-path stat raises, the gate fails
        CLOSED (returns True) so the per-user install skips — never risks
        managed + user hooks both firing on a shared box."""
        managed = self.home / "etc-augment"
        (managed / "hooks").mkdir(parents=True, exist_ok=True)
        boom = (managed / "hooks" / "unbound.py")
        boom.write_text("x")
        with patch.object(setup, "get_managed_settings_dir", return_value=managed), \
             patch.object(setup.Path, "exists", side_effect=OSError("stat boom")):
            self.assertTrue(setup.check_enterprise_hooks_conflict())

    def test_conflict_gate_normal_path_false_when_unmanaged(self):
        """FIX 4: normal-path behavior is unchanged — a truly unmanaged box
        (no markers) still returns False so per-user setup proceeds."""
        managed = self.home / "etc-augment-empty"
        managed.mkdir(parents=True, exist_ok=True)  # exists but no markers inside
        with patch.object(setup, "get_managed_settings_dir", return_value=managed):
            self.assertFalse(setup.check_enterprise_hooks_conflict())


# --------------------------------------------------------------------------- #
# FIX 2 (W1): remove-files is always policy-evaluated (no cache fast-path)     #
# --------------------------------------------------------------------------- #
class TestRemoveFilesAlwaysEvaluated(_HomeTmp):
    def _run(self, tool_name):
        """Run process_pre_tool_use against a FRESH cache whose tools_to_check is
        empty, and report whether send_to_hook_api was reached."""
        event = {
            "hook_event_name": "PreToolUse", "session_id": "c",
            "tool_name": tool_name, "tool_input": {"path": "/tmp/x"},
            "is_mcp_tool": False,
        }
        # Fresh cache (not stale) with an EMPTY tools_to_check, so need_pull is
        # False and only the fast-path gate decides whether we reach the gateway.
        unbound.save_policy_cache(tools_to_check=[], policy_check_failure_action="allow")
        called = {"hit": False}

        def _capture(body, key):
            called["hit"] = True
            return {"decision": "allow"}

        with patch.object(unbound, "send_to_hook_api", side_effect=_capture), \
             patch.object(unbound, "report_error_to_gateway"):
            unbound.process_pre_tool_use(event, "sk-test")
        return called["hit"]

    def test_remove_files_reaches_gateway_despite_empty_cache(self):
        """remove-files (destructive) is NOT in NATIVE_FILE_TOOLS, so the fast
        path never suppresses it — it always reaches the gateway."""
        self.assertNotIn("remove-files", unbound.NATIVE_FILE_TOOLS)
        self.assertIn("remove-files", unbound.ALLOWED_NON_MCP_HOOK_NAMES)
        self.assertTrue(self._run("remove-files"))

    def test_view_is_suppressed_by_fast_path(self):
        """view (read-only) stays in NATIVE_FILE_TOOLS, so an empty fresh cache
        suppresses it (gateway not called) — contrast with remove-files."""
        self.assertIn("view", unbound.NATIVE_FILE_TOOLS)
        self.assertFalse(self._run("view"))


# --------------------------------------------------------------------------- #
# FIX 3 (security): API keys / bearer tokens stay OFF the curl argv            #
# --------------------------------------------------------------------------- #
class TestAuthHeaderOffArgv(_HomeTmp):
    SECRET = "sk-super-secret-key-1234567890"

    def _capture_argv(self, call):
        """Run `call`, capturing the curl argv passed to subprocess.run and the
        contents of the 0600 temp header file at invocation time."""
        captured = {"argv": None, "header_file": None, "header_mode": None}

        real_run = subprocess.run

        def fake_run(cmd, **kw):
            captured["argv"] = list(cmd)
            # Find the `-H @<tmpfile>` and read it back before the finally unlinks.
            for i, a in enumerate(cmd):
                if isinstance(a, str) and a.startswith("@") and i > 0 and cmd[i - 1] == "-H":
                    p = a[1:]
                    captured["header_file"] = p
                    try:
                        captured["header_mode"] = oct(os.stat(p).st_mode & 0o777)
                        captured["header_contents"] = Path(p).read_text()
                    except OSError:
                        pass

            class R:
                returncode = 0
                stdout = b"{}"
                stderr = b""
            return R()

        with patch.object(subprocess, "run", side_effect=fake_run):
            call()
        return captured

    def _assert_secret_off_argv(self, captured):
        argv = captured["argv"]
        self.assertIsNotNone(argv, "curl was never invoked")
        for a in argv:
            self.assertNotIn("Authorization", str(a))
            self.assertNotIn("X-API-KEY", str(a))
            self.assertNotIn(self.SECRET, str(a))
        # The secret lives only in the 0600 temp header file.
        self.assertIsNotNone(captured["header_file"])
        self.assertEqual(captured.get("header_mode"), oct(0o600))
        self.assertIn(self.SECRET, captured.get("header_contents", ""))

    def test_send_to_hook_api_keeps_key_off_argv(self):
        captured = self._capture_argv(
            lambda: unbound.send_to_hook_api({"x": 1}, self.SECRET)
        )
        self._assert_secret_off_argv(captured)

    def test_send_to_api_keeps_key_off_argv(self):
        captured = self._capture_argv(
            lambda: unbound.send_to_api({"conversation_id": "c", "messages": []}, self.SECRET)
        )
        self._assert_secret_off_argv(captured)

    def test_helper_deletes_temp_file_after_call(self):
        """curl_with_auth removes the 0600 temp file in its finally."""
        captured = self._capture_argv(
            lambda: unbound.send_to_hook_api({"x": 1}, self.SECRET)
        )
        self.assertFalse(Path(captured["header_file"]).exists())


# --------------------------------------------------------------------------- #
# FIX 5 (W2): tz-aware datetimes keep cache-staleness math correct             #
# --------------------------------------------------------------------------- #
class TestCacheStalenessTzAware(_HomeTmp):
    def test_fresh_cache_not_stale(self):
        unbound.save_policy_cache(tools_to_check=["launch-process"])
        cache = unbound.load_policy_cache()
        self.assertIsNotNone(cache)
        self.assertFalse(unbound.is_cache_stale(cache))

    def test_old_cache_is_stale(self):
        from datetime import datetime, timezone, timedelta
        old = (datetime.now(timezone.utc) - timedelta(seconds=unbound.CACHE_TTL_SECONDS + 60))
        cache = {"last_synced": old.isoformat() + "Z", "tools_to_check": []}
        self.assertTrue(unbound.is_cache_stale(cache))

    def test_legacy_naive_timestamp_does_not_raise(self):
        """A legacy naive on-disk timestamp (no offset) must still compare cleanly
        against the now-aware datetime.now(timezone.utc) — no TypeError."""
        from datetime import datetime, timezone
        naive_now = datetime.now(timezone.utc).replace(tzinfo=None).isoformat() + "Z"
        cache = {"last_synced": naive_now, "tools_to_check": []}
        # Fresh legacy stamp -> not stale, and crucially does not raise.
        self.assertFalse(unbound.is_cache_stale(cache))

    # --- FIX E: timestamps must emit a clean '...Z', never '...+00:00Z' --- #
    def test_last_synced_has_no_double_tz_designator_and_round_trips(self):
        """FIX E: save_policy_cache must write a clean ISO timestamp with a single
        'Z' (no malformed '+00:00Z' double designator), and is_cache_stale must
        parse the value it wrote (fresh write -> not stale)."""
        unbound.save_policy_cache(tools_to_check=["launch-process"])
        on_disk = json.loads(unbound.POLICY_CACHE_FILE.read_text())
        last_synced = on_disk["last_synced"]
        self.assertNotIn("+00:00", last_synced)
        self.assertTrue(last_synced.endswith("Z"))
        # Round-trips through the parser used in production.
        self.assertFalse(unbound.is_cache_stale({"last_synced": last_synced,
                                                  "tools_to_check": []}))

    def test_utc_now_z_helper_format(self):
        """FIX E: the shared helper emits a single 'Z' and no '+00:00'."""
        stamp = unbound._utc_now_z()
        self.assertNotIn("+00:00", stamp)
        self.assertTrue(stamp.endswith("Z"))

    def test_error_log_timestamp_has_no_double_tz_designator(self):
        """FIX E: log_error writes a clean '...Z' timestamp to error.log."""
        with patch.object(unbound, "report_error_to_gateway"):
            unbound.log_error("boom", category="general")
        line = unbound.ERROR_LOG.read_text().strip().splitlines()[-1]
        timestamp = line.split(": ", 1)[0]
        self.assertNotIn("+00:00", timestamp)
        self.assertTrue(timestamp.endswith("Z"))

    def test_legacy_malformed_timestamp_still_parses(self):
        """FIX E (back-compat): a legacy on-disk '...+00:00Z' (the old malformed
        form) must still parse — is_cache_stale tolerates it, no TypeError."""
        from datetime import datetime, timezone
        malformed = datetime.now(timezone.utc).isoformat() + "Z"  # '...+00:00Z'
        self.assertIn("+00:00Z", malformed)
        self.assertFalse(unbound.is_cache_stale({"last_synced": malformed,
                                                 "tools_to_check": []}))


# --------------------------------------------------------------------------- #
# FIX 6 (W3): empty-string command is forwarded as-is                          #
# --------------------------------------------------------------------------- #
class TestEmptyCommandGuard(unittest.TestCase):
    def test_empty_command_forwarded_not_dumped(self):
        """launch-process with command:"" forwards "" (not a tool_input dump)."""
        ev = {"tool_name": "launch-process", "tool_input": {"command": ""}}
        self.assertEqual(unbound.extract_command_for_pretool(ev), "")

    def test_missing_command_still_falls_back(self):
        """No command key at all -> the json dump fallback still applies."""
        ev = {"tool_name": "launch-process", "tool_input": {"other": "x"}}
        self.assertEqual(
            unbound.extract_command_for_pretool(ev), json.dumps({"other": "x"})
        )


# --------------------------------------------------------------------------- #
# FIX 8 (WARNING-3): no SILENT analytics drop                                  #
# --------------------------------------------------------------------------- #
class TestNoSilentDrop(_HomeTmp):
    def test_stop_with_posttool_but_no_prompt_emits_drop_signal(self):
        """A Stop that had PostToolUse records but no userPrompt (exchange None)
        emits a visible drop signal instead of silently doing nothing."""
        unbound.append_to_audit_log({
            "timestamp": "2026-01-01T00:00:00Z", "session_id": "drop-1",
            "event": {
                "hook_event_name": "PostToolUse", "session_id": "drop-1",
                "tool_name": "launch-process", "tool_input": {"command": "ls"},
                "tool_output": "x",
            },
        })
        stop_event = {"hook_event_name": "Stop", "session_id": "drop-1",
                      "conversation": {}}  # no userPrompt, no assistant text

        with patch.object(unbound, "log_error") as log_err, \
             patch.object(unbound, "send_to_api") as send:
            unbound.process_stop_event(stop_event, "sk-test")
            send.assert_not_called()                       # exchange was None
            log_err.assert_called_once()                   # visible drop signal
        msg, category = log_err.call_args[0][0], log_err.call_args[0][1]
        self.assertEqual(category, "dropped_turn")
        self.assertIn("drop-1", msg)

    def test_stop_with_no_records_and_no_prompt_stays_silent(self):
        """No PostToolUse records AND no exchange -> genuinely nothing to send,
        so no drop signal (we only warn when records existed)."""
        stop_event = {"hook_event_name": "Stop", "session_id": "empty-1",
                      "conversation": {}}
        with patch.object(unbound, "log_error") as log_err, \
             patch.object(unbound, "send_to_api") as send:
            unbound.process_stop_event(stop_event, "sk-test")
            send.assert_not_called()
            log_err.assert_not_called()


# --------------------------------------------------------------------------- #
# Bugbot FIX 1: pretool network budget fits under the 15000ms PreToolUse       #
# timeout                                                                      #
# --------------------------------------------------------------------------- #
class TestPretoolNetworkBudget(_HomeTmp):
    PRETOOL_HOOK_TIMEOUT_MS = 15000  # build_hooks_block PreToolUse timeout

    def test_pretool_curl_uses_reduced_per_attempt_timeout(self):
        """send_to_hook_api passes the reduced PRETOOL_CURL_TIMEOUT (not 20s) to
        curl, so a slow gateway cannot blow the 15000ms hook budget."""
        seen = {"timeouts": []}

        def fake_run(cmd, **kw):
            seen["timeouts"].append(kw.get("timeout"))

            class R:
                returncode = 0
                stdout = b"{}"
                stderr = b""
            return R()

        with patch.object(subprocess, "run", side_effect=fake_run):
            unbound.send_to_hook_api({"x": 1}, "sk-test")

        self.assertTrue(seen["timeouts"], "curl was never invoked")
        for t in seen["timeouts"]:
            self.assertEqual(t, unbound.PRETOOL_CURL_TIMEOUT)
        # Guard against silent regression back to the old 20s value.
        self.assertEqual(unbound.PRETOOL_CURL_TIMEOUT, 4)

    def test_worst_case_budget_is_under_pretool_hook_timeout(self):
        """attempts x per-attempt curl timeout + inter-attempt backoffs must be
        comfortably under the installed 15000ms PreToolUse hook timeout, or
        Augment kills the hook mid-request instead of letting it fail open."""
        attempts = 3            # for attempt in range(3)
        backoff_s = 0.5         # time.sleep(0.5) between attempts (attempts - 1)
        worst_case_ms = (
            attempts * unbound.PRETOOL_CURL_TIMEOUT * 1000
            + (attempts - 1) * backoff_s * 1000
        )
        self.assertLess(worst_case_ms, self.PRETOOL_HOOK_TIMEOUT_MS)

    def test_reduced_budget_does_not_break_fail_open(self):
        """A gateway returning nothing (empty result) still yields {} (allow) —
        the reduced timeout must not change fail-open behavior."""
        def fake_run(cmd, **kw):
            class R:
                returncode = 28      # curl timeout exit code
                stdout = b""
                stderr = b"timed out"
            return R()

        with patch.object(subprocess, "run", side_effect=fake_run):
            out = unbound.send_to_hook_api({"x": 1}, "sk-test")
        self.assertEqual(out, {})


# --------------------------------------------------------------------------- #
# Bugbot FIX 2: deny must merge additionalContext into                         #
# permissionDecisionReason (Augment renders only the reason on deny)           #
# --------------------------------------------------------------------------- #
class TestDenyMergesAdditionalContext(unittest.TestCase):
    def test_deny_with_reason_and_additional_context_merges_both(self):
        out = unbound.transform_response_for_claude({
            "decision": "deny",
            "reason": "blocked by policy",
            "additionalContext": "do not attempt workarounds",
        })
        decision_reason = out["hookSpecificOutput"]["permissionDecisionReason"]
        self.assertIn("blocked by policy", decision_reason)
        self.assertIn("do not attempt workarounds", decision_reason)
        self.assertEqual(
            decision_reason, "blocked by policy\n\ndo not attempt workarounds"
        )

    def test_deny_with_only_reason_is_unchanged(self):
        out = unbound.transform_response_for_claude({
            "decision": "deny",
            "reason": "blocked by policy",
        })
        self.assertEqual(
            out["hookSpecificOutput"]["permissionDecisionReason"],
            "blocked by policy",
        )

    def test_deny_with_only_additional_context_uses_it(self):
        """No reason, only additionalContext -> the agent-facing context still
        reaches the deny output (no stray leading separator)."""
        out = unbound.transform_response_for_claude({
            "decision": "deny",
            "additionalContext": "do not attempt workarounds",
        })
        self.assertEqual(
            out["hookSpecificOutput"]["permissionDecisionReason"],
            "do not attempt workarounds",
        )


if __name__ == "__main__":
    unittest.main()
