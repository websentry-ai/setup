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
            captured["url"] = cmd[-1]

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
        # Pre/Post carry per-matcher metadata flags.
        pre = data["hooks"]["PreToolUse"][0]["hooks"][0]
        self.assertEqual(pre["timeout"], 15000)
        self.assertEqual(pre["metadata"], {"includeMCPMetadata": True, "includeUserContext": True})
        stop = data["hooks"]["Stop"][0]["hooks"][0]
        self.assertEqual(stop["metadata"], {"includeConversationData": True, "includeUserContext": True})
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
        names = {r["toolName"] for r in data["toolPermissions"]}
        self.assertEqual(names, {"launch-process", "mcp:.*"})

    def test_managed_replaces_hooks_preserves_other_keys(self):
        self.managed.mkdir(parents=True, exist_ok=True)
        (self.managed / "settings.json").write_text(json.dumps({
            "hooks": {"PreToolUse": [{"matcher": "x", "hooks": [{"command": "stale"}]}]},
            "foreignKey": 7,
        }))
        with patch.object(self.mdm, "download_file", return_value=True):
            (self.managed / "hooks").mkdir(parents=True, exist_ok=True)
            (self.managed / "hooks" / "unbound.py").write_text("# stub")
            self.assertTrue(self.mdm.setup_managed_hooks())
        data = self._settings()
        # Whole hooks block replaced (no 'stale').
        cmds = [h.get("command") for item in data["hooks"]["PreToolUse"] for h in item["hooks"]]
        self.assertNotIn("stale", cmds)
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

    def test_check_conflict_true_when_managed_settings_present(self):
        managed = self.home / "etc-augment"
        managed.mkdir(parents=True, exist_ok=True)
        (managed / "settings.json").write_text("{}")
        with patch.object(setup, "get_managed_settings_dir", return_value=managed):
            self.assertTrue(setup.check_enterprise_hooks_conflict())


if __name__ == "__main__":
    unittest.main()
