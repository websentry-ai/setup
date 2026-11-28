"""Antigravity hook behavior, driven the way Antigravity runs it: the real unbound.py as a
subprocess, camelCase JSON on stdin. A fake `curl` on PATH records every request and
plays back a canned gateway verdict, so nothing reaches the network."""

import hashlib
import json
from datetime import datetime, timezone
import stat
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from tests.conftest import REPO, tool_module

HOOK = REPO / "antigravity" / "hooks" / "unbound.py"
unbound = tool_module("antigravity/hooks")

FAKE_CURL = r'''#!/usr/bin/env python3
import json, os, sys
args = sys.argv[1:]
url = next((a for a in reversed(args) if a.startswith('http')), '')
body = sys.stdin.read() if '@-' in args else ''
with open(os.environ['FAKE_CURL_LOG'], 'a') as log:
    log.write(json.dumps({'url': url, 'body': body}) + '\n')
if url.endswith('/v1/hooks/pretool'):
    sys.stdout.write(os.environ.get('FAKE_PRETOOL_RESPONSE', '{}'))
'''

CONVERSATION = "b48df887-2550-4867-b6fc-6c1ffcb11aee"


def payload(event, **extra):
    body = {
        "hookEventName": event,
        "conversationId": CONVERSATION,
        "cwd": "/work/repo",
        "workspacePaths": ["/work/repo"],
        "modelName": "gemini-4-carbon-medium",
        "lastUserInput": "tidy up the repo",
        "transcriptPath": "",
    }
    body.update(extra)
    return body


def tool_call(name, args, call_id="call_1"):
    return {"toolCall": {"id": call_id, "name": name, "args": args}, "stepIdx": 2}


class HookRun(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name)
        self.home = self.root / "home"
        self.home.mkdir()
        bin_dir = self.root / "bin"
        bin_dir.mkdir()
        curl = bin_dir / "curl"
        curl.write_text(FAKE_CURL)
        curl.chmod(curl.stat().st_mode | stat.S_IEXEC)
        self.log = self.root / "curl.log"
        self.env = {
            "HOME": str(self.home),
            "PATH": "%s:/usr/bin:/bin" % bin_dir,
            "UNBOUND_GATEWAY_URL": "http://gateway.test",
            "UNBOUND_ANTIGRAVITY_API_KEY": "key-1",
            "FAKE_CURL_LOG": str(self.log),
        }

    def run_hook(self, body, verdict=None):
        env = dict(self.env)
        if verdict is not None:
            env["FAKE_PRETOOL_RESPONSE"] = json.dumps(verdict)
        r = subprocess.run([sys.executable, str(HOOK)], input=json.dumps(body),
                           capture_output=True, text=True, timeout=60, env=env)
        self.assertEqual(r.returncode, 0, r.stderr[-400:])
        return json.loads(r.stdout)

    def requests(self, suffix):
        if not self.log.exists():
            return []
        rows = [json.loads(line) for line in self.log.read_text().splitlines()]
        return [json.loads(r["body"]) for r in rows if r["url"].endswith(suffix)]


class PreToolUseTests(HookRun):
    def test_a_shell_command_is_sent_as_bash_under_the_antigravity_label(self):
        self.run_hook(payload("PreToolUse", **tool_call(
            "run_command", {"CommandLine": "rm -rf build", "toolSummary": "clean"})))
        [sent] = self.requests("/v1/hooks/pretool")
        self.assertEqual(sent["unbound_app_label"], "antigravity")
        self.assertEqual(sent["conversation_id"], CONVERSATION)
        self.assertEqual(sent["model"], "gemini-4-carbon-medium")
        self.assertEqual(sent["pre_tool_use_data"]["tool_name"], "Bash")
        self.assertEqual(sent["pre_tool_use_data"]["command"], "rm -rf build")
        self.assertEqual(sent["pre_tool_use_data"]["tool_use_id"], "call_1")

    def test_file_tools_are_sent_as_canonical_native_tools_with_their_path(self):
        for raw, canonical in (("read_file", "Read"), ("write_file", "Write"), ("edit_file", "Edit")):
            with self.subTest(tool=raw):
                self.log.unlink(missing_ok=True)
                self.run_hook(payload("PreToolUse", **tool_call(raw, {"Path": "/work/repo/.env"})))
                sent = self.requests("/v1/hooks/pretool")[-1]["pre_tool_use_data"]
                self.assertEqual(sent["tool_name"], canonical)
                self.assertEqual(sent["metadata"]["file_path"], "/work/repo/.env")

    def test_the_verdict_is_rendered_in_antigravity_shape(self):
        call = payload("PreToolUse", **tool_call("run_command", {"CommandLine": "rm -rf /"}))
        cases = (
            ({"decision": "deny", "reason": "Blocked by policy"}, {"decision": "deny", "reason": "Blocked by policy"}),
            ({"decision": "ask", "reason": "Confirm this"}, {"decision": "force_ask", "reason": "Confirm this"}),
            ({"decision": "allow"}, {"decision": "allow"}),
        )
        for verdict, expected in cases:
            with self.subTest(verdict=verdict["decision"]):
                self.assertEqual(self.run_hook(call, verdict), expected)

    # Antigravity blocks the tool when a hook prints `{}`, so every failure must allow explicitly.
    def test_an_unreachable_gateway_allows_explicitly(self):
        self.env["PATH"] = "/usr/bin:/bin"
        self.env["UNBOUND_GATEWAY_URL"] = "http://127.0.0.1:9"
        out = self.run_hook(payload("PreToolUse", **tool_call("run_command", {"CommandLine": "ls"})))
        self.assertEqual(out, {"decision": "allow"})

    def test_unreadable_input_allows_explicitly(self):
        r = subprocess.run([sys.executable, str(HOOK)], input="not json",
                           capture_output=True, text=True, timeout=60, env=self.env)
        self.assertEqual((r.returncode, json.loads(r.stdout)), (0, {"decision": "allow"}))

    def write_policy_cache(self, tools_to_check):
        cache = self.home / ".gemini" / "antigravity-hooks" / ".policy_cache.json"
        cache.parent.mkdir(parents=True, exist_ok=True)
        cache.write_text(json.dumps({"last_synced": datetime.now(timezone.utc).isoformat(),
                                     "tools_to_check": tools_to_check}))

    def test_a_fresh_cache_listing_the_canonical_name_still_checks_the_raw_tool(self):
        self.write_policy_cache(["Read"])
        self.run_hook(payload("PreToolUse", **tool_call("read_file", {"Path": "/work/repo/.env"})))
        [sent] = self.requests("/v1/hooks/pretool")
        self.assertEqual(sent["pre_tool_use_data"]["tool_name"], "Read")

    def test_a_fresh_cache_without_the_family_skips_the_gateway(self):
        self.write_policy_cache(["Write"])
        out = self.run_hook(payload("PreToolUse", **tool_call("read_file", {"Path": "/work/repo/a.txt"})))
        self.assertEqual((out, self.requests("/v1/hooks/pretool")), ({"decision": "allow"}, []))

    def test_input_typed_into_a_running_command_is_checked_as_bash(self):
        self.run_hook(payload("PreToolUse", **tool_call(
            "manage_task", {"Action": "send_input", "TaskId": "t1", "Input": "git push --force"})))
        sent = self.requests("/v1/hooks/pretool")[0]["pre_tool_use_data"]
        self.assertEqual((sent["tool_name"], sent["command"]), ("Bash", "git push --force"))

    def test_other_task_actions_are_not_sent(self):
        out = self.run_hook(payload("PreToolUse", **tool_call("manage_task", {"Action": "list"})))
        self.assertEqual((out, self.requests("/v1/hooks/pretool")), ({"decision": "allow"}, []))

    def test_a_lazy_mcp_call_carries_its_server_and_tool(self):
        self.run_hook(payload("PreToolUse", **tool_call("call_mcp_tool", {
            "ServerName": "github", "ToolName": "create_issue", "Arguments": {"title": "x"}})))
        sent = self.requests("/v1/hooks/pretool")[0]["pre_tool_use_data"]
        self.assertEqual(sent["tool_name"], "mcp__github__create_issue")
        self.assertEqual((sent["metadata"]["mcp_server"], sent["metadata"]["mcp_tool"]),
                         ("github", "create_issue"))
        self.assertEqual(sent["metadata"]["tool_input"], {"title": "x"})

    def test_an_eager_mcp_call_is_split_using_the_configured_server_names(self):
        config = self.home / ".gemini" / "config"
        config.mkdir(parents=True)
        (config / "mcp_config.json").write_text(json.dumps(
            {"mcpServers": {"my_server": {"command": "node", "args": ["srv.js"]}}}))
        self.run_hook(payload("PreToolUse", **tool_call("mcp_my_server_list_items", {"q": "a"})))
        meta = self.requests("/v1/hooks/pretool")[0]["pre_tool_use_data"]["metadata"]
        self.assertEqual((meta["mcp_server"], meta["mcp_tool"]), ("my_server", "list_items"))


class PromptTests(HookRun):
    def test_a_blocked_prompt_ends_the_turn_before_the_model_runs(self):
        out = self.run_hook(payload("PreInvocation", invocationNum=0, initialNumSteps=1),
                            {"decision": "deny", "reason": "Prompt contains a secret"})
        self.assertEqual(out, {"injectSteps": [{"errorMessage": {"userMessage": "Prompt contains a secret"}}],
                               "terminationBehavior": "terminate"})
        [sent] = self.requests("/v1/hooks/pretool")
        self.assertEqual(sent["event_name"], "user_prompt")
        self.assertEqual(sent["messages"], [{"role": "user", "content": "tidy up the repo"}])

    def test_prompt_guidance_reaches_the_model_as_a_system_message(self):
        out = self.run_hook(payload("PreInvocation", invocationNum=0),
                            {"decision": "allow", "additionalContext": "Load the unbound-sql skill."})
        self.assertEqual(out, {"injectSteps": [{"systemMessage": {"systemMessage": "Load the unbound-sql skill."}}]})

    def test_later_model_calls_in_a_turn_are_not_rechecked(self):
        self.assertEqual(self.run_hook(payload("PreInvocation", invocationNum=1)), {})
        self.assertEqual(self.requests("/v1/hooks/pretool"), [])


class TurnLogTests(HookRun):
    def test_stop_sends_the_turn_with_its_tool_calls(self):
        transcript = self.root / "transcript_full.jsonl"
        transcript.write_text("\n".join(json.dumps(s) for s in (
            {"step_index": 0, "type": "USER_INPUT", "content": "tidy up the repo"},
            {"step_index": 1, "type": "PLANNER_RESPONSE", "tool_calls": [{"name": "run_command"}]},
            {"step_index": 3, "type": "PLANNER_RESPONSE", "content": "Removed the build folder."},
        )))
        self.run_hook(payload("PostToolUse", error="", **tool_call(
            "run_command", {"CommandLine": "rm -rf build"}, call_id="call_9")))
        self.run_hook(payload("Stop", transcriptPath=str(transcript), executionNum=0,
                              terminationReason="NO_TOOL_CALL", fullyIdle=True))
        [turn] = self.requests("/v1/hooks/antigravity")
        self.assertEqual(turn["conversation_id"], CONVERSATION)
        self.assertEqual(turn["model"], "gemini-4-carbon-medium")
        user, assistant = turn["messages"]
        self.assertEqual(user, {"role": "user", "content": "tidy up the repo"})
        self.assertEqual(assistant["content"], "Removed the build folder.")
        [use] = assistant["tool_use"]
        self.assertEqual((use["tool_name"], use["tool_input"]["command"], use["tool_use_id"]),
                         ("Bash", "rm -rf build", "call_9"))


    def test_a_text_only_turn_does_not_repeat_the_previous_turns_tools(self):
        transcript = self.root / "transcript_full.jsonl"
        transcript.write_text(json.dumps({"step_index": 0, "type": "PLANNER_RESPONSE", "content": "Done."}))
        self.run_hook(payload("PostToolUse", error="", **tool_call(
            "run_command", {"CommandLine": "rm -rf build"}, call_id="call_9")))
        stop = payload("Stop", transcriptPath=str(transcript))
        self.run_hook(stop)
        self.run_hook(dict(stop, lastUserInput="thanks"))
        first, second = self.requests("/v1/hooks/antigravity")
        self.assertEqual(len(first["messages"][1]["tool_use"]), 1)
        self.assertFalse(second["messages"][1].get("tool_use"))

    def pad_audit_log(self, count, session_id=CONVERSATION):
        log = self.home / ".gemini" / "antigravity-hooks" / "agent-audit.log"
        record = json.loads(log.read_text().splitlines()[0])
        with log.open("a") as f:
            for i in range(count):
                row = json.loads(json.dumps(record))
                row["session_id"] = row["event"]["session_id"] = session_id
                row["event"]["tool_use_id"] = "pad_%d" % i
                f.write(json.dumps(row) + "\n")

    def stop_tool_ids(self):
        transcript = self.root / "transcript_full.jsonl"
        transcript.write_text(json.dumps({"step_index": 0, "type": "PLANNER_RESPONSE", "content": "Done."}))
        self.run_hook(payload("Stop", transcriptPath=str(transcript)))
        [turn] = self.requests("/v1/hooks/antigravity")
        return [use["tool_use_id"] for use in turn["messages"][1]["tool_use"]]

    def test_another_conversations_activity_keeps_an_open_turns_tool_calls(self):
        self.run_hook(payload("PostToolUse", error="", **tool_call(
            "run_command", {"CommandLine": "rm -rf build"}, call_id="call_9")))
        other = "0f3c2a51-7d7e-4c4b-9a43-5b1f0f6d2e10"
        self.pad_audit_log(100, session_id=other)
        self.run_hook(payload("PostToolUse", conversationId=other, error="", **tool_call(
            "run_command", {"CommandLine": "ls"}, call_id="call_other")))
        self.assertEqual(self.stop_tool_ids(), ["call_9"])

    def test_a_turn_over_the_log_limit_keeps_its_first_tool_call(self):
        self.run_hook(payload("PostToolUse", error="", **tool_call(
            "run_command", {"CommandLine": "rm -rf build"}, call_id="call_9")))
        self.pad_audit_log(100)
        self.run_hook(payload("PostToolUse", error="", **tool_call(
            "run_command", {"CommandLine": "ls"}, call_id="call_last")))
        ids = self.stop_tool_ids()
        self.assertEqual((ids[0], ids[-1], len(ids)), ("call_9", "call_last", 102))

    def test_each_command_is_attributed_from_its_own_working_directory(self):
        calls = [unbound._antigravity_event(payload("PostToolUse", **tool_call("run_command", args, call_id=cid)))
                 for cid, args in (("c1", {"CommandLine": "git status", "Cwd": "/work/other"}),
                                   ("c2", {"CommandLine": "git status"}))]
        dirs = []

        def capture(tool_name, tool_input, shell_dir, root_projects):
            dirs.append(shell_dir)
            return None, None, "/work/other"
        with patch.object(unbound, "_repo_for_tool_use", side_effect=capture):
            unbound.build_llm_exchange(unbound._antigravity_event(payload("Stop")),
                                       [{"event": ev} for ev in calls])
        self.assertEqual(dirs, ["/work/other", "/work/repo"])


class RepoGateTests(unittest.TestCase):
    def candidates_cwd(self, event):
        seen = {}

        def capture(tool_name, tool_input, cwd):
            seen["cwd"] = cwd
            return []
        with patch.object(unbound, "_repo_gate_block_policies", return_value=[{"id": "p"}]), \
                patch.object(unbound, "_repo_gate_candidates", side_effect=capture):
            unbound._repo_gate_evaluate(event)
        return seen.get("cwd")

    def test_a_shell_command_is_gated_in_its_own_working_directory(self):
        event = unbound._antigravity_event(payload("PreToolUse", **tool_call(
            "run_command", {"CommandLine": "git push", "Cwd": "/work/other-org-repo"})))
        self.assertEqual(self.candidates_cwd(event), "/work/other-org-repo")

    def test_without_a_cwd_the_workspace_root_is_used(self):
        event = unbound._antigravity_event(payload("PreToolUse", **tool_call(
            "run_command", {"CommandLine": "git push"})))
        self.assertEqual(self.candidates_cwd(event), "/work/repo")


class SkillTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name) / "skills"
        patcher = patch.object(unbound, "MANAGED_SKILLS_ROOT", self.root)
        patcher.start()
        self.addCleanup(patcher.stop)

    def test_an_injected_skill_is_installed_reported_and_pruned(self):
        content = "---\nname: unbound-secure-sql\ndescription: SQL rules\n---\n\nUse bind params.\n"
        digest = hashlib.sha256(content.encode()).hexdigest()
        self.assertTrue(unbound.install_injected_skills(
            [{"slug": "secure-sql", "content": content, "sha256": digest}]))
        self.assertEqual((self.root / "unbound-secure-sql" / "SKILL.md").read_text(), content)
        self.assertEqual(unbound.installed_skill_report(), [{"slug": "secure-sql", "sha256": digest}])
        unbound.prune_injected_skills(["secure-sql"])
        self.assertFalse((self.root / "unbound-secure-sql").exists())

    def test_the_sync_plan_is_read_only_from_a_200(self):
        plan = {"install": [], "remove": ["old"]}
        ok = subprocess.CompletedProcess([], 0, stdout=(json.dumps(plan) + "\n200").encode())
        bad = subprocess.CompletedProcess([], 0, stdout=b'{"install": []}\n500')
        with patch.object(unbound, "curl_with_auth", return_value=ok):
            self.assertEqual(unbound._request_skill_sync("key", {"installed": []}), plan)
        with patch.object(unbound, "curl_with_auth", return_value=bad):
            self.assertIsNone(unbound._request_skill_sync("key", {"installed": []}))


if __name__ == "__main__":
    unittest.main()
