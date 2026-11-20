"""
The UserPromptSubmit hook reports how big the session's context is
(metadata.session_context), so the gateway can warn on or block an oversized session.
A gateway warning arrives as user_notice on an allow and must reach the user.
"""

import json
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from tests.conftest import tool_module

unbound = tool_module("claude-code/hooks")

USAGE = {"input_tokens": 2, "cache_read_input_tokens": 296705,
         "cache_creation": {"ephemeral_1h_input_tokens": 799, "ephemeral_5m_input_tokens": 0},
         "cache_creation_input_tokens": 799, "output_tokens": 171}
CONTEXT_TOKENS = 2 + 296705 + 799 + 171


def _assistant(usage=USAGE, sidechain=False):
    return {"type": "assistant", "isSidechain": sidechain,
            "message": {"role": "assistant", "model": "claude-opus-4-1", "usage": usage,
                        "content": [{"type": "text", "text": "done"}]}}


def _user(text="go"):
    return {"type": "user",
            "message": {"role": "user", "content": text}}


def _compact():
    return {"type": "system", "subtype": "compact_boundary", "isSidechain": False,
            "compactMetadata": {"trigger": "auto"}}


def _gateway_body(module, event):
    """Run the prompt hook with curl faked out; return the JSON body piped to it."""
    real_run, bodies = module.subprocess.run, []

    def fake_run(cmd, *args, **kwargs):
        if cmd[0] != "curl":
            return real_run(cmd, *args, **kwargs)
        bodies.append(json.loads(kwargs["input"]))
        return subprocess.CompletedProcess(cmd, 0, stdout=b'{"decision": "allow"}', stderr=b"")

    with patch.object(module, "load_policy_cache", return_value={}), \
            patch.object(module, "is_cache_stale", return_value=False), \
            patch.object(module, "build_account_identity", return_value={}), \
            patch.object(module.subprocess, "run", side_effect=fake_run):
        module.process_user_prompt_submit(event, "key")
    return bodies[-1]


class TestPromptSendsSessionContext(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.path = Path(self._tmp.name) / "session.jsonl"

    def tearDown(self):
        self._tmp.cleanup()

    def _metadata(self, entries=None, transcript_path=None):
        if entries is not None:
            self.path.write_text("\n".join(json.dumps(e) for e in entries) + "\n")
            transcript_path = str(self.path)
        event = {"hook_event_name": "UserPromptSubmit", "session_id": "sess", "prompt": "hi",
                 "cwd": self._tmp.name, "transcript_path": transcript_path}
        with patch.object(unbound, "load_policy_cache", return_value={}), \
                patch.object(unbound, "is_cache_stale", return_value=False), \
                patch.object(unbound, "build_account_identity", return_value={}), \
                patch.object(unbound, "_get_session_model", return_value="auto"), \
                patch.object(unbound, "send_to_hook_api", return_value={"decision": "allow"}) as send:
            unbound.process_user_prompt_submit(event, "key")
        return send.call_args.args[0]["pre_tool_use_data"]["metadata"]

    def test_newest_usage_gives_context_size(self):
        older = dict(USAGE, cache_read_input_tokens=10)
        metadata = self._metadata([_user(), _assistant(older), _user(), _assistant(), _user()])
        self.assertEqual(metadata["session_context"], {"context_tokens": CONTEXT_TOKENS})
        self.assertEqual(metadata["cwd"], self._tmp.name)  # existing metadata kept

    def test_sidechain_and_zero_usage_entries_are_skipped(self):
        zero = {k: 0 for k in ("input_tokens", "output_tokens")}
        metadata = self._metadata([_assistant(), _assistant(sidechain=True), _assistant(zero)])
        self.assertEqual(metadata["session_context"], {"context_tokens": CONTEXT_TOKENS})

    def test_compaction_after_the_newest_usage_omits_the_key(self):
        metadata = self._metadata([_assistant(), _compact(), _user()])
        self.assertNotIn("session_context", metadata)

    def test_usage_after_a_compaction_is_reported(self):
        metadata = self._metadata([_assistant(), _compact(), _assistant()])
        self.assertEqual(metadata["session_context"], {"context_tokens": CONTEXT_TOKENS})

    def test_missing_unreadable_or_unusable_transcript_omits_the_key(self):
        self.assertNotIn("session_context", self._metadata(transcript_path=None))
        self.assertNotIn("session_context", self._metadata(transcript_path=str(self.path / "nope")))
        self.assertNotIn("session_context", self._metadata([_user()]))

    def test_tail_cut_mid_line_still_finds_usage(self):
        self.path.write_text("x" * 4096 + "\n" + json.dumps(_assistant()) + "\n")
        with patch.object(unbound, "_SESSION_CONTEXT_TAIL_BYTES", 1024):
            metadata = self._metadata(transcript_path=str(self.path))
        self.assertEqual(metadata["session_context"], {"context_tokens": CONTEXT_TOKENS})

    def test_usage_outside_the_first_window_is_not_searched_for(self):
        self.path.write_text(json.dumps(_assistant()) + "\n" + json.dumps(_user("x" * 4096)) + "\n")
        with patch.object(unbound, "_SESSION_CONTEXT_TAIL_BYTES", 1024):
            metadata = self._metadata(transcript_path=str(self.path))
        self.assertNotIn("session_context", metadata)


class TestGatewayRequestBody(unittest.TestCase):
    """The session_context must survive into the bytes curl posts to the gateway."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.path = Path(self._tmp.name) / "session.jsonl"

    def tearDown(self):
        self._tmp.cleanup()

    def _body(self, transcript_path):
        event = {"hook_event_name": "UserPromptSubmit", "session_id": "sess", "prompt": "hi",
                 "cwd": self._tmp.name, "transcript_path": transcript_path}
        with patch.object(unbound, "_get_session_model", return_value="auto"):
            return _gateway_body(unbound, event)

    def test_measurable_transcript_puts_session_context_in_the_body(self):
        self.path.write_text(json.dumps(_assistant()) + "\n")
        context = self._body(str(self.path))["pre_tool_use_data"]["metadata"]["session_context"]
        self.assertEqual(context, {"context_tokens": CONTEXT_TOKENS})

    def test_unmeasurable_transcript_leaves_it_out_of_the_body(self):
        self.path.write_text(json.dumps(_user()) + "\n")
        self.assertNotIn("session_context", self._body(str(self.path))["pre_tool_use_data"]["metadata"])


class TestPromptUserNotice(unittest.TestCase):
    def test_warn_only_notice_is_shown_without_model_context(self):
        out = unbound.transform_response_for_claude_prompt(
            {"decision": "allow", "user_notice": "This session's context is over 300k tokens."})
        self.assertEqual(out, {"systemMessage": "This session's context is over 300k tokens."})

    def test_notice_with_context_keeps_both(self):
        out = unbound.transform_response_for_claude_prompt(
            {"decision": "allow", "additionalContext": "ctx", "user_notice": "notice"})
        self.assertEqual(out["systemMessage"], "notice")
        self.assertEqual(out["hookSpecificOutput"]["additionalContext"], "ctx")

    def test_plain_allow_is_noop(self):
        self.assertEqual(unbound.transform_response_for_claude_prompt({"decision": "allow"}), {})


if __name__ == "__main__":
    unittest.main()
