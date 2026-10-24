"""
The Codex UserPromptSubmit hook reports how big the session's context is
(metadata.session_context), read off the rollout's cumulative token_count snapshots.
A gateway warning arrives as user_notice on an allow and must reach the user.
"""

import json
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from tests.conftest import tool_module

unbound = tool_module("codex/hooks")


def _token_count(input_tokens, output_tokens, last=None):
    total = {"input_tokens": input_tokens, "cached_input_tokens": 0,
             "output_tokens": output_tokens, "total_tokens": input_tokens + output_tokens}
    return {"type": "event_msg",
            "payload": {"type": "token_count",
                        "info": {"total_token_usage": total, "last_token_usage": last or total,
                                 "model_context_window": 258400}}}


def _rate_limits_only():
    return {"type": "event_msg",
            "payload": {"type": "token_count", "info": None, "rate_limits": {}}}


def _user_message():
    return {"type": "response_item",
            "payload": {"type": "message", "role": "user",
                        "content": [{"type": "input_text", "text": "go"}]}}


def _compacted():
    return {"type": "compacted",
            "payload": {"message": "summary"}}


def _context_compacted():
    return {"type": "event_msg",
            "payload": {"type": "context_compacted"}}


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
        self.path = Path(self._tmp.name) / "rollout.jsonl"

    def tearDown(self):
        self._tmp.cleanup()

    def _metadata(self, entries=None, transcript_path=None):
        if entries is not None:
            self.path.write_text("\n".join(json.dumps(e) for e in entries) + "\n")
            transcript_path = str(self.path)
        event = {"hook_event_name": "UserPromptSubmit", "session_id": "sess", "prompt": "hi",
                 "cwd": "/work/codex", "transcript_path": transcript_path}
        with patch.object(unbound, "load_policy_cache", return_value={}), \
                patch.object(unbound, "is_cache_stale", return_value=False), \
                patch.object(unbound, "installed_skill_report", return_value=[]), \
                patch.object(unbound, "build_account_identity", return_value={}), \
                patch.object(unbound, "send_to_hook_api", return_value={"decision": "allow"}) as send:
            unbound.process_user_prompt_submit(event, "key")
        return send.call_args.args[0]["pre_tool_use_data"]["metadata"]

    def _assert_context(self, context, tokens):
        self.assertEqual(context, {"context_tokens": tokens})

    def test_delta_of_the_last_two_cumulative_snapshots(self):
        # last_token_usage is deliberately wrong (openai/codex#14489); the delta is what counts.
        bogus_last = {"input_tokens": 1, "output_tokens": 1}
        metadata = self._metadata([
            _token_count(10_000, 200),
            _token_count(30_000, 500),
            _token_count(75_000, 1_100, last=bogus_last),
            _rate_limits_only(),
            _token_count(75_000, 1_100),  # sticky re-emit of the same totals
            _user_message(),
        ])
        self._assert_context(metadata["session_context"], (75_000 - 30_000) + (1_100 - 500))
        self.assertEqual(metadata["cwd"], "/work/codex")  # existing metadata kept

    def test_single_snapshot_uses_its_totals(self):
        metadata = self._metadata([_token_count(13_563, 13), _user_message()])
        self._assert_context(metadata["session_context"], 13_576)

    def test_whole_file_single_snapshot_ignores_last_token_usage(self):
        metadata = self._metadata([_token_count(13_563, 13, last={"input_tokens": 1, "output_tokens": 1})])
        self._assert_context(metadata["session_context"], 13_576)

    def _truncated_metadata(self, newest):
        # older snapshots sit before the tail window, so only the newest one is visible
        self.path.write_text("\n".join(json.dumps(e) for e in [
            _token_count(10_000, 100), _user_message(), newest]) + "\n")
        tail = len(json.dumps(newest)) + 2
        with patch.object(unbound, "SKILL_TRANSCRIPT_TAIL_BYTES", tail):
            return self._metadata(transcript_path=str(self.path))

    def test_truncated_tail_single_snapshot_uses_last_token_usage(self):
        last = {"input_tokens": 40_000, "cached_input_tokens": 0, "output_tokens": 250}
        metadata = self._truncated_metadata(_token_count(90_000, 900, last=last))
        self._assert_context(metadata["session_context"], 40_250)

    def test_truncated_tail_single_snapshot_without_last_usage_omits_the_key(self):
        newest = _token_count(90_000, 900)
        newest["payload"]["info"].pop("last_token_usage")
        self.assertNotIn("session_context", self._truncated_metadata(newest))

    def test_compaction_after_the_newest_snapshot_omits_the_key(self):
        for compaction in (_compacted, _context_compacted):
            with self.subTest(compaction=compaction.__name__):
                metadata = self._metadata([_token_count(10_000, 100),
                                           _token_count(50_000, 300),
                                           compaction(), _user_message()])
                self.assertNotIn("session_context", metadata)

    def test_compaction_between_snapshots_still_measures_the_newest_request(self):
        metadata = self._metadata([_token_count(50_000, 300), _compacted(),
                                   _token_count(62_000, 400)])
        self._assert_context(metadata["session_context"], 12_000 + 100)

    def test_missing_unreadable_or_unusable_rollout_omits_the_key(self):
        self.assertNotIn("session_context", self._metadata(transcript_path=None))
        self.assertNotIn("session_context", self._metadata(transcript_path=str(self.path / "nope")))
        self.assertNotIn("session_context", self._metadata([_user_message(), _rate_limits_only()]))


class TestGatewayRequestBody(unittest.TestCase):
    """The session_context must survive into the bytes curl posts to the gateway."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.path = Path(self._tmp.name) / "rollout.jsonl"

    def tearDown(self):
        self._tmp.cleanup()

    def _body(self, transcript_path):
        event = {"hook_event_name": "UserPromptSubmit", "session_id": "sess", "prompt": "hi",
                 "cwd": self._tmp.name, "transcript_path": transcript_path}
        with patch.object(unbound, "installed_skill_report", return_value=[]):
            return _gateway_body(unbound, event)

    def test_measurable_rollout_puts_session_context_in_the_body(self):
        self.path.write_text(json.dumps(_token_count(13_563, 13)) + "\n")
        context = self._body(str(self.path))["pre_tool_use_data"]["metadata"]["session_context"]
        self.assertEqual(context, {"context_tokens": 13_576})

    def test_unmeasurable_rollout_leaves_it_out_of_the_body(self):
        self.path.write_text(json.dumps(_user_message()) + "\n")
        self.assertNotIn("session_context", self._body(str(self.path))["pre_tool_use_data"]["metadata"])


class TestPromptUserNotice(unittest.TestCase):
    def test_warn_only_notice_is_shown_without_model_context(self):
        out = unbound.transform_response_for_codex_prompt(
            {"decision": "allow", "user_notice": "This session's context is over 300k tokens."})
        self.assertEqual(out, {"systemMessage": "This session's context is over 300k tokens."})

    def test_notice_with_context_keeps_both(self):
        out = unbound.transform_response_for_codex_prompt(
            {"decision": "allow", "additionalContext": "ctx", "user_notice": "notice"})
        self.assertEqual(out["systemMessage"], "notice")
        self.assertEqual(out["hookSpecificOutput"]["additionalContext"], "ctx")

    def test_plain_allow_is_noop(self):
        self.assertEqual(unbound.transform_response_for_codex_prompt({"decision": "allow"}), {})


if __name__ == "__main__":
    unittest.main()
