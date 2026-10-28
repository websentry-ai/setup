"""
Tests for agent messages (e.g. a subagent hand-back) in claude-code/hooks/unbound.py.

Claude Code delivers another session's message as a UserPromptSubmit whose prompt
starts with `<agent-message `, and records it in the transcript with origin kind
'peer'. Confirmed by that record, it never becomes, or joins, a turn's user prompt.
The prefix alone can be typed, so it is still policy-checked and still recorded.
"""

import io
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

from tests.conftest import tool_module

unbound = tool_module("claude-code/hooks")
setup = tool_module("claude-code/hooks", "setup")
mdm = tool_module("claude-code/hooks/mdm", "setup")
SESSION = "sess-agent-message"
HANDBACK = '<agent-message from="a2eaece700394f3d9">\n[Subagent hand-back] The report follows:\n  done'


def _log(hook_event_name, timestamp, **fields):
    event = {"hook_event_name": hook_event_name, "session_id": SESSION}
    event.update(fields)
    return {"timestamp": timestamp, "session_id": SESSION, "event": event}


def _user_messages(exchange):
    return [m["content"] for m in (exchange or {}).get("messages", [])
            if m.get("role") == "user"]


class TestAgentMessageSubmit(unittest.TestCase):
    def test_is_still_policy_checked(self):
        event = json.dumps({"hook_event_name": "UserPromptSubmit", "session_id": SESSION,
                            "prompt": HANDBACK})
        out = io.StringIO()
        with patch.object(unbound, "process_user_prompt_submit", Mock()) as check, \
             patch.object(unbound, "append_to_audit_log", Mock()) as audit, \
             patch.object(unbound, "cleanup_old_logs", lambda: None), \
             patch.object(unbound, "get_api_key", lambda: "K"), \
             patch.object(unbound.sys, "stdin", io.StringIO(event)), \
             patch.object(unbound.sys, "stdout", out):
            unbound.main()
        check.assert_called_once()
        self.assertEqual(audit.call_count, 1)

    def test_only_a_prefixed_message_the_transcript_marks_as_a_peer_counts(self):
        peers = ["Another Claude session sent a message:\n" + HANDBACK]
        self.assertTrue(unbound._is_agent_message("\n  " + HANDBACK, peers))
        self.assertFalse(unbound._is_agent_message(HANDBACK, []))
        # A user quoting part of a report is still their own prompt.
        self.assertFalse(unbound._is_agent_message(HANDBACK.split("\n")[0], peers))
        self.assertFalse(unbound._is_agent_message("explain <agent-message from=x>", peers))


class TestAgentMessageTurn(unittest.TestCase):
    def setUp(self):
        self.captured = {}
        self.peers = [HANDBACK]

        def fake_parse(path, prompt_timestamp=None, include_usage=True,
                       subagent_floor=None, subagent_ceiling=None):
            self.captured["anchor"] = prompt_timestamp
            return {"assistant_messages": [], "usage": None, "model": None, "agent_messages": self.peers}

        real_build = unbound.build_llm_exchange

        def spy_build(events, **kwargs):
            self.captured["events"] = events
            self.captured["exchange"] = real_build(events, **kwargs)
            return None

        for p in (patch.object(unbound, "parse_transcript_file", fake_parse),
                  patch.object(unbound, "build_llm_exchange", spy_build),
                  patch.object(unbound, "_extract_session_model", lambda *a, **k: "auto")):
            p.start()
            self.addCleanup(p.stop)

    def _run(self, logs):
        with patch.object(unbound, "load_existing_logs", lambda: logs):
            unbound.process_stop_event(
                {"session_id": SESSION, "transcript_path": "/tmp/t.jsonl",
                 "last_assistant_message": "ok"}, "key")
        return self.captured

    def test_mid_turn_it_neither_joins_the_prompt_nor_resets_the_turn(self):
        out = self._run([
            _log("UserPromptSubmit", "2026-10-28T06:01:05Z", prompt="real prompt", prompt_id="p1"),
            _log("PostToolUse", "2026-10-28T06:01:09Z", tool_name="Bash",
                 tool_input={"command": "ls"}, tool_response={}),
            _log("UserPromptSubmit", "2026-10-28T06:01:22Z", prompt=HANDBACK, prompt_id="p2"),
            _log("Stop", "2026-10-28T06:01:24Z"),
        ])
        self.assertEqual(_user_messages(out["exchange"]), ["real prompt"])
        self.assertEqual(out["anchor"], "2026-10-28T06:01:05Z")
        self.assertEqual(len(out["exchange"]["messages"][1]["tool_use"]), 1)

    def test_a_turn_it_starts_alone_is_still_sent_with_no_user_text(self):
        out = self._run([
            _log("UserPromptSubmit", "2026-10-28T06:01:05Z", prompt="real prompt", prompt_id="p1"),
            _log("Stop", "2026-10-28T06:01:24Z"),
            _log("UserPromptSubmit", "2026-10-28T06:05:00Z", prompt=HANDBACK, prompt_id="p2"),
            _log("PostToolUse", "2026-10-28T06:05:09Z", tool_name="Bash",
                 tool_input={"command": "ls"}, tool_response={}),
            _log("Stop", "2026-10-28T06:05:30Z"),
        ])
        self.assertEqual(_user_messages(out["exchange"]), [""])
        self.assertEqual(len(out["exchange"]["messages"][1]["tool_use"]), 1)
        self.assertEqual(out["anchor"], "2026-10-28T06:05:00Z")

    def test_a_typed_prefix_with_no_peer_record_stays_the_user_prompt(self):
        self.peers = []
        out = self._run([
            _log("UserPromptSubmit", "2026-10-28T06:05:00Z", prompt=HANDBACK, prompt_id="p2"),
            _log("Stop", "2026-10-28T06:05:30Z"),
        ])
        self.assertEqual(_user_messages(out["exchange"]), [HANDBACK])


class TestAgentMessageInTranscript(unittest.TestCase):
    def _queued(self, *records):
        path = Path(tempfile.mkdtemp()) / "session.jsonl"
        with open(path, "w", encoding="utf-8") as f:
            for content in (HANDBACK, "queued question"):
                f.write(json.dumps({"type": "queue-operation", "operation": "remove",
                                    "timestamp": "2026-10-28T06:01:22Z", "content": content}) + "\n")
            f.write("".join(json.dumps(record) + "\n" for record in records))
        return unbound.parse_transcript_file(str(path), "2026-10-28T06:01:05Z")["queued_prompts"]

    def test_a_consumed_agent_message_is_not_a_queued_prompt(self):
        attachment = {"type": "attachment", "timestamp": "2026-10-28T06:01:22Z",
                      "attachment": {"type": "queued_command", "prompt": HANDBACK,
                                     "origin": {"kind": "peer", "from": "a2eaece700394f3d9"}}}
        self.assertEqual(self._queued(attachment), ["queued question"])

    def test_a_peer_entry_written_as_content_blocks_still_confirms_it(self):
        peer = {"type": "user", "isMeta": True, "timestamp": "2026-10-28T06:01:22Z",
                "origin": {"kind": "peer", "handback": True},
                "message": {"role": "user", "content": [
                    {"type": "text", "text": "Another Claude session sent a message:\n" + HANDBACK}]}}
        self.assertEqual(self._queued(peer), ["queued question"])

    def test_a_peer_record_from_an_earlier_turn_confirms_nothing(self):
        attachment = {"type": "attachment", "timestamp": "2026-10-28T06:00:00Z",
                      "attachment": {"type": "queued_command", "prompt": HANDBACK, "origin": {"kind": "peer"}}}
        self.assertEqual(self._queued(attachment), [HANDBACK, "queued question"])

    def test_a_queued_prompt_typed_with_the_prefix_is_kept(self):
        self.assertEqual(self._queued(), [HANDBACK, "queued question"])

    def test_backfill_does_not_cut_an_exchange_at_it(self):
        peer = {"type": "user", "isMeta": True, "origin": {"kind": "peer", "handback": True},
                "message": {"role": "user",
                            "content": "Another Claude session sent a message:\n" + HANDBACK}}
        human = {"type": "user", "origin": {"kind": "human"},
                 "message": {"role": "user", "content": "real prompt"}}
        for module in (setup, mdm):
            self.assertEqual(module._backfill_exchange_boundaries([human, peer]), [0])


if __name__ == "__main__":
    unittest.main()
