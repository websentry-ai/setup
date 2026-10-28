"""
A Stop that fires before the turn's last reply reaches the transcript, in claude-code/hooks/unbound.py.

process_stop_event re-reads the transcript, a bounded number of times, until the turn's last reply
carries its final stop_reason.
"""

import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from tests.conftest import tool_module

unbound = tool_module("claude-code/hooks")
SESSION = "sess-lag"
PROMPT_AT = "2026-10-28T10:00:00Z"


def _reply(timestamp, stop_reason, tokens, text="done"):
    return {"type": "assistant", "timestamp": timestamp, "sessionId": SESSION,
            "message": {"id": "msg-" + timestamp, "role": "assistant", "model": "claude-opus-4-7",
                        "stop_reason": stop_reason, "content": [{"type": "text", "text": text}],
                        "usage": {"input_tokens": tokens, "output_tokens": 1,
                                  "cache_read_input_tokens": 0, "cache_creation_input_tokens": 0}}}


class TestStopBeforeTheLastReplyLands(unittest.TestCase):

    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.transcript = Path(tmp.name) / "session.jsonl"
        self.logs = [
            {"timestamp": PROMPT_AT, "session_id": SESSION,
             "event": {"hook_event_name": "UserPromptSubmit", "session_id": SESSION, "prompt": "hi"}},
            {"timestamp": "2026-10-28T10:00:09Z", "session_id": SESSION,
             "event": {"hook_event_name": "Stop", "session_id": SESSION}},
        ]

    def _write(self, *lines):
        with open(self.transcript, "a", encoding="utf-8") as f:
            f.write("".join(json.dumps(line) + "\n" for line in lines))

    def _stop(self, sleep):
        with patch.object(unbound, "load_existing_logs", lambda: self.logs), \
                patch.object(unbound, "send_to_api") as send, \
                patch.object(unbound.time, "sleep", side_effect=sleep) as slept:
            unbound.process_stop_event({"session_id": SESSION, "transcript_path": str(self.transcript),
                                        "last_assistant_message": "done"}, "key")
        return send.call_args.args[0], slept.call_count

    def test_the_reply_written_after_the_stop_is_counted(self):
        self._write(_reply("2026-10-28T10:00:02Z", "tool_use", 100, "working"))
        exchange, slept = self._stop(lambda _: self._write(_reply("2026-10-28T10:00:08Z", "end_turn", 20)))
        self.assertEqual(exchange["usage"]["input_tokens"], 120)
        self.assertEqual(exchange["model"], "claude-opus-4-7")
        self.assertEqual(slept, 1)

    def test_a_one_reply_turn_with_nothing_written_yet_gets_its_usage_and_model(self):
        self.transcript.write_text("")
        exchange, _ = self._stop(lambda _: self._write(_reply("2026-10-28T10:00:08Z", "end_turn", 20)))
        self.assertEqual(exchange["usage"]["input_tokens"], 20)
        self.assertEqual(exchange["model"], "claude-opus-4-7")

    def test_a_finished_transcript_is_read_once(self):
        self._write(_reply("2026-10-28T10:00:08Z", "end_turn", 20))
        _, slept = self._stop(lambda _: None)
        self.assertEqual(slept, 0)

    def test_a_reply_that_never_lands_waits_a_bounded_time_and_still_sends(self):
        self._write(_reply("2026-10-28T10:00:02Z", "tool_use", 100, "working"))
        exchange, slept = self._stop(lambda _: None)
        self.assertEqual(slept, unbound.STOP_TRANSCRIPT_REREADS)
        self.assertEqual(exchange["usage"]["input_tokens"], 100)


    def test_a_missing_transcript_is_not_waited_on(self):
        self.transcript = self.transcript.with_name("missing.jsonl")
        _, slept = self._stop(lambda _: None)
        self.assertEqual(slept, 0)

if __name__ == "__main__":
    unittest.main()
