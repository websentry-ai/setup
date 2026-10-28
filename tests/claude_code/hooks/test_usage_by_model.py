"""
Per-model usage in claude-code/hooks/unbound.py: parse_transcript_file splits a turn's tokens by the model that
served each part (main agent, advisor, subagent), beside the summed totals, so each part prices at its own rate.
"""

import json
import tempfile
import unittest
from pathlib import Path

from tests.conftest import tool_module

unbound = tool_module("claude-code/hooks")
PROMPT_AT = "2026-10-28T10:00:00Z"
FIELDS = ("input_tokens", "output_tokens", "cache_read_input_tokens", "cache_creation_input_tokens")


def _usage(*values):
    return dict(zip(FIELDS, values))


def _reply(message_id, model, usage, timestamp="2026-10-28T10:00:05Z"):
    return {"type": "assistant", "timestamp": timestamp,
            "message": {"id": message_id, "role": "assistant", "model": model, "stop_reason": "end_turn",
                        "content": [{"type": "text", "text": "ok"}], "usage": usage}}


class TestUsageByModel(unittest.TestCase):

    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.transcript = Path(tmp.name) / "session.jsonl"

    def _write(self, path, *lines):
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("".join(json.dumps(line) + "\n" for line in lines))

    def test_main_advisor_and_subagent_tokens_are_split_by_their_model(self):
        main, advisor, sub = _usage(3, 400, 20000, 1000), _usage(7, 30, 0, 0), _usage(4, 203, 38975, 46072)
        main_with_advisor = dict(main, iterations=[dict(advisor, type="advisor_message", model="claude-opus-4-7")])
        self._write(self.transcript, _reply("m1", "claude-sonnet-4-5", main_with_advisor))
        self._write(self.transcript.with_suffix("") / "subagents" / "agent.jsonl",
                    _reply("s1", "claude-haiku-4-5", sub, "2026-10-28T10:00:03Z"))

        usage = unbound.parse_transcript_file(str(self.transcript), PROMPT_AT)["usage"]

        self.assertEqual(usage["by_model"], {"claude-sonnet-4-5": main, "claude-opus-4-7": advisor,
                                             "claude-haiku-4-5": sub})
        for field in FIELDS:
            self.assertEqual(usage[field], main[field] + advisor[field] + sub[field], field)

    def test_a_reply_written_as_several_lines_counts_once_under_its_model(self):
        self._write(self.transcript, _reply("m1", "claude-opus-4-7", _usage(3, 10, 100, 0)),
                    _reply("m1", "claude-opus-4-7", _usage(3, 50, 100, 0)),
                    _reply("m2", "claude-haiku-4-5", _usage(1, 1, 0, 0)))
        usage = unbound.parse_transcript_file(str(self.transcript), PROMPT_AT)["usage"]
        self.assertEqual(usage["by_model"], {"claude-opus-4-7": _usage(3, 50, 100, 0),
                                             "claude-haiku-4-5": _usage(1, 1, 0, 0)})

    def test_a_turn_one_model_served_sends_no_split(self):
        self._write(self.transcript, _reply("m1", "claude-opus-4-7", _usage(3, 50, 100, 0)))
        usage = unbound.parse_transcript_file(str(self.transcript), PROMPT_AT)["usage"]
        self.assertEqual(usage["output_tokens"], 50)
        self.assertNotIn("by_model", usage)

    def test_a_malformed_model_still_counts_every_token(self):
        self._write(self.transcript, _reply("m1", ["not", "a", "name"], _usage(3, 50, 100, 0)),
                    _reply("m2", "claude-haiku-4-5", _usage(1, 1, 0, 0)))
        usage = unbound.parse_transcript_file(str(self.transcript), PROMPT_AT)["usage"]
        self.assertEqual((usage["input_tokens"], usage["output_tokens"]), (4, 51))
        self.assertEqual(usage["by_model"], {"claude-haiku-4-5": _usage(1, 1, 0, 0)})


if __name__ == "__main__":
    unittest.main()
