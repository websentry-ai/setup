"""
Tests for turn scoping in copilot/hooks/unbound.py.

A prompt typed while Copilot is working is appended to the running turn as another
user.message, so the turn starts at its FIRST prompt, not its last. Covers:
  - build_exchange_from_transcript
"""

import json
import tempfile
import unittest
from pathlib import Path

import unbound

SESSION = "sess-1"


def _entry(entry_type, **data):
    return {"id": data.pop("_id", entry_type), "type": entry_type, "data": data}


def _transcript(entries):
    path = Path(tempfile.mkdtemp()) / "events.jsonl"
    with open(path, "w", encoding="utf-8") as f:
        for entry in entries:
            f.write(json.dumps(entry) + "\n")
    return str(path)


def _tool(call_id):
    return [_entry("tool.execution_start", toolCallId=call_id, toolName="shell",
                   arguments={"command": "ls"}),
            _entry("tool.execution_complete", toolCallId=call_id, success=True,
                   result={"output": "ok"})]


def _user_text(exchange):
    return [m["content"] for m in (exchange or {}).get("messages", [])
            if m.get("role") == "user"]


class TestTurnStartsAtItsFirstPrompt(unittest.TestCase):
    def setUp(self):
        # the shape Copilot writes when a prompt is typed mid-turn: the queued
        # user.message lands between two assistant turns, before any real reply
        self.path = _transcript([
            _entry("session.start", sessionId=SESSION),
            _entry("user.message", _id="u1", content="first question"),
            _entry("assistant.turn_start"),
            _entry("assistant.message", content=""),
            *_tool("call-a"),
            _entry("assistant.turn_end"),
            _entry("user.message", _id="u2", content="second question"),
            *_tool("call-b"),
            _entry("assistant.message", content="the answer"),
            _entry("assistant.turn_end"),
        ])

    def test_both_prompts_are_kept(self):
        exchange, _forwarded, _sig = unbound.build_exchange_from_transcript(
            self.path, SESSION)
        self.assertEqual(_user_text(exchange), ["first question\n\nsecond question"])

    def test_the_earlier_prompts_tool_calls_are_included(self):
        _exchange, forwarded, _sig = unbound.build_exchange_from_transcript(
            self.path, SESSION)
        self.assertEqual(forwarded, {"call-a", "call-b"})

    def test_a_prompt_after_a_reply_starts_a_new_turn(self):
        path = _transcript([
            _entry("session.start", sessionId=SESSION),
            _entry("user.message", _id="u1", content="first question"),
            *_tool("call-a"),
            _entry("assistant.message", content="the first answer"),
            _entry("assistant.turn_end"),
            _entry("user.message", _id="u2", content="second question"),
            *_tool("call-b"),
            _entry("assistant.message", content="the second answer"),
        ])
        exchange, forwarded, _sig = unbound.build_exchange_from_transcript(path, SESSION)
        self.assertEqual(_user_text(exchange), ["second question"])
        self.assertEqual(forwarded, {"call-b"})

    def test_a_transcript_with_no_prompt_yields_nothing(self):
        path = _transcript([_entry("session.start", sessionId=SESSION)])
        exchange, forwarded, sig = unbound.build_exchange_from_transcript(path, SESSION)
        self.assertIsNone(exchange)
        self.assertEqual(forwarded, set())
        self.assertIsNone(sig)


if __name__ == "__main__":
    unittest.main()
