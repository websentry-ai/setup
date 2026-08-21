"""
Tests for turn scoping in copilot/hooks/unbound.py.

A prompt typed while Copilot is working joins the running turn, but where it lands
differs by surface: inside the open agent turn in the CLI, outside it in VS Code. The
turn is therefore defined as the prompts not yet reported, not by position. Covers:
  - build_exchange_from_transcript
  - get_forwarded_state / record_forwarded_tool_ids  (reported-prompt watermark)
"""

import json
import tempfile
import unittest
import unittest.mock
from pathlib import Path

import unbound

SESSION = "sess-1"


def _entry(entry_type, _id=None, **data):
    entry = {"type": entry_type, "data": data}
    if _id:
        entry["id"] = _id
    return entry


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


class TestTurnIsTheUnreportedPrompts(unittest.TestCase):
    def test_cli_shape_queued_prompt_inside_the_agent_turn(self):
        path = _transcript([
            _entry("user.message", _id="u1", content="first question"),
            _entry("assistant.turn_start"),
            _entry("assistant.message", content="let me look into that"),
            *_tool("call-a"),
            _entry("user.message", _id="u2", content="second question"),
            *_tool("call-b"),
            _entry("assistant.message", content="the answer"),
            _entry("assistant.turn_end"),
        ])
        exchange, forwarded, _sig, prompts = unbound.build_exchange_from_transcript(
            path, SESSION)
        self.assertEqual(_user_text(exchange), ["first question\n\nsecond question"])
        self.assertEqual(forwarded, {"call-a", "call-b"})
        self.assertEqual(prompts, {"u1", "u2"})

    def test_vscode_shape_queued_prompt_outside_the_agent_turn(self):
        path = _transcript([
            _entry("user.message", _id="u1", content="first question"),
            _entry("assistant.turn_start"),
            _entry("assistant.message", content="scanning"),
            _entry("assistant.turn_end"),
            _entry("user.message", _id="u2", content="second question"),
            _entry("assistant.turn_start"),
            *_tool("call-a"),
            _entry("assistant.message", content="the answer"),
            _entry("assistant.turn_end"),
        ])
        exchange, _forwarded, _sig, prompts = unbound.build_exchange_from_transcript(
            path, SESSION)
        self.assertEqual(_user_text(exchange), ["first question\n\nsecond question"])
        self.assertEqual(prompts, {"u1", "u2"})

    def test_an_already_reported_prompt_is_not_resent(self):
        path = _transcript([
            _entry("user.message", _id="u1", content="first question"),
            *_tool("call-a"),
            _entry("assistant.message", content="the first answer"),
            _entry("user.message", _id="u2", content="second question"),
            *_tool("call-b"),
            _entry("assistant.message", content="the second answer"),
        ])
        exchange, forwarded, _sig, prompts = unbound.build_exchange_from_transcript(
            path, SESSION, already_forwarded={"call-a"}, already_prompted={"u1"})
        self.assertEqual(_user_text(exchange), ["second question"])
        self.assertEqual(forwarded, {"call-b"})
        self.assertEqual(prompts, {"u2"})

    def test_nothing_new_yields_no_exchange(self):
        path = _transcript([
            _entry("user.message", _id="u1", content="first question"),
            _entry("assistant.message", content="the answer"),
        ])
        exchange, forwarded, sig, prompts = unbound.build_exchange_from_transcript(
            path, SESSION, already_prompted={"u1"})
        self.assertIsNone(exchange)
        self.assertEqual((forwarded, sig, prompts), (set(), None, set()))

    def test_a_transcript_with_no_prompt_yields_nothing(self):
        path = _transcript([_entry("session.start", sessionId=SESSION)])
        exchange, forwarded, sig, prompts = unbound.build_exchange_from_transcript(
            path, SESSION)
        self.assertIsNone(exchange)
        self.assertEqual((forwarded, sig, prompts), (set(), None, set()))


class TestReportedPromptWatermark(unittest.TestCase):
    def test_state_round_trips_through_the_marker(self):
        logs = [{"timestamp": "2026-08-20T10:00:00Z",
                 "event": {"hook_event_name": unbound.FORWARDED_TOOLS_EVENT,
                           "session_id": SESSION,
                           "forwarded_tool_ids": ["call-a"],
                           "forwarded_prompt_ids": ["u1"],
                           "text_sig": "sig"}}]
        with unittest.mock.patch.object(unbound, "load_existing_logs", lambda: logs):
            tools, sig, prompts = unbound.get_forwarded_state(SESSION)
        self.assertEqual(tools, {"call-a"})
        self.assertEqual(sig, "sig")
        self.assertEqual(prompts, {"u1"})

    def test_a_marker_without_prompt_ids_still_reads(self):
        logs = [{"timestamp": "2026-08-20T10:00:00Z",
                 "event": {"hook_event_name": unbound.FORWARDED_TOOLS_EVENT,
                           "session_id": SESSION,
                           "forwarded_tool_ids": ["call-a"]}}]
        with unittest.mock.patch.object(unbound, "load_existing_logs", lambda: logs):
            tools, _sig, prompts = unbound.get_forwarded_state(SESSION)
        self.assertEqual(tools, {"call-a"})
        self.assertEqual(prompts, set())

    def test_no_session_id_is_empty_state(self):
        self.assertEqual(unbound.get_forwarded_state(None), (set(), None, set()))


if __name__ == "__main__":
    unittest.main()
