"""
Tests for turn-start anchoring in copilot/hooks/unbound.py.

Typing while Copilot is still working adds prompts to the running turn. Covers:
  - get_turn_start_timestamp_for_session
"""

import unittest
from unittest.mock import patch

from tests.conftest import tool_module

unbound = tool_module("copilot/hooks")
SESSION = "sess-queued"
FIRST_PROMPT = "2026-08-20T10:00:00Z"
SECOND_PROMPT = "2026-08-20T10:00:10Z"
FIRST_STOP = "2026-08-20T10:00:20Z"
THIRD_PROMPT = "2026-08-20T10:00:30Z"
SECOND_STOP = "2026-08-20T10:00:40Z"


def _log(hook_event_name, timestamp, session_id=SESSION):
    return {"timestamp": timestamp,
            "event": {"hook_event_name": hook_event_name, "session_id": session_id}}


def _turn_start(logs):
    with patch.object(unbound, "load_existing_logs", lambda: logs):
        return unbound.get_turn_start_timestamp_for_session(SESSION)


class TestTurnStartTimestamp(unittest.TestCase):
    def test_queued_prompts_anchor_on_the_first(self):
        self.assertEqual(
            _turn_start([_log("UserPromptSubmit", FIRST_PROMPT),
                         _log("UserPromptSubmit", SECOND_PROMPT),
                         _log("Stop", FIRST_STOP)]),
            FIRST_PROMPT)

    def test_open_turn_reports_its_first_prompt(self):
        # mid-turn, as a gated tool call sees it
        self.assertEqual(
            _turn_start([_log("UserPromptSubmit", FIRST_PROMPT),
                         _log("UserPromptSubmit", SECOND_PROMPT)]),
            FIRST_PROMPT)

    def test_a_queued_prompt_does_not_change_turn_identity(self):
        one = _turn_start([_log("UserPromptSubmit", FIRST_PROMPT)])
        two = _turn_start([_log("UserPromptSubmit", FIRST_PROMPT),
                           _log("UserPromptSubmit", SECOND_PROMPT)])
        self.assertEqual(one, two)

    def test_several_stops_in_one_turn_keep_the_anchor(self):
        # Copilot uploads on each Stop and watermarks replays, so a turn can close more
        # than once; the anchor must stay on the prompt that opened it
        self.assertEqual(
            _turn_start([_log("UserPromptSubmit", FIRST_PROMPT),
                         _log("Stop", FIRST_STOP),
                         _log("Stop", "2026-08-20T10:00:25Z")]),
            FIRST_PROMPT)

    def test_a_call_after_a_stop_keeps_the_last_turns_anchor(self):
        self.assertEqual(
            _turn_start([_log("UserPromptSubmit", FIRST_PROMPT),
                         _log("Stop", FIRST_STOP)]),
            FIRST_PROMPT)

    def test_next_turn_anchors_on_its_own_prompt(self):
        self.assertEqual(
            _turn_start([_log("UserPromptSubmit", FIRST_PROMPT),
                         _log("Stop", FIRST_STOP),
                         _log("UserPromptSubmit", THIRD_PROMPT)]),
            THIRD_PROMPT)

    def test_next_turn_at_its_own_stop(self):
        self.assertEqual(
            _turn_start([_log("UserPromptSubmit", FIRST_PROMPT),
                         _log("Stop", FIRST_STOP),
                         _log("UserPromptSubmit", THIRD_PROMPT),
                         _log("Stop", SECOND_STOP)]),
            THIRD_PROMPT)

    def test_single_prompt_turn_is_unchanged(self):
        self.assertEqual(
            _turn_start([_log("UserPromptSubmit", FIRST_PROMPT),
                         _log("Stop", FIRST_STOP)]),
            FIRST_PROMPT)

    def test_other_sessions_are_ignored(self):
        self.assertEqual(
            _turn_start([_log("UserPromptSubmit", "2026-08-20T09:59:00Z", session_id="other"),
                         _log("UserPromptSubmit", FIRST_PROMPT),
                         _log("Stop", FIRST_STOP)]),
            FIRST_PROMPT)

    def test_no_session_id_returns_none(self):
        self.assertIsNone(unbound.get_turn_start_timestamp_for_session(None))

    def test_no_prompts_returns_none(self):
        self.assertIsNone(_turn_start([_log("Stop", FIRST_STOP)]))


if __name__ == "__main__":
    unittest.main()
