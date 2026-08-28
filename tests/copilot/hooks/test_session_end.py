"""
Tests for the SessionEnd hook in copilot/hooks/unbound.py and both installers.

A session can end before a final Stop fires, leaving its last turn unreported. SessionEnd
runs the same flush so that turn still lands. A turn already sent is deliberately left
alone: usage is part of the backend's request id, so re-sending would add a second row
rather than complete the first.
"""

import unittest
from pathlib import Path
from unittest.mock import patch

from tests.conftest import tool_module

unbound = tool_module("copilot/hooks")
setup = tool_module("copilot/hooks", "setup")
mdm = tool_module("copilot/hooks/mdm", "setup")

SESSION = "sess-end"
CLI = "/h/.copilot/session-state/" + SESSION + "/events.jsonl"


class TestSessionEndIsRegistered(unittest.TestCase):
    """Copilot aliases the PascalCase key to its internal sessionEnd event."""

    def test_both_installers_register_session_end(self):
        for module in (setup, mdm):
            config = module._copilot_hooks_config(Path("/x/unbound.py"))
            self.assertIn("SessionEnd", config["hooks"], module.__name__)

    def test_the_entry_matches_the_shape_of_the_others(self):
        for module in (setup, mdm):
            hooks = module._copilot_hooks_config(Path("/x/unbound.py"))["hooks"]
            self.assertEqual(set(hooks["SessionEnd"][0]), set(hooks["Stop"][0]))
            self.assertEqual(hooks["SessionEnd"][0]["type"], "command")
            self.assertGreater(hooks["SessionEnd"][0]["timeoutSec"], 0)

    def test_the_existing_events_are_untouched(self):
        for module in (setup, mdm):
            hooks = module._copilot_hooks_config(Path("/x/unbound.py"))["hooks"]
            for name in ("SessionStart", "UserPromptSubmit", "PreToolUse",
                         "PostToolUse", "Stop"):
                self.assertIn(name, hooks, name)


class TestTranscriptPathRecovery(unittest.TestCase):
    """sessionEnd carries sessionId, timestamp, cwd and reason, but no transcript path."""

    @staticmethod
    def _log(name, sess, path=None):
        event = {"hook_event_name": name, "session_id": sess}
        if path:
            event["transcript_path"] = path
        return {"timestamp": "t", "event": event}

    def _recover(self, logs, session=SESSION, path=None):
        event = {"hook_event_name": "SessionEnd"}
        if session:
            event["session_id"] = session
        if path:
            event["transcript_path"] = path
        with patch.object(unbound, "load_existing_logs", lambda: logs):
            return unbound._transcript_path_for_session(event)

    def test_it_comes_from_this_session_s_newest_event_that_had_one(self):
        logs = [self._log("UserPromptSubmit", SESSION, CLI),
                self._log("Stop", SESSION, CLI),
                self._log("SessionEnd", SESSION)]
        self.assertEqual(self._recover(logs), CLI)

    def test_another_session_s_path_is_not_borrowed(self):
        logs = [self._log("Stop", "other", "/h/.copilot/session-state/other/events.jsonl"),
                self._log("SessionEnd", SESSION)]
        self.assertIsNone(self._recover(logs))

    def test_no_session_id_recovers_nothing(self):
        self.assertIsNone(self._recover([self._log("Stop", SESSION, CLI)], session=None))

    def test_a_non_string_path_is_ignored(self):
        logs = [self._log("Stop", SESSION, CLI),
                {"timestamp": "t", "event": {"hook_event_name": "Stop",
                                             "session_id": SESSION,
                                             "transcript_path": {"corrupt": 1}}}]
        self.assertEqual(self._recover(logs), CLI)

    def test_nothing_logged_recovers_nothing(self):
        self.assertIsNone(self._recover([]))

    def test_a_row_that_omits_session_id_is_still_matched(self):
        # matched by stop_session_key, like the window floor and log cleanup, so a Stop
        # that carries only a transcript path still supplies the path
        logs = [{"timestamp": "t", "event": {"hook_event_name": "Stop",
                                             "transcript_path": CLI}}]
        self.assertEqual(self._recover(logs), CLI)

    def test_an_event_with_no_identity_recovers_nothing(self):
        logs = [self._log("Stop", SESSION, CLI)]
        with patch.object(unbound, "load_existing_logs", lambda: logs):
            self.assertIsNone(unbound._transcript_path_for_session({}))
