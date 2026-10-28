"""
Audit-log trimming in claude-code/hooks/unbound.py never drops a turn still in progress.

Each event is logged and the log trimmed, as main() does, then the turn's Stop is processed.
"""

import tempfile
import unittest
from datetime import datetime, timedelta
from pathlib import Path
from unittest.mock import patch

from tests.conftest import tool_module

unbound = tool_module("claude-code/hooks")


def _now(seconds=0):
    return (datetime.utcnow() + timedelta(seconds=seconds)).isoformat() + "Z"


def _event(name, session, **fields):
    return dict({"hook_event_name": name, "session_id": session}, **fields)


class TestAuditLogTrim(unittest.TestCase):

    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        patcher = patch.object(unbound, "AUDIT_LOG", Path(tmp.name) / "agent-audit.log")
        patcher.start()
        self.addCleanup(patcher.stop)
        self.clock = 0

    def _log(self, event, timestamp=None, trim=True):
        self.clock += 1
        unbound.append_to_audit_log({"timestamp": timestamp or _now(self.clock),
                                     "session_id": event["session_id"], "event": event})
        if trim:
            unbound.cleanup_old_logs()

    def _turn(self, session, prompt, tool_calls):
        self._log(_event("UserPromptSubmit", session, prompt=prompt))
        for i in range(tool_calls):
            self._log(_event("PostToolUse", session, tool_name="Bash",
                             tool_input={"command": "echo %d" % i}, tool_response={}))

    def _stop(self, session):
        stop = _event("Stop", session, last_assistant_message="done")
        self._log(stop, trim=False)
        with patch.object(unbound, "send_to_api") as send:
            unbound.process_stop_event(stop, "key")
        unbound.cleanup_old_logs()
        return [call.args[0] for call in send.call_args_list]

    def _prompts(self, exchanges):
        return [m["content"] for e in exchanges for m in e["messages"] if m["role"] == "user"]

    def test_a_turn_with_more_tool_calls_than_the_log_holds_is_still_sent(self):
        self._turn("s1", "run them all", 150)
        exchanges = self._stop("s1")
        self.assertEqual(self._prompts(exchanges), ["run them all"])

    def test_an_older_terminal_mid_turn_keeps_its_turn_when_a_newer_one_is_busy(self):
        self._turn("older", "long job", 5)
        self._turn("newer", "busy elsewhere", 120)
        self.assertEqual(self._prompts(self._stop("older")), ["long job"])

    def test_the_session_kept_is_the_one_active_last_not_the_one_started_last(self):
        self._turn("first", "first prompt", 0)
        self._turn("second", "second prompt", 0)
        for i in range(120):
            self._log(_event("PostToolUse", "first", tool_name="Bash",
                             tool_input={"command": str(i)}, tool_response={}))
        calls = [log for log in unbound.load_existing_logs() if log["session_id"] == "first"
                 and log["event"]["hook_event_name"] == "PostToolUse"]
        self.assertGreaterEqual(len(calls), unbound.AUDIT_LOG_TOTAL_LIMIT - 10)

    def test_an_interrupted_turn_elsewhere_does_not_let_the_log_grow(self):
        self._turn("interrupted", "never stopped", 1)
        for n in range(40):
            self._turn("busy", "turn %d" % n, 10)
            self._stop("busy")
        self.assertLessEqual(len(unbound.load_existing_logs()), unbound.AUDIT_LOG_TOTAL_LIMIT + 3)

    def test_a_very_long_turn_keeps_the_log_bounded_and_still_sends(self):
        self._turn("s1", "run them all", 400)
        self.assertLessEqual(len(unbound.load_existing_logs()), unbound.AUDIT_LOG_TOTAL_LIMIT + 2)
        self.assertEqual(self._prompts(self._stop("s1")), ["run them all"])

    def test_a_finished_turn_is_trimmed_as_before(self):
        self._turn("s1", "short", 1)
        self._stop("s1")
        self._turn("s1", "long", 150)
        self._stop("s1")
        self.assertLessEqual(len(unbound.load_existing_logs()), unbound.AUDIT_LOG_TOTAL_LIMIT + 1)

    def test_a_turn_idle_for_a_day_is_let_go(self):
        self._log(_event("UserPromptSubmit", "gone", prompt="abandoned"), _now(-2 * 86400))
        self._turn("s1", "current", 120)
        sessions = {log["session_id"] for log in unbound.load_existing_logs()}
        self.assertNotIn("gone", sessions)


if __name__ == "__main__":
    unittest.main()
