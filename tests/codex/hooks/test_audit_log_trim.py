"""Audit-log trimming in codex/hooks/unbound.py keeps every turn still in progress."""

import tempfile
import unittest
from datetime import datetime, timedelta
from pathlib import Path
from unittest.mock import patch

from tests.conftest import tool_module

unbound = tool_module("codex/hooks")


class TestAuditLogTrim(unittest.TestCase):

    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        patcher = patch.object(unbound, "AUDIT_LOG", Path(tmp.name) / "agent-audit.log")
        patcher.start()
        self.addCleanup(patcher.stop)
        self.clock = 0

    def _log(self, name, session, **fields):
        self.clock += 1
        timestamp = (datetime.utcnow() + timedelta(seconds=self.clock)).isoformat() + "Z"
        unbound.append_to_audit_log({"timestamp": timestamp, "session_id": session,
                                     "event": dict({"hook_event_name": name, "session_id": session}, **fields)})
        unbound.cleanup_old_logs()

    def _prompts(self):
        return [log["event"]["prompt"] for log in unbound.load_existing_logs()
                if log["event"]["hook_event_name"] == "UserPromptSubmit"]

    def test_a_long_turn_keeps_its_prompt(self):
        self._log("UserPromptSubmit", "s1", prompt="run them all")
        for _ in range(150):
            self._log("PostToolUse", "s1")
        self.assertEqual(self._prompts(), ["run them all"])

    def test_an_older_session_mid_turn_keeps_its_prompt(self):
        self._log("UserPromptSubmit", "older", prompt="long job")
        self._log("UserPromptSubmit", "newer", prompt="busy elsewhere")
        for _ in range(120):
            self._log("PostToolUse", "newer")
        self.assertEqual(self._prompts(), ["long job", "busy elsewhere"])


if __name__ == "__main__":
    unittest.main()
