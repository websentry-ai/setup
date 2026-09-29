"""
Tests for AI-GATEWAY-3J: a benign BrokenPipeError raised while emitting the
hook response (host closed the read end of stdout) must NOT be self-reported,
while genuine exceptions must still be reported. Also verifies _emit itself
swallows a dead pipe instead of crashing.
"""

import io
import json
import sys
import unittest
from unittest.mock import Mock, patch

from tests.conftest import tool_module

unbound = tool_module("copilot/hooks")


class TestMainBrokenPipeNotReported(unittest.TestCase):
    def setUp(self):
        self._real_stdout = sys.stdout

    def tearDown(self):
        swapped = unbound.sys.stdout
        sys.stdout = self._real_stdout
        if swapped is not self._real_stdout:
            try:
                swapped.close()
            except Exception:
                pass

    def test_dead_stdout_pipe_is_not_reported(self):
        # Empty stdin -> main() emits its response into a stdout whose reader
        # is gone. The real _emit must swallow it: no log, no gateway report,
        # nothing escapes. (No except BrokenPipeError in main(); _emit alone
        # carries this, so a non-stdout broken pipe still reaches the
        # catch-all and is reported like any real error.)
        class DeadPipe:
            def write(self, _):
                raise BrokenPipeError(32, "Broken pipe")

            def flush(self):
                raise BrokenPipeError(32, "Broken pipe")

        unbound.sys.stdout = DeadPipe()
        with patch.object(unbound, "report_error_to_gateway", Mock()) as report, \
             patch.object(unbound, "log_error", Mock()) as log, \
             patch.object(unbound, "get_api_key", lambda: "K"), \
             patch.object(unbound.sys, "stdin", io.StringIO("")):
            try:
                unbound.main()
            except BrokenPipeError:
                self.fail("main() let BrokenPipeError escape")
        self.assertEqual(report.call_count, 0)
        self.assertEqual(log.call_count, 0)


class TestMainRealExceptionStillReported(unittest.TestCase):
    def test_real_exception_is_reported(self):
        # A Stop event reaches append_to_audit_log; make that collaborator raise
        # a genuine error. main() must report it via log_error with category
        # 'general' and a message containing the original text.
        event = '{"hook_event_name": "Stop", "session_id": "s"}'
        with patch.object(unbound, "log_error", Mock()) as log, \
             patch.object(unbound, "append_to_audit_log", side_effect=RuntimeError("boom")), \
             patch.object(unbound, "get_api_key", lambda: "K"), \
             patch.object(unbound.sys, "stdin", io.StringIO(event)), \
             patch.object(unbound.sys, "stdout", io.StringIO()):
            unbound.main()
        self.assertEqual(log.call_count, 1)
        args, _ = log.call_args
        self.assertIn("Exception in main: boom", args[0])
        self.assertEqual(args[1], "general")


class TestEmitDeadPipe(unittest.TestCase):
    def setUp(self):
        self._real_stdout = sys.stdout

    def tearDown(self):
        swapped = unbound.sys.stdout
        sys.stdout = self._real_stdout
        if swapped is not self._real_stdout:
            try:
                swapped.close()
            except Exception:
                pass

    def test_emit_to_dead_pipe_does_not_raise(self):
        class DeadPipe:
            def write(self, _):
                raise BrokenPipeError(32, "Broken pipe")

            def flush(self):
                raise BrokenPipeError(32, "Broken pipe")

        unbound.sys.stdout = DeadPipe()
        try:
            unbound._emit("{}")
        except Exception as e:
            self.fail(f"_emit raised on dead pipe: {e!r}")
        # _emit swapped stdout to a working sink, so a second emit is also safe.
        self.assertNotIsInstance(unbound.sys.stdout, DeadPipe)
        try:
            unbound._emit("{}")
        except Exception as e:
            self.fail(f"second _emit raised after swap: {e!r}")


class TestNonStdoutBrokenPipeStillDenied(unittest.TestCase):
    def test_cloud_pretool_broken_pipe_denies(self):
        # A broken pipe raised inside the policy check (not stdout) is a real
        # failure. In the cloud sandbox empty output means allow, so it must
        # reach the catch-all and emit the deny, never fall silent.
        out = []
        payload = json.dumps({"hook_event_name": "PreToolUse", "tool_name": "Bash"})
        with patch.object(unbound, "RUNNING_CLOUD", True), \
             patch.dict(unbound.os.environ, {"UNBOUND_HOOK_EVENT": "preToolUse"}), \
             patch.object(unbound, "get_api_key", return_value="key"), \
             patch.object(unbound.sys.stdin, "read", return_value=payload), \
             patch.object(unbound, "process_pre_tool_use",
                          side_effect=BrokenPipeError(32, "Broken pipe")), \
             patch.object(unbound, "log_error", Mock()) as log, \
             patch("builtins.print", lambda *a, **k: out.append(a[0] if a else "")):
            unbound.main()
        self.assertEqual(json.loads(out[-1]).get("permissionDecision"), "deny")
        self.assertEqual(log.call_count, 1)

if __name__ == "__main__":
    unittest.main()
