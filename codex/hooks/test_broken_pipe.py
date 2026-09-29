"""
Tests for AI-GATEWAY-3J: a benign BrokenPipeError raised while emitting the
hook response (host closed the read end of stdout) must NOT be self-reported,
while genuine exceptions must still be reported. Also verifies _emit itself
swallows a dead pipe instead of crashing.
"""

import io
import sys
import unittest
from unittest.mock import Mock, patch

import unbound


class TestMainBrokenPipeNotReported(unittest.TestCase):
    def test_broken_pipe_on_emit_is_not_reported(self):
        # Empty stdin -> main() hits the first _emit; make that _emit raise a
        # broken pipe. main() must catch it, NOT log, NOT report to gateway.
        with patch.object(unbound, "_emit", side_effect=BrokenPipeError(32, "Broken pipe")), \
             patch.object(unbound, "report_error_to_gateway", Mock()) as report, \
             patch.object(unbound, "log_error", Mock()) as log, \
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


if __name__ == "__main__":
    unittest.main()
