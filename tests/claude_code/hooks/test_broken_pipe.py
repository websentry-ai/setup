"""
Tests for AI-GATEWAY-3J: a benign BrokenPipeError raised while emitting the
hook response (host closed the read end of stdout) must NOT be self-reported,
while genuine exceptions must still be reported. Also verifies _emit itself
swallows a dead pipe instead of crashing.

AI-GATEWAY-5M is the same teardown on Windows, where the errno is EINVAL(22)
rather than EPIPE(32). Either way a dropped allow stays silent, while a dropped
deny/ask/block is reported as undelivered_verdict because the call ran ungated.
"""

import io
import sys
import unittest
from unittest.mock import Mock, patch

from tests.conftest import tool_module

unbound = tool_module("claude-code/hooks")

EPIPE_ERROR = BrokenPipeError(32, "Broken pipe")
EINVAL_ERROR = OSError(22, "Invalid argument")  # Windows' form of the same teardown


def dead_pipe(error):
    class DeadPipe:
        def write(self, _):
            raise error

        def flush(self):
            raise error

    return DeadPipe()


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


class TestUndeliveredVerdict(unittest.TestCase):
    """The host stopped listening before the verdict landed. What that means
    depends entirely on which verdict it was."""

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

    def _run_pretool(self, response, error):
        unbound.sys.stdout = dead_pipe(error)
        with patch.object(unbound, "log_error", Mock()) as log, \
             patch.object(unbound, "process_pre_tool_use", lambda *_: dict(response)), \
             patch.object(unbound, "get_api_key", lambda: "K"), \
             patch.object(unbound.sys, "stdin", io.StringIO('{"hook_event_name": "PreToolUse"}')):
            unbound.main()
        return log

    def _deny(self, decision="deny"):
        return {"hookSpecificOutput": {"hookEventName": "PreToolUse",
                                       "permissionDecision": decision}}

    def test_dropped_allow_stays_silent(self):
        log = self._run_pretool({}, EPIPE_ERROR)
        self.assertEqual(log.call_count, 0)

    def test_dropped_deny_is_reported(self):
        log = self._run_pretool(self._deny(), EPIPE_ERROR)
        self.assertEqual(log.call_count, 1)
        args, _ = log.call_args
        self.assertEqual(args[1], "undelivered_verdict")
        self.assertIn("decision=deny", args[0])
        self.assertIn("event=PreToolUse", args[0])

    def test_dropped_ask_is_reported(self):
        log = self._run_pretool(self._deny("ask"), EPIPE_ERROR)
        self.assertEqual(log.call_count, 1)
        self.assertIn("decision=ask", log.call_args[0][0])

    def test_windows_einval_is_treated_as_the_same_teardown(self):
        # AI-GATEWAY-5M: EINVAL(22), not EPIPE(32), and no filename on the
        # message. Must classify identically, not fall through to 'general'.
        log = self._run_pretool(self._deny(), EINVAL_ERROR)
        self.assertEqual(log.call_count, 1)
        self.assertEqual(log.call_args[0][1], "undelivered_verdict")

    def test_dropped_prompt_block_is_reported(self):
        unbound.sys.stdout = dead_pipe(EPIPE_ERROR)
        with patch.object(unbound, "log_error", Mock()) as log, \
             patch.object(unbound, "process_user_prompt_submit", lambda *_: {"decision": "block"}), \
             patch.object(unbound, "append_to_audit_log", Mock()), \
             patch.object(unbound, "get_api_key", lambda: "K"), \
             patch.object(unbound.sys, "stdin",
                          io.StringIO('{"hook_event_name": "UserPromptSubmit"}')):
            unbound.main()
        self.assertEqual(log.call_count, 1)
        self.assertEqual(log.call_args[0][1], "undelivered_verdict")
        self.assertIn("decision=block", log.call_args[0][0])

    def test_delivered_deny_is_not_reported(self):
        unbound.sys.stdout = io.StringIO()
        with patch.object(unbound, "log_error", Mock()) as log, \
             patch.object(unbound, "process_pre_tool_use", lambda *_: self._deny()), \
             patch.object(unbound, "get_api_key", lambda: "K"), \
             patch.object(unbound.sys, "stdin", io.StringIO('{"hook_event_name": "PreToolUse"}')):
            unbound.main()
        self.assertEqual(log.call_count, 0)


class TestEmitContract(unittest.TestCase):
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

    def test_returns_true_when_delivered(self):
        unbound.sys.stdout = io.StringIO()
        self.assertTrue(unbound._emit("{}"))

    def test_returns_false_on_epipe(self):
        unbound.sys.stdout = dead_pipe(EPIPE_ERROR)
        self.assertFalse(unbound._emit("{}"))

    def test_returns_false_on_einval(self):
        unbound.sys.stdout = dead_pipe(EINVAL_ERROR)
        self.assertFalse(unbound._emit("{}"))


class TestReadStdin(unittest.TestCase):
    def test_returns_none_when_stdin_pipe_is_gone(self):
        class DeadStdin:
            def read(self):
                raise OSError(22, "Invalid argument")

        with patch.object(unbound.sys, "stdin", DeadStdin()):
            self.assertIsNone(unbound._read_stdin())

    def test_returns_stripped_payload(self):
        with patch.object(unbound.sys, "stdin", io.StringIO('  {"a": 1}  ')):
            self.assertEqual(unbound._read_stdin(), '{"a": 1}')


if __name__ == "__main__":
    unittest.main()
