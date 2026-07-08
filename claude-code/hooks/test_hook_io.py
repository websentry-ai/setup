import json
import os
import subprocess
import sys
import unittest
from pathlib import Path

HOOK = Path(__file__).resolve().parent / "unbound.py"


class TestHookBrokenPipe(unittest.TestCase):
    """The hook must fail open when Claude Code closes its stdout early.

    Claude closes the hook's pipe as soon as it has the response it needs (or
    when it times the hook out). Writing to that closed pipe used to raise
    BrokenPipeError, which (a) flooded error.log with "Exception in main:
    Broken pipe" and (b) made the interpreter print "Exception ignored ...
    BrokenPipeError" and exit non-zero at shutdown. See WEB-4745.

    These run the real hook as a subprocess so they exercise the actual
    stdout/stderr/exit-code behavior Claude Code sees.
    """

    EVENT = json.dumps({
        "hook_event_name": "PreToolUse",
        "tool_name": "Bash",
        "tool_input": {"command": "echo hi"},
        "session_id": "test-broken-pipe",
    }).encode()

    def _run(self, close_stdout):
        proc = subprocess.Popen(
            [sys.executable, str(HOOK)],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            # Point error.log at a throwaway dir so the test never touches the
            # developer's real ~/.claude/hooks/error.log.
            env={**os.environ, "HOME": str(Path(self._tmp))},
        )
        if close_stdout:
            proc.stdout.close()
        try:
            proc.stdin.write(self.EVENT)
            proc.stdin.close()
        except BrokenPipeError:
            pass
        rc = proc.wait(timeout=30)
        err = proc.stderr.read().decode()
        out = b"" if close_stdout else proc.stdout.read()
        proc.stderr.close()
        return rc, out, err

    def setUp(self):
        import tempfile
        self._tmpdir = tempfile.TemporaryDirectory()
        self._tmp = self._tmpdir.name
        self.addCleanup(self._tmpdir.cleanup)

    def test_closed_stdout_exits_cleanly_with_no_traceback(self):
        rc, _out, err = self._run(close_stdout=True)
        self.assertEqual(rc, 0, f"expected clean exit on closed pipe, got {rc}")
        self.assertNotIn("BrokenPipeError", err)
        self.assertNotIn("Traceback", err)

    def test_closed_stdout_does_not_log_broken_pipe(self):
        self._run(close_stdout=True)
        log = Path(self._tmp) / ".claude" / "hooks" / "error.log"
        contents = log.read_text() if log.exists() else ""
        self.assertNotIn("Broken pipe", contents)

    def test_open_stdout_still_emits_valid_json(self):
        rc, out, _err = self._run(close_stdout=False)
        self.assertEqual(rc, 0)
        parsed = json.loads(out.decode())
        self.assertIn("suppressOutput", parsed)


if __name__ == "__main__":
    unittest.main()
