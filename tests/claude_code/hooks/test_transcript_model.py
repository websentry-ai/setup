"""
Tests for transcript-derived model resolution in claude-code/hooks/unbound.py.
Only SessionStart carries a model in the hook input, so PreToolUse and
UserPromptSubmit have to read it off the transcript or report 'auto'.
"""

import json
import tempfile
import unittest
from pathlib import Path

from unittest.mock import patch

from tests.conftest import tool_module
from tests.claude_code.hooks.test_pretool_mcp import ProcessPreToolUseBase

unbound = tool_module("claude-code/hooks")


def _assistant(model, text="hi"):
    return {"type": "assistant", "timestamp": "2026-09-08T18:01:57.000Z",
            "message": {"role": "assistant", "model": model,
                        "content": [{"type": "text", "text": text}]}}


def _user(text="go"):
    return {"type": "user", "timestamp": "2026-09-08T18:01:50.000Z",
            "message": {"role": "user", "content": text}}


class TestTranscriptModel(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.path = Path(self._tmp.name) / "session.jsonl"

    def tearDown(self):
        self._tmp.cleanup()

    def _write(self, entries):
        self.path.write_text("\n".join(json.dumps(e) for e in entries) + "\n")
        return str(self.path)

    def test_returns_newest_assistant_model(self):
        path = self._write([_assistant("claude-opus-4-1"), _user(),
                            _assistant("claude-sonnet-4-6"), _user()])
        self.assertEqual(unbound._transcript_model(path), "claude-sonnet-4-6")

    def test_missing_and_unusable_paths_return_none(self):
        self.assertIsNone(unbound._transcript_model(None))
        self.assertIsNone(unbound._transcript_model("undefined"))
        self.assertIsNone(unbound._transcript_model(str(self.path / "nope")))

    def test_no_assistant_entry_returns_none(self):
        self.assertIsNone(unbound._transcript_model(self._write([_user(), _user()])))

    def test_skips_malformed_lines(self):
        self.path.write_text("not json\n" + json.dumps(_assistant("claude-sonnet-4-6"))
                             + "\n{broken\n")
        self.assertEqual(unbound._transcript_model(str(self.path)), "claude-sonnet-4-6")

    def test_newest_wins_across_a_large_intervening_entry(self):
        path = self._write([_assistant("claude-opus-4-1"), _user("x" * 4096),
                            _assistant("claude-sonnet-4-6")])
        with patch.object(unbound, "_TRANSCRIPT_MODEL_WINDOWS", (1024, 65536)):
            self.assertEqual(unbound._transcript_model(path), "claude-sonnet-4-6")

    def test_record_larger_than_the_first_window_is_found_by_the_second(self):
        # A single tool-result record can fill the first window on its own.
        path = self._write([_assistant("claude-sonnet-4-6"), _user("x" * 4096)])
        with patch.object(unbound, "_TRANSCRIPT_MODEL_WINDOWS", (1024, 65536)):
            self.assertEqual(unbound._transcript_model(path), "claude-sonnet-4-6")

    def test_model_bearing_record_exceeding_the_first_window(self):
        path = self._write([_assistant("claude-sonnet-4-6", "y" * 4096)])
        with patch.object(unbound, "_TRANSCRIPT_MODEL_WINDOWS", (1024, 65536)):
            self.assertEqual(unbound._transcript_model(path), "claude-sonnet-4-6")

    def test_beyond_every_window_is_none(self):
        path = self._write([_assistant("claude-opus-4-1"), _user("x" * 4096)])
        with patch.object(unbound, "_TRANSCRIPT_MODEL_WINDOWS", (256, 1024)):
            self.assertIsNone(unbound._transcript_model(path))

    def test_short_file_is_read_once_not_per_window(self):
        path = self._write([_assistant("claude-sonnet-4-6")])
        opened = []
        real_open = unbound.open if hasattr(unbound, "open") else open
        with patch("builtins.open", side_effect=lambda *a, **k: opened.append(a[0]) or real_open(*a, **k)):
            self.assertEqual(unbound._transcript_model(path), "claude-sonnet-4-6")
        self.assertEqual(len(opened), 1)


class TestPreToolUseReportsTranscriptModel(ProcessPreToolUseBase):
    """The gateway logs a warned/blocked call under whatever model the hook sends,
    so a pre-tool row reads 'auto' unless the transcript is consulted."""

    def _capture(self, transcript_path):
        captured = {}

        def capturing_gw(request_body, api_key):
            captured["body"] = request_body
            return {"decision": "allow"}

        event = {
            "hook_event_name": "PreToolUse",
            "tool_name": "mcp__github__create_issue",
            "tool_input": {"q": "x"},
            "cwd": self.cwd,
            "session_id": "sess",
            "transcript_path": transcript_path,
        }
        with patch.object(unbound, "send_to_hook_api", capturing_gw):
            unbound.process_pre_tool_use(event, "API_KEY")
        return captured["body"]

    def test_sends_the_model_that_is_running_the_turn(self):
        path = self.root / "session.jsonl"
        path.write_text(json.dumps(_assistant("claude-sonnet-4-6")) + "\n")
        self.assertEqual(self._capture(str(path))["model"], "claude-sonnet-4-6")

    def test_falls_back_when_the_transcript_names_no_model(self):
        path = self.root / "empty.jsonl"
        path.write_text(json.dumps(_user()) + "\n")
        self.assertEqual(self._capture(str(path))["model"], "auto")


if __name__ == "__main__":
    unittest.main()
