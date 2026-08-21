"""
Tests for generations that carry more than one prompt in cursor/unbound.py.

Typing while Cursor is still working can add prompts to the running generation. Covers:
  - build_llm_exchange  (every prompt kept, joined into one message, anchored on the first)
"""

import unittest

import unbound

CONVERSATION = "conv-1"
GENERATION = "gen-1"
FIRST_PROMPT = "2026-08-20T10:00:00Z"
SECOND_PROMPT = "2026-08-20T10:00:10Z"
STOP = "2026-08-20T10:00:20Z"


def _log(hook_event_name, timestamp, **fields):
    event = {"hook_event_name": hook_event_name,
             "conversation_id": CONVERSATION,
             "generation_id": GENERATION,
             "model": "auto"}
    event.update(fields)
    return {"timestamp": timestamp, "event": event}


def _user_messages(exchange):
    return [m["content"] for m in (exchange or {}).get("messages", [])
            if m.get("role") == "user"]


class TestGenerationCarryingSeveralPrompts(unittest.TestCase):
    def test_two_prompts_become_one_joined_message(self):
        exchange = unbound.build_llm_exchange([
            _log("beforeSubmitPrompt", FIRST_PROMPT, prompt="first"),
            _log("beforeSubmitPrompt", SECOND_PROMPT, prompt="second"),
            _log("stop", STOP, agentTextResponse="done"),
        ])
        self.assertEqual(_user_messages(exchange), ["first\n\nsecond"])

    def test_turn_anchors_on_the_first_prompt(self):
        exchange = unbound.build_llm_exchange([
            _log("beforeSubmitPrompt", FIRST_PROMPT, prompt="first"),
            _log("beforeSubmitPrompt", SECOND_PROMPT, prompt="second"),
            _log("stop", STOP, agentTextResponse="done"),
        ])
        self.assertEqual(exchange.get("requestInitialized"), FIRST_PROMPT)

    def test_single_prompt_generation_is_unchanged(self):
        exchange = unbound.build_llm_exchange([
            _log("beforeSubmitPrompt", FIRST_PROMPT, prompt="only"),
            _log("stop", STOP, agentTextResponse="done"),
        ])
        self.assertEqual(_user_messages(exchange), ["only"])
        self.assertEqual(exchange.get("requestInitialized"), FIRST_PROMPT)

    def test_empty_prompt_is_ignored(self):
        exchange = unbound.build_llm_exchange([
            _log("beforeSubmitPrompt", FIRST_PROMPT, prompt=""),
            _log("beforeSubmitPrompt", SECOND_PROMPT, prompt="real"),
            _log("stop", STOP, agentTextResponse="done"),
        ])
        self.assertEqual(_user_messages(exchange), ["real"])


class TestPromptsFromCursorTranscript(unittest.TestCase):
    """A prompt typed while Cursor is working joins the running generation without firing
    beforeSubmitPrompt, so the hook events see only the first one. Cursor's own transcript
    carries both."""

    @staticmethod
    def _transcript(entries):
        import json as _json
        import tempfile as _tempfile
        from pathlib import Path as _Path
        path = _Path(_tempfile.mkdtemp()) / "transcript.jsonl"
        with open(path, "w", encoding="utf-8") as f:
            for entry in entries:
                f.write(_json.dumps(entry) + "\n")
        return str(path)

    @staticmethod
    def _user(text):
        return {"role": "user", "message": {"content": [
            {"type": "text",
             "text": "<timestamp>Friday, Aug 21, 2026</timestamp>\n"
                     "<user_query>\n%s\n</user_query>" % text}]}}

    @staticmethod
    def _assistant(text):
        return {"role": "assistant", "message": {"content": [{"type": "text", "text": text}]}}

    def test_user_query_wrapper_is_stripped(self):
        self.assertEqual(
            unbound._cursor_user_query(
                "<timestamp>x</timestamp>\n<user_query>\nhello\n</user_query>"),
            "hello")

    def test_unwrapped_text_is_returned_as_is(self):
        self.assertEqual(unbound._cursor_user_query("  plain  "), "plain")

    def test_every_prompt_of_the_turn_is_read(self):
        path = self._transcript([
            self._user("first question"),
            self._assistant("working on it"),
            self._user("second question"),
            self._assistant("the answer"),
            {"type": "turn_ended", "status": "success"},
        ])
        self.assertEqual(unbound._cursor_turn_prompts(path),
                         ["first question", "second question"])

    def test_an_earlier_completed_turn_is_not_carried_forward(self):
        path = self._transcript([
            self._user("older question"),
            self._assistant("older answer"),
            {"type": "turn_ended", "status": "success"},
            self._user("current question"),
            self._assistant("current answer"),
            {"type": "turn_ended", "status": "success"},
        ])
        self.assertEqual(unbound._cursor_turn_prompts(path), ["current question"])

    def test_a_missing_transcript_is_not_an_error(self):
        self.assertEqual(unbound._cursor_turn_prompts("/nonexistent/x.jsonl"), [])
        self.assertEqual(unbound._cursor_turn_prompts(None), [])

    def test_the_exchange_uses_the_transcript_prompts(self):
        path = self._transcript([
            self._user("first question"),
            self._assistant("working on it"),
            self._user("second question"),
            self._assistant("the answer"),
            {"type": "turn_ended", "status": "success"},
        ])
        exchange = unbound.build_llm_exchange([
            _log("beforeSubmitPrompt", FIRST_PROMPT, prompt="first question"),
            _log("stop", STOP, agentTextResponse="done", transcript_path=path),
        ])
        self.assertEqual(_user_messages(exchange),
                         ["first question\n\nsecond question"])
        self.assertEqual(exchange.get("requestInitialized"), FIRST_PROMPT)


if __name__ == "__main__":
    unittest.main()
