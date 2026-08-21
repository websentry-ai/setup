"""
Tests for turns that carry more than one prompt in claude-code/hooks/unbound.py.

Typing while Claude is still working adds prompts to the running turn. Covers:
  - build_llm_exchange  (every prompt kept, joined into one message)
  - process_stop_event  (turn anchored on its first prompt, events not discarded)
"""

import unittest
from unittest.mock import patch

import unbound

SESSION = "sess-queued"
FIRST_PROMPT = "2026-08-20T10:00:00Z"
TOOL_CALL = "2026-08-20T10:00:05Z"
SECOND_PROMPT = "2026-08-20T10:00:10Z"
FIRST_STOP = "2026-08-20T10:00:20Z"
THIRD_PROMPT = "2026-08-20T10:00:25Z"
SECOND_STOP = "2026-08-20T10:00:40Z"


def _log(hook_event_name, timestamp, **fields):
    event = {"hook_event_name": hook_event_name, "session_id": SESSION}
    event.update(fields)
    return {"timestamp": timestamp, "session_id": SESSION, "event": event}


def _bash_call(timestamp):
    return _log("PostToolUse", timestamp, tool_name="Bash",
                tool_input={"command": "ls"}, tool_response={})


def _user_messages(exchange):
    return [m["content"] for m in (exchange or {}).get("messages", [])
            if m.get("role") == "user"]


class TestBuildExchangeJoinsPrompts(unittest.TestCase):
    def test_two_prompts_become_one_joined_message(self):
        exchange = unbound.build_llm_exchange(
            [_log("UserPromptSubmit", FIRST_PROMPT, prompt="first"),
             _bash_call(TOOL_CALL),
             _log("UserPromptSubmit", SECOND_PROMPT, prompt="second")],
            stop_assistant_message="done")
        self.assertEqual(_user_messages(exchange), ["first\n\nsecond"])

    def test_single_prompt_is_unchanged(self):
        exchange = unbound.build_llm_exchange(
            [_log("UserPromptSubmit", FIRST_PROMPT, prompt="only"),
             _bash_call(TOOL_CALL)],
            stop_assistant_message="done")
        self.assertEqual(_user_messages(exchange), ["only"])

    def test_a_typed_skill_in_the_earlier_prompt_is_recovered(self):
        # the queued prompt follows it, so a last-wins read would never see the slash
        with patch.object(unbound, "_resolve_skill_path",
                          side_effect=lambda name, _cwd: "/skills/%s" % name):
            exchange = unbound.build_llm_exchange(
                [_log("UserPromptSubmit", FIRST_PROMPT, prompt="/deploy now"),
                 _log("UserPromptSubmit", SECOND_PROMPT, prompt="plain text")],
                stop_assistant_message="done")
        assistant = [m for m in exchange["messages"] if m["role"] == "assistant"]
        skills = [use.get("skill_name") for msg in assistant
                  for use in msg.get("tool_use", [])]
        self.assertIn("deploy", skills)


class TestStopEventTurnAssembly(unittest.TestCase):
    def setUp(self):
        self.captured = {}

        def fake_parse(path, prompt_timestamp=None, include_usage=True, subagent_floor=None):
            self.captured["anchor"] = prompt_timestamp
            self.captured["floor"] = subagent_floor
            return {"assistant_messages": [], "usage": None, "model": None}

        real_build = unbound.build_llm_exchange

        def spy_build(events, **kwargs):
            self.captured["events"] = events
            self.captured["exchange"] = real_build(events, **kwargs)
            return None  # stop before any upload

        self.patches = [
            patch.object(unbound, "parse_transcript_file", fake_parse),
            patch.object(unbound, "build_llm_exchange", spy_build),
            patch.object(unbound, "_extract_session_model", lambda *a, **k: "auto"),
        ]
        for p in self.patches:
            p.start()
        self.addCleanup(lambda: [p.stop() for p in self.patches])

    def _run(self, logs):
        with patch.object(unbound, "load_existing_logs", lambda: logs):
            unbound.process_stop_event(
                {"session_id": SESSION, "transcript_path": "/tmp/t.jsonl",
                 "last_assistant_message": "ok"}, "key")
        return self.captured

    def test_turn_anchors_on_its_first_prompt(self):
        out = self._run([_log("UserPromptSubmit", FIRST_PROMPT, prompt="first"),
                         _bash_call(TOOL_CALL),
                         _log("UserPromptSubmit", SECOND_PROMPT, prompt="second"),
                         _log("Stop", FIRST_STOP)])
        self.assertEqual(out["anchor"], FIRST_PROMPT)

    def test_queued_prompt_does_not_discard_earlier_events(self):
        out = self._run([_log("UserPromptSubmit", FIRST_PROMPT, prompt="first"),
                         _bash_call(TOOL_CALL),
                         _log("UserPromptSubmit", SECOND_PROMPT, prompt="second"),
                         _log("Stop", FIRST_STOP)])
        names = [e["event"]["hook_event_name"] for e in out["events"]]
        self.assertEqual(names.count("UserPromptSubmit"), 2)
        self.assertEqual(names.count("PostToolUse"), 1)

    def test_earlier_turn_does_not_leak_into_this_one(self):
        out = self._run([_log("UserPromptSubmit", FIRST_PROMPT, prompt="old"),
                         _log("Stop", FIRST_STOP),
                         _log("UserPromptSubmit", THIRD_PROMPT, prompt="new a"),
                         _log("UserPromptSubmit", SECOND_STOP, prompt="new b"),
                         _log("Stop", "2026-08-20T10:00:50Z")])
        self.assertEqual(out["anchor"], THIRD_PROMPT)
        self.assertEqual(_user_messages(out["exchange"]), ["new a\n\nnew b"])

    def test_single_prompt_turn_is_unchanged(self):
        out = self._run([_log("UserPromptSubmit", FIRST_PROMPT, prompt="only"),
                         _bash_call(TOOL_CALL),
                         _log("Stop", FIRST_STOP)])
        self.assertEqual(out["anchor"], FIRST_PROMPT)
        self.assertEqual(_user_messages(out["exchange"]), ["only"])


if __name__ == "__main__":
    unittest.main()
