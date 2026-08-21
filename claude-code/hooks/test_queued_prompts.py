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

    def test_each_queued_skill_resolves_with_its_own_cwd(self):
        seen = {}

        def resolve(name, cwd):
            seen[name] = cwd
            return "/skills/%s" % name

        with patch.object(unbound, "_resolve_skill_path", side_effect=resolve):
            unbound.build_llm_exchange(
                [_log("UserPromptSubmit", FIRST_PROMPT, prompt="/alpha", cwd="/repo/one"),
                 _log("UserPromptSubmit", SECOND_PROMPT, prompt="/beta", cwd="/repo/two")],
                stop_assistant_message="done")
        self.assertEqual(seen["alpha"], "/repo/one")
        self.assertEqual(seen["beta"], "/repo/two")

    def test_a_prompt_without_a_cwd_falls_back_to_the_previous_one(self):
        seen = {}
        with patch.object(unbound, "_resolve_skill_path",
                          side_effect=lambda name, cwd: seen.setdefault(name, cwd) and None):
            unbound.build_llm_exchange(
                [_log("UserPromptSubmit", FIRST_PROMPT, prompt="plain", cwd="/repo/one"),
                 _log("UserPromptSubmit", SECOND_PROMPT, prompt="/beta")],
                stop_assistant_message="done")
        self.assertEqual(seen["beta"], "/repo/one")


class TestStopEventTurnAssembly(unittest.TestCase):
    def setUp(self):
        self.captured = {}

        def fake_parse(path, prompt_timestamp=None, include_usage=True,
                       subagent_floor=None, subagent_ceiling=None):
            self.captured["anchor"] = prompt_timestamp
            self.captured["floor"] = subagent_floor
            self.captured["ceiling"] = subagent_ceiling
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

    def test_window_is_bounded_by_this_turns_stop(self):
        out = self._run([_log("UserPromptSubmit", FIRST_PROMPT, prompt="first"),
                         _log("UserPromptSubmit", SECOND_PROMPT, prompt="second"),
                         _log("Stop", FIRST_STOP)])
        self.assertEqual(out["ceiling"], FIRST_STOP)

    def test_a_retained_stop_before_this_turn_is_the_floor(self):
        # audit-log trimming can retain a Stop that precedes this turn's first prompt
        out = self._run([_log("Stop", "2026-08-20T09:59:00Z"),
                         _log("UserPromptSubmit", FIRST_PROMPT, prompt="first"),
                         _log("UserPromptSubmit", SECOND_PROMPT, prompt="second"),
                         _log("Stop", FIRST_STOP)])
        self.assertEqual(out["floor"], "2026-08-20T09:59:00Z")
        self.assertEqual(out["anchor"], FIRST_PROMPT)
        self.assertEqual(_user_messages(out["exchange"]), ["first\n\nsecond"])

    def test_single_prompt_turn_is_unchanged(self):
        out = self._run([_log("UserPromptSubmit", FIRST_PROMPT, prompt="only"),
                         _bash_call(TOOL_CALL),
                         _log("Stop", FIRST_STOP)])
        self.assertEqual(out["anchor"], FIRST_PROMPT)
        self.assertEqual(_user_messages(out["exchange"]), ["only"])


class TestQueuedPromptFromTranscript(unittest.TestCase):
    """Claude Code consumes a prompt typed mid-turn from a queue: it never becomes a user
    message and never fires UserPromptSubmit, so the queue-operation record is its only
    trace and the turn must pick it up from there."""

    def _transcript(self, entries):
        import json as _json
        import tempfile as _tempfile
        from pathlib import Path as _Path
        path = _Path(_tempfile.mkdtemp()) / "session.jsonl"
        with open(path, "w", encoding="utf-8") as f:
            for entry in entries:
                f.write(_json.dumps(entry) + "\n")
        return str(path)

    def test_a_consumed_prompt_joins_the_turn(self):
        path = self._transcript([
            {"type": "queue-operation", "operation": "enqueue",
             "timestamp": SECOND_PROMPT, "content": "queued question"},
            {"type": "queue-operation", "operation": "remove",
             "timestamp": FIRST_STOP, "content": "queued question"},
        ])
        data = unbound.parse_transcript_file(path, FIRST_PROMPT)
        self.assertEqual(data["queued_prompts"], ["queued question"])

    def test_a_prompt_taken_back_for_editing_never_ran(self):
        # pulling a queued prompt back out to edit it leaves through popAll
        path = self._transcript([
            {"type": "queue-operation", "operation": "enqueue",
             "timestamp": SECOND_PROMPT, "content": "never sent"},
            {"type": "queue-operation", "operation": "popAll",
             "timestamp": FIRST_STOP, "content": "never sent"},
        ])
        data = unbound.parse_transcript_file(path, FIRST_PROMPT)
        self.assertEqual(data["queued_prompts"], [])

    def test_an_interrupted_queue_drain_is_not_this_turns(self):
        # interrupting drains the queue as a contentless dequeue
        path = self._transcript([
            {"type": "queue-operation", "operation": "enqueue",
             "timestamp": SECOND_PROMPT, "content": "interrupted"},
            {"type": "queue-operation", "operation": "dequeue",
             "timestamp": FIRST_STOP, "content": ""},
        ])
        data = unbound.parse_transcript_file(path, FIRST_PROMPT)
        self.assertEqual(data["queued_prompts"], [])

    def test_enqueue_alone_is_not_enough(self):
        path = self._transcript([
            {"type": "queue-operation", "operation": "enqueue",
             "timestamp": SECOND_PROMPT, "content": "still queued"},
        ])
        data = unbound.parse_transcript_file(path, FIRST_PROMPT)
        self.assertEqual(data["queued_prompts"], [])

    def test_a_queue_outside_the_turn_is_ignored(self):
        path = self._transcript([
            {"type": "queue-operation", "operation": "remove",
             "timestamp": "2026-08-20T09:00:00Z", "content": "earlier turn"},
            {"type": "queue-operation", "operation": "remove",
             "timestamp": "2026-08-20T11:00:00Z", "content": "later turn"},
        ])
        data = unbound.parse_transcript_file(path, FIRST_PROMPT,
                                             subagent_ceiling=FIRST_STOP)
        self.assertEqual(data["queued_prompts"], [])

    def test_a_prompt_consumed_between_turns_belongs_to_the_later_one(self):
        # consumed after the previous turn closed and before this one was typed
        path = self._transcript([
            {"type": "queue-operation", "operation": "enqueue",
             "timestamp": "2026-08-20T10:00:05Z", "content": "between turns"},
            {"type": "queue-operation", "operation": "remove",
             "timestamp": "2026-08-20T10:00:40Z", "content": "between turns"},
        ])
        earlier = unbound.parse_transcript_file(
            path, "2026-08-20T10:00:00Z", subagent_ceiling="2026-08-20T10:00:30Z")
        later = unbound.parse_transcript_file(
            path, "2026-08-20T10:01:00Z", subagent_floor="2026-08-20T10:00:30Z",
            subagent_ceiling="2026-08-20T10:01:30Z")
        self.assertEqual(earlier["queued_prompts"], [])
        self.assertEqual(later["queued_prompts"], ["between turns"])

    def test_consecutive_turns_claim_it_exactly_once(self):
        path = self._transcript([
            {"type": "queue-operation", "operation": "remove",
             "timestamp": "2026-08-20T10:00:10Z", "content": "inside"},
        ])
        earlier = unbound.parse_transcript_file(
            path, "2026-08-20T10:00:00Z", subagent_ceiling="2026-08-20T10:00:30Z")
        later = unbound.parse_transcript_file(
            path, "2026-08-20T10:01:00Z", subagent_floor="2026-08-20T10:00:30Z",
            subagent_ceiling="2026-08-20T10:01:30Z")
        self.assertEqual((earlier["queued_prompts"], later["queued_prompts"]),
                         (["inside"], []))

    def test_the_queued_prompt_is_joined_into_the_message(self):
        exchange = unbound.build_llm_exchange(
            [_log("UserPromptSubmit", FIRST_PROMPT, prompt="typed question")],
            stop_assistant_message="done",
            queued_prompts=["queued question"])
        self.assertEqual(_user_messages(exchange),
                         ["typed question\n\nqueued question"])

    def test_a_queued_skill_resolves_against_the_turn_cwd(self):
        # the queue record carries no cwd, so borrowing another prompt's would resolve a
        # repo-scoped skill against the wrong repo
        seen = {}

        def resolve(name, cwd):
            seen[name] = cwd
            return "/skills/%s" % name

        with patch.object(unbound, "_resolve_skill_path", side_effect=resolve):
            unbound.build_llm_exchange(
                [_log("UserPromptSubmit", FIRST_PROMPT, prompt="/alpha", cwd="/repo/one")],
                stop_assistant_message="done", cwd="/session/dir",
                queued_prompts=["/beta"])
        self.assertEqual(seen["alpha"], "/repo/one")
        self.assertEqual(seen["beta"], "/session/dir")


if __name__ == "__main__":
    unittest.main()
