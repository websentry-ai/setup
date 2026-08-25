"""
Tests for subagent token accounting in claude-code/hooks/unbound.py.

Covers:
  - _fold_subagent_usage  (window floor and ceiling)
  - parse_transcript_file (pass-through)
  - _keep_latest_stop     (boundary survives audit-log trimming)
"""

import json
import tempfile
import unittest
from pathlib import Path

from tests.conftest import tool_module

unbound = tool_module("claude-code/hooks")
PREVIOUS_STOP = "2026-08-20T11:17:00Z"
TURN_PROMPT = "2026-08-20T11:32:13Z"


def _session_with_subagent(entries):
    """A transcript path whose subagents/ dir holds one agent file of (timestamp, tokens)."""
    root = Path(tempfile.mkdtemp())
    transcript = root / "session.jsonl"
    transcript.write_text("")
    agent_dir = root / "session" / "subagents" / "workflows" / "wf_1"
    agent_dir.mkdir(parents=True)
    with open(agent_dir / "agent.jsonl", "w", encoding="utf-8") as f:
        for index, (timestamp, tokens) in enumerate(entries):
            f.write(json.dumps({
                "type": "assistant",
                "timestamp": timestamp,
                "message": {
                    "id": "msg-%d" % index,
                    "usage": {
                        "input_tokens": tokens,
                        "output_tokens": 0,
                        "cache_read_input_tokens": 0,
                        "cache_creation_input_tokens": 0,
                    },
                },
            }) + "\n")
    return str(transcript)


def _folded_input_tokens(transcript, prompt_timestamp, floor=None):
    usage_by_key = {}
    unbound._fold_subagent_usage(transcript, prompt_timestamp, usage_by_key, floor)
    return sum(usage.get("input_tokens", 0) for usage, _ in usage_by_key.values())


class TestFoldSubagentUsageFloor(unittest.TestCase):
    def setUp(self):
        self.transcript = _session_with_subagent([
            ("2026-08-20T11:10:00Z", 100),   # before the previous Stop
            ("2026-08-20T11:20:00Z", 6000),  # between the two turns
            ("2026-08-20T11:47:28Z", 300),   # after this turn's prompt
        ])

    def test_previous_stop_floor_covers_work_between_turns(self):
        self.assertEqual(
            _folded_input_tokens(self.transcript, TURN_PROMPT, PREVIOUS_STOP), 6300)

    def test_work_before_the_previous_stop_is_excluded(self):
        # 100 belongs to the earlier turn, which already reported it
        self.assertNotIn(
            100, [_folded_input_tokens(self.transcript, TURN_PROMPT, PREVIOUS_STOP)])

    def test_falls_back_to_the_prompt_when_there_is_no_previous_stop(self):
        self.assertEqual(_folded_input_tokens(self.transcript, TURN_PROMPT, None), 300)

    def test_consecutive_turns_do_not_overlap(self):
        transcript = _session_with_subagent([
            ("2026-08-20T11:05:00Z", 10),
            ("2026-08-20T11:20:00Z", 20),
            ("2026-08-20T11:40:00Z", 30),
        ])
        first_stop, second_stop = "2026-08-20T11:00:00Z", "2026-08-20T11:17:00Z"
        after_first = _folded_input_tokens(transcript, None, first_stop)
        after_second = _folded_input_tokens(transcript, None, second_stop)
        self.assertEqual(after_first - after_second, 10)
        self.assertEqual(after_second, 50)

    def test_entry_without_a_timestamp_is_skipped(self):
        root = Path(tempfile.mkdtemp())
        transcript = root / "session.jsonl"
        transcript.write_text("")
        agent_dir = root / "session" / "subagents"
        agent_dir.mkdir(parents=True)
        with open(agent_dir / "agent.jsonl", "w", encoding="utf-8") as f:
            f.write(json.dumps({
                "type": "assistant",
                "message": {"id": "no-ts", "usage": {"input_tokens": 999}},
            }) + "\n")
        self.assertEqual(
            _folded_input_tokens(str(transcript), TURN_PROMPT, PREVIOUS_STOP), 0)


class TestParseTranscriptFloorPassThrough(unittest.TestCase):
    def setUp(self):
        self.transcript = _session_with_subagent([
            ("2026-08-20T11:20:00Z", 6000),
            ("2026-08-20T11:47:28Z", 300),
        ])

    def test_default_scopes_to_the_prompt(self):
        data = unbound.parse_transcript_file(self.transcript, TURN_PROMPT)
        self.assertEqual(data["usage"]["input_tokens"], 300)

    def test_floor_widens_the_window(self):
        data = unbound.parse_transcript_file(
            self.transcript, TURN_PROMPT, subagent_floor=PREVIOUS_STOP)
        self.assertEqual(data["usage"]["input_tokens"], 6300)



class TestWindowUpperBound(unittest.TestCase):
    """An entry flushed just after a Stop must be billed to the next turn only."""

    def setUp(self):
        self.transcript = _session_with_subagent([
            ("2026-08-20T11:16:00Z", 50),    # inside turn N
            ("2026-08-20T11:18:00Z", 700),   # written after turn N's Stop
        ])
        self.turn_n_stop = "2026-08-20T11:17:00Z"

    def test_entry_after_this_stop_is_not_counted_now(self):
        usage_by_key = {}
        unbound._fold_subagent_usage(self.transcript, "2026-08-20T11:15:00Z", usage_by_key,
                                     None, self.turn_n_stop)
        self.assertEqual(
            sum(u.get("input_tokens", 0) for u, _ in usage_by_key.values()), 50)

    def test_the_next_turn_counts_it_exactly_once(self):
        usage_by_key = {}
        unbound._fold_subagent_usage(self.transcript, "2026-08-20T11:32:00Z", usage_by_key,
                                     self.turn_n_stop, "2026-08-20T11:35:00Z")
        self.assertEqual(
            sum(u.get("input_tokens", 0) for u, _ in usage_by_key.values()), 700)

    def test_windows_partition_the_stream(self):
        first, second = {}, {}
        unbound._fold_subagent_usage(self.transcript, "2026-08-20T11:15:00Z", first,
                                     None, self.turn_n_stop)
        unbound._fold_subagent_usage(self.transcript, "2026-08-20T11:32:00Z", second,
                                     self.turn_n_stop, "2026-08-20T11:35:00Z")
        counted = sum(u.get("input_tokens", 0) for u, _ in first.values()) \
            + sum(u.get("input_tokens", 0) for u, _ in second.values())
        self.assertEqual(counted, 750)
        self.assertEqual(set(first) & set(second), set())


class TestBoundaryRetention(unittest.TestCase):
    """The previous Stop must survive audit-log trimming; it is the next turn's floor."""

    @staticmethod
    def _log(name, timestamp, session="s1"):
        return {"timestamp": timestamp, "session_id": session,
                "event": {"hook_event_name": name, "session_id": session}}

    def test_trimming_keeps_the_latest_stop(self):
        stop = self._log("Stop", "2026-08-20T11:00:00Z")
        noise = [self._log("PostToolUse", "2026-08-20T11:%02d:00Z" % (i % 60))
                 for i in range(1, 200)]
        logs = [stop] + noise
        kept = unbound._keep_latest_stop(logs, logs[-unbound.AUDIT_LOG_TOTAL_LIMIT:])
        self.assertIs(kept[0], stop)

    def test_no_duplicate_when_the_stop_survived_on_its_own(self):
        stop = self._log("Stop", "2026-08-20T11:00:00Z")
        logs = [self._log("PostToolUse", "2026-08-20T10:00:00Z"), stop]
        kept = unbound._keep_latest_stop(logs, logs)
        self.assertEqual(kept.count(stop), 1)
        self.assertEqual(len(kept), 2)


class TestStreamedMessageStraddlingAStop(unittest.TestCase):
    """Claude Code rewrites one message id as its output grows. A message whose lines span
    a Stop must be billed once, to the turn it began in, not counted whole by both."""

    def setUp(self):
        root = Path(tempfile.mkdtemp())
        self.transcript = root / "session.jsonl"
        self.transcript.write_text("")
        agent_dir = root / "session" / "subagents"
        agent_dir.mkdir(parents=True)
        with open(agent_dir / "agent.jsonl", "w", encoding="utf-8") as f:
            for timestamp, tokens in (("2026-08-20T11:16:50Z", 48751),
                                      ("2026-08-20T11:17:30Z", 48985)):
                f.write(json.dumps({
                    "type": "assistant",
                    "timestamp": timestamp,
                    "message": {"id": "msg-streamed",
                                "usage": {"input_tokens": tokens, "output_tokens": 0,
                                          "cache_read_input_tokens": 0,
                                          "cache_creation_input_tokens": 0}},
                }) + "\n")
        self.stop = "2026-08-20T11:17:00Z"

    def _fold(self, floor, ceiling):
        usage_by_key = {}
        unbound._fold_subagent_usage(str(self.transcript), None, usage_by_key, floor, ceiling)
        return usage_by_key

    def test_the_turn_it_began_in_counts_it(self):
        kept = self._fold(None, self.stop)
        self.assertEqual(sum(u.get("input_tokens", 0) for u, _ in kept.values()), 48985)

    def test_the_next_turn_does_not_count_it_again(self):
        kept = self._fold(self.stop, "2026-08-20T11:20:00Z")
        self.assertEqual(sum(u.get("input_tokens", 0) for u, _ in kept.values()), 0)

    def test_neither_turn_shares_a_key(self):
        first = self._fold(None, self.stop)
        second = self._fold(self.stop, "2026-08-20T11:20:00Z")
        self.assertEqual(set(first) & set(second), set())


if __name__ == "__main__":
    unittest.main()
