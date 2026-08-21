"""
Tests for subagent token accounting in claude-code/hooks/unbound.py.

Covers:
  - _fold_subagent_usage  (scoping floor)
  - parse_transcript_file (subagent_floor pass-through)
"""

import json
import tempfile
import unittest
from pathlib import Path

import unbound

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


if __name__ == "__main__":
    unittest.main()
