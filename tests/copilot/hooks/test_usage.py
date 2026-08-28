"""
Tests for local token-usage capture in copilot/hooks/unbound.py.

Copilot forwards no usage, so the hook reads it from the store behind each surface.
Covers:
  - _cli_turn_usage (CLI sqlite store, cache-inclusive input)
  - _vscode_turn_usage (VS Code append-only chat journal)
  - get_previous_stop_timestamp_for_session / get_turn_usage (windowing, guards)
"""

import importlib.util
import json
import os
import sqlite3
import tempfile
import unittest
from pathlib import Path, PureWindowsPath
from unittest.mock import patch

from tests.conftest import tool_module

unbound = tool_module("copilot/hooks")

SESSION = "sess-usage"
FLOOR = "2026-08-28T10:37:00.000+05:30"   # 05:07:00Z, as the audit log writes it
CEILING = "2026-08-28T10:40:00.000+05:30"
BEFORE = "2026-08-28T05:06:00.000Z"
INSIDE = "2026-08-28T05:08:00.000Z"
AFTER = "2026-08-28T05:20:00.000Z"

SCHEMA = """CREATE TABLE assistant_usage_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT, session_id TEXT, turn_index INTEGER, model TEXT,
    input_tokens INTEGER, output_tokens INTEGER, cache_read_tokens INTEGER,
    cache_write_tokens INTEGER, reasoning_tokens INTEGER, created_at TEXT)"""


def _store(rows, tmpdir):
    path = Path(tmpdir) / "session-store.db"
    conn = sqlite3.connect(str(path))
    conn.execute(SCHEMA)
    conn.executemany(
        "INSERT INTO assistant_usage_events (session_id, input_tokens, output_tokens,"
        " cache_read_tokens, cache_write_tokens, created_at) VALUES (?,?,?,?,?,?)", rows)
    conn.commit()
    conn.close()
    return path


def _cli_usage(rows, since=None, until=None, session=SESSION):
    with tempfile.TemporaryDirectory() as tmpdir:
        with patch.object(unbound, "_COPILOT_STORE", _store(rows, tmpdir)):
            return unbound._cli_turn_usage(session, since, until or float("inf"))


def _journal(tmpdir, session, lines):
    root = Path(tmpdir) / "ws" / "hash"
    (root / "chatSessions").mkdir(parents=True)
    (root / "GitHub.copilot-chat" / "transcripts").mkdir(parents=True)
    (root / "chatSessions" / (session + ".jsonl")).write_text(
        "\n".join(json.dumps(line) for line in lines), encoding="utf-8")
    transcript = root / "GitHub.copilot-chat" / "transcripts" / (session + ".jsonl")
    transcript.write_text("", encoding="utf-8")
    return str(transcript)


def _request(ts_ms, prompt=None, completion=None):
    obj = {"timestamp": ts_ms}
    if prompt is not None:
        obj["promptTokens"] = prompt
    if completion is not None:
        obj["completionTokens"] = completion
    return obj


class TestCliUsage(unittest.TestCase):
    def test_cache_tiers_come_out_of_input(self):
        # 26941 = 10 fresh + 0 read + 26931 write, the shape Copilot actually records
        usage = _cli_usage([(SESSION, 26941, 274, 0, 26931, INSIDE)])
        self.assertEqual(usage, {"input_tokens": 10, "output_tokens": 274,
                                 "cache_read_input_tokens": 0,
                                 "cache_creation_input_tokens": 26931})

    def test_window_excludes_the_floor_and_includes_the_ceiling(self):
        rows = [(SESSION, 1000, 10, 0, 0, BEFORE), (SESSION, 2000, 20, 0, 0, INSIDE),
                (SESSION, 4000, 40, 0, 0, AFTER)]
        usage = _cli_usage(rows, unbound._epoch(FLOOR), unbound._epoch(CEILING))
        self.assertEqual(usage["input_tokens"], 2000)
        self.assertEqual(usage["output_tokens"], 20)

    def test_no_floor_takes_everything_up_to_the_ceiling(self):
        rows = [(SESSION, 1000, 10, 0, 0, BEFORE), (SESSION, 2000, 20, 0, 0, INSIDE)]
        self.assertEqual(_cli_usage(rows, None, unbound._epoch(CEILING))["input_tokens"], 3000)

    def test_other_sessions_are_not_counted(self):
        rows = [("other", 5000, 50, 0, 0, INSIDE), (SESSION, 7, 1, 0, 0, INSIDE)]
        self.assertEqual(_cli_usage(rows)["input_tokens"], 7)

    def test_input_never_goes_negative(self):
        self.assertEqual(_cli_usage([(SESSION, 100, 5, 900, 900, INSIDE)])["input_tokens"], 0)

    def test_missing_store_returns_none(self):
        with patch.object(unbound, "_COPILOT_STORE", Path("/nonexistent/session-store.db")):
            self.assertIsNone(unbound._cli_turn_usage(SESSION, None, float("inf")))

    def test_store_without_the_table_returns_none(self):
        # older Copilot builds predate assistant_usage_events
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "session-store.db"
            sqlite3.connect(str(path)).close()
            with patch.object(unbound, "_COPILOT_STORE", path):
                self.assertIsNone(unbound._cli_turn_usage(SESSION, None, float("inf")))


class TestPreviousStop(unittest.TestCase):
    @staticmethod
    def _logs(*events):
        return [{"timestamp": ts,
                 "event": {"hook_event_name": name, "session_id": sess}}
                for name, ts, sess in events]

    def _previous(self, logs):
        with patch.object(unbound, "load_existing_logs", lambda: logs):
            return unbound.get_previous_stop_timestamp_for_session(SESSION)

    def test_the_stop_before_the_one_being_handled(self):
        logs = self._logs(("Stop", "t1", SESSION), ("Stop", "t2", SESSION))
        self.assertEqual(self._previous(logs), "t1")

    def test_first_stop_of_a_session_has_no_floor(self):
        self.assertIsNone(self._previous(self._logs(("Stop", "t1", SESSION))))

    def test_other_sessions_are_ignored(self):
        logs = self._logs(("Stop", "t1", "other"), ("Stop", "t2", SESSION))
        self.assertIsNone(self._previous(logs))


class TestEpoch(unittest.TestCase):
    def test_local_offset_and_zulu_compare_equal(self):
        self.assertEqual(unbound._epoch("2026-08-28T10:37:00.000+05:30"),
                         unbound._epoch("2026-08-28T05:07:00.000Z"))

    def test_epoch_millis_are_accepted(self):
        self.assertEqual(unbound._epoch(1787893680000), 1787893680.0)

    def test_garbage_is_none(self):
        for value in (None, "", "not-a-date", True):
            self.assertIsNone(unbound._epoch(value))


class TestWindows(unittest.TestCase):
    """The store paths must resolve on Windows too. `Path` is `WindowsPath` there, so it
    accepts both separators; hook payloads use '/' even on Windows."""

    WS = "C:/Users/dev/AppData/Roaming/Code/User/workspaceStorage/abc123"

    def _derive(self, transcript):
        # mirrors _vscode_store_path's relative walk, under Windows path semantics
        parent = PureWindowsPath(transcript).parent
        if parent.name != "transcripts":
            return None
        return parent.parent.parent / "chatSessions" / (SESSION + ".jsonl")

    def test_forward_slash_payload_resolves_the_sibling_store(self):
        got = self._derive(self.WS + "/GitHub.copilot-chat/transcripts/" + SESSION + ".jsonl")
        self.assertEqual(got, PureWindowsPath(self.WS) / "chatSessions" / (SESSION + ".jsonl"))

    def test_backslash_payload_resolves_the_same_store(self):
        transcript = (self.WS + "/GitHub.copilot-chat/transcripts/" + SESSION + ".jsonl").replace("/", "\\")
        got = self._derive(transcript)
        self.assertEqual(got, PureWindowsPath(self.WS) / "chatSessions" / (SESSION + ".jsonl"))

    def test_cli_transcript_is_recognised_by_stem(self):
        self.assertEqual(PureWindowsPath("C:/Users/dev/.copilot/session-state/s/events.jsonl").stem,
                         "events")


class TestCopilotHome(unittest.TestCase):
    @staticmethod
    def _store_path(env):
        with patch.dict(os.environ, env, clear=False):
            spec = importlib.util.spec_from_file_location(
                "unb_home_probe", Path(unbound.__file__))
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)
            return module._COPILOT_STORE

    def test_copilot_home_relocates_the_store(self):
        # COPILOT_HOME replaces the whole ~/.copilot path
        self.assertEqual(self._store_path({"COPILOT_HOME": "/tmp/custom-copilot"}),
                         Path("/tmp/custom-copilot/session-store.db"))

    def test_default_is_the_home_dotfile_dir(self):
        env = {k: v for k, v in os.environ.items() if k != "COPILOT_HOME"}
        with patch.dict(os.environ, env, clear=True):
            self.assertEqual(self._store_path({}), Path.home() / ".copilot" / "session-store.db")


def _request(ts_ms=1787893680000, prompt=None, completion=None, elapsed=1234):
    """A finished request. VS Code writes elapsedMs last, after the final counts."""
    obj = {"timestamp": ts_ms}
    if prompt is not None:
        obj["promptTokens"] = prompt
    if completion is not None:
        obj["completionTokens"] = completion
    if elapsed is not None:
        obj["elapsedMs"] = elapsed
    return obj


class TestVscodeUsage(unittest.TestCase):
    """Index-driven: report contiguous finished requests, leave the rest for a later Stop."""

    def _usage(self, lines, start_index=0):
        with tempfile.TemporaryDirectory() as tmpdir:
            transcript = _journal(tmpdir, SESSION, lines)
            return unbound._vscode_turn_usage(transcript, SESSION, start_index)

    def test_appends_then_patches_resolve_to_the_last_write(self):
        usage, nxt = self._usage([
            {"kind": 1, "v": {"requests": []}},
            {"kind": 2, "k": ["requests"], "v": [_request()]},
            {"kind": 2, "k": ["requests", "0", "promptTokens"], "v": 40355},
            {"kind": 2, "k": ["requests", "0", "promptTokens"], "v": 40669},
            {"kind": 2, "k": ["requests", "0", "completionTokens"], "v": 248},
        ])
        self.assertEqual(usage["input_tokens"], 40669)
        self.assertEqual(nxt, 1)

    def test_unfinished_request_is_left_for_a_later_stop(self):
        # idx1 has no tokens yet: report idx0 only, and do not advance past idx1
        usage, nxt = self._usage([
            {"kind": 1, "v": {"requests": []}},
            {"kind": 2, "k": ["requests"], "v": [_request(prompt=100, completion=5), _request()]},
        ])
        self.assertEqual(usage["input_tokens"], 100)
        self.assertEqual(nxt, 1)

    def test_half_written_request_is_not_reported(self):
        # prompt present but completion still pending
        usage, nxt = self._usage([
            {"kind": 1, "v": {"requests": []}},
            {"kind": 2, "k": ["requests"], "v": [_request(prompt=100, elapsed=None)]},
        ])
        self.assertEqual(usage["input_tokens"], 0)
        self.assertEqual(nxt, 0)

    def test_streaming_counts_are_not_trusted_until_elapsed_is_written(self):
        # counts appear mid-stream and climb; without elapsedMs they must not be reported
        usage, nxt = self._usage([
            {"kind": 1, "v": {"requests": []}},
            {"kind": 2, "k": ["requests"], "v": [_request(prompt=40369, completion=178, elapsed=None)]},
        ])
        self.assertEqual((usage["input_tokens"], nxt), (0, 0))

    def test_final_counts_are_reported_once_elapsed_lands(self):
        usage, nxt = self._usage([
            {"kind": 1, "v": {"requests": []}},
            {"kind": 2, "k": ["requests"], "v": [_request(prompt=40369, completion=178, elapsed=None)]},
            {"kind": 2, "k": ["requests", "0", "completionTokens"], "v": 591},
            {"kind": 2, "k": ["requests", "0", "promptTokens"], "v": 44090},
            {"kind": 2, "k": ["requests", "0", "elapsedMs"], "v": 10980},
        ])
        self.assertEqual((usage["input_tokens"], usage["output_tokens"], nxt), (44090, 591, 1))

    def test_start_index_skips_what_was_already_reported(self):
        lines = [{"kind": 1, "v": {"requests": []}},
                 {"kind": 2, "k": ["requests"], "v": [_request(prompt=100, completion=5),
                                                      _request(prompt=200, completion=7)]}]
        usage, nxt = self._usage(lines, start_index=1)
        self.assertEqual(usage["input_tokens"], 200)
        self.assertEqual(nxt, 2)

    def test_late_request_is_picked_up_on_the_next_read(self):
        first = [{"kind": 1, "v": {"requests": []}},
                 {"kind": 2, "k": ["requests"], "v": [_request(prompt=100, completion=5), _request()]}]
        usage, nxt = self._usage(first)
        self.assertEqual(nxt, 1)
        later = first + [{"kind": 2, "k": ["requests", "1", "promptTokens"], "v": 900},
                         {"kind": 2, "k": ["requests", "1", "completionTokens"], "v": 9}]
        usage2, nxt2 = self._usage(later, start_index=nxt)
        self.assertEqual(usage2["input_tokens"], 900)
        self.assertEqual(nxt2, 2)

    def test_store_path_requires_a_transcripts_parent(self):
        self.assertIsNone(unbound._vscode_store_path("/tmp/elsewhere/x.jsonl", SESSION))

    def test_unparseable_lines_are_skipped(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            transcript = _journal(tmpdir, SESSION, [
                {"kind": 1, "v": {"requests": []}},
                {"kind": 2, "k": ["requests"], "v": [_request(prompt=7, completion=1)]}])
            with open(unbound._vscode_store_path(transcript, SESSION), "a", encoding="utf-8") as handle:
                handle.write("\nnot json\n")
            usage, _ = unbound._vscode_turn_usage(transcript, SESSION, 0)
        self.assertEqual(usage["input_tokens"], 7)


class TestVscodeSettle(unittest.TestCase):
    """VS Code writes counts while the response streams, then rewrites them when done."""

    def _settle(self, reads, start=0, cap=0.3):
        with patch.object(unbound, "_VSCODE_POLL_SECONDS", 0), \
             patch.object(unbound, "_VSCODE_SETTLE_SECONDS", cap), \
             patch.object(unbound, "_vscode_turn_usage", side_effect=reads):
            return unbound._vscode_settled_usage("/ws/transcripts/x.jsonl", SESSION, start)

    def test_returns_at_once_when_the_turn_is_already_final(self):
        usage, nxt = self._settle([({"input_tokens": 500}, 1)])
        self.assertEqual((usage["input_tokens"], nxt), (500, 1))

    def test_waits_for_a_late_turn_to_be_finalised(self):
        usage, nxt = self._settle([({"input_tokens": 0}, 0), ({"input_tokens": 0}, 0),
                                   ({"input_tokens": 44090}, 1)])
        self.assertEqual((usage["input_tokens"], nxt), (44090, 1))

    def test_never_settles_leaves_the_watermark_alone(self):
        with patch.object(unbound, "_VSCODE_POLL_SECONDS", 0), \
             patch.object(unbound, "_VSCODE_SETTLE_SECONDS", 0.05), \
             patch.object(unbound, "_vscode_turn_usage",
                          side_effect=lambda *a: ({"input_tokens": 0}, 0)):
            usage, nxt = unbound._vscode_settled_usage("/ws/transcripts/x.jsonl", SESSION, 0)
        self.assertEqual(nxt, 0)

    def test_no_store_returns_immediately(self):
        with patch.object(unbound, "_vscode_turn_usage", side_effect=[(None, 3)]) as reader:
            usage, nxt = unbound._vscode_settled_usage("/nope.jsonl", SESSION, 3)
        self.assertEqual((usage, nxt, reader.call_count), (None, 3, 1))


class TestGetTurnUsage(unittest.TestCase):
    def test_cli_needs_a_window_ceiling(self):
        usage, nxt = unbound.get_turn_usage("/x/events.jsonl", SESSION, FLOOR, None)
        self.assertIsNone(usage)

    def test_cli_transcript_selects_the_cli_store(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            store = _store([(SESSION, 26941, 274, 0, 26931, INSIDE)], tmpdir)
            with patch.object(unbound, "_COPILOT_STORE", store):
                usage, nxt = unbound.get_turn_usage(
                    os.path.join(tmpdir, SESSION, "events.jsonl"), SESSION, FLOOR, CEILING)
        self.assertEqual(usage["input_tokens"], 10)
        self.assertEqual(usage["total_tokens"], 10 + 274 + 26931)

    def test_cli_watermark_passes_through_untouched(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            store = _store([(SESSION, 0, 0, 0, 0, INSIDE)], tmpdir)
            with patch.object(unbound, "_COPILOT_STORE", store):
                usage, nxt = unbound.get_turn_usage(
                    os.path.join(tmpdir, SESSION, "events.jsonl"), SESSION, FLOOR, CEILING, 7)
        self.assertEqual((usage, nxt), (None, 7))

    def test_consecutive_cli_stops_partition_the_session(self):
        rows = [(SESSION, 100, 1, 0, 0, "2026-08-28T05:06:00.000Z"),
                (SESSION, 200, 2, 0, 0, "2026-08-28T05:08:00.000Z"),
                (SESSION, 400, 4, 0, 0, "2026-08-28T05:12:00.000Z")]
        stops = [None, "2026-08-28T10:37:00.000+05:30", "2026-08-28T10:39:00.000+05:30",
                 "2026-08-28T10:45:00.000+05:30"]
        with tempfile.TemporaryDirectory() as tmpdir:
            store = _store(rows, tmpdir)
            transcript = os.path.join(tmpdir, SESSION, "events.jsonl")
            total = 0
            with patch.object(unbound, "_COPILOT_STORE", store):
                for floor, ceiling in zip(stops, stops[1:]):
                    usage, _ = unbound.get_turn_usage(transcript, SESSION, floor, ceiling)
                    total += usage["input_tokens"] if usage else 0
        self.assertEqual(total, 700)


class TestForwardedStateWatermark(unittest.TestCase):
    def test_watermark_round_trips_through_the_marker(self):
        logs = []
        with patch.object(unbound, "load_existing_logs", lambda: list(logs)), \
             patch.object(unbound, "save_logs", lambda new: logs.__setitem__(slice(None), new)):
            unbound.record_forwarded_tool_ids(SESSION, ["t1"], "sig", ["p1"], 4)
            _, _, _, index = unbound.get_forwarded_state(SESSION)
        self.assertEqual(index, 4)

    def test_watermark_is_carried_forward_when_not_supplied(self):
        logs = []
        with patch.object(unbound, "load_existing_logs", lambda: list(logs)), \
             patch.object(unbound, "save_logs", lambda new: logs.__setitem__(slice(None), new)):
            unbound.record_forwarded_tool_ids(SESSION, ["t1"], "sig", ["p1"], 4)
            unbound.record_forwarded_tool_ids(SESSION, ["t2"], "sig2", ["p2"], None)
            _, _, _, index = unbound.get_forwarded_state(SESSION)
        self.assertEqual(index, 4)

    def test_unknown_session_starts_at_zero(self):
        with patch.object(unbound, "load_existing_logs", lambda: []):
            _, _, _, index = unbound.get_forwarded_state(SESSION)
        self.assertEqual(index, 0)
