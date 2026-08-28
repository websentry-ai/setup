"""
Tests for backfill token-usage collection in copilot/hooks/setup.py.

Copilot's transcripts carry no token counts, so the backfill client reads them from the
stores Copilot keeps them in and ships one usage dict per exchange. Covers:
  - _backfill_cli_usage      (CLI sqlite store, cache-inclusive input, grouped per turn)
  - _backfill_vscode_usage   (VS Code chat journal, finalised requests only)
  - _backfill_collect_session / _backfill_slice_session (payload + boundary-aligned slicing)
"""

import json
import os
import sqlite3
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from tests.conftest import tool_module

setup = tool_module("copilot/hooks", "setup")

SESSION = "sess-backfill"
SCHEMA = """CREATE TABLE assistant_usage_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT, session_id TEXT, turn_index INTEGER, model TEXT,
    input_tokens INTEGER, output_tokens INTEGER, cache_read_tokens INTEGER,
    cache_write_tokens INTEGER, reasoning_tokens INTEGER, created_at TEXT)"""


def _cli_tree(tmpdir, rows, session=SESSION):
    """<copilot home>/session-state/<id>/events.jsonl, with the store beside session-state.
    The store is resolved from the transcript path, so MDM's per-user homes work too."""
    copilot = Path(tmpdir) / ".copilot"
    (copilot / "session-state" / session).mkdir(parents=True)
    transcript = copilot / "session-state" / session / "events.jsonl"
    transcript.write_text("", encoding="utf-8")
    conn = sqlite3.connect(str(copilot / "session-store.db"))
    conn.execute(SCHEMA)
    conn.executemany(
        "INSERT INTO assistant_usage_events (session_id, turn_index, input_tokens,"
        " output_tokens, cache_read_tokens, cache_write_tokens) VALUES (?,?,?,?,?,?)", rows)
    conn.commit()
    conn.close()
    return transcript


def _cli_usage(rows, session=SESSION):
    with tempfile.TemporaryDirectory() as tmpdir:
        return setup._backfill_cli_usage(_cli_tree(tmpdir, rows), session)


def _vscode_tree(tmpdir, session, lines):
    root = Path(tmpdir) / "ws" / "hash"
    (root / "chatSessions").mkdir(parents=True)
    (root / "GitHub.copilot-chat" / "transcripts").mkdir(parents=True)
    (root / "chatSessions" / (session + ".jsonl")).write_text(
        "\n".join(json.dumps(line) for line in lines), encoding="utf-8")
    transcript = root / "GitHub.copilot-chat" / "transcripts" / (session + ".jsonl")
    transcript.write_text("", encoding="utf-8")
    return transcript


def _request(prompt=None, completion=None, elapsed=1234):
    obj = {"timestamp": 1787893680000}
    for key, value in (("promptTokens", prompt), ("completionTokens", completion),
                       ("elapsedMs", elapsed)):
        if value is not None:
            obj[key] = value
    return obj


class TestBackfillCliUsage(unittest.TestCase):
    def test_one_entry_per_turn_in_order(self):
        usage = _cli_usage([(SESSION, 0, 100, 5, 0, 0), (SESSION, 1, 200, 7, 0, 0)])
        self.assertEqual([u["input_tokens"] for u in usage], [100, 200])
        self.assertEqual([u["output_tokens"] for u in usage], [5, 7])

    def test_requests_within_a_turn_are_summed(self):
        usage = _cli_usage([(SESSION, 0, 100, 5, 0, 0), (SESSION, 0, 50, 3, 0, 0)])
        self.assertEqual(len(usage), 1)
        self.assertEqual((usage[0]["input_tokens"], usage[0]["output_tokens"]), (150, 8))

    def test_cache_tiers_come_out_of_input(self):
        # 26941 = 10 fresh + 0 read + 26931 write, the shape Copilot records
        usage = _cli_usage([(SESSION, 0, 26941, 274, 0, 26931)])
        self.assertEqual(usage[0], {"input_tokens": 10, "output_tokens": 274,
                                    "cache_read_input_tokens": 0,
                                    "cache_creation_input_tokens": 26931})

    def test_other_sessions_are_ignored(self):
        usage = _cli_usage([("other", 0, 9999, 1, 0, 0), (SESSION, 0, 7, 1, 0, 0)])
        self.assertEqual(usage[0]["input_tokens"], 7)

    def test_missing_store_is_empty(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            transcript = Path(tmpdir) / ".copilot" / "session-state" / SESSION / "events.jsonl"
            transcript.parent.mkdir(parents=True)
            transcript.write_text("", encoding="utf-8")
            self.assertEqual(setup._backfill_cli_usage(transcript, SESSION), [])

    def test_store_without_the_table_is_empty(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            copilot = Path(tmpdir) / ".copilot"
            (copilot / "session-state" / SESSION).mkdir(parents=True)
            transcript = copilot / "session-state" / SESSION / "events.jsonl"
            transcript.write_text("", encoding="utf-8")
            sqlite3.connect(str(copilot / "session-store.db")).close()
            self.assertEqual(setup._backfill_cli_usage(transcript, SESSION), [])

    def test_shallow_path_cannot_resolve_a_store(self):
        self.assertEqual(setup._backfill_cli_usage(Path("/events.jsonl"), SESSION), [])

    def test_each_home_resolves_its_own_store(self):
        # the MDM case: two users, two stores, no shared Path.home()
        with tempfile.TemporaryDirectory() as one, tempfile.TemporaryDirectory() as two:
            a = _cli_tree(one, [(SESSION, 0, 111, 1, 0, 0)])
            b = _cli_tree(two, [(SESSION, 0, 222, 2, 0, 0)])
            self.assertEqual(setup._backfill_cli_usage(a, SESSION)[0]["input_tokens"], 111)
            self.assertEqual(setup._backfill_cli_usage(b, SESSION)[0]["input_tokens"], 222)


class TestBackfillVscodeUsage(unittest.TestCase):
    def _usage(self, lines):
        with tempfile.TemporaryDirectory() as tmpdir:
            transcript = _vscode_tree(tmpdir, SESSION, lines)
            return setup._backfill_vscode_usage(transcript, SESSION)

    def test_finalised_requests_are_reported_in_order(self):
        usage = self._usage([
            {"kind": 1, "v": {"requests": []}},
            {"kind": 2, "k": ["requests"], "v": [_request(100, 5), _request(200, 7)]},
        ])
        self.assertEqual([u["input_tokens"] for u in usage], [100, 200])

    def test_patches_win_over_the_streaming_values(self):
        usage = self._usage([
            {"kind": 1, "v": {"requests": []}},
            {"kind": 2, "k": ["requests"], "v": [_request(40369, 178, elapsed=None)]},
            {"kind": 2, "k": ["requests", "0", "completionTokens"], "v": 591},
            {"kind": 2, "k": ["requests", "0", "promptTokens"], "v": 44090},
            {"kind": 2, "k": ["requests", "0", "elapsedMs"], "v": 10980},
        ])
        self.assertEqual((usage[0]["input_tokens"], usage[0]["output_tokens"]), (44090, 591))

    def test_unfinished_request_truncates_the_list(self):
        # counts appear mid-stream; without elapsedMs the request is not final
        usage = self._usage([
            {"kind": 1, "v": {"requests": []}},
            {"kind": 2, "k": ["requests"], "v": [_request(100, 5), _request(200, 7, elapsed=None)]},
        ])
        self.assertEqual(len(usage), 1)

    def test_non_transcript_path_is_empty(self):
        self.assertEqual(setup._backfill_vscode_usage(Path("/tmp/x/y.jsonl"), SESSION), [])


class TestBackfillPayload(unittest.TestCase):
    def test_usage_is_omitted_when_there_is_none(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            transcript = Path(tmpdir) / "events.jsonl"
            transcript.write_text(json.dumps(
                {"type": "user.message", "data": {"content": "hi"}}) + "\n", encoding="utf-8")
            with patch.object(setup, "_backfill_session_usage", lambda *a: []):
                session = setup._backfill_collect_session(transcript)
        self.assertNotIn("usage", session)

    def test_slices_cut_usage_on_the_same_boundaries_as_entries(self):
        entries = []
        for turn in range(3):
            entries.append({"type": "user.message", "data": {"content": "prompt %d" % turn}})
            entries.append({"type": "assistant.message", "data": {"content": "x" * 400}})
        usage = [{"input_tokens": n, "output_tokens": 0, "cache_read_input_tokens": 0,
                  "cache_creation_input_tokens": 0} for n in (11, 22, 33)]
        session = {"session_id": SESSION, "entries": entries, "usage": usage}
        slices = list(setup._backfill_slice_session(session, 900))
        rebuilt = []
        for chunk in slices:
            rebuilt.extend(chunk.get("usage") or [])
        self.assertGreater(len(slices), 1)
        self.assertEqual(rebuilt, usage)

    def test_a_session_that_fits_is_yielded_whole_with_its_usage(self):
        session = {"session_id": SESSION,
                   "entries": [{"type": "user.message", "data": {"content": "hi"}}],
                   "usage": [{"input_tokens": 5, "output_tokens": 1,
                              "cache_read_input_tokens": 0, "cache_creation_input_tokens": 0}]}
        slices = list(setup._backfill_slice_session(session, 1_000_000))
        self.assertEqual(len(slices), 1)
        self.assertEqual(slices[0]["usage"], session["usage"])
