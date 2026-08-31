"""
Tests for backfill token-usage collection in copilot/hooks/mdm/setup.py.

MDM walks several user homes in one run, so the CLI store has to be resolved from each
transcript's own path rather than from Path.home(). The reader block itself is shared
with the user-level installer and must not drift.
"""

import json
import sqlite3
import tempfile
import unittest
from pathlib import Path

from tests.conftest import tool_module

mdm = tool_module("copilot/hooks/mdm", "setup")

SESSION = "sess-mdm-backfill"
SCHEMA = """CREATE TABLE assistant_usage_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT, session_id TEXT, turn_index INTEGER, model TEXT,
    input_tokens INTEGER, output_tokens INTEGER, cache_read_tokens INTEGER,
    cache_write_tokens INTEGER, reasoning_tokens INTEGER, created_at TEXT)"""


def _cli_tree(tmpdir, rows, session=SESSION):
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


class TestMdmBackfillUsage(unittest.TestCase):
    def test_cache_tiers_come_out_of_input(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            transcript = _cli_tree(tmpdir, [(SESSION, 0, 26941, 274, 0, 26931)])
            usage = mdm._backfill_cli_usage(transcript, SESSION)
        self.assertEqual(usage[0], {"input_tokens": 10, "output_tokens": 274,
                                    "cache_read_input_tokens": 0,
                                    "cache_creation_input_tokens": 26931})

    def test_each_user_home_resolves_its_own_store(self):
        # the reason MDM cannot use Path.home(): one run, several users
        with tempfile.TemporaryDirectory() as one, tempfile.TemporaryDirectory() as two:
            a = _cli_tree(one, [(SESSION, 0, 111, 1, 0, 0)])
            b = _cli_tree(two, [(SESSION, 0, 222, 2, 0, 0)])
            self.assertEqual(mdm._backfill_cli_usage(a, SESSION)[0]["input_tokens"], 111)
            self.assertEqual(mdm._backfill_cli_usage(b, SESSION)[0]["input_tokens"], 222)

    def test_vscode_journal_is_read_beside_the_transcript(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir) / "ws" / "hash"
            (root / "chatSessions").mkdir(parents=True)
            (root / "GitHub.copilot-chat" / "transcripts").mkdir(parents=True)
            (root / "chatSessions" / (SESSION + ".jsonl")).write_text("\n".join(json.dumps(x) for x in [
                {"kind": 1, "v": {"requests": []}},
                {"kind": 2, "k": ["requests"], "v": [
                    {"timestamp": 1787893680000, "promptTokens": 44090,
                     "completionTokens": 591, "elapsedMs": 10980}]},
            ]), encoding="utf-8")
            transcript = root / "GitHub.copilot-chat" / "transcripts" / (SESSION + ".jsonl")
            transcript.write_text("", encoding="utf-8")
            usage = mdm._backfill_vscode_usage(transcript, SESSION)
        self.assertEqual((usage[0]["input_tokens"], usage[0]["output_tokens"]), (44090, 591))

    def test_collected_session_carries_usage(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            transcript = _cli_tree(tmpdir, [(SESSION, 0, 100, 5, 0, 0)])
            transcript.write_text(json.dumps(
                {"type": "user.message", "data": {"content": "hi"}}) + "\n", encoding="utf-8")
            session = mdm._backfill_collect_session(transcript)
        self.assertEqual(session["usage"][0]["input_tokens"], 100)


class TestReaderBlockStaysInSync(unittest.TestCase):
    """Both installers embed the readers (single-file constraint), so they must not drift."""

    START = "# KEEP IN SYNC: copilot/hooks/unbound.py's usage readers"

    def _block(self, relpath, end_marker):
        text = (Path(__file__).resolve().parents[4] / relpath).read_text(encoding="utf-8")
        return text[text.index(self.START):text.index(end_marker, text.index(self.START))]

    def test_user_and_mdm_installers_share_the_same_readers(self):
        user = self._block("copilot/hooks/setup.py", "def _backfill_edr_headers(")
        managed = self._block("copilot/hooks/mdm/setup.py", "def _backfill_vscode_workspace_roots(")
        self.assertEqual(user, managed)
