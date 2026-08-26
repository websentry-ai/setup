"""Tests for the capture-audit skill.

The skill's job is to say where data was lost, so the tests care about two things:
that a real gap is reported, and that a gap which is only an artefact of the audit
log's hundred-entry cap is not.
"""

import json
import unittest
from datetime import datetime, timedelta, timezone

from tests.conftest import load_module

scan = load_module(".claude/skills/capture-audit/scan_local.py")
compare = load_module(".claude/skills/capture-audit/compare.py")

WINDOW_START = "2026-08-26T05:00:00+00:00"
WINDOW_END = "2026-08-26T06:00:00+00:00"
INSIDE = "2026-08-26T05:30:00+00:00"
OUTSIDE = "2026-08-20T01:00:00+00:00"


def rec(kind, at=INSIDE, session="S1", **extra):
    item = {"kind": kind, "session": session, "at": at}
    item.update(extra)
    return item


MATCHING_AUDIT = [rec("tool_call", tool="Bash", call_id="c1")]


def local(transcript=None, audit=None, **overrides):
    """Defaults to a consistent session, so a test only has to introduce the one gap
    it is about."""
    base = {
        "transcript": transcript if transcript is not None else [],
        "audit": MATCHING_AUDIT if audit is None else audit,
        "sessions_transcript": ["S1"],
        "audit_log": "/tmp/agent-audit.log",
        "audit_log_present": True,
        "audit_window_start": WINDOW_START,
        "audit_window_end": WINDOW_END,
        "audit_entries": 12,
        "audit_limit": 100,
    }
    base.update(overrides)
    return base


MATCHED_TRANSCRIPT = [
    rec("user_prompt", text="hello there"),
    rec("assistant_message", text="hi back"),
    rec("tool_call", tool="Bash", call_id="c1"),
    rec("usage", input=100, output=50),
]
MATCHED_DB = {
    "metrics": [{"input_token_size": 100, "output_token_size": 50}],
    "prompts": [{"prompt": {"messages": [{"role": "user", "content": "hello there"},
                                         {"role": "assistant", "content": "hi back"}]}}],
    "tool_calls": [{"tool_name": "Bash", "thread_id": "S1"}],
}


def titles(findings):
    return [f["title"] for f in findings]


class TestNothingWrongIsReportedAsNothing(unittest.TestCase):
    def test_a_matching_session_yields_no_findings(self):
        got = compare.compare("claude-code",
                              local(MATCHED_TRANSCRIPT,
                                    [rec("tool_call", tool="Bash", call_id="c1")]),
                              MATCHED_DB, 3)
        self.assertEqual(got, [])


class TestRealGapsAreFound(unittest.TestCase):
    def test_a_prompt_that_never_reached_the_database(self):
        t = MATCHED_TRANSCRIPT + [rec("user_prompt", text="the queued one")]
        got = titles(compare.compare("claude-code", local(t), MATCHED_DB, 3))
        self.assertIn("User prompts recorded locally are absent from the database", got)

    def test_an_assistant_message_that_never_reached_the_database(self):
        t = MATCHED_TRANSCRIPT + [rec("assistant_message", text="unrecorded answer")]
        got = titles(compare.compare("claude-code", local(t), MATCHED_DB, 3))
        self.assertIn("Assistant messages recorded locally are absent from the database",
                      got)

    def test_tokens_that_do_not_reconcile(self):
        t = MATCHED_TRANSCRIPT + [rec("usage", input=900, output=400)]
        found = compare.compare("claude-code", local(t), MATCHED_DB, 3)
        self.assertIn("Input tokens do not reconcile", titles(found))
        self.assertIn("90% apart", [f["evidence"] for f in found
                                    if f["title"].startswith("Input")][0])

    def test_a_token_difference_under_five_percent_is_not_reported(self):
        """Rounding and clipping differ between the two sides; only real drift counts."""
        db = json.loads(json.dumps(MATCHED_DB))
        db["metrics"] = [{"input_token_size": 98, "output_token_size": 50}]
        got = titles(compare.compare("claude-code", local(MATCHED_TRANSCRIPT), db, 3))
        self.assertNotIn("Input tokens do not reconcile", got)

    def test_under_recorded_tool_calls(self):
        t = MATCHED_TRANSCRIPT + [rec("tool_call", tool="Write", call_id="c2")]
        got = titles(compare.compare("claude-code", local(t), MATCHED_DB, 3))
        self.assertIn("Tool calls made locally are under-recorded", got)

    def test_a_session_absent_from_the_database(self):
        t = MATCHED_TRANSCRIPT + [rec("tool_call", session="S2", tool="Bash", call_id="c3")]
        got = titles(compare.compare("claude-code",
                                     local(t, sessions_transcript=["S1", "S2"]),
                                     MATCHED_DB, 3))
        self.assertIn("Sessions present locally are absent from the database", got)


class TestTheLossIsLocalised(unittest.TestCase):
    """Direction is the point: a hook that never saw a call is a different bug from an
    upload that dropped it, and they are fixed in different places."""

    def test_a_call_the_hook_never_logged_is_blamed_on_the_hook(self):
        t = MATCHED_TRANSCRIPT + [rec("tool_call", tool="Write", call_id="c2")]
        got = titles(compare.compare("claude-code", local(t), MATCHED_DB, 3))
        self.assertIn("The hook never saw some tool calls it should have", got)

    def test_a_call_that_aged_out_of_the_audit_log_is_not(self):
        """The log keeps its last hundred entries. Older absence is the cap, not a bug,
        and reporting it would bury the real findings in noise."""
        t = MATCHED_TRANSCRIPT + [rec("tool_call", at=OUTSIDE, tool="Write", call_id="c9")]
        got = titles(compare.compare("claude-code", local(t), MATCHED_DB, 3))
        self.assertNotIn("The hook never saw some tool calls it should have", got)

    def test_no_audit_log_is_reported_as_unattributable(self):
        got = compare.compare("claude-code",
                              local(MATCHED_TRANSCRIPT, audit_log_present=False,
                                    audit_window_start=None, audit_window_end=None),
                              MATCHED_DB, 3)
        self.assertIn("No hook audit log on this machine", titles(got))

    def test_an_empty_database_is_one_finding_not_one_per_row(self):
        """Nothing stored at all is a setup problem, not thousands of separate gaps."""
        empty = {"metrics": [], "prompts": [], "tool_calls": []}
        got = compare.compare("claude-code", local(MATCHED_TRANSCRIPT), empty, 3)
        self.assertEqual(len(got), 1)
        self.assertIn("almost no record", got[0]["title"])


class TestNoiseIsSuppressedWithoutHidingRealLoss(unittest.TestCase):
    """The two ways this tool could become useless: shouting about a database that
    simply is not the one the machine uploads to, and blaming the hook for entries a
    capped log discarded."""

    def test_a_window_the_database_barely_has_is_one_finding(self):
        transcript = [rec("user_prompt", text="turn %d" % i) for i in range(200)]
        db = {"metrics": [{"input_token_size": 1, "output_token_size": 1}],
              "prompts": [], "tool_calls": []}
        got = compare.compare("claude-code", local(transcript), db, 14)
        self.assertEqual(len(got), 1)
        self.assertIn("almost no record", got[0]["title"])

    def test_a_mostly_captured_window_still_reports_the_gap(self):
        """The queued-prompt bug uploaded nearly every turn and dropped a prompt inside
        them. Coverage stays high, so the per-category findings must still fire."""
        transcript = [rec("user_prompt", text="turn %d" % i) for i in range(100)]
        transcript.append(rec("user_prompt", text="the queued one"))
        db = {
            "metrics": [{"input_token_size": 1, "output_token_size": 1} for _ in range(100)],
            "prompts": [{"prompt": {"messages": [
                {"role": "user", "content": "turn %d" % i}]}} for i in range(100)],
            "tool_calls": [],
        }
        got = titles(compare.compare("claude-code", local(transcript), db, 14))
        self.assertIn("User prompts recorded locally are absent from the database", got)
        self.assertNotIn("This database holds almost no record of the window", got)

    def test_a_full_audit_log_cannot_accuse_the_hook(self):
        t = MATCHED_TRANSCRIPT + [rec("tool_call", tool="Write", call_id="c2")]
        got = titles(compare.compare(
            "claude-code", local(t, audit_entries=100, audit_limit=100), MATCHED_DB, 3))
        self.assertNotIn("The hook never saw some tool calls it should have", got)
        self.assertIn("Cannot attribute the loss: the audit log is full", got)

    def test_a_log_with_room_still_can(self):
        t = MATCHED_TRANSCRIPT + [rec("tool_call", tool="Write", call_id="c2")]
        got = titles(compare.compare(
            "claude-code", local(t, audit_entries=12, audit_limit=100), MATCHED_DB, 3))
        self.assertIn("The hook never saw some tool calls it should have", got)


class TestTheScannerReadsEveryFormat(unittest.TestCase):
    def test_every_supported_tool_has_a_scanner_and_a_label(self):
        self.assertEqual(sorted(scan.TOOLS), sorted(scan.SCANNERS))
        self.assertEqual(sorted(scan.TOOLS), sorted(compare.APP_LABEL))

    def test_the_app_labels_match_what_the_hooks_stamp(self):
        """The label is the join key: if it drifts, every query returns nothing."""
        self.assertEqual(scan.TOOLS["augment"]["app_label"], "augment_code")
        for tool in ("claude-code", "cursor", "copilot", "codex"):
            self.assertEqual(scan.TOOLS[tool]["app_label"], tool)

    def test_codex_text_blocks_are_read(self):
        """Codex spells its text blocks input_text/output_text, not text."""
        self.assertEqual(
            scan._text_of([{"type": "input_text", "text": "typed this"}]), "typed this")
        self.assertEqual(scan._text_of("plain string"), "plain string")
        self.assertEqual(scan._text_of([{"type": "thinking", "text": "hidden"}]), "")

    def test_timestamps_in_every_spelling_the_files_use(self):
        for value in ("2026-08-26T05:00:00Z", "2026-08-26T05:00:00+00:00",
                      1756180800, 1756180800000):
            self.assertIsNotNone(scan._ts(value), value)
        for value in (None, "", "not a date", {}):
            self.assertIsNone(scan._ts(value))

    def test_a_truncated_last_line_does_not_stop_the_scan(self):
        """A live session is being written while this reads it."""
        import tempfile
        from pathlib import Path
        p = Path(tempfile.mkdtemp()) / "t.jsonl"
        p.write_text('{"a": 1}\n{"b": 2}\n{"c": ')
        self.assertEqual(list(scan._lines(p)), [{"a": 1}, {"b": 2}])

    def test_a_missing_file_is_not_an_error(self):
        from pathlib import Path
        self.assertEqual(list(scan._lines(Path("/nonexistent/x.jsonl"))), [])


class TestTheWindowIsBounded(unittest.TestCase):
    def test_more_than_fourteen_days_is_refused(self):
        import subprocess, sys
        from tests.conftest import REPO
        r = subprocess.run(
            [sys.executable, str(REPO / ".claude/skills/capture-audit/scan_local.py"),
             "--tools", "claude-code", "--days", "15"],
            capture_output=True, text=True, timeout=60)
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("between 1 and 14", r.stderr)

    def test_an_unknown_tool_is_refused(self):
        import subprocess, sys
        from tests.conftest import REPO
        r = subprocess.run(
            [sys.executable, str(REPO / ".claude/skills/capture-audit/scan_local.py"),
             "--tools", "not-a-tool", "--days", "3"],
            capture_output=True, text=True, timeout=60)
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("unknown tool", r.stderr)


if __name__ == "__main__":
    unittest.main()
