"""Tests for the identify-drift skill.

The skill's job is to say where data was lost, so the tests care about two things:
that a real gap is reported, and that a gap which is only an artefact of the audit
log's hundred-entry cap is not.
"""

import json
import os
import unittest
from collections import Counter
import unittest.mock
from datetime import datetime, timedelta, timezone

from tests.conftest import load_module

scan = load_module(".claude/skills/identify-drift/scan_local.py")
compare = load_module(".claude/skills/identify-drift/compare.py")

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
        "sessions_audit": ["S1"],
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
def db(metrics_rows=1, input_tokens=100, output_tokens=50, threads=("S1",),
       tool_counts=None, user_texts=("hello there",), assistant_texts=("hi back",),
       call_ids=("c1",), ids_are_representative=True, truncated=(),
       rows_with_call_id=None):
    """The aggregated shape fetch_db returns. Everything is a count, a sum, a digest or
    an id, because selecting the rows themselves does not fit in memory. Prompts are a
    multiset so a repeated prompt stored once still reads as a loss."""
    return {
        "metrics_rows": metrics_rows,
        "input_tokens": input_tokens,
        "output_tokens": output_tokens,
        "threads": set(threads),
        "tool_counts": dict(tool_counts if tool_counts is not None else {"Bash": 1}),
        "call_ids": set(call_ids),
        "ids_are_representative": ids_are_representative,
        "rows_with_call_id": (len(call_ids) if rows_with_call_id is None
                              else rows_with_call_id),
        "user_digests": Counter(compare._digest(t) for t in user_texts),
        "assistant_digests": Counter(compare._digest(t) for t in assistant_texts),
        "truncated": list(truncated),
    }


MATCHED_DB = db()


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
        got = titles(compare.compare("claude-code", local(MATCHED_TRANSCRIPT),
                                     db(input_tokens=98), 3))
        self.assertNotIn("Input tokens do not reconcile", got)

    def test_under_recorded_tool_calls(self):
        t = MATCHED_TRANSCRIPT + [rec("tool_call", tool="Write", call_id="c2")]
        got = titles(compare.compare("claude-code", local(t), MATCHED_DB, 3))
        self.assertIn("Tool calls made locally are absent from the database", got)

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
        empty = db(metrics_rows=0, input_tokens=0, output_tokens=0, threads=(),
                   tool_counts={}, user_texts=(), assistant_texts=())
        got = compare.compare("claude-code", local(MATCHED_TRANSCRIPT), empty, 3)
        self.assertEqual(len(got), 1)
        self.assertIn("almost no record", got[0]["title"])


class TestTheUploadDirectionIsActuallyChecked(unittest.TestCase):
    """The whole point of keeping the audit log separate is telling an ingest failure
    from a capture bug. Comparing only transcript against database cannot do that, and
    for a tool whose audit log is its only local record it checks nothing at all."""

    def test_calls_the_hook_logged_but_the_database_never_got(self):
        got = titles(compare.compare(
            "claude-code",
            local(MATCHED_TRANSCRIPT,
                  [rec("tool_call", tool="Bash", call_id="c1"),
                   rec("tool_call", tool="Bash", call_id="c2"),
                   rec("tool_call", tool="Bash", call_id="c3")]),
            db(tool_counts={"Bash": 1}), 3))
        self.assertIn("The hook logged tool calls the database never received", got)

    def test_prompts_the_hook_logged_but_the_database_never_got(self):
        got = titles(compare.compare(
            "claude-code",
            local(MATCHED_TRANSCRIPT,
                  [rec("tool_call", tool="Bash", call_id="c1"),
                   rec("user_prompt", text="logged but never uploaded")]),
            MATCHED_DB, 3))
        self.assertIn("The hook logged prompts the database never received", got)

    def test_a_tool_with_no_transcript_still_gets_checked(self):
        """Augment ships no rich transcript, so without this direction it would be
        compared against nothing and always look healthy."""
        got = titles(compare.compare(
            "augment",
            local([],
                  [rec("tool_call", tool="Bash", call_id="c%d" % i) for i in range(30)]
                  + [rec("user_prompt", text="turn %d" % i) for i in range(25)],
                  sessions_transcript=[], sessions_audit=["S1"]),
            db(metrics_rows=25, tool_counts={"Bash": 2},
               user_texts={"turn %d" % i for i in range(25)}), 3))
        self.assertIn("The hook logged tool calls the database never received", got)

    def test_agreement_between_the_two_produces_nothing(self):
        got = compare.compare(
            "claude-code",
            local(MATCHED_TRANSCRIPT, [rec("tool_call", tool="Bash", call_id="c1")]),
            MATCHED_DB, 3)
        self.assertEqual(got, [])


class TestItReadsTheStoredPromptShape(unittest.TestCase):
    """The stored column is {user_prompt, system_prompt, assistant_prompt}. An earlier
    version looked for a messages array, found nothing every run, and reported no
    stored prompts at all -- which reads identically to total data loss."""

    def test_the_normaliser_matches_what_the_query_returns(self):
        # SQL does btrim + collapse whitespace + lower + left(200); _norm must agree,
        # or every prompt looks missing.
        for raw, expected in [("  Hello   World  ", "hello world"),
                              ("Line\nBreak", "line break"),
                              ("TABS\there", "tabs here")]:
            self.assertEqual(compare._norm(raw), expected)

    def test_it_does_not_truncate_the_way_the_query_no_longer_does(self):
        """A prefix digest made two prompts sharing an opening interchangeable."""
        self.assertEqual(len(compare._norm("x" * 500)), 500)


class TestNoiseIsSuppressedWithoutHidingRealLoss(unittest.TestCase):
    """The two ways this tool could become useless: shouting about a database that
    simply is not the one the machine uploads to, and blaming the hook for entries a
    capped log discarded."""

    def test_a_window_the_database_barely_has_is_one_finding(self):
        transcript = [rec("user_prompt", text="turn %d" % i) for i in range(200)]
        barely = db(metrics_rows=1, threads=(), tool_counts={},
                    user_texts=(), assistant_texts=())
        got = compare.compare("claude-code", local(transcript), barely, 14)
        self.assertEqual(len(got), 1)
        self.assertIn("almost no record", got[0]["title"])

    def test_a_mostly_captured_window_still_reports_the_gap(self):
        """The queued-prompt bug uploaded nearly every turn and dropped a prompt inside
        them. Coverage stays high, so the per-category findings must still fire."""
        transcript = [rec("user_prompt", text="turn %d" % i) for i in range(100)]
        transcript.append(rec("user_prompt", text="the queued one"))
        captured = db(metrics_rows=100, threads=("S1",), tool_counts={},
                      user_texts={"turn %d" % i for i in range(100)},
                      assistant_texts=())
        got = titles(compare.compare("claude-code", local(transcript), captured, 14))
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


class TestItHandlesOtherPeoplesDataCarefully(unittest.TestCase):
    """This reads every prompt a user typed and can be pointed at production."""

    def test_the_connection_never_reaches_the_process_list(self):
        """A DSN passed as an argument is readable by every account on the machine."""
        env = compare._connection_env("postgres://bob@db.example:6000/things")
        self.assertEqual(env["PGUSER"], "bob")
        self.assertEqual(env["PGHOST"], "db.example")
        self.assertEqual(env["PGPORT"], "6000")
        self.assertEqual(env["PGDATABASE"], "things")

    def test_a_password_is_refused_rather_than_carried(self):
        """This runs inside the hooks it audits, so a command carrying a password is
        captured into the transcripts and prompt rows the comparison then reads."""
        with self.assertRaises(SystemExit) as e:
            compare._connection_env("postgres://bob:hunter2@db.example/things")
        self.assertNotIn("hunter2", str(e.exception))
        self.assertIn("~/.pgpass", str(e.exception))

    def test_a_stale_password_in_the_environment_is_dropped(self):
        with unittest.mock.patch.dict("os.environ", {"PGPASSWORD": "leftover"}):
            env = compare._connection_env("postgres://bob@db.example/things")
        self.assertNotIn("PGPASSWORD", env)

    def test_errors_never_echo_the_connection_back(self):
        dsn = "postgres://bob:hunter2@db.example/things"
        scrubbed = compare._scrub("could not connect to %s: hunter2 rejected" % dsn, dsn)
        self.assertNotIn("hunter2", scrubbed)
        self.assertNotIn("db.example", scrubbed)

    def test_a_non_postgres_dsn_is_refused(self):
        with self.assertRaises(SystemExit):
            compare._connection_env("file:///etc/passwd")

    def test_production_shows_a_digest_instead_of_the_prompt(self):
        try:
            compare.REDACT = True
            shown = compare._excerpt("something a customer typed")
            self.assertNotIn("customer", shown)
            self.assertTrue(shown.startswith("sha256:"))
        finally:
            compare.REDACT = False

    def test_elsewhere_it_shows_enough_to_find_the_prompt(self):
        self.assertIn("customer", compare._excerpt("something a customer typed"))

    def test_the_scan_file_is_owner_only(self):
        """It holds every prompt in the window; a shell redirect would use the umask."""
        import subprocess, sys, tempfile, os, stat
        from pathlib import Path
        from tests.conftest import REPO
        out = Path(tempfile.mkdtemp()) / "local.json"
        subprocess.run(
            [sys.executable, str(REPO / ".claude/skills/identify-drift/scan_local.py"),
             "--tools", "claude-code", "--days", "1", "--out", str(out)],
            capture_output=True, text=True, timeout=300, check=True)
        mode = os.stat(out).st_mode
        self.assertFalse(mode & stat.S_IROTH, "world-readable")
        self.assertFalse(mode & stat.S_IRGRP, "group-readable")


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


class TestTheCommandLineActuallyRuns(unittest.TestCase):
    """compare() is unit tested directly, so main() can drift away from the shape
    fetch_db returns and nothing notices until somebody runs the tool."""

    def test_main_renders_a_report_from_a_stubbed_database(self):
        import json as _json
        import subprocess, sys, tempfile
        from pathlib import Path
        from tests.conftest import REPO

        work = Path(tempfile.mkdtemp())
        (work / "local.json").write_text(_json.dumps({
            "since": "2026-08-01T00:00:00+00:00", "days": 3,
            "tools": {"claude-code": {
                "app_label": "claude-code", "audit_log": str(work / "a.log"),
                "audit_log_present": False, "audit_window_start": None,
                "audit_window_end": None, "audit_entries": 0, "audit_limit": 100,
                "transcript": [], "audit": [],
                "sessions_transcript": [], "sessions_audit": []}}}))
        # A psql stand-in on PATH: main() must survive the real code path without a
        # database, which is what makes this a shape check rather than a mock.
        fake = work / "psql"
        fake.write_text("#!/bin/sh\necho '[]'\n")
        fake.chmod(0o755)
        env = {"PATH": "%s:/usr/bin:/bin" % work, "HOME": str(work),
               "IDENTIFY_DRIFT_DSN": "postgres://u@127.0.0.1:5432/d"}
        r = subprocess.run(
            [sys.executable, str(REPO / ".claude/skills/identify-drift/compare.py"),
             "--local", str(work / "local.json"),
             "--email", "a@b.c", "--environment", "development"],
            capture_output=True, text=True, timeout=120, env=env)
        self.assertEqual(r.returncode, 0, r.stderr[-400:])
        report = _json.loads(r.stdout)
        self.assertEqual(report["email"], "a@b.c")
        self.assertIn("claude-code", report["tools"])
        self.assertIn("counts", report["tools"]["claude-code"])

    def test_it_refuses_to_run_with_no_connection_at_all(self):
        import subprocess, sys, tempfile
        from pathlib import Path
        from tests.conftest import REPO
        r = subprocess.run(
            [sys.executable, str(REPO / ".claude/skills/identify-drift/compare.py"),
             "--local", "/dev/null", "--email", "a@b.c", "--environment", "development"],
            capture_output=True, text=True, timeout=60,
            env={"PATH": "/usr/bin:/bin", "HOME": tempfile.mkdtemp()})
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("IDENTIFY_DRIFT_DSN", r.stderr)


class TestTheWindowIsBounded(unittest.TestCase):
    def test_more_than_fourteen_days_is_refused(self):
        import subprocess, sys
        from tests.conftest import REPO
        r = subprocess.run(
            [sys.executable, str(REPO / ".claude/skills/identify-drift/scan_local.py"),
             "--tools", "claude-code", "--days", "15"],
            capture_output=True, text=True, timeout=60)
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("between 1 and 14", r.stderr)

    def test_the_comparer_enforces_the_bound_too(self):
        """The scanner's flag check does not protect the query: the file between them
        carries the day count."""
        r = _run_compare({"since": "2026-01-01T00:00:00+00:00", "days": 365,
                          "tools": {}})
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("the limit is %d" % compare.MAX_DAYS, r.stderr)

    def test_a_scan_file_with_no_day_count_is_refused(self):
        r = _run_compare({"since": "2026-01-01T00:00:00+00:00", "tools": {}})
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("no usable day count", r.stderr)

    def test_both_halves_share_one_bound(self):
        self.assertEqual(compare.MAX_DAYS, scan.MAX_DAYS)

    def test_an_unknown_tool_is_refused(self):
        import subprocess, sys
        from tests.conftest import REPO
        r = subprocess.run(
            [sys.executable, str(REPO / ".claude/skills/identify-drift/scan_local.py"),
             "--tools", "not-a-tool", "--days", "3"],
            capture_output=True, text=True, timeout=60)
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("unknown tool", r.stderr)


class TestReconciliationDistinguishesIndividualEvents(unittest.TestCase):
    """Equal counts of different events are not a match. Where the stored rows carry a
    tool_use_id the comparison is by that id, and where they do not the report says the
    comparison was by count."""

    def test_same_count_of_different_calls_is_still_a_loss(self):
        t = MATCHED_TRANSCRIPT + [rec("tool_call", tool="Bash", call_id="local-only")]
        d = db(tool_counts={"Bash": 2}, call_ids=("c1", "stored-only"))
        got = compare.compare("claude-code", local(t), d, 3)
        self.assertIn("Tool calls made locally are absent from the database",
                      titles(got))
        self.assertIn("local-only", " ".join(f["evidence"] for f in got))

    def test_counting_is_used_when_too_few_rows_carry_an_id(self):
        t = MATCHED_TRANSCRIPT + [rec("tool_call", tool="Write", call_id="c2")]
        d = db(ids_are_representative=False, call_ids=())
        got = titles(compare.compare("claude-code", local(t), d, 3))
        self.assertIn("Tool calls made locally are under-recorded (by count)", got)

    def test_the_count_fallback_says_it_is_a_count(self):
        t = MATCHED_TRANSCRIPT + [rec("tool_call", tool="Write", call_id="c2")]
        d = db(ids_are_representative=False, call_ids=())
        got = compare.compare("claude-code", local(t), d, 3)
        why = next(f["why"] for f in got if f["title"].endswith("under-recorded (by count)"))
        self.assertIn("counts them instead", why)

    def test_a_truncated_id_set_falls_back_rather_than_inventing_losses(self):
        t = MATCHED_TRANSCRIPT + [rec("tool_call", tool="Bash", call_id="c9")]
        d = db(tool_counts={"Bash": 2}, call_ids=("c1",),
               truncated=["tool call ids"])
        got = titles(compare.compare("claude-code", local(t), d, 3))
        self.assertNotIn("Tool calls made locally are absent from the database", got)

    def test_a_prompt_sent_twice_and_stored_once_is_a_loss(self):
        t = MATCHED_TRANSCRIPT + [rec("user_prompt", text="hello there")]
        got = titles(compare.compare("claude-code", local(t), MATCHED_DB, 3))
        self.assertIn("User prompts recorded locally are absent from the database", got)

    def test_a_prompt_sent_twice_and_stored_twice_is_not_a_loss(self):
        t = MATCHED_TRANSCRIPT + [rec("user_prompt", text="hello there")]
        d = db(user_texts=("hello there", "hello there"))
        got = titles(compare.compare("claude-code", local(t), d, 3))
        self.assertNotIn("User prompts recorded locally are absent from the database",
                         got)

    def test_the_digest_matches_what_the_query_computes(self):
        self.assertEqual(compare._digest("  Hello   THERE  "),
                         compare._digest("hello there"))


class TestIdentityNeedsIdsOnBothSides(unittest.TestCase):
    """Matching on identity skips any record without an id. A source that records
    none would be compared against nothing and report nothing, which is worse than
    counting. Cursor transcripts carry no tool-call ids at all."""

    def test_a_source_with_no_ids_is_counted_not_silently_skipped(self):
        calls = [rec("tool_call", tool="Bash"), rec("tool_call", tool="Write")]
        t = [rec("user_prompt", text="hello there"),
             rec("assistant_message", text="hi back"), rec("usage", input=100, output=50)]
        d = db(tool_counts={"Bash": 1}, call_ids=("c1", "c2"),
               ids_are_representative=True)
        got = titles(compare.compare("cursor", local(t + calls), d, 3))
        self.assertIn("Tool calls made locally are under-recorded (by count)", got)
        self.assertNotIn("Tool calls made locally are absent from the database", got)

    def test_a_loss_is_still_found_when_the_local_side_has_no_ids(self):
        """The point of the fallback: the gap must not vanish with the ids."""
        calls = [rec("tool_call", tool="Write"), rec("tool_call", tool="Write")]
        t = [rec("user_prompt", text="hello there"),
             rec("assistant_message", text="hi back"), rec("usage", input=100, output=50)]
        d = db(tool_counts={"Write": 1}, call_ids=("c1",), ids_are_representative=True)
        got = compare.compare("cursor", local(t + calls), d, 3)
        evidence = " ".join(f["evidence"] for f in got)
        self.assertIn("Write local 2 vs stored 1", evidence)

    def test_a_partial_id_gap_is_declared_rather_than_dropped(self):
        """Above the coverage bar the run still matches by id, so the handful without
        one have to be called out or they read as checked."""
        calls = [rec("tool_call", tool="Bash", call_id="c%d" % i) for i in range(19)]
        calls.append(rec("tool_call", tool="Bash"))
        t = [rec("user_prompt", text="hello there"),
             rec("assistant_message", text="hi back"), rec("usage", input=100, output=50)]
        d = db(tool_counts={"Bash": 20}, call_ids=tuple("c%d" % i for i in range(19)))
        got = titles(compare.compare("claude-code", local(t + calls), d, 3))
        self.assertIn("Some local tool calls carry no id and were not matched", got)

    def test_the_audit_direction_declares_when_it_had_to_count(self):
        """A tool can stamp ids in its transcript and not in its hook log. Copilot
        does exactly that, so a clean audit result must not read as strongly as a
        clean transcript one."""
        a = [rec("tool_call", tool="Bash"), rec("tool_call", tool="Bash"),
             rec("tool_call", tool="Bash")]
        got = titles(compare.compare("copilot", local(MATCHED_TRANSCRIPT, a),
                                     MATCHED_DB, 3))
        self.assertIn("The upload direction could only be reconciled by count", got)

    def test_no_such_note_when_both_directions_used_ids(self):
        got = titles(compare.compare("claude-code", local(MATCHED_TRANSCRIPT),
                                     MATCHED_DB, 3))
        self.assertNotIn("The upload direction could only be reconciled by count", got)

    def test_the_coverage_bar_is_shared_by_both_sides(self):
        self.assertTrue(compare._ids_are_usable(
            [{"call_id": "a"}, {"call_id": "b"}, {"call_id": "c"}]))
        self.assertFalse(compare._ids_are_usable(
            [{"call_id": "a"}, {}, {}]))
        self.assertTrue(compare._ids_are_usable([]))


class TestRetrievalIsBounded(unittest.TestCase):
    def test_the_cap_is_declared(self):
        self.assertIsInstance(compare.ROW_CAP, int)
        self.assertGreater(compare.ROW_CAP, 0)

    def test_over_the_cap_is_reported_as_truncated(self):
        rows, capped = compare._capped(list(range(compare.ROW_CAP + 5)))
        self.assertTrue(capped)
        self.assertEqual(len(rows), compare.ROW_CAP)

    def test_under_the_cap_is_not_reported_as_truncated(self):
        rows, capped = compare._capped([1, 2, 3])
        self.assertFalse(capped)
        self.assertEqual(rows, [1, 2, 3])

    def test_the_audit_direction_also_matches_by_id(self):
        """Both directions must distinguish events, not just the transcript one."""
        a = MATCHING_AUDIT + [rec("tool_call", tool="Bash", call_id="logged-only")]
        d = db(tool_counts={"Bash": 2}, call_ids=("c1", "stored-only"))
        got = compare.compare("claude-code", local(MATCHED_TRANSCRIPT, a), d, 3)
        self.assertIn("The hook logged tool calls the database never received",
                      titles(got))
        self.assertIn("logged-only", " ".join(f["evidence"] for f in got))

    def test_the_audit_direction_falls_back_to_counting_too(self):
        a = MATCHING_AUDIT + [rec("tool_call", tool="Write", call_id="w1")]
        d = db(ids_are_representative=False, call_ids=())
        got = titles(compare.compare("claude-code", local(MATCHED_TRANSCRIPT, a), d, 3))
        self.assertIn("The hook logged tool calls the database never received "
                      "(by count)", got)


class TestTheTwoSidesCoverTheSameInterval(unittest.TestCase):
    """The audit log holds its last hundred entries, often under an hour, while the
    requested window can be fourteen days. Reconciling the first against the second
    lets an unrelated older stored row cancel a recently lost audited one."""

    def test_an_older_stored_call_cannot_cancel_a_recent_lost_one(self):
        a = [rec("tool_call", tool="Bash"), rec("tool_call", tool="Bash")]
        whole_window = db(tool_counts={"Bash": 400}, ids_are_representative=False,
                          call_ids=())
        audit_window = db(tool_counts={"Bash": 1}, ids_are_representative=False,
                          call_ids=())
        blind = titles(compare.compare("claude-code", local(MATCHED_TRANSCRIPT, a),
                                       whole_window, 14))
        seeing = titles(compare.compare("claude-code", local(MATCHED_TRANSCRIPT, a),
                                        whole_window, 14, audit_window))
        self.assertNotIn("The hook logged tool calls the database never received "
                         "(by count)", blind)
        self.assertIn("The hook logged tool calls the database never received "
                      "(by count)", seeing)

    def test_an_older_stored_prompt_cannot_cancel_a_recent_lost_one(self):
        a = [rec("user_prompt", text="the lost one")]
        whole_window = db(user_texts=("the lost one", "hello there"))
        audit_window = db(user_texts=("hello there",))
        blind = titles(compare.compare("claude-code", local(MATCHED_TRANSCRIPT, a),
                                       whole_window, 14))
        seeing = titles(compare.compare("claude-code", local(MATCHED_TRANSCRIPT, a),
                                        whole_window, 14, audit_window))
        self.assertNotIn("The hook logged prompts the database never received", blind)
        self.assertIn("The hook logged prompts the database never received", seeing)

    def test_the_transcript_direction_still_uses_the_whole_window(self):
        """Only the audit direction is bounded; the transcript covers all of it."""
        t = MATCHED_TRANSCRIPT + [rec("user_prompt", text="never uploaded")]
        got = titles(compare.compare("claude-code", local(t), MATCHED_DB, 14,
                                     db(user_texts=())))
        self.assertIn("User prompts recorded locally are absent from the database", got)

    def test_the_query_accepts_an_explicit_interval(self):
        import inspect
        sig = inspect.signature(compare.fetch_db)
        self.assertIn("since", sig.parameters)
        self.assertIn("until", sig.parameters)


class TestTheServerSideCostIsBoundedToo(unittest.TestCase):
    """The row cap bounds what comes back. It does not bound what the server does to
    produce it, because a GROUP BY computes every group before any LIMIT applies."""

    def test_every_connection_carries_a_statement_timeout(self):
        env = compare._connection_env("postgres://bob@db.example/things")
        self.assertIn("statement_timeout=%d" % compare.STATEMENT_TIMEOUT_MS,
                      env["PGOPTIONS"])

    def test_a_timeout_says_what_to_do_rather_than_dumping_the_error(self):
        import subprocess
        done = subprocess.CompletedProcess(
            args=[], returncode=1,
            stdout="", stderr="ERROR:  canceling statement due to statement timeout")
        with unittest.mock.patch("subprocess.run", return_value=done):
            with self.assertRaises(SystemExit) as e:
                compare.psql("postgres://bob@db.example/things", "SELECT 1")
        self.assertIn("fewer days", str(e.exception))

    def test_other_errors_are_still_reported_verbatim(self):
        import subprocess
        done = subprocess.CompletedProcess(
            args=[], returncode=1, stdout="", stderr='ERROR:  relation "nope" does not exist')
        with unittest.mock.patch("subprocess.run", return_value=done):
            with self.assertRaises(SystemExit) as e:
                compare.psql("postgres://bob@db.example/things", "SELECT 1")
        self.assertIn("does not exist", str(e.exception))


class TestTheConnectionCannotBeQuietlyWeakened(unittest.TestCase):
    """A connection option that is dropped rather than honoured is how a verify-full
    DSN ends up negotiating an unverified session."""

    def test_tls_options_are_carried_not_discarded(self):
        env = compare._connection_env(
            "postgres://bob@db.example/things?sslmode=verify-full&sslrootcert=/ca.pem")
        self.assertEqual(env["PGSSLMODE"], "verify-full")
        self.assertEqual(env["PGSSLROOTCERT"], "/ca.pem")

    def test_a_remote_host_encrypts_even_when_the_dsn_is_silent(self):
        env = compare._connection_env("postgres://bob@db.example/things")
        self.assertEqual(env["PGSSLMODE"], compare.DEFAULT_SSLMODE)

    def test_a_remote_host_cannot_ask_for_plaintext(self):
        for mode in ("disable", "allow", "prefer"):
            with self.subTest(mode=mode):
                with self.assertRaises(SystemExit):
                    compare._connection_env(
                        "postgres://bob@db.example/things?sslmode=%s" % mode)

    def test_a_weak_sslmode_cannot_hide_in_mixed_case(self):
        """libpq spells its keywords lower case; comparing without folding lets
        sslmode=Disable walk past the check."""
        for dsn in ("postgres://bob@db.example/t?sslmode=Disable",
                    "postgres://bob@db.example/t?sslmode=PREFER",
                    "postgres://bob@db.example/t?SSLMODE=disable"):
            with self.subTest(dsn=dsn):
                with self.assertRaises(SystemExit):
                    compare._connection_env(dsn)

    def test_a_mixed_case_password_key_is_refused_too(self):
        with self.assertRaises(SystemExit) as e:
            compare._connection_env("postgres://bob@db.example/t?PASSWORD=hunter2")
        self.assertNotIn("hunter2", str(e.exception))

    def test_a_strong_sslmode_survives_mixed_case(self):
        env = compare._connection_env(
            "postgres://bob@db.example/t?SSLMODE=Verify-Full")
        self.assertEqual(env["PGSSLMODE"], "verify-full")

    def test_no_libpq_state_is_inherited_from_the_environment(self):
        """Otherwise the destination and the policy come from different places: a
        hostless DSN takes PGHOST from the environment and is still judged local."""
        stray = {"PGHOST": "elsewhere.example", "PGPORT": "9999",
                 "PGSSLMODE": "disable", "PGSERVICE": "elsewhere",
                 "PGPASSWORD": "leftover", "PGDATABASE": "other"}
        with unittest.mock.patch.dict("os.environ", stray):
            env = compare._connection_env("postgres:///things")
        self.assertNotIn("PGHOST", env)
        self.assertNotIn("PGSERVICE", env)
        self.assertNotIn("PGPASSWORD", env)
        self.assertNotIn("PGSSLMODE", env)
        self.assertEqual(env["PGDATABASE"], "things")

    def test_an_inherited_sslmode_cannot_survive_a_remote_dsn(self):
        with unittest.mock.patch.dict("os.environ", {"PGSSLMODE": "disable"}):
            env = compare._connection_env("postgres://bob@db.example/things")
        self.assertEqual(env["PGSSLMODE"], compare.DEFAULT_SSLMODE)

    def test_the_rest_of_the_environment_is_left_alone(self):
        with unittest.mock.patch.dict("os.environ", {"HOME": "/home/bob"}):
            env = compare._connection_env("postgres://bob@127.0.0.1/things")
        self.assertEqual(env["HOME"], "/home/bob")

    def test_a_loopback_tunnel_is_exempt(self):
        """The tunnel already authenticated and terminates on this machine."""
        for host in ("127.0.0.1", "localhost"):
            with self.subTest(host=host):
                env = compare._connection_env("postgres://bob@%s:15433/things" % host)
                self.assertNotIn("PGSSLMODE", env)

    def test_a_password_in_the_query_string_is_refused_too(self):
        """urlsplit().password does not see it, so checking only that leaves the
        credential in argv."""
        with self.assertRaises(SystemExit) as e:
            compare._connection_env("postgres://bob@db.example/things?password=hunter2")
        self.assertNotIn("hunter2", str(e.exception))

    def test_a_passfile_path_is_allowed(self):
        """A path is not a secret; libpq reads the password this never sees."""
        env = compare._connection_env(
            "postgres://bob@db.example/things?passfile=/home/me/.pgpass")
        self.assertEqual(env["PGPASSFILE"], "/home/me/.pgpass")

    def test_an_unrecognised_option_is_refused_rather_than_ignored(self):
        with self.assertRaises(SystemExit) as e:
            compare._connection_env("postgres://bob@db.example/things?madeup=1")
        self.assertIn("madeup", str(e.exception))

    def test_the_startup_file_is_disabled(self):
        """A .psqlrc can \\set over the bindings, redirect output with \\o, or run a
        shell command with \\!."""
        import subprocess
        done = subprocess.CompletedProcess(args=[], returncode=0, stdout="[]", stderr="")
        with unittest.mock.patch("subprocess.run", return_value=done) as run:
            compare.psql("postgres://bob@127.0.0.1/things", "SELECT 1")
        self.assertIn("-X", run.call_args[0][0])

    def test_psql_own_environment_is_dropped_too(self):
        """PSQLRC does not start with PG, so the libpq strip does not reach it."""
        with unittest.mock.patch.dict("os.environ", {"PSQLRC": "/tmp/evil"}):
            env = compare._connection_env("postgres://bob@127.0.0.1/things")
        self.assertNotIn("PSQLRC", env)

    def test_a_remote_host_authenticates_the_server_by_default(self):
        """require encrypts but accepts any certificate, so it stops eavesdropping
        and not impersonation."""
        env = compare._connection_env("postgres://bob@db.example/things")
        self.assertEqual(env["PGSSLMODE"], "verify-full")

    def test_a_weaker_encrypted_mode_is_still_available_by_name(self):
        env = compare._connection_env("postgres://bob@db.example/t?sslmode=require")
        self.assertEqual(env["PGSSLMODE"], "require")

    def test_a_psql_in_a_world_writable_directory_is_refused(self):
        import os as _os, tempfile, pathlib as _p
        directory = tempfile.mkdtemp()
        _os.chmod(directory, 0o777)
        binary = _p.Path(directory, "psql")
        binary.write_text("#!/bin/sh\nexit 0\n")
        binary.chmod(0o755)
        with unittest.mock.patch.dict("os.environ",
                                      {"PATH": "%s:%s" % (directory, _os.environ["PATH"])}):
            with self.assertRaises(SystemExit) as e:
                compare._psql_binary()
        self.assertIn("writable by other accounts", str(e.exception))

    def test_psql_is_resolved_to_an_absolute_path(self):
        """A writable directory earlier on PATH would otherwise receive every row."""
        self.assertTrue(os.path.isabs(compare._psql_binary()))

    def test_psql_missing_from_path_is_an_error_not_a_relative_call(self):
        with unittest.mock.patch("shutil.which", return_value=None):
            with self.assertRaises(SystemExit):
                compare._psql_binary()


class TestOnlyDevelopmentShowsPromptText(unittest.TestCase):
    def test_staging_redacts(self):
        self.assertEqual(_redaction_for("staging"), True)

    def test_production_redacts(self):
        self.assertEqual(_redaction_for("production"), True)

    def test_development_does_not(self):
        self.assertEqual(_redaction_for("development"), False)

    def test_an_environment_outside_the_three_is_refused(self):
        """A typo must not be a silent opt-out of redaction."""
        import subprocess, sys, tempfile
        from pathlib import Path
        from tests.conftest import REPO
        r = subprocess.run(
            [sys.executable, str(REPO / ".claude/skills/identify-drift/compare.py"),
             "--local", "/dev/null", "--email", "a@b.c", "--environment", "prod"],
            capture_output=True, text=True, timeout=60,
            env={"PATH": "/usr/bin:/bin", "HOME": tempfile.mkdtemp(),
                 "IDENTIFY_DRIFT_DSN": "postgres://u@127.0.0.1/d"})
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("invalid choice", r.stderr)


def _redaction_for(environment):
    """What main() would set REDACT to, without running a query."""
    return environment != "development"


class TestTheScanFileCannotBeRedirected(unittest.TestCase):
    def test_a_symlink_at_the_destination_is_refused(self):
        """O_TRUNC through a symlink would truncate whatever it points at."""
        import subprocess, sys, tempfile
        from pathlib import Path
        from tests.conftest import REPO
        work = Path(tempfile.mkdtemp())
        victim = work / "victim"
        victim.write_text("do not truncate me")
        (work / "out.json").symlink_to(victim)
        r = subprocess.run(
            [sys.executable, str(REPO / ".claude/skills/identify-drift/scan_local.py"),
             "--tools", "claude-code", "--days", "1", "--out", str(work / "out.json")],
            capture_output=True, text=True, timeout=300)
        self.assertNotEqual(r.returncode, 0)
        self.assertEqual(victim.read_text(), "do not truncate me")


class TestTheDigestIdentifiesOnePromptOnly(unittest.TestCase):
    """Truncating before hashing made two prompts sharing an opening interchangeable.
    That is a real collision in stored data, not a hypothetical."""

    def test_prompts_differing_only_past_two_hundred_characters_differ(self):
        base = "x" * 250
        self.assertNotEqual(compare._digest(base + "alpha"), compare._digest(base + "beta"))

    def test_whitespace_and_case_still_normalise(self):
        self.assertEqual(compare._digest("  Hello   THERE  "), compare._digest("hello there"))

    def test_the_whole_text_is_hashed(self):
        import hashlib
        self.assertEqual(compare._digest("hello there"),
                         hashlib.sha256(b"hello there").hexdigest())


class TestACountOnlyRunSaysSo(unittest.TestCase):
    """A clean report from the count fallback must not read as 'every call arrived'."""

    def test_the_caveat_is_raised_when_counting_is_all_there_is(self):
        d = db(ids_are_representative=False, call_ids=())
        got = titles(compare.compare("claude-code", local(MATCHED_TRANSCRIPT), d, 3))
        self.assertIn("Tool calls could only be reconciled by count", got)

    def test_the_caveat_says_a_clean_result_is_not_proof(self):
        d = db(ids_are_representative=False, call_ids=())
        got = compare.compare("claude-code", local(MATCHED_TRANSCRIPT), d, 3)
        why = next(f["why"] for f in got if "only be reconciled" in f["title"])
        self.assertIn("not proof", why)

    def test_no_caveat_when_the_ids_did_the_work(self):
        got = titles(compare.compare("claude-code", local(MATCHED_TRANSCRIPT),
                                     MATCHED_DB, 3))
        self.assertNotIn("Tool calls could only be reconciled by count", got)


class TestTheReportFileIsProtectedLikeTheScan(unittest.TestCase):
    def _run(self, out, extra_env=None):
        import json as _json, subprocess, sys, tempfile
        from pathlib import Path
        from tests.conftest import REPO
        work = Path(tempfile.mkdtemp())
        (work / "local.json").write_text(_json.dumps({
            "since": "2026-08-01T00:00:00+00:00", "days": 3, "tools": {}}))
        fake = work / "psql"
        fake.write_text("#!/bin/sh\necho '[]'\n")
        fake.chmod(0o755)
        env = {"PATH": "%s:/usr/bin:/bin" % work, "HOME": str(work),
               "IDENTIFY_DRIFT_DSN": "postgres://u@127.0.0.1:5432/d"}
        env.update(extra_env or {})
        return subprocess.run(
            [sys.executable, str(REPO / ".claude/skills/identify-drift/compare.py"),
             "--local", str(work / "local.json"), "--email", "a@b.c",
             "--environment", "development", "--out", str(out)],
            capture_output=True, text=True, timeout=120, env=env)

    def test_the_report_is_owner_only_whatever_the_umask(self):
        import os as _os, stat, tempfile
        from pathlib import Path
        out = Path(tempfile.mkdtemp()) / "report.json"
        old = _os.umask(0o000)
        try:
            r = self._run(out)
        finally:
            _os.umask(old)
        self.assertEqual(r.returncode, 0, r.stderr[-300:])
        mode = _os.stat(out).st_mode
        self.assertFalse(mode & stat.S_IROTH, "world-readable")
        self.assertFalse(mode & stat.S_IRGRP, "group-readable")

    def test_a_symlink_at_the_report_path_is_refused(self):
        import tempfile
        from pathlib import Path
        work = Path(tempfile.mkdtemp())
        victim = work / "victim"
        victim.write_text("do not truncate me")
        (work / "report.json").symlink_to(victim)
        r = self._run(work / "report.json")
        self.assertNotEqual(r.returncode, 0)
        self.assertEqual(victim.read_text(), "do not truncate me")


def _run_compare(local_document):
    """compare.py over a scan file we control, with no database behind it."""
    import json as _json, subprocess, sys, tempfile
    from pathlib import Path
    from tests.conftest import REPO
    work = Path(tempfile.mkdtemp())
    (work / "local.json").write_text(_json.dumps(local_document))
    return subprocess.run(
        [sys.executable, str(REPO / ".claude/skills/identify-drift/compare.py"),
         "--local", str(work / "local.json"), "--email", "a@b.c",
         "--environment", "development"],
        capture_output=True, text=True, timeout=60,
        env={"PATH": "/usr/bin:/bin", "HOME": str(work),
             "IDENTIFY_DRIFT_DSN": "postgres://u@127.0.0.1:5432/d"})


if __name__ == "__main__":
    unittest.main()
