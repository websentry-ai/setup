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
       rows_with_call_id=None, threads_are_representative=True,
       first_stored_at=None):
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
        "threads_are_representative": threads_are_representative,
        "first_stored_at": first_stored_at,
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

    def test_a_session_the_hook_logged_but_nothing_reached(self):
        """A session the hook saw and the database has no row for lost every one of
        its turns, which is worse than losing some of them."""
        t = MATCHED_TRANSCRIPT + [rec("tool_call", session="S2", tool="Bash", call_id="c3")]
        a = MATCHING_AUDIT + [rec("tool_call", session="S2", tool="Bash", call_id="c3")]
        got = titles(compare.compare("claude-code",
                                     local(t, a, sessions_transcript=["S1", "S2"],
                                           sessions_audit=["S1", "S2"]),
                                     MATCHED_DB, 3))
        self.assertIn("The hook logged sessions the database has no record of", got)

    def test_activity_predating_the_first_upload_is_not_a_loss(self):
        """Most stored rows carry no thread_id for some tools, so scoping by session
        is unavailable there. The first stored row is the floor instead: nothing older
        than it was ever uploaded, so it cannot have been lost."""
        old = [rec("user_prompt", at="2026-01-01T00:00:00+00:00", text="p%d" % i)
               for i in range(50)]
        d = db(metrics_rows=500, threads_are_representative=False, threads=(),
               user_texts=(), first_stored_at="2026-08-01 00:00:00+00")
        got = titles(compare.compare("claude-code", local(old), d, 14))
        self.assertIn("Local activity predates anything this tool ever uploaded", got)
        self.assertNotIn("User prompts recorded locally are absent from the database",
                         got)

    def test_activity_after_the_first_upload_still_counts(self):
        recent = [rec("user_prompt", text="never sent")]
        d = db(metrics_rows=500, threads_are_representative=False, threads=(),
               user_texts=(), first_stored_at="2026-08-01 00:00:00+00")
        got = titles(compare.compare("claude-code", local(recent), d, 14))
        self.assertIn("User prompts recorded locally are absent from the database", got)

    def test_no_scoping_finding_when_scoping_is_unavailable(self):
        """An empty scope must not make every session look unknown."""
        got = titles(compare.compare("claude-code",
                                     local(MATCHED_TRANSCRIPT, MATCHING_AUDIT),
                                     db(threads_are_representative=False, threads=()),
                                     3))
        self.assertNotIn("The hook logged sessions the database has no record of", got)
        self.assertNotIn("Some local sessions were never instrumented", got)

    def test_a_session_nobody_instrumented_is_not_a_loss(self):
        """A tool runs whether or not the integration was installed, so a machine can
        hold months of transcripts the gateway was never told about."""
        t = MATCHED_TRANSCRIPT + [rec("user_prompt", session="S2", text="never sent")]
        got = titles(compare.compare("claude-code",
                                     local(t, sessions_transcript=["S1", "S2"]),
                                     MATCHED_DB, 3))
        self.assertIn("Some local sessions were never instrumented", got)
        self.assertNotIn("User prompts recorded locally are absent from the database",
                         got)


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

    def test_errors_never_echo_the_infrastructure_either(self):
        """A password cannot reach the scrubber any more, but the host, user and
        database still name infrastructure that should not land in a report."""
        dsn = "postgres://reporting_ro@replica.internal.example:5432/gateway_prod"
        scrubbed = compare._scrub(
            'could not connect to server "replica.internal.example" as user '
            '"reporting_ro" database "gateway_prod"', dsn)
        for piece in ("replica.internal.example", "reporting_ro", "gateway_prod"):
            self.assertNotIn(piece, scrubbed)

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

    def test_no_finding_quotes_local_data_when_redacting(self):
        """Redaction has to hold across every finding, not the two that remember to
        call the helper. Session and call ids name a person's project and turn."""
        import json as _json
        secret = "CUSTOMERSECRETPHRASE"
        t = [rec("user_prompt", text=secret + " one"),
             rec("assistant_message", text=secret + " two"),
             rec("tool_call", tool="Bash", call_id=secret + "-call"),
             rec("usage", input=100, output=50)]
        a = [rec("user_prompt", text=secret + " three"),
             rec("tool_call", tool="Bash", call_id=secret + "-audit")]
        loc = local(t, a, sessions_transcript=[secret + "-session"])
        empty = db(threads=("S1",), tool_counts={}, call_ids=(),
                   user_texts=(), assistant_texts=(), rows_with_call_id=10)
        try:
            compare.REDACT = True
            found = compare.compare("claude-code", loc, empty, 14, empty)
        finally:
            compare.REDACT = False
        self.assertTrue(found, "expected findings to check")
        self.assertNotIn(secret, _json.dumps(found))

    def test_the_same_run_does_quote_them_off_production(self):
        """The redaction test would pass trivially if nothing were ever quoted."""
        import json as _json
        secret = "CUSTOMERSECRETPHRASE"
        t = [rec("user_prompt", text=secret + " one"),
             rec("assistant_message", text=secret + " two"),
             rec("tool_call", tool="Bash", call_id=secret + "-call"),
             rec("usage", input=100, output=50)]
        loc = local(t, sessions_transcript=[secret + "-session"])
        empty = db(threads=("S1",), tool_counts={}, call_ids=(),
                   user_texts=(), assistant_texts=(), rows_with_call_id=10)
        found = compare.compare("claude-code", loc, empty, 14, empty)
        self.assertIn(secret, _json.dumps(found))

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


class TestAnUndatedRecordStillHasAnAge(unittest.TestCase):
    """A record with no timestamp of its own is never filtered by the window, so a
    transcript from months ago is compared against a fourteen-day database window and
    every prompt in it reads as lost. Cursor writes no per-record timestamp at all."""

    def _cursor_transcript(self, age_days, body):
        import os, tempfile, time
        from pathlib import Path
        home = Path(tempfile.mkdtemp())
        path = home / ".cursor/projects/p/agent-transcripts/s/session.jsonl"
        path.parent.mkdir(parents=True)
        path.write_text(body)
        old_time = time.time() - age_days * 86400
        os.utime(path, (old_time, old_time))
        return home

    def _scan(self, home, days=14):
        import json as _json, subprocess, sys
        from tests.conftest import REPO
        env = dict(os.environ)
        env["HOME"] = str(home)
        r = subprocess.run(
            [sys.executable, str(REPO / ".claude/skills/identify-drift/scan_local.py"),
             "--tools", "cursor", "--days", str(days)],
            capture_output=True, text=True, timeout=300, env=env, check=True)
        return _json.loads(r.stdout)["tools"]["cursor"]["transcript"]

    def test_an_undated_record_in_an_old_file_is_outside_the_window(self):
        body = _json_line({"role": "user",
                           "message": {"content": [{"type": "text", "text": "ancient"}]}})
        got = self._scan(self._cursor_transcript(200, body))
        self.assertEqual(got, [])

    def test_an_undated_record_in_a_recent_file_is_inside_it(self):
        body = _json_line({"role": "user",
                           "message": {"content": [{"type": "text", "text": "recent"}]}})
        got = self._scan(self._cursor_transcript(1, body))
        self.assertEqual([r["text"] for r in got], ["recent"])

    def test_the_fallback_gives_the_record_a_usable_time(self):
        """Without one the localisation check silently compares nothing."""
        body = _json_line({"role": "user",
                           "message": {"content": [{"type": "text", "text": "recent"}]}})
        got = self._scan(self._cursor_transcript(1, body))
        self.assertTrue(got[0]["at"], "record has no timestamp to place it by")

    def test_a_records_own_timestamp_still_wins(self):
        """The file time is a fallback, not an override."""
        from pathlib import Path
        stamp = "2026-08-20T10:00:00+00:00"
        body = _json_line({"role": "user", "timestamp": stamp,
                           "message": {"content": [{"type": "text", "text": "dated"}]}})
        got = self._scan(self._cursor_transcript(1, body))
        self.assertEqual(got[0]["at"], stamp)


def _json_line(document):
    import json as _json
    return _json.dumps(document) + "\n"


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


class TestACheckThatDoesNotRunSaysSo(unittest.TestCase):
    """Codex reports a cumulative total per turn rather than a delta per message, so
    the token comparison cannot run for it. Silence would read as a pass."""

    def test_a_running_total_tool_declares_the_gap(self):
        t = [rec("user_prompt", text="hello there"),
             rec("assistant_message", text="hi back"),
             rec("tool_call", tool="Bash", call_id="c1"),
             rec("usage_total", input=500, output=200)]
        got = titles(compare.compare("codex", local(t), MATCHED_DB, 3))
        self.assertIn("Token totals were not reconciled for this tool", got)

    def test_a_per_message_tool_does_not(self):
        got = titles(compare.compare("claude-code", local(MATCHED_TRANSCRIPT),
                                     MATCHED_DB, 3))
        self.assertNotIn("Token totals were not reconciled for this tool", got)


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

    def test_a_capped_audit_aggregate_does_not_invent_upload_losses(self):
        """The cap bounds what came back. Treating the remainder as absent turns every
        row it omitted into a loss the upload never had."""
        a = [rec("user_prompt", text="only in the log"),
             rec("tool_call", tool="Bash")]
        capped = db(user_texts=(), tool_counts={}, call_ids=(),
                    ids_are_representative=False,
                    truncated=["prompts", "tool names"])
        got = titles(compare.compare("claude-code", local(MATCHED_TRANSCRIPT, a),
                                     MATCHED_DB, 14, capped))
        self.assertNotIn("The hook logged prompts the database never received", got)
        self.assertNotIn("The hook logged tool calls the database never received "
                         "(by count)", got)
        self.assertIn("Prompt uploads could not be checked for this window", got)
        self.assertIn("Upload losses could not be checked for this window", got)

    def test_an_uncapped_audit_aggregate_still_finds_the_loss(self):
        """The suppression must not swallow real findings."""
        a = [rec("user_prompt", text="only in the log"),
             rec("tool_call", tool="Bash")]
        empty = db(user_texts=(), tool_counts={}, call_ids=(),
                   ids_are_representative=False)
        got = titles(compare.compare("claude-code", local(MATCHED_TRANSCRIPT, a),
                                     MATCHED_DB, 14, empty))
        self.assertIn("The hook logged prompts the database never received", got)

    def test_a_capped_full_window_aggregate_does_not_invent_losses_either(self):
        """The same rule as the audit window: the cap bounds what came back, so what
        it left out is not evidence of absence."""
        capped = db(threads=(), tool_counts={}, call_ids=(), user_texts=(),
                    assistant_texts=(), ids_are_representative=False,
                    truncated=["sessions", "tool names", "prompts"])
        got = titles(compare.compare("claude-code", local(MATCHED_TRANSCRIPT),
                                     capped, 14))
        for invented in ("User prompts recorded locally are absent from the database",
                         "Sessions present locally are absent from the database",
                         "Tool calls made locally are under-recorded (by count)"):
            self.assertNotIn(invented, got)
        for said in ("Sessions could not be checked for this window",
                     "Prompts could not be checked for this window",
                     "Tool calls could not be checked for this window"):
            self.assertIn(said, got)

    def test_the_capped_notice_fires_for_assistant_messages_alone(self):
        """A window with replies but no prompts must not skip the check in silence."""
        t = [rec("assistant_message", text="unrecorded answer")]
        capped = db(user_texts=(), assistant_texts=(), truncated=["prompts"])
        got = titles(compare.compare("claude-code", local(t), capped, 14))
        self.assertIn("Prompts could not be checked for this window", got)

    def test_nothing_local_means_nothing_to_say(self):
        capped = db(user_texts=(), assistant_texts=(), truncated=["prompts"])
        got = titles(compare.compare("claude-code", local([]), capped, 14))
        self.assertNotIn("Prompts could not be checked for this window", got)

    def test_an_uncapped_full_window_still_reports_the_real_losses(self):
        empty = db(threads=("S1",), tool_counts={}, call_ids=(), user_texts=(),
                   assistant_texts=(), ids_are_representative=False)
        got = titles(compare.compare("claude-code", local(MATCHED_TRANSCRIPT),
                                     empty, 14))
        self.assertIn("User prompts recorded locally are absent from the database", got)
        self.assertIn("Tool calls made locally are under-recorded (by count)", got)

    def test_an_interval_bounds_the_rows_not_the_request_that_made_them(self):
        """A turn that began before the audit log's first retained entry still writes
        rows inside the audited interval. Bounding the parent dropped them, so the
        audit entries for them read as uploads that never arrived."""
        import subprocess
        done = subprocess.CompletedProcess(args=[], returncode=0, stdout="[]", stderr="")
        with unittest.mock.patch("subprocess.run", return_value=done) as run:
            with unittest.mock.patch.object(compare, "PSQL", _a_psql()):
                compare.fetch_db("postgres://bob@127.0.0.1/t", "a@b.c", "claude-code",
                                 14, since="2026-08-01T00:00:00+00:00",
                                 until="2026-08-05T00:00:00+00:00")
        bounded = [c[1]["input"] for c in run.call_args_list
                   if "prompt_analytics" in c[1]["input"] or "prompts p" in c[1]["input"]]
        self.assertTrue(bounded, "expected the child queries")
        for statement in bounded:
            self.assertRegex(statement, r"(pa|p)\.created_at >=")
            self.assertNotRegex(statement, r"request_initialized_at >= \$drift")

    def test_the_whole_window_is_bounded_by_row_time_too(self):
        """The requested window has the same skew problem as the audit one: a request
        that began before it still writes rows inside it."""
        import subprocess
        done = subprocess.CompletedProcess(args=[], returncode=0, stdout="[]", stderr="")
        with unittest.mock.patch("subprocess.run", return_value=done) as run:
            with unittest.mock.patch.object(compare, "PSQL", _a_psql()):
                compare.fetch_db("postgres://bob@127.0.0.1/t", "a@b.c", "claude-code", 14)
        rows = [c[1]["input"] for c in run.call_args_list
                if "prompt_analytics" in c[1]["input"] or "prompts p" in c[1]["input"]]
        self.assertTrue(rows)
        for statement in rows:
            self.assertRegex(statement, r"(pa|p)\.created_at >= now\(\)")
            self.assertNotIn("request_initialized_at", statement)

    def test_tokens_are_still_counted_by_when_the_request_ran(self):
        """A token belongs to a request, so that one is bounded by request time."""
        import subprocess
        done = subprocess.CompletedProcess(args=[], returncode=0, stdout="[]", stderr="")
        with unittest.mock.patch("subprocess.run", return_value=done) as run:
            with unittest.mock.patch.object(compare, "PSQL", _a_psql()):
                compare.fetch_db("postgres://bob@127.0.0.1/t", "a@b.c", "claude-code", 14)
        totals = [c[1]["input"] for c in run.call_args_list
                  if "input_token_size" in c[1]["input"]]
        self.assertTrue(totals)
        self.assertIn("request_initialized_at", totals[0])

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
            with unittest.mock.patch.object(compare, "PSQL", _a_psql()):
                with self.assertRaises(SystemExit) as e:
                    compare.psql("postgres://bob@db.example/things", "SELECT 1")
        self.assertIn("fewer days", str(e.exception))

    def test_other_errors_are_still_reported_verbatim(self):
        import subprocess
        done = subprocess.CompletedProcess(
            args=[], returncode=1, stdout="", stderr='ERROR:  relation "nope" does not exist')
        with unittest.mock.patch("subprocess.run", return_value=done):
            with unittest.mock.patch.object(compare, "PSQL", _a_psql()):
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

    def test_no_bind_value_reaches_the_process_arguments(self):
        """The scanned user's email was on the command line, readable by every local
        account for the length of the query."""
        import subprocess
        done = subprocess.CompletedProcess(args=[], returncode=0, stdout="[]", stderr="")
        with unittest.mock.patch("subprocess.run", return_value=done) as run:
            with unittest.mock.patch.object(compare, "PSQL", _a_psql()):
                compare.psql("postgres://bob@127.0.0.1/t", "SELECT :'email' AS v",
                             {"email": "someone@example.com"})
        self.assertNotIn("someone@example.com", " ".join(run.call_args[0][0]))

    def test_the_bind_values_still_arrive(self):
        """Off the command line is only useful if the query still carries them."""
        import subprocess
        done = subprocess.CompletedProcess(args=[], returncode=0, stdout="[]", stderr="")
        with unittest.mock.patch("subprocess.run", return_value=done) as run:
            with unittest.mock.patch.object(compare, "PSQL", _a_psql()):
                compare.psql("postgres://bob@127.0.0.1/t", "SELECT :'email' AS v",
                             {"email": "someone@example.com"})
        fed = run.call_args[1]["input"]
        self.assertIn("someone@example.com", fed)
        self.assertNotIn(":'email'", fed)

    def test_a_value_cannot_end_its_own_quoting(self):
        """Dollar quoting takes everything between the tags verbatim, and the tag is
        chosen so the value does not contain it. Carrying values through psql
        variables meant crossing psql's parser and then a shell, where a backquote or
        an apostrophe silently produced an empty binding instead of an error."""
        for value in ("a'; DROP TABLE prompts; --", "back\\slash", "`id`", "$(id)",
                      "line\nbreak", "'", "$drift$ nested $drift$"):
            with self.subTest(value=value):
                literal = compare._sql_literal(value)
                tag = literal.split("$")[1]
                self.assertNotIn("$%s$" % tag, value)
                self.assertTrue(literal.startswith("$%s$" % tag))
                self.assertTrue(literal.endswith("$%s$" % tag))
                self.assertEqual(literal[len(tag) + 2:-(len(tag) + 2)], value)

    def test_the_tag_moves_when_the_value_contains_it(self):
        self.assertTrue(compare._sql_literal("$drift$").startswith("$drift1$"))

    def test_every_marker_in_a_query_is_substituted(self):
        """A marker left in place is sent to the server verbatim, which only shows at
        runtime. fetch_db builds five statements across several parameter sets."""
        import re, subprocess
        done = subprocess.CompletedProcess(args=[], returncode=0, stdout="[]", stderr="")
        with unittest.mock.patch("subprocess.run", return_value=done) as run:
            with unittest.mock.patch.object(compare, "PSQL", _a_psql()):
                compare.fetch_db("postgres://bob@127.0.0.1/t", "someone@example.com",
                                 "claude-code", 14, since="2026-08-01T00:00:00+00:00",
                                 until="2026-08-05T00:00:00+00:00")
        self.assertGreater(run.call_count, 1)
        for call in run.call_args_list:
            statement = call[1]["input"]
            self.assertEqual(re.findall(r":'[a-z_]+'", statement), [], statement[:200])

    def test_a_value_holding_another_marker_is_not_rewritten(self):
        """Substituting one name at a time let a later pass edit text inside an
        already-finished literal, so an email containing :'label' came out changed."""
        import subprocess
        done = subprocess.CompletedProcess(args=[], returncode=0, stdout="[]", stderr="")
        hostile = "victim:'label'@example.com"
        with unittest.mock.patch("subprocess.run", return_value=done) as run:
            with unittest.mock.patch.object(compare, "PSQL", _a_psql()):
                compare.psql("postgres://bob@127.0.0.1/t",
                             "SELECT :'email' AS v, :'label' AS w",
                             {"email": hostile, "label": "claude-code"})
        fed = run.call_args[1]["input"]
        self.assertIn("$drift$%s$drift$" % hostile, fed)

    def test_a_marker_with_no_value_is_refused(self):
        """It would otherwise reach the server verbatim and fail there."""
        with unittest.mock.patch.object(compare, "PSQL", _a_psql()):
            with self.assertRaises(SystemExit) as e:
                compare.psql("postgres://bob@127.0.0.1/t", "SELECT :'nope' AS v",
                             {"email": "x"})
        self.assertIn("nope", str(e.exception))

    def test_the_startup_file_is_disabled(self):
        """A .psqlrc can \\set over the bindings, redirect output with \\o, or run a
        shell command with \\!."""
        import subprocess
        done = subprocess.CompletedProcess(args=[], returncode=0, stdout="[]", stderr="")
        with unittest.mock.patch("subprocess.run", return_value=done) as run:
            with unittest.mock.patch.object(compare, "PSQL", _a_psql()):
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
        self.assertIn("writable by accounts other than yours", str(e.exception))

    def _psql_at(self, dir_mode, bin_mode, via_symlink=False):
        import os as _os, tempfile, pathlib as _p
        directory = tempfile.mkdtemp()
        target = _p.Path(directory, "psql-real" if via_symlink else "psql")
        target.write_text("#!/bin/sh\nexit 0\n")
        target.chmod(bin_mode)
        if via_symlink:
            _p.Path(directory, "psql").symlink_to(target)
        _os.chmod(directory, dir_mode)
        return directory

    def _resolve_with(self, directory):
        import os as _os
        with unittest.mock.patch.dict("os.environ", {"PATH": directory}):
            return compare._psql_binary()

    def test_a_world_writable_binary_in_a_safe_directory_is_refused(self):
        """Checking the directory catches replacing the file. It does not catch
        editing the file that is already there."""
        with self.assertRaises(SystemExit):
            self._resolve_with(self._psql_at(0o755, 0o777))

    def test_a_group_writable_binary_in_a_shared_group_is_refused(self):
        """Whether a group is shared depends on the machine, so the membership is
        stated here rather than inherited from whatever group temp files land in."""
        directory = self._psql_at(0o755, 0o775)
        with unittest.mock.patch.object(compare, "_group_members",
                                        return_value={"someone-else"}):
            with self.assertRaises(SystemExit):
                self._resolve_with(directory)

    def test_a_group_writable_binary_in_a_private_group_is_accepted(self):
        import pwd as _pwd
        directory = self._psql_at(0o755, 0o775)
        me = _pwd.getpwuid(os.getuid()).pw_name
        with unittest.mock.patch.object(compare, "_group_members",
                                        return_value={me, "root"}):
            self.assertTrue(self._resolve_with(directory))

    def test_a_symlink_to_a_writable_target_is_refused(self):
        """The name on PATH is often a link; what runs is what it points at."""
        with self.assertRaises(SystemExit):
            self._resolve_with(self._psql_at(0o755, 0o777, via_symlink=True))

    def test_a_symlink_to_a_safe_target_is_accepted(self):
        directory = self._psql_at(0o755, 0o755, via_symlink=True)
        got = self._resolve_with(directory)
        self.assertTrue(got)

    def test_the_resolved_target_is_what_runs(self):
        """Running the name again would re-follow a link that could have been
        repointed since it was checked."""
        import os as _os
        directory = self._psql_at(0o755, 0o755, via_symlink=True)
        self.assertEqual(self._resolve_with(directory),
                         _os.path.realpath(_os.path.join(directory, "psql-real")))

    def test_a_symlinks_permission_bits_are_ignored(self):
        """Linux creates every symlink 0777 and the kernel ignores the bits. Reading
        them refuses a perfectly sound link on Linux while passing on macOS, which is
        how this differed between the two."""
        import os as _os, stat as _stat
        directory = self._psql_at(0o755, 0o755, via_symlink=True)
        real_lstat = _os.lstat

        def like_linux(path, *a, **k):
            info = real_lstat(path, *a, **k)
            if _stat.S_ISLNK(info.st_mode):
                return _os.stat_result((_stat.S_IFLNK | 0o777,) + tuple(info)[1:])
            return info

        with unittest.mock.patch("os.lstat", side_effect=like_linux):
            self.assertTrue(self._resolve_with(directory))

    def test_a_link_owned_by_another_account_is_refused(self):
        """Its owner can delete and recreate it, so a sound target proves nothing."""
        import os as _os
        directory = self._psql_at(0o755, 0o755, via_symlink=True)
        link = _os.path.join(directory, "psql")
        real_lstat = _os.lstat

        def foreign(path, *a, **k):
            info = real_lstat(path, *a, **k)
            if str(path) == link:
                return _os.stat_result((info.st_mode, 0, 0, 1, 4242, 4242, 0, 0, 0, 0))
            return info

        with unittest.mock.patch("os.lstat", side_effect=foreign):
            with self.assertRaises(SystemExit):
                self._resolve_with(directory)

    def test_a_writable_directory_above_the_binary_is_refused(self):
        """Writing the parent lets you swap the whole bin directory, so a sound
        directory inside a shared one is not sound."""
        import os as _os, tempfile, pathlib as _p
        parent = tempfile.mkdtemp()
        inner = _p.Path(parent, "bin")
        inner.mkdir()
        binary = inner / "psql"
        binary.write_text("#!/bin/sh\nexit 0\n")
        binary.chmod(0o755)
        _os.chmod(inner, 0o755)
        _os.chmod(parent, 0o777)
        with self.assertRaises(SystemExit):
            self._resolve_with(str(inner))

    def test_a_sticky_world_writable_parent_is_not_a_hazard(self):
        """/tmp is 1777: anyone may create an entry, only its owner may replace it.
        Treating that as unsafe would refuse every path under it for no gain."""
        import os as _os, tempfile, pathlib as _p
        parent = tempfile.mkdtemp()
        _os.chmod(parent, 0o1777)
        self.assertFalse(compare._writable_by_others(parent))
        inner = _p.Path(parent, "bin")
        inner.mkdir()
        binary = inner / "psql"
        binary.write_text("#!/bin/sh\nexit 0\n")
        binary.chmod(0o755)
        _os.chmod(inner, 0o755)
        self.assertTrue(self._resolve_with(str(inner)))

    def test_a_plain_world_writable_parent_still_is(self):
        """Without the sticky bit anyone can replace anyone's entry."""
        import os as _os, tempfile
        parent = tempfile.mkdtemp()
        _os.chmod(parent, 0o777)
        self.assertTrue(compare._writable_by_others(parent))

    def test_a_path_owned_by_another_account_is_unsafe_whatever_its_mode(self):
        """Its owner can rewrite it, so clear group and world bits prove nothing."""
        import os as _os
        info = _os.stat_result((0o040755, 0, 0, 1, 4242, 4242, 0, 0, 0, 0))
        with unittest.mock.patch("os.stat", return_value=info):
            self.assertTrue(compare._writable_by_others("/anywhere"))

    def test_a_path_owned_by_root_is_fine(self):
        import os as _os
        info = _os.stat_result((0o040755, 0, 0, 1, 0, 0, 0, 0, 0, 0))
        with unittest.mock.patch("os.stat", return_value=info):
            self.assertFalse(compare._writable_by_others("/anywhere"))

    def test_a_missing_path_counts_as_unsafe(self):
        self.assertTrue(compare._writable_by_others("/nonexistent/path/here"))

    def test_a_shared_group_directory_is_refused_even_when_we_own_it(self):
        """Owning the directory says nothing about who else is in its group. A prefix
        owned by this user but group-writable by a group with other members can still
        have its psql replaced."""
        import os as _os, tempfile, pathlib as _p
        directory = tempfile.mkdtemp()
        _os.chmod(directory, 0o775)
        binary = _p.Path(directory, "psql")
        binary.write_text("#!/bin/sh\nexit 0\n")
        binary.chmod(0o755)
        with unittest.mock.patch.dict("os.environ",
                                      {"PATH": "%s:%s" % (directory, _os.environ["PATH"])}):
            with unittest.mock.patch.object(compare, "_group_members",
                                            return_value={"someone-else"}):
                with self.assertRaises(SystemExit):
                    compare._psql_binary()

    def test_a_private_group_directory_is_accepted(self):
        import os as _os, tempfile, pathlib as _p
        directory = tempfile.mkdtemp()
        _os.chmod(directory, 0o775)
        binary = _p.Path(directory, "psql")
        binary.write_text("#!/bin/sh\nexit 0\n")
        binary.chmod(0o755)
        import pwd as _pwd
        me = _pwd.getpwuid(_os.getuid()).pw_name
        with unittest.mock.patch.dict("os.environ",
                                      {"PATH": "%s:%s" % (directory, _os.environ["PATH"])}):
            with unittest.mock.patch.object(compare, "_group_members",
                                            return_value={me, "root"}):
                self.assertEqual(compare._psql_binary(), os.path.realpath(str(binary)))

    def test_unknown_group_membership_is_treated_as_shared(self):
        """A group this cannot enumerate is not one to vouch for."""
        import os as _os, tempfile, pathlib as _p
        directory = tempfile.mkdtemp()
        _os.chmod(directory, 0o775)
        binary = _p.Path(directory, "psql")
        binary.write_text("#!/bin/sh\nexit 0\n")
        binary.chmod(0o755)
        with unittest.mock.patch.dict("os.environ",
                                      {"PATH": "%s:%s" % (directory, _os.environ["PATH"])}):
            with unittest.mock.patch.object(compare, "_group_members", return_value=None):
                with self.assertRaises(SystemExit):
                    compare._psql_binary()

    def test_an_explicit_path_must_still_be_absolute_and_executable(self):
        clean = _a_psql()
        self.assertEqual(compare._psql_binary(clean), os.path.realpath(clean))
        for bad in ("relative/psql", "/nonexistent/psql"):
            with self.subTest(path=bad):
                with self.assertRaises(SystemExit):
                    compare._psql_binary(bad)

    def test_an_explicit_path_is_checked_like_any_other(self):
        """Naming a binary must not be a way to skip the checks: the documented
        workaround would otherwise be the one route with no integrity checking."""
        import os as _os, tempfile, pathlib as _p
        directory = tempfile.mkdtemp()
        binary = _p.Path(directory, "psql")
        binary.write_text("#!/bin/sh\nexit 0\n")
        binary.chmod(0o777)
        with self.assertRaises(SystemExit) as e:
            compare._psql_binary(str(binary))
        self.assertIn("--allow-shared-psql", str(e.exception))

    def test_a_shared_psql_runs_only_when_explicitly_accepted(self):
        import os as _os, tempfile, pathlib as _p
        directory = tempfile.mkdtemp()
        binary = _p.Path(directory, "psql")
        binary.write_text("#!/bin/sh\nexit 0\n")
        binary.chmod(0o777)
        with unittest.mock.patch.object(compare, "ACCEPT_SHARED_PSQL", True):
            self.assertEqual(compare._psql_binary(str(binary)),
                             os.path.realpath(str(binary)))

    def test_psql_is_resolved_to_an_absolute_path(self):
        """A writable directory earlier on PATH would otherwise receive every row.
        Uses a controlled tree: how a distribution packages psql is not this test's
        subject, and Debian resolves it through a wrapper in a different prefix."""
        directory = self._psql_at(0o755, 0o755)
        self.assertTrue(os.path.isabs(self._resolve_with(directory)))

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


class TestTheOutputCannotBeSiphoned(unittest.TestCase):
    """Owner-only permissions and a symlink check do not stop a pipe. Anything opened
    for the scan or the report has to be a regular file, checked on the descriptor so
    nothing can be swapped in after the look."""

    def _fifo(self):
        import os as _os, tempfile
        from pathlib import Path
        path = Path(tempfile.mkdtemp()) / "out.json"
        _os.mkfifo(path)
        return path

    def test_the_scan_refuses_a_pipe(self):
        import subprocess, sys
        from tests.conftest import REPO
        target = self._fifo()
        r = subprocess.run(
            [sys.executable, str(REPO / ".claude/skills/identify-drift/scan_local.py"),
             "--tools", "claude-code", "--days", "1", "--out", str(target)],
            capture_output=True, text=True, timeout=300)
        self.assertNotEqual(r.returncode, 0)

    def test_the_report_refuses_a_pipe(self):
        import json as _json, subprocess, sys, tempfile
        from pathlib import Path
        from tests.conftest import REPO
        work = Path(tempfile.mkdtemp())
        (work / "local.json").write_text(_json.dumps(
            {"since": "2026-08-01T00:00:00+00:00", "days": 3, "tools": {}}))
        fake = work / "psql"
        fake.write_text("#!/bin/sh\necho '[]'\n")
        fake.chmod(0o755)
        target = self._fifo()
        r = subprocess.run(
            [sys.executable, str(REPO / ".claude/skills/identify-drift/compare.py"),
             "--local", str(work / "local.json"), "--email", "a@b.c",
             "--environment", "development", "--out", str(target)],
            capture_output=True, text=True, timeout=120,
            env={"PATH": "%s:/usr/bin:/bin" % work, "HOME": str(work),
                 "IDENTIFY_DRIFT_DSN": "postgres://u@127.0.0.1:5432/d"})
        self.assertNotEqual(r.returncode, 0)

    def test_a_pipe_with_no_reader_fails_rather_than_waiting(self):
        """Opening one for writing otherwise blocks until somebody reads, which would
        hang the run instead of ending it."""
        import subprocess, sys
        from tests.conftest import REPO
        target = self._fifo()
        r = subprocess.run(
            [sys.executable, str(REPO / ".claude/skills/identify-drift/scan_local.py"),
             "--tools", "claude-code", "--days", "1", "--out", str(target)],
            capture_output=True, text=True, timeout=120)
        self.assertNotEqual(r.returncode, 0)


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


class TestEveryFindingCanBeRendered(unittest.TestCase):
    """The report format needs a title, a where, an evidence and a why from every
    finding. A new one missing a field renders as a blank line in front of a human."""

    REQUIRED = ("title", "where", "evidence", "why")

    def _states(self):
        import itertools
        for ids, trunc, saturated, present, usage in itertools.product(
                (True, False), ([], ["prompts"]), (False, True), (True, False),
                ("usage", "usage_total")):
            t = [rec("user_prompt", text="a"), rec("assistant_message", text="b"),
                 rec("tool_call", tool="Bash", call_id="c1"),
                 rec(usage, input=100, output=50)]
            a = [rec("user_prompt", text="c"), rec("tool_call", tool="Bash", call_id="c2")]
            loc = local(t, a, audit_log_present=present,
                        audit_entries=100 if saturated else 5)
            yield loc, db(metrics_rows=50, input_tokens=999999, output_tokens=1,
                          threads=("S1",), tool_counts={"Write": 3},
                          call_ids=("zzz",), ids_are_representative=ids,
                          user_texts=(), assistant_texts=(), truncated=trunc)

    def test_no_finding_is_missing_a_field(self):
        seen = set()
        for loc, d in self._states():
            for finding in compare.compare("claude-code", loc, d, 14, d):
                seen.add(finding["title"])
                for field in self.REQUIRED:
                    self.assertTrue(str(finding.get(field, "")).strip(),
                                    "%r has no %s" % (finding.get("title"), field))
        self.assertGreaterEqual(len(seen), 12, "expected the states to exercise more")


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


def _a_psql():
    """A binary the integrity checks accept, built here rather than borrowed from the
    machine: how this host's PATH is owned is not the subject of those tests."""
    import os as _os, tempfile, pathlib as _p
    directory = tempfile.mkdtemp()
    _os.chmod(directory, 0o700)
    binary = _p.Path(directory, "psql")
    binary.write_text("#!/bin/sh\nexit 0\n")
    binary.chmod(0o755)
    return str(binary)


if __name__ == "__main__":
    unittest.main()
