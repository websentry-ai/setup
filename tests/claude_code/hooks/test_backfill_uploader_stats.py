"""Every backfill upload reports what the walk saw and what it had to leave behind, so the size cap can be set
from real file sizes: transcripts seen, those over the cap (count, largest, total bytes), and unreadable ones."""

import io
import json
import os
import shutil
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest import mock
from unittest.mock import patch

from tests.conftest import tool_module

mdm = tool_module("claude-code/hooks/mdm", "setup")
setup = tool_module("claude-code/hooks", "setup")


def _fake_http(bodies):
    def http(url, method, headers, body=None, timeout=30):
        if url.endswith("/upload-url/"):
            return 200, json.dumps({"upload_url": "https://s3/put", "object_key": "k"}).encode()
        if method == "PUT":
            bodies.append(json.loads(body.decode("utf-8")))
        return 200, b"{}"
    return http


def _patches(up, bodies):
    return [patch.object(up, "_backfill_http_request", side_effect=_fake_http(bodies)),
            patch.object(up, "_backfill_force_config", return_value=(None, None)),
            patch.object(up, "_backfill_account_email", return_value=None),
            patch.object(up, "get_device_identifier", return_value="SERIAL"),
            patch.object(up, "BACKFILL_MAX_FILE_BYTES", 1000),
            redirect_stdout(io.StringIO())]


def _run(up, home, more=()):
    """The real run_backfill of either uploader, the network faked at the HTTP layer; returns the uploaded bodies."""
    bodies = []
    stack = _patches(up, bodies)
    if up is mdm:
        stack.append(patch.object(mdm, "_run_as_user", side_effect=lambda u, fn, *a, **k: fn(*a, **k)))
    else:
        stack.append(patch.object(setup.Path, "home", return_value=home))
    for ctx in stack:
        ctx.__enter__()
    try:
        if up is mdm:
            mdm.run_backfill("key", "https://backend", [("alice", home)] + list(more))
        else:
            setup.run_backfill("key", "https://backend", home / ".claude")
    finally:
        for ctx in reversed(stack):
            ctx.__exit__(None, None, None)
    return bodies


class UploaderStatsTestCase(unittest.TestCase):

    def _home(self):
        home = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, home)
        projects = home / ".claude" / "projects" / "p"
        projects.mkdir(parents=True)
        return home, projects

    def _populated_home(self):
        home, projects = self._home()
        for name in ("a", "b"):
            (projects / f"{name}.jsonl").write_text(json.dumps({"type": "user", "sessionId": name}) + "\n")
        (projects / "big1.jsonl").write_text(json.dumps({"sessionId": "big1", "pad": "x" * 5000}) + "\n")
        (projects / "big2.jsonl").write_text(json.dumps({"sessionId": "big2", "pad": "x" * 9000}) + "\n")
        (projects / "nosession.jsonl").write_text(json.dumps({"type": "summary"}) + "\n")
        (projects / "garbage.jsonl").write_bytes(b"\xff\xfe\x00 not utf-8\n")
        # Not transcripts of their own, so never counted.
        (projects / ".hidden.jsonl").write_text(json.dumps({"sessionId": "h"}) + "\n")
        (projects / "a" / "subagents").mkdir(parents=True)
        (projects / "a" / "subagents" / "agent-x.jsonl").write_text(json.dumps({"sessionId": "a"}) + "\n")
        self.big = sorted(len((projects / n).read_bytes()) for n in ("big1.jsonl", "big2.jsonl"))
        return home

    def _expected(self, seen):
        return {"files_seen": seen, "unreadable": 2,
                "skipped_over_cap": {"count": 2, "largest_bytes": self.big[1], "total_bytes": sum(self.big)}}

    def test_every_standalone_upload_reports_what_was_seen_and_left_behind(self):
        bodies = _run(setup, self._populated_home())
        self.assertEqual(sorted(s["session_id"] for b in bodies for s in b["sessions"]), ["a", "b"])
        for body in bodies:
            self.assertEqual(set(body), {"tool_type", "sessions", "uploader_stats"})
            self.assertEqual(body["uploader_stats"], self._expected(6))

    def test_mdm_uploads_first_then_sends_the_counts_once(self):
        bodies = _run(mdm, self._populated_home())
        *uploads, counts = bodies
        self.assertEqual(sorted(s["session_id"] for b in uploads for s in b["sessions"]), ["a", "b"])
        self.assertTrue(all("uploader_stats" not in b for b in uploads))
        self.assertEqual((counts["sessions"], counts["uploader_stats"]), ([], self._expected(6)))

    def test_mdm_skips_the_count_when_the_run_is_out_of_time(self):
        # Time for the one batch this home needs, none left for the count.
        with patch.object(mdm._BackfillRun, "has_time_for_a_batch", side_effect=[True, False]):
            bodies = _run(mdm, self._populated_home())
        self.assertTrue(bodies)
        self.assertTrue(all("uploader_stats" not in b for b in bodies))

    def test_mdm_counts_every_profile_of_the_run(self):
        other, projects = self._home()
        (projects / "c.jsonl").write_text(json.dumps({"type": "user", "sessionId": "c"}) + "\n")
        bodies = _run(mdm, self._populated_home(), more=[("bob", other)])
        self.assertEqual(bodies[-1]["uploader_stats"], self._expected(7))

    def test_a_run_that_only_skips_still_reports_its_counts(self):
        for up in (mdm, setup):
            with self.subTest(up.__name__):
                home, projects = self._home()
                (projects / "big.jsonl").write_text(json.dumps({"sessionId": "big", "pad": "x" * 5000}) + "\n")
                bodies = _run(up, home)
                self.assertEqual([b["sessions"] for b in bodies], [[]])
                self.assertEqual(bodies[0]["uploader_stats"]["skipped_over_cap"]["count"], 1)

    def test_a_run_with_nothing_skipped_and_nothing_to_send_uploads_nothing(self):
        for up in (mdm, setup):
            with self.subTest(up.__name__):
                home, _ = self._home()
                self.assertEqual(_run(up, home), [])

    def test_unreadable_counts_the_files_the_collector_drops(self):
        for up in (mdm, setup):
            with self.subTest(up.__name__):
                home, projects = self._home()
                (projects / "array-first.jsonl").write_text("[1, 2]\n" + json.dumps({"sessionId": "x"}) + "\n")
                (projects / "late-id.jsonl").write_text("{}\n" * 6 + json.dumps({"sessionId": "y"}) + "\n")
                with patch.object(up, "BACKFILL_MAX_LINES_PER_FILE", 5):
                    stats = up._backfill_walk_stats(home / ".claude" / "projects")
                    dropped = [p.name for p in sorted(projects.iterdir()) if up._backfill_collect_session(p) is None]
                self.assertEqual(stats["unreadable"], len(dropped))
                self.assertEqual(stats["unreadable"], 2)

    def test_mdm_counts_nothing_for_a_profile_it_refuses(self):
        home = self._populated_home()
        (home / ".claude" / "hooks").mkdir()
        hooks, real_lstat = str(home / ".claude" / "hooks"), os.lstat

        def lstat(path, *args, **kwargs):
            result = real_lstat(path, *args, **kwargs)
            # A junction's reparse tag, as Windows reports it, on the profile's hooks folder.
            return mock.Mock(wraps=result, st_reparse_tag=0xA0000003, st_mode=result.st_mode) if str(path) == hooks else result
        with patch("os.lstat", side_effect=lstat), patch.object(mdm.platform, "system", return_value="Windows"):
            self.assertEqual(mdm._backfill_home_stats(home), mdm._backfill_empty_stats())

    def test_the_size_cap_is_unchanged(self):
        self.assertEqual((mdm.BACKFILL_MAX_FILE_BYTES, setup.BACKFILL_MAX_FILE_BYTES), (50 * 1024 * 1024,) * 2)


if __name__ == "__main__":
    unittest.main()
