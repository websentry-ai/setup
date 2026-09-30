import unittest
import unittest.mock
from unittest.mock import patch
import io
import json
import os
import shutil
import socket
import subprocess
import tempfile
import threading
import urllib.request
import urllib.error
import urllib.parse
import time
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path

from tests.conftest import tool_module

setup = tool_module("claude-code/hooks", "setup")


class TestCallbackHandler(unittest.TestCase):
    """Tests for the CallbackHandler inside run_callback_server.

    These tests exercise the real run_callback_server function by mocking
    webbrowser.open to intercept the URL, then sending an HTTP request
    to the actual server it spins up.
    """

    def _run_server_with_query(self, query_string):
        """Call run_callback_server, intercept its URL, hit it with query_string.

        Returns (http_status, response_body, result_dict).
        """
        run_callback_server = setup.run_callback_server
        captured_url = {}
        http_response = {}

        def fake_browser_open(url):
            """Instead of opening a browser, parse the callback_url and hit it."""
            parsed = urllib.parse.urlparse(url)
            qs = dict(urllib.parse.parse_qsl(parsed.query))
            callback_url = qs.get("callback_url", "")
            target = f"{callback_url}?{query_string}"
            captured_url["target"] = target

            # Small delay to let the server finish binding
            time.sleep(0.05)

            try:
                # Bounded: an unanswered loopback exchange would otherwise hang the
                # test thread past the server's own wait, and CI with it.
                resp = urllib.request.urlopen(target, timeout=30)
                http_response["code"] = resp.getcode()
                http_response["body"] = resp.read().decode()
            except urllib.error.HTTPError as e:
                http_response["code"] = e.code
                http_response["body"] = e.read().decode()

        with patch("webbrowser.open", side_effect=fake_browser_open):
            result = run_callback_server("https://example.com")

        return http_response.get("code"), http_response.get("body", ""), result

    def test_success_returns_200(self):
        """CallbackHandler returns 200 on success (no error param)."""
        code, body, result = self._run_server_with_query("api_key=abc123")
        self.assertEqual(code, 200)
        self.assertIn("Logged in successfully", body)
        self.assertEqual(result["query"]["api_key"], "abc123")

    def test_error_returns_400(self):
        """CallbackHandler returns 400 with error message when error param present."""
        code, body, result = self._run_server_with_query("error=something+went+wrong")
        self.assertEqual(code, 400)
        self.assertIn("Setup failed: something went wrong", body)

    def test_error_truncated_to_200_chars(self):
        """Error message in HTTP response is truncated to 200 characters."""
        long_error = "x" * 300
        code, body, _ = self._run_server_with_query(f"error={long_error}")
        self.assertEqual(code, 400)
        self.assertIn("x" * 200, body)
        self.assertNotIn("x" * 201, body)


class TestMainErrorHandling(unittest.TestCase):
    """Tests for error display in main()."""

    def _run_main_with_callback(self, query):
        """Run main() with a mocked callback response and capture stdout."""
        pass  # module loaded at import time
        import sys
        from io import StringIO

        with patch.object(setup, "run_callback_server") as mock_server, \
             patch.object(setup, "install_macos_certificates"), \
             patch.object(setup, "check_enterprise_hooks_conflict", return_value=False):
            mock_server.return_value = {
                "method": "GET",
                "path": "/callback",
                "query": query,
                "headers": {},
                "body": None,
            }

            old_argv = sys.argv
            sys.argv = ["setup.py", "--domain", "example.com"]
            captured = StringIO()
            old_stdout = sys.stdout
            sys.stdout = captured
            try:
                setup.main()
            finally:
                sys.stdout = old_stdout
                sys.argv = old_argv

        return captured.getvalue()

    def test_main_prints_specific_error(self):
        """main() prints specific error when callback has error param."""
        output = self._run_main_with_callback({"error": "token expired"})
        self.assertIn("Setup failed: token expired", output)

    def test_ansi_stripped_from_terminal_output(self):
        """ANSI escape sequences are stripped from terminal error output."""
        output = self._run_main_with_callback({"error": "\x1b[31mred error\x1b[0m"})
        self.assertNotIn("\x1b", output)
        self.assertIn("red error", output)

    def test_error_truncated_in_terminal(self):
        """Error message displayed in terminal is truncated to 200 chars."""
        long_error = "A" * 300
        output = self._run_main_with_callback({"error": long_error})
        self.assertIn("A" * 200, output)
        self.assertNotIn("A" * 201, output)

    def test_cb_response_error_without_guard(self):
        """Error path works when cb_response is non-None with no api_key.

        Validates that removing the redundant 'if cb_response else None'
        guard does not break error extraction -- cb_response is guaranteed
        non-None at that point because line 543-545 returns early if None.
        """
        output = self._run_main_with_callback({"error": "access denied"})
        self.assertIn("Setup failed: access denied", output)
        self.assertNotIn("No API key received", output)


class TestBackfillCutoffCache(unittest.TestCase):
    """Tests for the per-tool last-backfill cache that lets cron reruns seed only
    sessions touched since the previous run instead of the full 30-day window."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.home = Path(self._tmp.name)
        self.addCleanup(self._tmp.cleanup)

    def test_read_cutoff_defaults_to_max_age_when_no_file(self):
        """No cache file -> fall back to BACKFILL_MAX_AGE_DAYS ago (first run)."""
        pass  # module loaded at import time
        cutoff = setup._backfill_read_cutoff(self.home)
        expected = time.time() - (setup.BACKFILL_MAX_AGE_DAYS * 86400)
        self.assertAlmostEqual(cutoff, expected, delta=5)

    def test_write_then_read_roundtrip(self):
        """A persisted timestamp is read back as the cutoff on the next run."""
        pass  # module loaded at import time
        ts = time.time() - 3600
        setup._backfill_write_cutoff(self.home, ts)
        self.assertTrue(setup._backfill_state_path(self.home).exists())
        self.assertAlmostEqual(setup._backfill_read_cutoff(self.home), ts, delta=0.01)

    def test_read_cutoff_ignores_corrupt_value(self):
        """A non-numeric cache file falls back to the default window."""
        pass  # module loaded at import time
        path = setup._backfill_state_path(self.home)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("not-a-number")
        expected = time.time() - (setup.BACKFILL_MAX_AGE_DAYS * 86400)
        self.assertAlmostEqual(setup._backfill_read_cutoff(self.home), expected, delta=5)

    def test_read_cutoff_ignores_future_timestamp(self):
        """A future timestamp (clock skew) is rejected for the default window."""
        pass  # module loaded at import time
        setup._backfill_write_cutoff(self.home, time.time() + 10000)
        expected = time.time() - (setup.BACKFILL_MAX_AGE_DAYS * 86400)
        self.assertAlmostEqual(setup._backfill_read_cutoff(self.home), expected, delta=5)

    def test_iter_transcripts_respects_cutoff(self):
        """Only transcripts modified at/after the cutoff are yielded."""
        pass  # module loaded at import time
        root = self.home / ".claude" / "projects"
        root.mkdir(parents=True)
        old = root / "old.jsonl"
        new = root / "new.jsonl"
        old.write_text("{}\n")
        new.write_text("{}\n")
        now = time.time()
        os.utime(old, (now - 10 * 86400, now - 10 * 86400))
        os.utime(new, (now - 1 * 86400, now - 1 * 86400))

        cutoff = now - (5 * 86400)
        found = {p.name for p in setup._backfill_iter_transcripts(root, cutoff)}
        self.assertEqual(found, {"new.jsonl"})

    def test_write_is_atomic_and_leaves_no_temp(self):
        """The atomic write produces the final file and no leftover .tmp."""
        pass  # module loaded at import time
        setup._backfill_write_cutoff(self.home, 123.0)
        path = setup._backfill_state_path(self.home)
        self.assertEqual(path.read_text(), "123.0")
        self.assertEqual(list(path.parent.glob("*.tmp")), [])

    def test_cutoff_not_advanced_when_session_cap_fires(self):
        """When the per-run session cap is hit, the cutoff must NOT advance, or
        the unprocessed older files would be skipped forever next run."""
        pass  # module loaded at import time
        root = self.home / ".claude" / "projects"
        root.mkdir(parents=True)
        for i in range(3):
            (root / f"s{i}.jsonl").write_text('{"sessionId":"x%d"}\n' % i)
        with patch.object(setup, "BACKFILL_MAX_SESSIONS_PER_RUN", 2), \
             patch.object(setup, "_backfill_upload_chunk", return_value=True), \
             patch.object(Path, "home", return_value=self.home):
            setup.run_backfill("key", "https://backend")
        self.assertFalse(setup._backfill_state_path(self.home).exists())


class TestMdmBackfillCutoff(unittest.TestCase):
    """Tests for the multi-user MDM run_backfill: a user's cutoff must advance
    only when that user's transcripts were actually collected, so a failed
    privilege-drop never strands their history behind an advanced cutoff."""

    @staticmethod
    def _load_mdm():
        return tool_module("claude-code/hooks/mdm", "setup")

    def _run(self, mdm, collect_by_home, send_result):
        """Run run_backfill with _run_as_user mocked; return list of homes
        whose cutoff was written."""
        writes = []

        def fake_run_as_user(username, fn, *args):
            if fn is mdm._backfill_collect_sessions:
                return collect_by_home[args[0]]
            if fn is mdm._backfill_write_cutoff:
                writes.append(args[0])
            return None

        homes = [(f"u{i}", home) for i, home in enumerate(collect_by_home)]
        with patch.object(mdm, "_run_as_user", side_effect=fake_run_as_user), \
             patch.object(mdm, "_backfill_force_config", return_value=(None, None)), \
             patch.object(mdm, "_backfill_send_sessions", return_value=send_result):
            mdm.run_backfill("key", "https://backend", homes)
        return writes

    def test_failed_home_cutoff_not_advanced(self):
        """Collection returning None (fork/perms failure) -> no cutoff write."""
        mdm = self._load_mdm()
        good, bad = Path("/home/good"), Path("/home/bad")
        # good: collected, empty, not capped; bad: collection failed (None)
        writes = self._run(mdm, {good: ([], False, False), bad: None}, send_result=(0, 0, 0))
        self.assertIn(good, writes)
        self.assertNotIn(bad, writes)

    def test_collected_homes_advanced_on_success(self):
        """Full upload success -> cutoff written for every collected home."""
        mdm = self._load_mdm()
        home = Path("/home/alice")
        writes = self._run(
            mdm,
            {home: ([{"session_id": "s1", "entries": [{}]}], False, False)},
            send_result=(1, 1, 0),
        )
        self.assertEqual(writes, [home])

    def test_partial_upload_failure_does_not_advance(self):
        """A failed chunk -> no cutoff write, so the next cron retries."""
        mdm = self._load_mdm()
        home = Path("/home/alice")
        writes = self._run(
            mdm,
            {home: ([{"session_id": "s1", "entries": [{}]}], False, False)},
            send_result=(1, 0, 1),  # one chunk failed
        )
        self.assertEqual(writes, [])

    def test_capped_home_not_advanced(self):
        """A home that hit the per-run cap -> its cutoff is not advanced even on
        a fully successful upload, so its overflow stays eligible next run."""
        mdm = self._load_mdm()
        capped_home, ok_home = Path("/home/heavy"), Path("/home/light")
        writes = self._run(
            mdm,
            {
                capped_home: ([{"session_id": "s1", "entries": [{}]}], True, False),
                ok_home: ([{"session_id": "s2", "entries": [{}]}], False, False),
            },
            send_result=(2, 1, 0),
        )
        self.assertEqual(writes, [ok_home])

    def test_capped_home_advances_to_its_resume_point(self):
        """A capped batch that reports where it stopped -> that home's cutoff moves to
        the resume mtime (not to now) once its upload lands, and the next batch
        continues from there instead of re-reading the same slice forever."""
        mdm = self._load_mdm()
        heavy = Path("/home/heavy")
        writes = []
        batches = iter([
            ([{"session_id": "s1", "entries": [{}]}], (1234.5, "t1"), False),
            ([{"session_id": "s2", "entries": [{}]}], False, False),
        ])

        def fake_run_as_user(username, fn, *args):
            if fn is mdm._backfill_collect_sessions:
                return next(batches)
            if fn is mdm._backfill_write_progress:
                writes.append(args[:2])
            if fn is mdm._backfill_write_cutoff:
                writes.append(args)
            return None

        with patch.object(mdm, "_run_as_user", side_effect=fake_run_as_user), \
             patch.object(mdm, "_backfill_force_config", return_value=(None, None)), \
             patch.object(mdm, "_backfill_send_sessions", return_value=(1, 1, 0)):
            mdm.run_backfill("key", "https://backend", [("heavy", heavy)])
        self.assertEqual(writes[0], (heavy, 1234.5))
        self.assertEqual(len(writes), 2)
        self.assertGreater(writes[1][1], 1234.5)


class TestMdmBackfillByteBudget(unittest.TestCase):
    """The collector holds every session in memory before upload, so one batch must
    stop at a byte budget. A heavy profile otherwise grew the MDM process to ~17 GB
    and outlived onboard's timeout every day."""

    def setUp(self):
        self.mdm = tool_module("claude-code/hooks/mdm", "setup")
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp)
        projects = self.tmp / ".claude" / "projects" / "p"
        projects.mkdir(parents=True)
        now = time.time()
        self.mtimes, self.paths = {}, {}
        # Written newest-name-first so path order and mtime order disagree.
        for i, name in enumerate(["c.jsonl", "b.jsonl", "a.jsonl"]):
            path = projects / name
            line = json.dumps({"sessionId": name, "type": "user", "pad": "x" * 1000})
            path.write_text(line + "\n")
            mtime = now - 3600 * (3 - i)
            os.utime(path, (mtime, mtime))
            self.mtimes[name] = mtime
            self.paths[name] = str(path)

    def _collect(self, budget):
        with patch.object(self.mdm, "BACKFILL_BATCH_BYTES", budget), \
             patch.object(self.mdm, "_backfill_account_email", return_value=None):
            return self.mdm._backfill_collect_sessions(self.tmp)

    def test_budget_stops_oldest_first_and_reports_resume_point(self):
        sessions, capped, _ = self._collect(budget=2500)
        self.assertEqual([s["session_id"] for s in sessions], ["c.jsonl", "b.jsonl"])
        self.assertEqual(capped, (self.mtimes["b.jsonl"], self.paths["b.jsonl"]))

    def test_under_budget_is_not_capped(self):
        sessions, capped, _ = self._collect(budget=10 ** 9)
        self.assertEqual(len(sessions), 3)
        self.assertIs(capped, False)

    def test_one_file_over_budget_is_still_read(self):
        """A single transcript larger than the budget must not stall the home."""
        sessions, capped, _ = self._collect(budget=10)
        self.assertEqual([s["session_id"] for s in sessions], ["c.jsonl"])
        self.assertEqual(capped, (self.mtimes["c.jsonl"], self.paths["c.jsonl"]))


class TestMdmBackfillBatches(unittest.TestCase):
    """run_backfill collects and uploads one bounded batch at a time and saves each
    home's progress after every upload, so a heavy history drains across batches and
    runs instead of restarting from zero whenever the MDM timeout kills it."""

    def setUp(self):
        self.mdm = tool_module("claude-code/hooks/mdm", "setup")

    def _run(self, batches_by_user, send=None, force=(None, None)):
        """Run run_backfill with privilege-drop, force config and upload faked.
        Returns (events, start_mtimes, stdout): events is the ordered list of
        ("send", user, ids, forced) and ("write", user, ts)."""
        mdm = self.mdm
        events, starts = [], []
        batches = {u: iter(b) for u, b in batches_by_user.items()}

        def fake_run_as_user(username, fn, *args):
            if fn is mdm._backfill_collect_sessions:
                starts.append((username, args[3]))
                return next(batches[username])
            if fn in (mdm._backfill_write_cutoff, mdm._backfill_write_progress):
                events.append(("write", username, args[1]))
            return None

        def fake_send(api_key, backend_url, sessions, forced=False):
            owner = sessions[0]["session_id"].split("-")[0]
            events.append(("send", owner, [s["session_id"] for s in sessions], forced))
            return send(sessions) if send else (len(sessions), 1, 0)

        homes = [(u, Path(f"/home/{u}")) for u in batches_by_user]
        out = io.StringIO()
        with patch.object(mdm, "_run_as_user", side_effect=fake_run_as_user), \
             patch.object(mdm, "_backfill_force_config", return_value=force), \
             patch.object(mdm, "_backfill_send_sessions", side_effect=fake_send), \
             patch.object(mdm, "get_device_identifier", return_value="SERIAL"), \
             redirect_stdout(out):
            mdm.run_backfill("key", "https://backend", homes)
        return events, starts, out.getvalue()

    @staticmethod
    def _batch(ids, capped, forced=False):
        if isinstance(capped, float):
            capped = (capped, f"p{capped}")
        return ([{"session_id": i, "entries": [{}]} for i in ids], capped, forced)

    def test_heavy_home_drains_in_one_run_saving_progress_after_each_upload(self):
        before = time.time()
        events, starts, out = self._run({"a": [
            self._batch(["a-1"], 100.0),
            self._batch(["a-2"], 200.0),
            self._batch(["a-3"], False),
        ]})
        self.assertEqual(events[:5], [
            ("send", "a", ["a-1"], False), ("write", "a", 100.0),
            ("send", "a", ["a-2"], False), ("write", "a", 200.0),
            ("send", "a", ["a-3"], False),
        ])
        # The last batch finishes the home: cutoff = when this run started, not a file mtime.
        self.assertEqual(events[5][:2], ("write", "a"))
        self.assertGreaterEqual(events[5][2], before)
        self.assertEqual(starts, [("a", None), ("a", (100.0, "p100.0")), ("a", (200.0, "p200.0"))])
        self.assertIn("Queued 3 sessions in 3 batches.", out)
        self.assertNotIn("More history remains", out)

    def test_failed_batch_stops_that_home_only_and_keeps_its_last_good_cutoff(self):
        events, _, out = self._run(
            {
                "a": [self._batch(["a-1"], 100.0), self._batch(["a-2"], 200.0)],
                "b": [self._batch(["b-1"], False)],
            },
            send=lambda s: (0, 0, 1) if s[0]["session_id"] == "a-2" else (1, 1, 0),
        )
        writes = [e for e in events if e[0] == "write"]
        self.assertEqual(writes[0], ("write", "a", 100.0))
        self.assertEqual([w[1] for w in writes], ["a", "b"])
        self.assertIn(("send", "b", ["b-1"], False), events)
        self.assertIn("Some uploads failed", out)

    def test_soft_deadline_stops_cleanly_at_the_last_saved_batch(self):
        mdm = self.mdm
        # The first upload runs past the soft stop: no further batch may start.
        def slow_send(sessions):
            mdm._SCRIPT_START -= mdm.BACKFILL_SOFT_STOP_SECONDS
            return len(sessions), 1, 0

        with patch.object(mdm, "_SCRIPT_START", time.time()):
            events, starts, out = self._run(
                {"a": [self._batch(["a-1"], 100.0), self._batch(["a-2"], False)],
                 "b": [self._batch(["b-1"], False)]},
                send=slow_send,
            )
        self.assertEqual(events, [("send", "a", ["a-1"], False), ("write", "a", 100.0)])
        self.assertEqual(starts, [("a", None)])
        self.assertIn("Queued 1 sessions in 1 batches.", out)
        self.assertIn("More history remains and will continue on the next run.", out)

    def test_files_sharing_an_mtime_past_the_budget_still_make_progress(self):
        """Real files: three transcripts share one mtime and together exceed the batch
        budget. The (mtime, path) cursor advances through the tie file by file, so
        ties of any size drain across bounded batches."""
        mdm = self.mdm
        home = _transcript_home(self, [("t1", 5, 60), ("t2", 5, 60), ("t3", 5, 60), ("t4", 4, 60)])
        uploads = _drain_real_home(self, home, batch_bytes=200)
        self.assertEqual(uploads, [(["t1"], False), (["t2"], False), (["t3"], False), (["t4"], False)])
        state = mdm._backfill_read_state(home)
        self.assertIsNone(state["cursor"])
        self.assertIsNotNone(state["completed_at"])

    def test_a_tie_cut_short_resumes_mid_tie_on_the_next_run(self):
        """Run 1 stops inside a shared-mtime group; run 2 resumes at the saved
        (mtime, path) position instead of re-reading or skipping the rest of the tie."""
        mdm = self.mdm
        home = _transcript_home(self, [("t1", 5, 60), ("t2", 5, 60), ("t3", 5, 60)])
        sent = {"n": 0}

        def stop_after_one(sessions):
            sent["n"] += 1
            if sent["n"] == 1:
                mdm._SCRIPT_START -= mdm.BACKFILL_SOFT_STOP_SECONDS
            return len(sessions), 1, 0

        with patch.object(mdm, "_SCRIPT_START", time.time()):
            run1 = _drain_real_home(self, home, batch_bytes=1, send=stop_after_one)
        self.assertEqual(run1, [(["t1"], False)])
        with patch.object(mdm, "_SCRIPT_START", time.time()):
            run2 = _drain_real_home(self, home, batch_bytes=1)
        self.assertEqual(run2, [(["t2"], False), (["t3"], False)])
        self.assertIsNone(mdm._backfill_read_state(home)["cursor"])

    def test_a_config_miss_does_not_clear_a_mid_walk_force_latch(self):
        """A forced walk cut short must stay forced when the next run's config fetch
        returns nothing: the walk finishes under the stored request, whose flag the
        server validates anyway."""
        mdm = self.mdm
        home = _transcript_home(self, [("s20", 20, 60), ("s10", 10, 60), ("s5", 5, 60)])
        epoch = time.time() - 86400
        s20 = home / ".claude" / "projects" / "p" / "s20.jsonl"
        mdm._backfill_write_progress(home, s20.stat().st_mtime, epoch, str(s20))

        uploads = _drain_real_home(self, home, batch_bytes=1, force=(None, None))
        self.assertEqual(uploads, [(["s10"], True), (["s5"], True)])
        state = mdm._backfill_read_state(home)
        self.assertIsNone(state["cursor"])
        self.assertIsNotNone(state["completed_at"])

    def test_a_future_dated_transcript_waits_without_pinning_the_walk(self):
        """A transcript with an mtime ahead of the clock is left for a later run —
        uploaded once the clock passes it, never re-uploaded in a loop meanwhile."""
        mdm = self.mdm
        home = _transcript_home(self, [("t1", 5, 60)])
        future = home / ".claude" / "projects" / "p" / "future.jsonl"
        future.write_text(json.dumps({"sessionId": "future", "type": "user"}) + "\n")
        ahead = time.time() + 3600
        os.utime(future, (ahead, ahead))

        run1 = _drain_real_home(self, home, batch_bytes=1)
        self.assertEqual(run1, [(["t1"], False)])
        self.assertIsNone(mdm._backfill_read_state(home)["cursor"])

        caught_up = time.time()
        os.utime(future, (caught_up, caught_up))
        run2 = _drain_real_home(self, home, batch_bytes=1)
        self.assertEqual(run2, [(["future"], False)])

    def test_a_force_request_arriving_mid_run_stays_pending(self):
        """completed_at is stamped before the force config is fetched, so a request
        filed during the run reads as newer than the walk that missed it."""
        mdm = self.mdm
        home = _transcript_home(self, [("t1", 5, 60)])
        fetch_time = {}

        def config_fetch(api_key, backend_url):
            fetch_time["t"] = time.time()
            return (None, None)

        with patch.object(mdm, "_run_as_user", side_effect=lambda u, fn, *a, **k: fn(*a, **k)), \
             patch.object(mdm, "_backfill_force_config", side_effect=config_fetch), \
             patch.object(mdm, "_backfill_send_sessions", return_value=(1, 1, 0)), \
             patch.object(mdm, "_backfill_account_email", return_value=None), \
             patch.object(mdm, "get_device_identifier", return_value="SERIAL"), \
             redirect_stdout(io.StringIO()):
            mdm.run_backfill("key", "https://backend", [("alice", home)])
        completed = mdm._backfill_read_state(home)["completed_at"]
        self.assertLessEqual(completed, fetch_time["t"])
        # A request filed at fetch time therefore still reads as pending.
        position, forced = mdm._backfill_walk_start(
            mdm._backfill_read_state(home), fetch_time["t"], None)
        self.assertTrue(forced)

    def test_slowest_batch_sets_the_margin_before_the_soft_stop(self):
        """Each batch takes 100s on a fake clock: a new batch needs 1.5x that (150s)
        left, not just the 90s floor, so the batch that would end at 600s never starts."""
        mdm = self.mdm
        clock = {"now": 0.0}
        fake_time = type("T", (), {"time": staticmethod(lambda: clock["now"])})

        def slow_send(sessions):
            clock["now"] += 100
            return len(sessions), 1, 0

        batches = [self._batch([f"a-{i}"], float(i + 1)) for i in range(10)]
        with patch.object(mdm, "time", fake_time), patch.object(mdm, "_SCRIPT_START", 0.0):
            events, starts, out = self._run({"a": batches}, send=slow_send)
        self.assertEqual(len(starts), 5)  # batches start at 0, 100, 200, 300, 400s
        self.assertEqual(events[-1], ("write", "a", 5.0))
        self.assertIn("More history remains", out)

    def test_batch_cap_bounds_one_run(self):
        batches = [self._batch([f"a-{i}"], float(i + 1)) for i in range(10)]
        with patch.object(self.mdm, "BACKFILL_MAX_BATCHES_PER_HOME", 3):
            events, starts, out = self._run({"a": batches})
        self.assertEqual(len(starts), 3)
        self.assertEqual(events[-1], ("write", "a", 3.0))
        self.assertIn("More history remains", out)

    def test_forced_home_forces_every_batch_and_later_batches_do_not_rewiden(self):
        """Real transcripts on disk: batch 2+ reads from the resume point only (no
        re-read of the widened window), and keeps forcing even once its persisted
        cutoff has moved past the org's request."""
        mdm = self.mdm
        home = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, home)
        projects = home / ".claude" / "projects" / "p"
        projects.mkdir(parents=True)
        now = time.time()
        for name, days_ago in (("s20", 20), ("s10", 10), ("s5", 5), ("s3", 3)):
            path = projects / f"{name}.jsonl"
            path.write_text(json.dumps({"sessionId": name, "type": "user"}) + "\n")
            os.utime(path, (now - days_ago * 86400, now - days_ago * 86400))
        (home / ".claude" / "hooks").mkdir(parents=True)
        (home / ".claude" / "hooks" / mdm.BACKFILL_STATE_FILE).write_text(str(now - 7 * 86400))
        uploads = []

        def fake_send(api_key, backend_url, sessions, forced=False):
            uploads.append(([s["session_id"] for s in sessions], forced))
            return len(sessions), 1, 0

        with patch.object(mdm, "_run_as_user", side_effect=lambda u, fn, *a, **k: fn(*a, **k)), \
             patch.object(mdm, "_backfill_force_config", return_value=(now - 6 * 86400, 30)), \
             patch.object(mdm, "_backfill_send_sessions", side_effect=fake_send), \
             patch.object(mdm, "_backfill_account_email", return_value=None), \
             patch.object(mdm, "get_device_identifier", return_value="SERIAL"), \
             patch.object(mdm, "BACKFILL_BATCH_BYTES", 1), \
             redirect_stdout(io.StringIO()):
            mdm.run_backfill("key", "https://backend", [("alice", home)])
        self.assertEqual(uploads, [(["s20"], True), (["s10"], True), (["s5"], True), (["s3"], True)])
        state = mdm._backfill_read_state(home)
        self.assertIsNone(state["cursor"])
        self.assertGreaterEqual(state["completed_at"], now)

    def test_forced_walk_cut_short_resumes_next_run_instead_of_restarting(self):
        """Run 1 hits the soft stop after two batches. Run 2 must carry on from its
        cursor under the same request (still forced), not re-widen to the window and
        re-send the oldest history; run 3, after the walk finished, is not forced."""
        mdm = self.mdm
        home = _transcript_home(self, [("s20", 20, 60), ("s10", 10, 60), ("s5", 5, 60), ("s3", 3, 60)])
        force = (time.time() - 86400, 30)
        sent = {"n": 0}

        def stop_after_two(sessions):
            sent["n"] += 1
            if sent["n"] == 2:
                mdm._SCRIPT_START -= mdm.BACKFILL_SOFT_STOP_SECONDS
            return len(sessions), 1, 0

        with patch.object(mdm, "_SCRIPT_START", time.time()):
            run1 = _drain_real_home(self, home, batch_bytes=1, force=force, send=stop_after_two)
        self.assertEqual(run1, [(["s20"], True), (["s10"], True)])
        with patch.object(mdm, "_SCRIPT_START", time.time()):
            run2 = _drain_real_home(self, home, batch_bytes=1, force=force)
        self.assertEqual(run2, [(["s5"], True), (["s3"], True)])
        with patch.object(mdm, "_SCRIPT_START", time.time()):
            run3 = _drain_real_home(self, home, batch_bytes=1, force=force)
        self.assertEqual(run3, [])

    def _drain_with_failing_chunk(self, failing_call):
        """Real _backfill_send_sessions over one three-chunk batch (calls 1-3), resuming
        from a saved cursor at b1. Returns (calls, cursor, b1 mtime, stdout)."""
        mdm = self.mdm
        home = _transcript_home(self, [("b1", 5, 6000), ("b2", 4, 6000), ("b3", 4, 6000), ("b4", 4, 6000)])
        b1 = home / ".claude" / "projects" / "p" / "b1.jsonl"
        mdm._backfill_write_progress(home, b1.stat().st_mtime, None, str(b1))
        calls = []

        def fake_chunk(api_key, backend_url, sessions, forced=False):
            calls.append([s["session_id"] for s in sessions])
            return len(calls) != failing_call

        with patch.object(mdm, "_backfill_upload_chunk", side_effect=fake_chunk), \
             patch.object(mdm, "BACKFILL_CHUNK_BYTES", 10000):
            out = _drain_real_home(self, home, batch_bytes=30000, real_send=True)
        return calls, mdm._backfill_read_state(home)["cursor"], b1.stat().st_mtime, out

    def test_first_failed_chunk_stops_the_batch_and_keeps_the_previous_cursor(self):
        """Against a hung backend each chunk burns ~2 min of curl retries, so the rest
        of a failing batch is never attempted; the batch is retried whole next run."""
        calls, cursor, b1_mtime, out = self._drain_with_failing_chunk(failing_call=1)
        self.assertEqual(calls, [["b2"]])
        self.assertEqual(cursor, b1_mtime)
        self.assertIn("Some uploads failed", out)

    def test_a_later_failed_chunk_also_stops_the_batch(self):
        calls, cursor, b1_mtime, out = self._drain_with_failing_chunk(failing_call=2)
        self.assertEqual(calls, [["b2"], ["b3"]])
        self.assertEqual(cursor, b1_mtime)
        self.assertIn("Some uploads failed", out)

    def test_uploads_do_not_wait_for_100_continue(self):
        """curl's Expect: 100-continue wait on a stalled server surfaced as "HTTP 100"."""
        mdm = self.mdm
        with patch.object(mdm.subprocess, "run") as run:
            run.return_value = subprocess.CompletedProcess([], 0, b"\n200", b"")
            mdm._backfill_http_request("https://s3/put", "PUT", {}, body=b"{}")
        cmd = run.call_args[0][0]
        self.assertIn("Expect:", cmd)


class TestMdmBackfillProcessSafety(unittest.TestCase):
    """Backfill is best effort: nothing about starting or deprioritising it may
    raise out of setup or change its exit code."""

    def setUp(self):
        self.mdm = tool_module("claude-code/hooks/mdm", "setup")

    @unittest.skipIf(os.name == "nt", "fork path is POSIX only")
    def test_fork_failure_skips_backfill_without_raising(self):
        mdm = self.mdm
        err = io.StringIO()
        with patch.object(mdm, "_SCRIPT_START", time.time()), \
             patch.object(mdm.os, "fork", side_effect=OSError(11, "Resource temporarily unavailable")), \
             patch.object(mdm, "run_backfill", side_effect=AssertionError("must not run")), \
             redirect_stderr(err):
            mdm._run_backfill_bounded("key", "https://backend", [("a", Path("/home/a"))])
        self.assertIn("could not start", err.getvalue())

    def test_lowering_priority_never_raises_when_nice_fails(self):
        mdm = self.mdm
        with patch.object(mdm.os, "nice", side_effect=OSError("denied")) as nice, \
             patch.object(mdm.subprocess, "run", side_effect=AssertionError("no subprocess")):
            self.assertFalse(mdm._lower_backfill_priority())
        nice.assert_called_once_with(19)

    def test_windows_priority_path_never_raises_without_win32(self):
        mdm = self.mdm
        with patch.object(mdm.os, "name", "nt"):
            lowered = mdm._lower_backfill_priority()
        mdm._restore_backfill_priority(lowered)
        mdm._restore_backfill_priority(True)

    def _windows_priority(self, set_results):
        """Lower then restore on a faked Windows with a mocked kernel32; returns
        (lowered, kernel32 mock, SetThreadPriority modes, debug output)."""
        import ctypes
        mdm = self.mdm
        k32 = unittest.mock.MagicMock()
        k32.GetCurrentThread.return_value = 0xFFFFFFFFFFFFFFFE  # the pseudo-handle, -2
        k32.SetThreadPriority.side_effect = list(set_results)
        out = io.StringIO()
        with patch.object(mdm.os, "name", "nt"), patch.object(mdm, "DEBUG", True), \
             patch.object(ctypes, "WinDLL", return_value=k32, create=True) as windll, \
             patch.object(ctypes, "get_last_error", return_value=6, create=True), \
             redirect_stdout(out):
            lowered = mdm._lower_backfill_priority()
            mdm._restore_backfill_priority(lowered)
        windll.assert_called_with("kernel32", use_last_error=True)
        modes = [c.args[1] for c in k32.SetThreadPriority.call_args_list]
        return lowered, k32, modes, out.getvalue()

    def test_windows_uses_a_typed_private_kernel32_and_restores(self):
        from ctypes import c_int, wintypes
        lowered, k32, modes, _ = self._windows_priority([True, True])
        self.assertTrue(lowered)
        self.assertEqual(modes, [0x00010000, 0x00020000])
        self.assertEqual(k32.GetCurrentThread.restype, wintypes.HANDLE)
        self.assertEqual(k32.SetThreadPriority.argtypes, [wintypes.HANDLE, c_int])
        self.assertEqual(k32.SetThreadPriority.restype, wintypes.BOOL)
        self.assertEqual(k32.SetThreadPriority.call_args_list[0].args[0], 0xFFFFFFFFFFFFFFFE)

    def test_windows_priority_refused_is_logged_not_raised(self):
        lowered, _, modes, out = self._windows_priority([False])
        self.assertFalse(lowered)
        self.assertEqual(modes, [0x00010000])  # nothing to restore
        self.assertIn("SetThreadPriority(0x10000) failed: error 6", out)

    @unittest.skipIf(os.name == "nt", "fork path is POSIX only")
    def test_child_killed_mid_upload_leaves_the_last_completed_batch_saved(self):
        """Real fork + hard kill: batch 1 uploads, batch 2's upload hangs past the
        deadline. The persisted cursor is exactly the last file batch 1 read."""
        mdm = self.mdm
        home = _transcript_home(self, [("k1", 5, 60), ("k2", 4, 60), ("k3", 3, 60)])
        calls = {"n": 0}

        def hanging_send(api_key, backend_url, sessions, forced=False):
            calls["n"] += 1
            if calls["n"] > 1:
                time.sleep(60)
            return len(sessions), 1, 0

        out = io.StringIO()
        with patch.object(mdm, "_run_as_user", side_effect=lambda u, fn, *a, **k: fn(*a, **k)), \
             patch.object(mdm, "_backfill_force_config", return_value=(None, None)), \
             patch.object(mdm, "_backfill_send_sessions", side_effect=hanging_send), \
             patch.object(mdm, "_backfill_account_email", return_value=None), \
             patch.object(mdm, "get_device_identifier", return_value="SERIAL"), \
             patch.object(mdm, "BACKFILL_BATCH_BYTES", 1), \
             patch.object(mdm, "BACKFILL_DEADLINE_SECONDS", 3), \
             patch.object(mdm, "_SCRIPT_START", time.time()), \
             redirect_stdout(out):
            mdm._run_backfill_bounded("key", "https://backend", [("me", home)])
        k1_mtime = (home / ".claude" / "projects" / "p" / "k1.jsonl").stat().st_mtime
        self.assertEqual(mdm._backfill_read_state(home)["cursor"], k1_mtime)
        self.assertIn("Did not finish in time", out.getvalue())


def _transcript_home(test, files):
    """A temp home with ~/.claude/projects/p/<name>.jsonl for each (name, days_ago,
    pad_bytes); every file with the same days_ago shares one exact mtime."""
    home = Path(tempfile.mkdtemp())
    test.addCleanup(shutil.rmtree, home)
    projects = home / ".claude" / "projects" / "p"
    projects.mkdir(parents=True)
    now = int(time.time())
    for name, days_ago, pad in files:
        path = projects / f"{name}.jsonl"
        path.write_text(json.dumps({"sessionId": name, "type": "user", "pad": "x" * pad}) + "\n")
        os.utime(path, (now - days_ago * 86400, now - days_ago * 86400))
    return home


def _drain_real_home(test, home, batch_bytes, force=(None, None), send=None, real_send=False):
    """run_backfill over one real home, uploads recorded as (ids, forced). With
    real_send the real _backfill_send_sessions runs and stdout is returned instead."""
    mdm = test.mdm
    uploads = []

    def fake_send(api_key, backend_url, sessions, forced=False):
        uploads.append(([s["session_id"] for s in sessions], forced))
        return send(sessions) if send else (len(sessions), 1, 0)

    out = io.StringIO()
    stack = [
        patch.object(mdm, "_run_as_user", side_effect=lambda u, fn, *a, **k: fn(*a, **k)),
        patch.object(mdm, "_backfill_force_config", return_value=force),
        patch.object(mdm, "_backfill_account_email", return_value=None),
        patch.object(mdm, "get_device_identifier", return_value="SERIAL"),
        patch.object(mdm, "BACKFILL_BATCH_BYTES", batch_bytes),
        redirect_stdout(out),
    ]
    if not real_send:
        stack.append(patch.object(mdm, "_backfill_send_sessions", side_effect=fake_send))
    for ctx in stack:
        ctx.__enter__()
    try:
        mdm.run_backfill("key", "https://backend", [("me", home)])
    finally:
        for ctx in reversed(stack):
            ctx.__exit__(None, None, None)
    return out.getvalue() if real_send else uploads


@unittest.skipIf(os.name == "nt", "fork-based privilege drop is POSIX only")
class TestRunAsUserLargePayload(unittest.TestCase):
    """_run_as_user used `bytes +=` per 64 KB pipe read: quadratic in the payload,
    which pinned a core and blew the MDM timeout on a multi-GB backfill."""

    def test_large_result_comes_back_fast(self):
        import pwd
        mdm = tool_module("claude-code/hooks/mdm", "setup")
        me = pwd.getpwuid(os.getuid()).pw_name
        payload = b"x" * (128 * 1024 * 1024)
        # The child drops privileges; as a non-root test user that must be a no-op.
        with patch.object(mdm.os, "setgroups", lambda *_: None), \
             patch.object(mdm.os, "setgid", lambda *_: None), \
             patch.object(mdm.os, "setuid", lambda *_: None):
            started = time.time()
            result = mdm._run_as_user(me, lambda: payload)
            elapsed = time.time() - started
        self.assertEqual(len(result), len(payload))
        self.assertLess(elapsed, 10)


class TestMdmWriteConfigReportsSuccess(unittest.TestCase):
    """A successful per-user config write must NOT be logged as a failure.

    Regression for the missing ``return True`` in the privilege-dropped
    ``_write`` closure of ``write_unbound_config_for_user``: without it the
    closure returned None on success, ``_run_as_user`` relayed that None, and
    the caller misreported every successful write as
    ``Could not write config for <user>``. The same closure ships verbatim in
    claude-code, codex, copilot and augment, so all four are checked here.
    """

    from tests.conftest import REPO as _REPO_ROOT
    TOOLS = {
        "claude-code": _REPO_ROOT / "claude-code" / "hooks" / "mdm" / "setup.py",
        "codex": _REPO_ROOT / "codex" / "hooks" / "mdm" / "setup.py",
        "copilot": _REPO_ROOT / "copilot" / "hooks" / "mdm" / "setup.py",
        "augment": _REPO_ROOT / "augment" / "hooks" / "mdm" / "setup.py",
    }

    @staticmethod
    def _load(name, path):
        import importlib.util
        spec = importlib.util.spec_from_file_location(
            f"mdm_setup_{name.replace('-', '_')}", str(path)
        )
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        return mod

    def test_successful_write_is_not_reported_as_failure(self):
        for name, path in self.TOOLS.items():
            with self.subTest(tool=name):
                mdm = self._load(name, path)
                logs = []
                home = Path(tempfile.mkdtemp())
                self.addCleanup(shutil.rmtree, home, ignore_errors=True)

                # Mimic a successful privilege drop: _run_as_user runs the
                # callback in-process and relays its return value verbatim.
                def fake_run_as_user(username, fn, *args, **kwargs):
                    return fn(*args, **kwargs)

                with patch.object(mdm, "_run_as_user", side_effect=fake_run_as_user), \
                     patch.object(mdm, "_repair_user_ownership", lambda *a, **k: None), \
                     patch.object(mdm, "debug_print", side_effect=logs.append):
                    mdm.write_unbound_config_for_user(
                        "tester", home, "sk-test-key",
                        urls={"base_url": "https://backend", "gateway_url": "https://gw"},
                    )

                config_file = home / ".unbound" / "config.json"
                self.assertTrue(config_file.exists(), f"{name}: config.json was not written")
                data = json.loads(config_file.read_text())
                self.assertEqual(data["api_key"], "sk-test-key")
                self.assertEqual(data["base_url"], "https://backend")
                self.assertFalse(
                    any("Could not write config" in m for m in logs),
                    f"{name}: success path falsely logged a failure: {logs}",
                )


class TestCommandTargetsHook(unittest.TestCase):
    def setUp(self):
        _command_targets_hook = setup._command_targets_hook
        self.match = _command_targets_hook
        self.target = Path("/Users/jane/.claude/hooks/unbound.py")

    def test_bare_path_matches(self):
        self.assertTrue(self.match(str(self.target), self.target))

    def test_double_quoted_matches(self):
        self.assertTrue(self.match(f'"{self.target}"', self.target))

    def test_single_quoted_matches(self):
        self.assertTrue(self.match(f"'{self.target}'", self.target))

    def test_launcher_prefixed_matches(self):
        self.assertTrue(self.match(f'py -3 "{self.target}"', self.target))
        self.assertTrue(self.match(f'python "{self.target}"', self.target))

    def test_exe_launcher_prefixed_matches(self):
        self.assertTrue(self.match(f'py.exe -3 "{self.target}"', self.target))
        self.assertTrue(self.match(f'python.exe "{self.target}"', self.target))
        self.assertTrue(self.match(f'python3.exe "{self.target}"', self.target))

    def test_path_with_spaces_matches(self):
        target = Path("/Users/Jane Doe/.claude/hooks/unbound.py")
        self.assertTrue(self.match(f'"{target}"', target))
        self.assertTrue(self.match(f'py -3 "{target}"', target))

    def test_foreign_command_does_not_match(self):
        self.assertFalse(self.match("/opt/other/hook.py", self.target))
        self.assertFalse(self.match('echo "hello world"', self.target))

    def test_target_as_argument_does_not_match(self):
        self.assertFalse(self.match(f'/opt/other/hook.py --config "{self.target}"', self.target))

    def test_sibling_path_does_not_match(self):
        self.assertFalse(self.match(f"{self.target}.backup", self.target))
        self.assertFalse(self.match(f"/opt/mirror{self.target}", self.target))

    def test_empty_command_does_not_match(self):
        self.assertFalse(self.match("", self.target))


class TestRemoveHooksFromSettings(unittest.TestCase):
    def setUp(self):
        self.home = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.home, ignore_errors=True)
        patcher = patch.object(setup.Path, "home", return_value=self.home)
        patcher.start()
        self.addCleanup(patcher.stop)
        self.settings_path = self.home / ".claude" / "settings.json"
        self.settings_path.parent.mkdir(parents=True, exist_ok=True)
        self.script = str(self.home / ".claude" / "hooks" / "unbound.py")

    def _write(self, settings):
        self.settings_path.write_text(json.dumps(settings))

    def _read(self):
        return json.loads(self.settings_path.read_text())

    def test_removes_quoted_bare_and_launcher_forms_preserving_foreign(self):
        remove_hooks_from_settings = setup.remove_hooks_from_settings
        self._write({"hooks": {
            "PreToolUse": [
                {"matcher": "*", "hooks": [
                    {"type": "command", "command": f'"{self.script}"'},
                    {"type": "command", "command": "/opt/other/hook.py"},
                ]},
            ],
            "Stop": [
                {"hooks": [{"type": "command", "command": self.script}]},
            ],
            "SessionStart": [
                {"hooks": [{"type": "command", "command": f'py -3 "{self.script}"'}]},
            ],
        }})
        self.assertEqual(remove_hooks_from_settings(), "cleared")
        result = self._read()
        self.assertEqual(
            result["hooks"]["PreToolUse"][0]["hooks"],
            [{"type": "command", "command": "/opt/other/hook.py"}],
        )
        self.assertNotIn("Stop", result["hooks"])
        self.assertNotIn("SessionStart", result["hooks"])

    def test_mixed_quoted_and_bare_both_removed(self):
        remove_hooks_from_settings = setup.remove_hooks_from_settings
        self._write({"hooks": {"PreToolUse": [
            {"matcher": "*", "hooks": [
                {"type": "command", "command": f'"{self.script}"'},
                {"type": "command", "command": self.script},
            ]},
        ]}})
        self.assertEqual(remove_hooks_from_settings(), "cleared")
        self.assertNotIn("hooks", self._read())

    def test_install_dedup_skips_when_quoted_entry_exists(self):
        configure_claude_settings = setup.configure_claude_settings
        self._write({"hooks": {"PreToolUse": [
            {"matcher": "*", "hooks": [
                {"type": "command", "command": f'"{self.script}"', "timeout": 15000},
            ]},
        ]}})
        self.assertTrue(configure_claude_settings())
        result = self._read()
        commands = [
            h["command"]
            for item in result["hooks"]["PreToolUse"]
            for h in item["hooks"]
        ]
        self.assertEqual(commands.count(f'"{self.script}"'), 1)
        self.assertNotIn(self.script, commands)


class TestMatcherParityAcrossTrees(unittest.TestCase):
    SENTINEL = "return os.path.normcase(os.path.normpath(tokens[0])) == normalized_target"

    def _extract(self, path):
        captured = []
        capturing = False
        for line in path.read_text().splitlines():
            if line.startswith("def _command_targets_hook"):
                capturing = True
            if capturing:
                captured.append(line)
                if line.strip() == self.SENTINEL:
                    break
        return "\n".join(captured)

    # The MDM trees carry one extra branch: managed settings can hold a hook
    # command that runs the /opt/unbound binary, which the python MDM setup has
    # to recognise. A user-level install never writes or reads that form.
    BINARY_BRANCH = 'if "/opt/unbound/" in command and "unbound-hook" in command:'

    def _tokenising_core(self, path):
        """The matcher with the binary-install branch and comments removed, which
        is the part every tree must implement identically."""
        out, skip = [], False
        for line in self._extract(path).splitlines():
            stripped = line.strip()
            if stripped.startswith(self.BINARY_BRANCH):
                skip = True
                continue
            if skip:
                skip = False
                continue          # the `return True` under that branch
            if stripped.startswith("#") or not stripped:
                continue
            out.append(stripped)
        return "\n".join(out)

    USER_LEVEL = (("claude-code", "hooks", "setup.py"),
                  ("codex", "hooks", "setup.py"),
                  ("binary", "src", "unbound_hook", "setup_cmd.py"))
    MDM = (("claude-code", "hooks", "mdm", "setup.py"),
           ("codex", "hooks", "mdm", "setup.py"))

    def _paths(self, group):
        from tests.conftest import REPO as root
        return [root.joinpath(*parts) for parts in group]

    def test_the_matcher_is_present_in_every_tree(self):
        for path in self._paths(self.USER_LEVEL) + self._paths(self.MDM):
            self.assertTrue(self._extract(path).strip(), "%s: matcher not found" % path)

    def test_the_tokenising_core_does_not_drift(self):
        """Comments and the binary branch aside, every tree tokenises identically."""
        cores = {self._tokenising_core(p)
                 for p in self._paths(self.USER_LEVEL) + self._paths(self.MDM)}
        self.assertEqual(len(cores), 1, "matcher drifted across trees")

    def test_only_the_mdm_trees_carry_the_binary_branch(self):
        for path in self._paths(self.MDM):
            self.assertIn(self.BINARY_BRANCH, self._extract(path),
                          "%s: MDM must recognise an /opt/unbound hook command" % path)
        for path in self._paths(self.USER_LEVEL):
            self.assertNotIn(self.BINARY_BRANCH, self._extract(path),
                             "%s: user-level never sees that form" % path)


if __name__ == "__main__":
    unittest.main()


class TestResolveClaudeConfigDir(unittest.TestCase):
    """CLAUDE_CONFIG_DIR env > --config-dir arg > ~/.claude."""

    def test_env_beats_arg_and_home(self):
        with patch.dict(os.environ, {"CLAUDE_CONFIG_DIR": "/env/cc"}):
            result = setup._resolve_claude_config_dir(["x", "--config-dir", "/arg/cc"])
        self.assertEqual(result, Path(os.path.abspath("/env/cc")))

    def test_arg_used_when_no_env(self):
        env = {k: v for k, v in os.environ.items() if k != "CLAUDE_CONFIG_DIR"}
        with patch.dict(os.environ, env, clear=True):
            result = setup._resolve_claude_config_dir(["x", "--config-dir", "/arg/cc"])
        self.assertEqual(result, Path(os.path.abspath("/arg/cc")))

    def test_env_used_when_no_arg(self):
        with patch.dict(os.environ, {"CLAUDE_CONFIG_DIR": "/env/cc"}):
            result = setup._resolve_claude_config_dir(["x"])
        self.assertEqual(result, Path(os.path.abspath("/env/cc")))

    def test_home_default_when_arg_and_env_absent(self):
        env = {k: v for k, v in os.environ.items() if k != "CLAUDE_CONFIG_DIR"}
        with patch.dict(os.environ, env, clear=True):
            result = setup._resolve_claude_config_dir(["x"])
        self.assertEqual(result, Path.home() / ".claude")

    def test_relative_value_is_absolutized(self):
        result = setup._resolve_claude_config_dir(["x", "--config-dir", "rel/cc"])
        self.assertEqual(result, Path(os.path.abspath("rel/cc")))

    def test_leading_tilde_stays_literal(self):
        # Claude Code creates a literal "~" directory rather than expanding it,
        # so expanding here would install where Claude never looks.
        with patch.dict(os.environ, {"CLAUDE_CONFIG_DIR": "~/cc"}):
            result = setup._resolve_claude_config_dir(["x"])
        self.assertEqual(result, Path(os.path.abspath("~/cc")))
        self.assertNotEqual(result, Path.home() / "cc")

    def test_blank_env_falls_back_to_home(self):
        with patch.dict(os.environ, {"CLAUDE_CONFIG_DIR": "   "}):
            result = setup._resolve_claude_config_dir(["x"])
        self.assertEqual(result, Path.home() / ".claude")

    def test_equals_form_of_config_dir_arg(self):
        env = {k: v for k, v in os.environ.items() if k != "CLAUDE_CONFIG_DIR"}
        with patch.dict(os.environ, env, clear=True):
            result = setup._resolve_claude_config_dir(["x", "--config-dir=/arg/cc"])
        self.assertEqual(result, Path(os.path.abspath("/arg/cc")))

    def test_arg_without_env_still_resolves_to_the_arg(self):
        # The install honours --config-dir, but Claude Code keys off the env var
        # alone, so main() warns that these hooks will not be read.
        env = {k: v for k, v in os.environ.items() if k != "CLAUDE_CONFIG_DIR"}
        with patch.dict(os.environ, env, clear=True):
            result = setup._resolve_claude_config_dir(["x", "--config-dir", "/arg/cc"])
        self.assertEqual(result, Path(os.path.abspath("/arg/cc")))



class TestInstallUnderResolvedDir(unittest.TestCase):
    """Hooks + settings + baked command must land under the resolved config dir."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.home = Path(self.tmp) / "home"
        self.home.mkdir(parents=True)
        self.config_dir = Path(self.tmp) / "custom-cc"

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_settings_and_hook_command_under_config_dir(self):
        with patch.object(Path, "home", staticmethod(lambda: self.home)), \
             patch.object(setup, "download_file", lambda url, dest: dest.parent.mkdir(parents=True, exist_ok=True) or dest.write_text("# hook") or True):
            self.assertTrue(setup.setup_hooks(config_dir=self.config_dir))
            self.assertTrue(setup.configure_claude_settings(config_dir=self.config_dir))

        hook_path = self.config_dir / "hooks" / "unbound.py"
        settings_path = self.config_dir / "settings.json"
        self.assertTrue(hook_path.exists())
        self.assertTrue(settings_path.exists())
        settings = json.loads(settings_path.read_text())
        cmd = settings["hooks"]["PreToolUse"][0]["hooks"][0]["command"]
        self.assertEqual(cmd, str(hook_path))
        self.assertNotIn(str(self.home / ".claude"), cmd)

    def test_backward_compat_no_env_uses_home_claude(self):
        env = {k: v for k, v in os.environ.items() if k != "CLAUDE_CONFIG_DIR"}
        with patch.dict(os.environ, env, clear=True), \
             patch.object(Path, "home", staticmethod(lambda: self.home)), \
             patch.object(setup, "download_file", lambda url, dest: dest.parent.mkdir(parents=True, exist_ok=True) or dest.write_text("# hook") or True):
            config_dir = setup._resolve_claude_config_dir(["x"])
            self.assertTrue(setup.setup_hooks(config_dir=config_dir))
            self.assertTrue(setup.configure_claude_settings(config_dir=config_dir))

        hook_path = self.home / ".claude" / "hooks" / "unbound.py"
        self.assertTrue(hook_path.exists())
        settings = json.loads((self.home / ".claude" / "settings.json").read_text())
        cmd = settings["hooks"]["PreToolUse"][0]["hooks"][0]["command"]
        self.assertEqual(cmd, str(hook_path))


class TestEnterpriseHooksConflict(unittest.TestCase):
    """The user-level setup must skip when the MDM install is present, or both
    hooks fire and every event is logged twice."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.managed = Path(self.tmp) / "ClaudeCode"
        self.managed.mkdir(parents=True, exist_ok=True)
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)

    def _conflict(self):
        with patch.object(setup, "get_managed_settings_dir", return_value=self.managed):
            return setup.check_enterprise_hooks_conflict()

    def test_flat_managed_settings_with_unbound_hook_is_a_conflict(self):
        # MDM's fallback: a flat managed-settings.json carrying the managed hook.
        (self.managed / "managed-settings.json").write_text(json.dumps({
            "hooks": {"UserPromptSubmit": [{"hooks": [
                {"type": "command",
                 "command": '"/opt/unbound/current/unbound-hook/unbound-hook" hook claude-code User'}
            ]}]}
        }))
        self.assertTrue(self._conflict())

    def test_managed_dropin_is_a_conflict(self):
        (self.managed / "managed-settings.d").mkdir(parents=True, exist_ok=True)
        (self.managed / "managed-settings.d" / "unbound.json").write_text("{}")
        self.assertTrue(self._conflict())

    def test_flat_managed_settings_without_our_hook_is_not_a_conflict(self):
        # Another org's managed hook must not be mistaken for ours.
        (self.managed / "managed-settings.json").write_text(json.dumps({
            "hooks": {"PreToolUse": [{"hooks": [
                {"type": "command", "command": "/opt/acme/their-hook.sh"}
            ]}]}
        }))
        self.assertFalse(self._conflict())

    def test_command_with_token_but_not_our_path_is_not_a_conflict(self):
        # A foreign command that merely mentions "unbound-hook" is not ours —
        # matching it would wrongly skip the user hook.
        (self.managed / "managed-settings.json").write_text(json.dumps({
            "hooks": {"PreToolUse": [{"hooks": [
                {"type": "command", "command": "/usr/local/bin/unbound-hook-lookalike"}
            ]}]}
        }))
        self.assertFalse(self._conflict())

    def test_a_malformed_entry_does_not_abandon_the_scan(self):
        # Dirty/foreign shapes earlier in the shared file (non-dict group, null
        # hooks list, non-dict hook) must not stop us finding a real one after.
        (self.managed / "managed-settings.json").write_text(json.dumps({
            "hooks": {
                "PreToolUse": ["not-a-dict", {"hooks": None}, {"hooks": ["also-bad"]},
                               {"hooks": [{"command": 1}]}],
                "UserPromptSubmit": [{"hooks": [
                    {"type": "command",
                     "command": '"/opt/unbound/current/unbound-hook/unbound-hook" hook claude-code User'}
                ]}],
            }
        }))
        self.assertTrue(self._conflict())

    def test_top_level_hooks_not_a_dict_is_not_a_conflict(self):
        # A hooks value that is a list (or otherwise malformed) must fail open,
        # not raise.
        (self.managed / "managed-settings.json").write_text(json.dumps({"hooks": ["x"]}))
        self.assertFalse(self._conflict())

    def test_unmanaged_box_is_not_a_conflict(self):
        self.assertFalse(self._conflict())
