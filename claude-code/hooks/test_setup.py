import unittest
from unittest.mock import patch
import json
import os
import socket
import tempfile
import threading
import urllib.request
import urllib.error
import urllib.parse
import time
from pathlib import Path


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
        from setup import run_callback_server

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
                resp = urllib.request.urlopen(target)
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
        import setup
        import sys
        from io import StringIO

        with patch("setup.run_callback_server") as mock_server, \
             patch("setup.install_macos_certificates"):
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
        import setup
        cutoff = setup._backfill_read_cutoff(self.home)
        expected = time.time() - (setup.BACKFILL_MAX_AGE_DAYS * 86400)
        self.assertAlmostEqual(cutoff, expected, delta=5)

    def test_write_then_read_roundtrip(self):
        """A persisted timestamp is read back as the cutoff on the next run."""
        import setup
        ts = time.time() - 3600
        setup._backfill_write_cutoff(self.home, ts)
        self.assertTrue(setup._backfill_state_path(self.home).exists())
        self.assertAlmostEqual(setup._backfill_read_cutoff(self.home), ts, delta=0.01)

    def test_read_cutoff_ignores_corrupt_value(self):
        """A non-numeric cache file falls back to the default window."""
        import setup
        path = setup._backfill_state_path(self.home)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("not-a-number")
        expected = time.time() - (setup.BACKFILL_MAX_AGE_DAYS * 86400)
        self.assertAlmostEqual(setup._backfill_read_cutoff(self.home), expected, delta=5)

    def test_read_cutoff_ignores_future_timestamp(self):
        """A future timestamp (clock skew) is rejected for the default window."""
        import setup
        setup._backfill_write_cutoff(self.home, time.time() + 10000)
        expected = time.time() - (setup.BACKFILL_MAX_AGE_DAYS * 86400)
        self.assertAlmostEqual(setup._backfill_read_cutoff(self.home), expected, delta=5)

    def test_iter_transcripts_respects_cutoff(self):
        """Only transcripts modified at/after the cutoff are yielded."""
        import setup
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
        import setup
        setup._backfill_write_cutoff(self.home, 123.0)
        path = setup._backfill_state_path(self.home)
        self.assertEqual(path.read_text(), "123.0")
        self.assertEqual(list(path.parent.glob("*.tmp")), [])

    def test_cutoff_not_advanced_when_session_cap_fires(self):
        """When the per-run session cap is hit, the cutoff must NOT advance, or
        the unprocessed older files would be skipped forever next run."""
        import setup
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
        import importlib.util
        spec = importlib.util.spec_from_file_location(
            "mdm_setup", str(Path(__file__).parent / "mdm" / "setup.py")
        )
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        return mod

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
             patch.object(mdm, "_backfill_send_sessions", return_value=send_result):
            mdm.run_backfill("key", "https://backend", homes)
        return writes

    def test_failed_home_cutoff_not_advanced(self):
        """Collection returning None (fork/perms failure) -> no cutoff write."""
        mdm = self._load_mdm()
        good, bad = Path("/home/good"), Path("/home/bad")
        # good: collected, empty, not capped; bad: collection failed (None)
        writes = self._run(mdm, {good: ([], False), bad: None}, send_result=(0, 0, 0))
        self.assertIn(good, writes)
        self.assertNotIn(bad, writes)

    def test_collected_homes_advanced_on_success(self):
        """Full upload success -> cutoff written for every collected home."""
        mdm = self._load_mdm()
        home = Path("/home/alice")
        writes = self._run(
            mdm,
            {home: ([{"session_id": "s1", "entries": [{}]}], False)},
            send_result=(1, 1, 0),
        )
        self.assertEqual(writes, [home])

    def test_partial_upload_failure_does_not_advance(self):
        """A failed chunk -> no cutoff write, so the next cron retries."""
        mdm = self._load_mdm()
        home = Path("/home/alice")
        writes = self._run(
            mdm,
            {home: ([{"session_id": "s1", "entries": [{}]}], False)},
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
                capped_home: ([{"session_id": "s1", "entries": [{}]}], True),
                ok_home: ([{"session_id": "s2", "entries": [{}]}], False),
            },
            send_result=(2, 1, 0),
        )
        self.assertEqual(writes, [ok_home])


class TestMdmManagedHooksMerge(unittest.TestCase):
    """WEB-4814: setup_managed_hooks must MERGE its hooks into any pre-existing
    managed-settings hooks block instead of overwriting it, must add Unbound's
    own entry exactly once, and must be idempotent across re-runs."""

    @staticmethod
    def _load_mdm():
        import importlib.util
        spec = importlib.util.spec_from_file_location(
            "mdm_setup", str(Path(__file__).parent / "mdm" / "setup.py")
        )
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        return mod

    def _run_setup(self, mdm, managed_dir):
        """Run setup_managed_hooks with the network download + path discovery
        stubbed, against a sandboxed managed dir. The download stub writes a
        stub script so the real post-download steps (gateway rewrite, chmod)
        have a file to operate on, exactly as in production."""
        def fake_download(url, dest):
            Path(dest).parent.mkdir(parents=True, exist_ok=True)
            Path(dest).write_text("# stub hook script\n")
            return True

        with patch.object(mdm, "download_file", side_effect=fake_download), \
             patch.object(mdm, "get_managed_settings_dir", return_value=managed_dir):
            ok = mdm.setup_managed_hooks()
        self.assertTrue(ok)
        return json.loads((managed_dir / "managed-settings.json").read_text())

    @staticmethod
    def _unbound_entries(settings, script_path, event):
        s = str(script_path)
        return [e for e in settings["hooks"].get(event, [])
                if any(s in h.get("command", "") for h in e.get("hooks", []))]

    def test_preserves_foreign_hook_and_adds_unbound_once_idempotently(self):
        mdm = self._load_mdm()
        with tempfile.TemporaryDirectory() as td:
            managed = Path(td) / "managed"
            managed.mkdir()
            script_path = managed / "hooks" / "unbound.py"
            foreign = {"matcher": "*", "hooks": [
                {"type": "command", "command": "/usr/local/bin/other pre"}]}
            (managed / "managed-settings.json").write_text(json.dumps(
                {"model": "opus", "hooks": {"PreToolUse": [foreign]}}))

            settings = self._run_setup(mdm, managed)
            # foreign survives, unrelated top-level key preserved
            self.assertIn(foreign, settings["hooks"]["PreToolUse"])
            self.assertEqual(settings["model"], "opus")
            # Unbound entry present exactly once
            self.assertEqual(
                len(self._unbound_entries(settings, script_path, "PreToolUse")), 1)

            # re-run: no duplicate, foreign still there
            settings2 = self._run_setup(mdm, managed)
            self.assertIn(foreign, settings2["hooks"]["PreToolUse"])
            self.assertEqual(
                len(self._unbound_entries(settings2, script_path, "PreToolUse")), 1)

    def test_keeps_foreign_hook_that_references_our_path_midcommand(self):
        """WEB-4814 ownership tightening: a FOREIGN hook whose command merely
        contains our script path mid-string (a wrapper exec'ing it as an arg)
        is NOT Unbound-owned and MUST survive the merge — only path-prefixed
        commands that invoke our script get stripped-and-replaced. Fails on the
        pre-fix substring matcher; passes after."""
        mdm = self._load_mdm()
        with tempfile.TemporaryDirectory() as td:
            managed = Path(td) / "managed"
            managed.mkdir()
            script_path = managed / "hooks" / "unbound.py"
            sp = str(script_path)
            wrapper = {"matcher": "*", "hooks": [
                {"type": "command", "command": f'/usr/local/bin/foo "{sp}" --as-arg pre'}]}
            drifted_unbound = {"matcher": "*", "hooks": [
                {"type": "command", "command": f'"{sp}" --old-flag'}]}
            (managed / "managed-settings.json").write_text(json.dumps(
                {"model": "opus",
                 "hooks": {"PreToolUse": [wrapper, drifted_unbound]}}))

            settings = self._run_setup(mdm, managed)

            entries = settings["hooks"]["PreToolUse"]
            # the foreign wrapper survives despite referencing our path
            self.assertIn(wrapper, entries)
            # by the PRODUCTION ownership matcher, exactly one entry is ours and
            # the wrapper is NOT ours
            owned = [e for e in entries if mdm._entry_is_unbound(e, sp)]
            self.assertEqual(len(owned), 1)
            self.assertFalse(mdm._entry_is_unbound(wrapper, sp))
            # the drifted form is gone (replaced, not stacked)
            cmds = [h["command"] for e in entries for h in e["hooks"]]
            self.assertNotIn(f'"{sp}" --old-flag', cmds)

    def test_managed_settings_write_is_atomic_and_leaves_no_temp(self):
        """WEB-4814 LOW-1: setup_managed_hooks must write managed-settings.json
        atomically (tmp + os.replace) so a crash mid-write never leaves a
        truncated file that Claude Code silently ignores. Asserts valid JSON and
        no stray .tmp left in the managed dir."""
        mdm = self._load_mdm()
        with tempfile.TemporaryDirectory() as td:
            managed = Path(td) / "managed"
            managed.mkdir()
            settings = self._run_setup(mdm, managed)
            # file is complete, parseable JSON with our hooks
            self.assertIsInstance(settings["hooks"], dict)
            # no temp artifacts left behind in the managed dir
            leftover = list(managed.glob("managed-settings.json.*.tmp"))
            self.assertEqual(leftover, [], f"stray temp files: {leftover}")

    def test_malformed_existing_hooks_block_does_not_crash(self):
        mdm = self._load_mdm()
        with tempfile.TemporaryDirectory() as td:
            managed = Path(td) / "managed"
            managed.mkdir()
            script_path = managed / "hooks" / "unbound.py"
            (managed / "managed-settings.json").write_text(json.dumps(
                {"model": "opus", "hooks": "garbage"}))
            settings = self._run_setup(mdm, managed)
            self.assertIsInstance(settings["hooks"], dict)
            self.assertEqual(
                len(self._unbound_entries(settings, script_path, "PreToolUse")), 1)
            self.assertEqual(settings["model"], "opus")


if __name__ == "__main__":
    unittest.main()
