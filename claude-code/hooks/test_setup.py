import unittest
from unittest.mock import patch
import json
import os
import shutil
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
        self.config_dir = self.home / ".claude"
        self.addCleanup(self._tmp.cleanup)

    def test_read_cutoff_defaults_to_max_age_when_no_file(self):
        """No cache file -> fall back to BACKFILL_MAX_AGE_DAYS ago (first run)."""
        import setup
        cutoff = setup._backfill_read_cutoff(self.config_dir)
        expected = time.time() - (setup.BACKFILL_MAX_AGE_DAYS * 86400)
        self.assertAlmostEqual(cutoff, expected, delta=5)

    def test_write_then_read_roundtrip(self):
        """A persisted timestamp is read back as the cutoff on the next run."""
        import setup
        ts = time.time() - 3600
        setup._backfill_write_cutoff(self.config_dir, ts)
        self.assertTrue(setup._backfill_state_path(self.config_dir).exists())
        self.assertAlmostEqual(setup._backfill_read_cutoff(self.config_dir), ts, delta=0.01)

    def test_read_cutoff_ignores_corrupt_value(self):
        """A non-numeric cache file falls back to the default window."""
        import setup
        path = setup._backfill_state_path(self.config_dir)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("not-a-number")
        expected = time.time() - (setup.BACKFILL_MAX_AGE_DAYS * 86400)
        self.assertAlmostEqual(setup._backfill_read_cutoff(self.config_dir), expected, delta=5)

    def test_read_cutoff_ignores_future_timestamp(self):
        """A future timestamp (clock skew) is rejected for the default window."""
        import setup
        setup._backfill_write_cutoff(self.config_dir, time.time() + 10000)
        expected = time.time() - (setup.BACKFILL_MAX_AGE_DAYS * 86400)
        self.assertAlmostEqual(setup._backfill_read_cutoff(self.config_dir), expected, delta=5)

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
        setup._backfill_write_cutoff(self.config_dir, 123.0)
        path = setup._backfill_state_path(self.config_dir)
        self.assertEqual(path.read_text(), "123.0")
        self.assertEqual(list(path.parent.glob("*.tmp")), [])

    def test_cutoff_not_advanced_when_session_cap_fires(self):
        """When the per-run session cap is hit, the cutoff must NOT advance, or
        the unprocessed older files would be skipped forever next run."""
        import setup
        root = self.config_dir / "projects"
        root.mkdir(parents=True)
        for i in range(3):
            (root / f"s{i}.jsonl").write_text('{"sessionId":"x%d"}\n' % i)
        with patch.object(setup, "BACKFILL_MAX_SESSIONS_PER_RUN", 2), \
             patch.object(setup, "_backfill_upload_chunk", return_value=True):
            setup.run_backfill("key", "https://backend", self.config_dir)
        self.assertFalse(setup._backfill_state_path(self.config_dir).exists())

    def test_run_backfill_reads_custom_config_dir_projects(self):
        """With a custom config_dir, backfill walks config_dir/projects and writes
        the cutoff there — not under ~/.claude."""
        import setup
        custom = self.home / "custom-cc"
        root = custom / "projects"
        root.mkdir(parents=True)
        (root / "s.jsonl").write_text('{"sessionId":"x"}\n')
        with patch.object(setup, "_backfill_upload_chunk", return_value=True):
            setup.run_backfill("key", "https://backend", custom)
        self.assertTrue(setup._backfill_state_path(custom).exists())
        self.assertFalse(setup._backfill_state_path(self.config_dir).exists())


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


class TestMdmWriteConfigReportsSuccess(unittest.TestCase):
    """A successful per-user config write must NOT be logged as a failure.

    Regression for the missing ``return True`` in the privilege-dropped
    ``_write`` closure of ``write_unbound_config_for_user``: without it the
    closure returned None on success, ``_run_as_user`` relayed that None, and
    the caller misreported every successful write as
    ``Could not write config for <user>``. The same closure ships verbatim in
    claude-code, codex, copilot and augment, so all four are checked here.
    """

    _REPO_ROOT = Path(__file__).resolve().parents[2]
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


class TestResolveClaudeConfigDir(unittest.TestCase):
    """WEB-4882: CLAUDE_CONFIG_DIR env > --config-dir arg > ~/.claude."""

    def test_env_beats_arg_and_home(self):
        import setup
        with patch.dict(os.environ, {"CLAUDE_CONFIG_DIR": "/env/cc"}):
            result = setup._resolve_claude_config_dir(["x", "--config-dir", "/arg/cc"])
        self.assertEqual(result, Path("/env/cc").resolve())

    def test_arg_used_when_no_env(self):
        import setup
        env = {k: v for k, v in os.environ.items() if k != "CLAUDE_CONFIG_DIR"}
        with patch.dict(os.environ, env, clear=True):
            result = setup._resolve_claude_config_dir(["x", "--config-dir", "/arg/cc"])
        self.assertEqual(result, Path("/arg/cc").resolve())

    def test_env_used_when_no_arg(self):
        import setup
        with patch.dict(os.environ, {"CLAUDE_CONFIG_DIR": "/env/cc"}):
            result = setup._resolve_claude_config_dir(["x"])
        self.assertEqual(result, Path("/env/cc").resolve())

    def test_home_default_when_arg_and_env_absent(self):
        import setup
        env = {k: v for k, v in os.environ.items() if k != "CLAUDE_CONFIG_DIR"}
        with patch.dict(os.environ, env, clear=True):
            result = setup._resolve_claude_config_dir(["x"])
        self.assertEqual(result, Path.home() / ".claude")

    def test_relative_value_is_absolutized(self):
        import setup
        result = setup._resolve_claude_config_dir(["x", "--config-dir", "rel/cc"])
        self.assertEqual(result, Path("rel/cc").resolve())


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
        import setup
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
        import setup
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


class TestCommandTargetsHook(unittest.TestCase):
    def setUp(self):
        from setup import _command_targets_hook
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
        patcher = patch("setup.Path.home", return_value=self.home)
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
        from setup import remove_hooks_from_settings
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
        from setup import remove_hooks_from_settings
        self._write({"hooks": {"PreToolUse": [
            {"matcher": "*", "hooks": [
                {"type": "command", "command": f'"{self.script}"'},
                {"type": "command", "command": self.script},
            ]},
        ]}})
        self.assertEqual(remove_hooks_from_settings(), "cleared")
        self.assertNotIn("hooks", self._read())

    def test_install_dedup_skips_when_quoted_entry_exists(self):
        from setup import configure_claude_settings
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

    def test_helper_is_byte_identical_across_trees(self):
        root = Path(__file__).resolve().parents[2]
        files = [
            root / "claude-code" / "hooks" / "setup.py",
            root / "claude-code" / "hooks" / "mdm" / "setup.py",
            root / "codex" / "hooks" / "setup.py",
            root / "codex" / "hooks" / "mdm" / "setup.py",
            root / "binary" / "src" / "unbound_hook" / "setup_cmd.py",
        ]
        bodies = [self._extract(f) for f in files]
        for path, body in zip(files, bodies):
            self.assertTrue(body.strip(), f"{path}: matcher not found")
        self.assertEqual(len(set(bodies)), 1, "matcher drifted across trees")


if __name__ == "__main__":
    unittest.main()
