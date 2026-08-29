"""Integration tests for antigravity/hooks/setup.py.

Run from this directory (or anywhere) with:

    cd antigravity/hooks && python3 -m unittest test_setup.py -v

These tests exercise the actual setup entrypoint — they call into
``setup.configure_antigravity_settings``, ``setup.remove_hooks_from_settings``,
and the top-level ``setup.main`` against an isolated ``HOME`` so the real
``~/.gemini/config/hooks.json`` and ``~/.unbound/`` are never touched.
"""

import json
import os
import shutil
import stat
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch


# Make ``setup`` importable when tests are run from this directory.
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))


def _reload_setup_with_home(home: Path):
    """Re-import setup with HOME pointing at the given temp dir so the
    module-level path constants (HOOKS_JSON_PATH, HOOKS_INSTALL_DIR, etc.) all
    pick up the test home. Returns the freshly imported module."""
    import importlib
    if "setup" in sys.modules:
        del sys.modules["setup"]
    os.environ["HOME"] = str(home)
    # Windows-only fallback; harmless on Unix.
    os.environ["USERPROFILE"] = str(home)
    import setup as _setup  # noqa: E402
    importlib.reload(_setup)
    return _setup


class TestSettingsMerge(unittest.TestCase):
    """Verify the non-destructive merge into ~/.gemini/config/hooks.json."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.home = Path(self.tmp)
        self._old_home = os.environ.get("HOME")
        self._old_userprofile = os.environ.get("USERPROFILE")
        self.setup = _reload_setup_with_home(self.home)

    def tearDown(self):
        if self._old_home is not None:
            os.environ["HOME"] = self._old_home
        if self._old_userprofile is not None:
            os.environ["USERPROFILE"] = self._old_userprofile
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _seed_third_party_settings(self):
        """Pre-seed hooks.json with an unrelated third-party hook so we
        can verify our merge doesn't clobber it."""
        self.setup.HOOKS_JSON_PATH.parent.mkdir(parents=True, exist_ok=True)
        third_party = {
            "hooks": {
                "PreToolUse": [
                    {
                        "matcher": "run_command",
                        "hooks": [
                            {"type": "command", "command": "/usr/local/bin/some-other-tool"}
                        ],
                    }
                ],
                "SessionEnd": [
                    {"hooks": [{"type": "command", "command": "/opt/foo/session_end"}]}
                ],
            },
            "someUnrelatedSetting": True,
        }
        with open(self.setup.HOOKS_JSON_PATH, "w", encoding="utf-8") as f:
            json.dump(third_party, f)
        return third_party

    def test_install_path_is_gemini_config_hooks_json(self):
        """Verified empirically: agy auto-loads ~/.gemini/config/hooks.json.
        Regression lock-in — never reintroduce the old chop-derived
        ~/.antigravity/settings.json path."""
        expected = self.home / ".gemini" / "config" / "hooks.json"
        self.assertEqual(self.setup.HOOKS_JSON_PATH, expected)
        # And our scripts land under ~/.unbound/antigravity-hooks/ (Unbound's
        # own namespace, not inside agy's tree).
        self.assertEqual(
            self.setup.HOOKS_INSTALL_DIR,
            self.home / ".unbound" / "antigravity-hooks",
        )

    def test_install_creates_settings_when_absent(self):
        """install with no pre-existing hooks.json writes a valid file."""
        ok = self.setup.configure_antigravity_settings()
        self.assertTrue(ok)
        self.assertTrue(self.setup.HOOKS_JSON_PATH.exists())
        with open(self.setup.HOOKS_JSON_PATH, "r", encoding="utf-8") as f:
            settings = json.load(f)
        # Only PreToolUse and PostToolUse — agy doesn't actually fire the
        # other event types in 1.0.5.
        self.assertEqual(set(settings["hooks"].keys()), {"PreToolUse", "PostToolUse"})
        for event in ("PreToolUse", "PostToolUse"):
            self.assertEqual(len(settings["hooks"][event]), 1)

    def test_install_does_not_write_unsupported_events(self):
        """Regression: UserPromptSubmit/SessionStart/PreInvocation/etc. must
        not be installed — they're either silently dropped (UserPromptSubmit,
        SessionStart) or log "executing command" but never spawn the process
        (PreInvocation/PostInvocation/Stop) in agy 1.0.5."""
        self.setup.configure_antigravity_settings()
        with open(self.setup.HOOKS_JSON_PATH, "r", encoding="utf-8") as f:
            settings = json.load(f)
        for unsupported in (
            "UserPromptSubmit", "SessionStart",
            "PreInvocation", "PostInvocation", "Stop",
        ):
            self.assertNotIn(unsupported, settings["hooks"])

    def test_install_preserves_third_party_hooks(self):
        """Pre-existing third-party hooks must survive our install."""
        original = self._seed_third_party_settings()
        ok = self.setup.configure_antigravity_settings()
        self.assertTrue(ok)
        with open(self.setup.HOOKS_JSON_PATH, "r", encoding="utf-8") as f:
            settings = json.load(f)

        # Third-party run_command hook must still be present in PreToolUse.
        pre = settings["hooks"]["PreToolUse"]
        third_party_cmds = [
            h["command"]
            for item in pre
            for h in item.get("hooks", [])
        ]
        self.assertIn("/usr/local/bin/some-other-tool", third_party_cmds)

        # SessionEnd was untouched by us, so it must still be there exactly as-is.
        self.assertEqual(settings["hooks"]["SessionEnd"], original["hooks"]["SessionEnd"])

        # Non-hook settings must be preserved.
        self.assertTrue(settings["someUnrelatedSetting"])

    def test_install_is_idempotent(self):
        """Running install twice produces the same on-disk state."""
        self.setup.configure_antigravity_settings()
        with open(self.setup.HOOKS_JSON_PATH, "r", encoding="utf-8") as f:
            first = f.read()
        self.setup.configure_antigravity_settings()
        with open(self.setup.HOOKS_JSON_PATH, "r", encoding="utf-8") as f:
            second = f.read()
        self.assertEqual(first, second)

    def test_clear_removes_only_our_entries(self):
        """After install + clear, only our entries are removed; third-party
        hooks and other settings are intact."""
        original = self._seed_third_party_settings()
        self.setup.configure_antigravity_settings()

        status = self.setup.remove_hooks_from_settings()
        self.assertEqual(status, "cleared")

        with open(self.setup.HOOKS_JSON_PATH, "r", encoding="utf-8") as f:
            settings = json.load(f)

        # Third-party hooks remain.
        self.assertEqual(settings["hooks"]["SessionEnd"], original["hooks"]["SessionEnd"])
        # PreToolUse still contains the third-party tool but NOT our scripts.
        pre = settings["hooks"]["PreToolUse"]
        cmds = [h["command"] for item in pre for h in item.get("hooks", [])]
        self.assertIn("/usr/local/bin/some-other-tool", cmds)
        for cmd in cmds:
            self.assertNotIn("unbound_", cmd)

        # Non-hook settings preserved.
        self.assertTrue(settings["someUnrelatedSetting"])

    def test_install_clear_roundtrip_no_third_party(self):
        """install then clear on a clean slate returns hooks.json to a state
        with no Unbound traces. ``hooks`` should be entirely gone."""
        self.setup.configure_antigravity_settings()
        self.setup.remove_hooks_from_settings()

        # The file may still exist but should have no `hooks` key.
        if self.setup.HOOKS_JSON_PATH.exists():
            with open(self.setup.HOOKS_JSON_PATH, "r", encoding="utf-8") as f:
                settings = json.load(f)
            self.assertNotIn("hooks", settings)

    def test_clear_when_nothing_installed(self):
        """clear with no hooks.json returns not_found and does nothing."""
        status = self.setup.remove_hooks_from_settings()
        self.assertEqual(status, "not_found")


class TestFullInstallFlow(unittest.TestCase):
    """Drive setup.main() end-to-end against an isolated HOME, mocking only
    the parts that touch the real network (callback server + backend POST)."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.home = Path(self.tmp)
        self._old_home = os.environ.get("HOME")
        self.setup = _reload_setup_with_home(self.home)

    def tearDown(self):
        if self._old_home is not None:
            os.environ["HOME"] = self._old_home
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_main_with_api_key_installs_files_and_settings(self):
        """``setup.py --api-key X`` writes hooks.json and both scripts."""
        old_argv = sys.argv
        sys.argv = ["setup.py", "--api-key", "test-api-key"]
        try:
            with patch.object(self.setup, "notify_setup_complete"):
                self.setup.main()
        finally:
            sys.argv = old_argv

        # hooks.json exists and lists only the two events agy actually fires.
        self.assertTrue(self.setup.HOOKS_JSON_PATH.exists())
        with open(self.setup.HOOKS_JSON_PATH, "r", encoding="utf-8") as f:
            settings = json.load(f)
        self.assertEqual(set(settings["hooks"].keys()), {"PreToolUse", "PostToolUse"})

        # Both hook scripts + _common.py exist on disk in ~/.unbound/antigravity-hooks/.
        for _event, installed_name in self.setup.HOOK_EVENT_SCRIPTS:
            self.assertTrue((self.setup.HOOKS_INSTALL_DIR / installed_name).exists())
        self.assertTrue((self.setup.HOOKS_INSTALL_DIR / "_common.py").exists())

        # Sentinel written.
        self.assertTrue(self.setup.SENTINEL_PATH.exists())

        # Unbound config got the API key.
        cfg_path = self.home / ".unbound" / "config.json"
        self.assertTrue(cfg_path.exists())
        with open(cfg_path, "r", encoding="utf-8") as f:
            cfg = json.load(f)
        self.assertEqual(cfg["api_key"], "test-api-key")

    def test_main_clear_after_install_returns_to_clean_state(self):
        """install --> clear should remove every artifact we wrote."""
        old_argv = sys.argv
        try:
            sys.argv = ["setup.py", "--api-key", "k"]
            with patch.object(self.setup, "notify_setup_complete"):
                self.setup.main()
            sys.argv = ["setup.py", "--clear"]
            self.setup.main()
        finally:
            sys.argv = old_argv

        # All installed scripts gone.
        for _event, installed_name in self.setup.HOOK_EVENT_SCRIPTS:
            self.assertFalse((self.setup.HOOKS_INSTALL_DIR / installed_name).exists())
        self.assertFalse((self.setup.HOOKS_INSTALL_DIR / "_common.py").exists())
        # Sentinel gone.
        self.assertFalse(self.setup.SENTINEL_PATH.exists())
        # hooks.json either gone or empty of hooks.
        if self.setup.HOOKS_JSON_PATH.exists():
            with open(self.setup.HOOKS_JSON_PATH, "r", encoding="utf-8") as f:
                settings = json.load(f)
            self.assertNotIn("hooks", settings)


class TestMatcherShape(unittest.TestCase):
    """Verify the matcher and event-key shape matches the agy wire format
    documented in AGY-EMPIRICAL-FINDINGS.md (catch-all matcher, only the two
    events agy actually fires)."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.home = Path(self.tmp)
        self.setup = _reload_setup_with_home(self.home)

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _find_our_entry(self, event_list, expected_script_substr):
        """Locate the entry whose hook command points at our installed script."""
        for item in event_list:
            for h in item.get("hooks", []):
                if expected_script_substr in h.get("command", ""):
                    return item
        return None

    def test_pre_tool_use_matcher_is_catch_all(self):
        """PreToolUse must use the empty-string catch-all so unknown tools
        (browser/*, notebook/*, subagent/*, future tools) still trigger our
        hook. Server-side filtering decides what's policy-relevant."""
        self.setup.configure_antigravity_settings()
        with open(self.setup.HOOKS_JSON_PATH, "r", encoding="utf-8") as f:
            settings = json.load(f)
        pre = settings["hooks"]["PreToolUse"]
        ours = self._find_our_entry(pre, "unbound_pre_tool_use.py")
        self.assertIsNotNone(ours, "our PreToolUse entry should be present")
        self.assertEqual(ours.get("matcher"), "")

    def test_post_tool_use_matcher_is_catch_all(self):
        self.setup.configure_antigravity_settings()
        with open(self.setup.HOOKS_JSON_PATH, "r", encoding="utf-8") as f:
            settings = json.load(f)
        post = settings["hooks"]["PostToolUse"]
        ours = self._find_our_entry(post, "unbound_post_tool_use.py")
        self.assertIsNotNone(ours, "our PostToolUse entry should be present")
        self.assertEqual(ours.get("matcher"), "")

    def test_matcher_does_not_allowlist_specific_tools(self):
        """Regression: no entry we write may use a regex allowlist like
        ``run_command|view_file|edit_file|...``. Any tool not in that list
        would silently bypass the gate."""
        self.setup.configure_antigravity_settings()
        with open(self.setup.HOOKS_JSON_PATH, "r", encoding="utf-8") as f:
            settings = json.load(f)
        for event in ("PreToolUse", "PostToolUse"):
            for item in settings["hooks"][event]:
                # Only inspect entries that include our hook script.
                if not any(
                    "unbound_" in h.get("command", "")
                    for h in item.get("hooks", [])
                ):
                    continue
                matcher = item.get("matcher", "")
                self.assertNotIn(
                    "|", matcher,
                    f"{event} matcher contains an allowlist: {matcher!r}",
                )


class TestNotifySetupCompleteNoCurl(unittest.TestCase):
    """Regression: ``notify_setup_complete`` MUST NOT shell out to ``curl``.
    Passing ``X-API-KEY: <key>`` on curl's argv leaks the key to any other
    user on the device via ``ps auxe`` / ``/proc/<pid>/cmdline``. The fix is
    to use stdlib urllib (headers stay inside the process). We assert that
    by putting a fake ``curl`` shim first on PATH and verifying it never
    gets invoked."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.home = Path(self.tmp)
        self.setup = _reload_setup_with_home(self.home)

        # Fake curl shim that logs every invocation. If we still shell to
        # curl, this log will contain entries.
        bin_dir = self.home / "bin"
        bin_dir.mkdir()
        self.curl_log = self.home / "curl.log"
        fake = bin_dir / "curl"
        fake.write_text(
            "#!/usr/bin/env python3\n"
            "import sys\n"
            f"with open({repr(str(self.curl_log))}, 'a') as f:\n"
            "    f.write(' '.join(sys.argv) + '\\n')\n"
            "sys.exit(0)\n"
        )
        os.chmod(fake, fake.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
        self._old_path = os.environ.get("PATH", "")
        os.environ["PATH"] = f"{bin_dir}{os.pathsep}{self._old_path}"

    def tearDown(self):
        os.environ["PATH"] = self._old_path
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_notify_setup_complete_does_not_invoke_curl(self):
        """Drive notify_setup_complete() at an unreachable URL and assert
        the curl shim was never executed. urllib raising URLError is fine —
        the point is that the secret never appeared on any argv."""
        # 127.0.0.1:1 is closed → urllib raises URLError. notify_setup_complete
        # is fail-soft (try/except), so the call returns cleanly.
        self.setup.notify_setup_complete(
            api_key="super-secret-key",
            backend_url="http://127.0.0.1:1",
        )
        self.assertFalse(
            self.curl_log.exists(),
            "curl was invoked from notify_setup_complete — API key leaked via argv",
        )


if __name__ == "__main__":
    unittest.main()
