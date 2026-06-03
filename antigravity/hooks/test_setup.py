"""Integration tests for antigravity/hooks/setup.py.

Run from this directory (or anywhere) with:

    cd antigravity/hooks && python3 -m unittest test_setup.py -v

These tests exercise the actual setup entrypoint — they call into
``setup.configure_antigravity_settings``, ``setup.remove_hooks_from_settings``,
and the top-level ``setup.main`` against an isolated ``HOME`` so the real
``~/.antigravity`` is never touched.
"""

import json
import os
import shutil
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch


# Make ``setup`` importable when tests are run from this directory.
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))


def _reload_setup_with_home(home: Path):
    """Re-import setup with HOME pointing at the given temp dir so the
    module-level path constants (ANTIGRAVITY_DIR, SETTINGS_PATH, etc.) all
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
    """Verify the non-destructive merge into ~/.antigravity/settings.json."""

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
        """Pre-seed settings.json with an unrelated third-party hook so we
        can verify our merge doesn't clobber it."""
        self.setup.SETTINGS_PATH.parent.mkdir(parents=True, exist_ok=True)
        third_party = {
            "hooks": {
                "PreToolUse": [
                    {
                        "matcher": "Bash",
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
        with open(self.setup.SETTINGS_PATH, "w", encoding="utf-8") as f:
            json.dump(third_party, f)
        return third_party

    def test_install_creates_settings_when_absent(self):
        """install with no pre-existing settings.json writes a valid file."""
        ok = self.setup.configure_antigravity_settings()
        self.assertTrue(ok)
        self.assertTrue(self.setup.SETTINGS_PATH.exists())
        with open(self.setup.SETTINGS_PATH, "r", encoding="utf-8") as f:
            settings = json.load(f)
        # All four events should have one entry — ours.
        for event in ("PreToolUse", "PostToolUse", "UserPromptSubmit", "SessionStart"):
            self.assertIn(event, settings["hooks"])
            self.assertEqual(len(settings["hooks"][event]), 1)

    def test_install_preserves_third_party_hooks(self):
        """Pre-existing third-party hooks must survive our install."""
        original = self._seed_third_party_settings()
        ok = self.setup.configure_antigravity_settings()
        self.assertTrue(ok)
        with open(self.setup.SETTINGS_PATH, "r", encoding="utf-8") as f:
            settings = json.load(f)

        # Third-party Bash hook must still be present in PreToolUse.
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
        with open(self.setup.SETTINGS_PATH, "r", encoding="utf-8") as f:
            first = f.read()
        self.setup.configure_antigravity_settings()
        with open(self.setup.SETTINGS_PATH, "r", encoding="utf-8") as f:
            second = f.read()
        self.assertEqual(first, second)

    def test_clear_removes_only_our_entries(self):
        """After install + clear, only our entries are removed; third-party
        hooks and other settings are intact."""
        original = self._seed_third_party_settings()
        self.setup.configure_antigravity_settings()

        status = self.setup.remove_hooks_from_settings()
        self.assertEqual(status, "cleared")

        with open(self.setup.SETTINGS_PATH, "r", encoding="utf-8") as f:
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
        """install then clear on a clean slate returns settings.json to a state
        with no Unbound traces. ``hooks`` should be entirely gone."""
        self.setup.configure_antigravity_settings()
        self.setup.remove_hooks_from_settings()

        # The file may still exist but should have no `hooks` key.
        if self.setup.SETTINGS_PATH.exists():
            with open(self.setup.SETTINGS_PATH, "r", encoding="utf-8") as f:
                settings = json.load(f)
            self.assertNotIn("hooks", settings)

    def test_clear_when_nothing_installed(self):
        """clear with no settings.json returns not_found and does nothing."""
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
        """``setup.py --api-key X`` writes settings.json and all four scripts."""
        old_argv = sys.argv
        sys.argv = ["setup.py", "--api-key", "test-api-key"]
        try:
            with patch.object(self.setup, "notify_setup_complete"):
                self.setup.main()
        finally:
            sys.argv = old_argv

        # Settings file exists and lists every event.
        self.assertTrue(self.setup.SETTINGS_PATH.exists())
        with open(self.setup.SETTINGS_PATH, "r", encoding="utf-8") as f:
            settings = json.load(f)
        for event in ("PreToolUse", "PostToolUse", "UserPromptSubmit", "SessionStart"):
            self.assertIn(event, settings["hooks"])

        # All four hook scripts + _common.py exist on disk.
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
        # settings.json either gone or empty of hooks.
        if self.setup.SETTINGS_PATH.exists():
            with open(self.setup.SETTINGS_PATH, "r", encoding="utf-8") as f:
                settings = json.load(f)
            self.assertNotIn("hooks", settings)


class TestMatcherShape(unittest.TestCase):
    """Verify the matcher and event-key shape matches the Antigravity wire
    format documented in the spike (PascalCase keys, regex alternation,
    case-insensitive ``bash``/``Bash``)."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.home = Path(self.tmp)
        self.setup = _reload_setup_with_home(self.home)

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_pre_tool_use_matcher_covers_both_bash_casings(self):
        self.setup.configure_antigravity_settings()
        with open(self.setup.SETTINGS_PATH, "r", encoding="utf-8") as f:
            settings = json.load(f)
        pre = settings["hooks"]["PreToolUse"]
        # Our entry is the only one — find it and check matcher.
        matchers = [item.get("matcher", "") for item in pre]
        self.assertTrue(any("bash" in m and "Bash" in m for m in matchers))

    def test_user_prompt_submit_has_no_matcher(self):
        self.setup.configure_antigravity_settings()
        with open(self.setup.SETTINGS_PATH, "r", encoding="utf-8") as f:
            settings = json.load(f)
        ups = settings["hooks"]["UserPromptSubmit"]
        # Our entry should NOT have a matcher key.
        for item in ups:
            self.assertNotIn("matcher", item)


if __name__ == "__main__":
    unittest.main()
