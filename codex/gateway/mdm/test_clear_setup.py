"""Tests for the MDM gateway clear path.

`sudo unbound nuke` clears the USER-level Codex (gateway) config before the MDM
one, so by the time this script's clear runs, openai_base_url is normally already
gone. "Nothing to remove" must therefore report success — treating it as a
failure made every `sudo unbound nuke` report `Codex (gateway)` as broken.

Loaded via importlib under a unique module name: several tools in this repo ship
a `setup.py`, so a bare `from setup import ...` collides across a pytest session.
"""
import importlib.util
import os
import tempfile
import unittest
from pathlib import Path

_SPEC = importlib.util.spec_from_file_location(
    "codex_gateway_mdm_setup", Path(__file__).resolve().parent / "setup.py"
)
setup = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(setup)


class TestRemoveCodexConfigBaseUrlForUser(unittest.TestCase):
    """Tri-state contract: "cleared" | "not_found" | "failed"."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.home = Path(self.tmp) / "alice"
        (self.home / ".codex").mkdir(parents=True)
        self.config = self.home / ".codex" / "config.toml"
        # No root here, so run the closure in-process instead of privilege-dropping.
        self._real_run_as_user = setup._run_as_user
        setup._run_as_user = lambda username, fn, *a, **k: fn(*a, **k)

    def tearDown(self):
        setup._run_as_user = self._real_run_as_user

    def _call(self):
        return setup.remove_codex_config_base_url_for_user("alice", self.home)

    def test_key_present_is_cleared_and_stripped(self):
        self.config.write_text(
            'openai_base_url = "https://api.getunbound.ai/v1"\nmodel = "gpt-5"\n'
        )
        self.assertEqual(self._call(), "cleared")
        self.assertNotIn("openai_base_url", self.config.read_text())
        self.assertIn('model = "gpt-5"', self.config.read_text())

    def test_config_exists_without_key_is_not_found(self):
        self.config.write_text('model = "gpt-5"\n\n[features]\njs_repl = false\n')
        self.assertEqual(self._call(), "not_found")

    def test_missing_config_is_not_found(self):
        self.assertEqual(self._call(), "not_found")

    def test_only_root_level_key_is_removed(self):
        self.config.write_text(
            'model = "gpt-5"\n\n[profiles.other]\nopenai_base_url = "https://elsewhere"\n'
        )
        self.assertEqual(self._call(), "not_found")
        self.assertIn("https://elsewhere", self.config.read_text())

    def test_privilege_drop_or_io_failure_is_failed(self):
        self.config.write_text('openai_base_url = "https://api.getunbound.ai/v1"\n')
        setup._run_as_user = lambda username, fn, *a, **k: None
        self.assertEqual(self._call(), "failed")

    def test_real_run_as_user_failure_maps_to_failed(self):
        """Exercises the REAL _run_as_user (no stub): an unresolvable user makes
        pwd.getpwnam raise, _run_as_user returns None, and that must be "failed"
        rather than being mistaken for "nothing to remove"."""
        self.config.write_text('openai_base_url = "https://api.getunbound.ai/v1"\n')
        setup._run_as_user = self._real_run_as_user
        status = setup.remove_codex_config_base_url_for_user(
            "unbound-no-such-user-web5259", self.home
        )
        self.assertEqual(status, "failed")
        # The key must survive a failed removal — no silent partial teardown.
        self.assertIn("openai_base_url", self.config.read_text())

    def test_unexpected_status_passes_through(self):
        """An unrecognised status is returned verbatim, never coerced to success."""
        self.config.write_text('openai_base_url = "https://api.getunbound.ai/v1"\n')
        setup._run_as_user = lambda username, fn, *a, **k: "fail"
        self.assertNotIn(self._call(), ("cleared", "not_found"))


class TestClearSetupExitStatus(unittest.TestCase):
    """clear_setup() drives the CLI's per-tool pass/fail line in `nuke`."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.home = Path(self.tmp) / "alice"
        (self.home / ".codex").mkdir(parents=True)
        self.config = self.home / ".codex" / "config.toml"
        self._saved = (
            setup.check_admin_privileges,
            setup.get_all_user_homes,
            setup._run_as_user,
            os.environ.get("HOME"),
        )
        setup.check_admin_privileges = lambda: True
        setup.get_all_user_homes = lambda: [("alice", self.home)]
        setup._run_as_user = lambda username, fn, *a, **k: fn(*a, **k)
        # Keep the env-var sweep inside the temp home.
        os.environ["HOME"] = str(self.home)

    def tearDown(self):
        (
            setup.check_admin_privileges,
            setup.get_all_user_homes,
            setup._run_as_user,
            home,
        ) = self._saved
        if home is not None:
            os.environ["HOME"] = home

    def test_nothing_left_to_clear_still_succeeds(self):
        """The `sudo unbound nuke` case: user-level clear already stripped the key."""
        self.config.write_text('model = "gpt-5"\n')
        self.assertTrue(setup.clear_setup())

    def test_no_codex_config_at_all_succeeds(self):
        self.assertTrue(setup.clear_setup())

    def test_key_present_is_removed_and_succeeds(self):
        self.config.write_text('openai_base_url = "https://api.getunbound.ai/v1"\n')
        self.assertTrue(setup.clear_setup())
        self.assertNotIn("openai_base_url", self.config.read_text())

    def test_real_removal_failure_still_fails(self):
        self.config.write_text('openai_base_url = "https://api.getunbound.ai/v1"\n')
        real = setup.remove_codex_config_base_url_for_user
        setup.remove_codex_config_base_url_for_user = lambda u, h: "failed"
        try:
            self.assertFalse(setup.clear_setup())
        finally:
            setup.remove_codex_config_base_url_for_user = real

    def test_unrecognised_status_fails_closed(self):
        """clear_setup must not read a typo'd/unknown status as success."""
        self.config.write_text('openai_base_url = "https://api.getunbound.ai/v1"\n')
        real = setup.remove_codex_config_base_url_for_user
        setup.remove_codex_config_base_url_for_user = lambda u, h: "fail"
        try:
            self.assertFalse(setup.clear_setup())
        finally:
            setup.remove_codex_config_base_url_for_user = real

    def test_one_user_failing_among_many_still_fails(self):
        """Absence is tolerated per-user, but a real failure must not be masked."""
        bob = Path(self.tmp) / "bob"
        (bob / ".codex").mkdir(parents=True)
        setup.get_all_user_homes = lambda: [("alice", self.home), ("bob", bob)]
        real = setup.remove_codex_config_base_url_for_user
        setup.remove_codex_config_base_url_for_user = (
            lambda u, h: "failed" if u == "bob" else "not_found"
        )
        try:
            self.assertFalse(setup.clear_setup())
        finally:
            setup.remove_codex_config_base_url_for_user = real

    def test_requires_root(self):
        setup.check_admin_privileges = lambda: False
        self.assertFalse(setup.clear_setup())


if __name__ == "__main__":
    unittest.main()
