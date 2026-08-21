"""
Tests that MDM ownership checks answer correctly in the context they run in.

MDM runs as root against other users' homes, so a check that consults Path.home() reads
/root and matches nothing, and a read that follows a symlink reads whatever the user
pointed it at. Covers:
  - _is_unbound_api_key / _is_unbound_base_url  (per-user config)
  - _user_env_value                             (privilege-dropped, symlink-refusing)
  - _managed_key_helper_paths / _is_unbound_key_helper
"""

import importlib.util
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

# Loaded by path: several trees in this repo have a module named `setup`, and importing
# it plainly makes whichever ran first win for all of them.
_spec = importlib.util.spec_from_file_location(
    "unbound_claude_hooks_mdm_setup", Path(__file__).resolve().parent / "setup.py")
setup = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(setup)


def _home_with_config(gateway_url="https://tenant.getunbound.ai", api_key="user-key"):
    home = Path(tempfile.mkdtemp())
    (home / ".unbound").mkdir()
    (home / ".unbound" / "config.json").write_text(
        json.dumps({"gateway_url": gateway_url, "api_key": api_key}))
    return home


class TestOwnershipReadsTheTargetUsersConfig(unittest.TestCase):
    def setUp(self):
        self.user_home = _home_with_config()
        self.root_home = Path(tempfile.mkdtemp())  # no config, as /root would have

    def test_the_users_recorded_key_matches(self):
        with patch.object(setup.Path, "home", staticmethod(lambda: self.root_home)):
            self.assertTrue(setup._is_unbound_api_key("user-key", self.user_home))

    def test_roots_home_does_not_decide(self):
        with patch.object(setup.Path, "home", staticmethod(lambda: self.root_home)):
            self.assertFalse(setup._is_unbound_api_key("user-key"))

    def test_a_tenant_specific_gateway_url_is_recognised(self):
        with patch.object(setup.Path, "home", staticmethod(lambda: self.root_home)):
            self.assertTrue(setup._is_unbound_base_url(
                "https://tenant.getunbound.ai", self.user_home))

    def test_a_foreign_endpoint_is_still_not_ours(self):
        with patch.object(setup.Path, "home", staticmethod(lambda: self.root_home)):
            self.assertFalse(setup._is_unbound_base_url(
                "https://llm.acme-corp.internal", self.user_home))


class TestPerUserRcRead(unittest.TestCase):
    def _read(self, home, name):
        with patch.object(setup.platform, "system", lambda: "Darwin"), \
             patch.object(setup, "_run_as_user", lambda _u, fn, *a, **k: fn(*a, **k)):
            return setup._user_env_value(home, name, "someone")

    def test_reads_the_values_a_user_persisted(self):
        home = Path(tempfile.mkdtemp())
        (home / ".zprofile").write_text(
            'export ANTHROPIC_BASE_URL="https://tenant.getunbound.ai"\n'
            'export UNBOUND_API_KEY="user-key"\n')
        self.assertEqual(self._read(home, "ANTHROPIC_BASE_URL"),
                         "https://tenant.getunbound.ai")
        self.assertEqual(self._read(home, "UNBOUND_API_KEY"), "user-key")

    def test_an_absent_variable(self):
        home = Path(tempfile.mkdtemp())
        (home / ".zprofile").write_text("export PATH=/usr/bin\n")
        self.assertIsNone(self._read(home, "ANTHROPIC_BASE_URL"))

    def test_a_symlinked_rc_file_is_refused(self):
        home = Path(tempfile.mkdtemp())
        elsewhere = Path(tempfile.mkdtemp()) / "secret"
        elsewhere.write_text('export UNBOUND_API_KEY="root-only"\n')
        (home / ".zprofile").symlink_to(elsewhere)
        self.assertIsNone(self._read(home, "UNBOUND_API_KEY"))


class TestManagedKeyHelperPaths(unittest.TestCase):
    def setUp(self):
        self.managed = Path("/Library/Application Support/ClaudeCode")

    def _paths(self):
        with patch.object(setup, "get_managed_settings_dir", lambda: self.managed):
            return setup._managed_key_helper_paths()

    def test_the_managed_helper_is_matched(self):
        paths = self._paths()
        self.assertTrue(setup._is_unbound_key_helper(
            str(self.managed / "anthropic_key.sh"), paths))

    def test_a_foreign_managed_path_is_not(self):
        self.assertFalse(setup._is_unbound_key_helper("/opt/acme/their_key.sh",
                                                      self._paths()))

    def test_the_per_user_path_still_matches(self):
        self.assertTrue(setup._is_unbound_key_helper("~/.claude/anthropic_key.sh",
                                                     self._paths()))


if __name__ == "__main__":
    unittest.main()
