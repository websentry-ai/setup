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


class TestPerLineRemovalAcrossRcFiles(unittest.TestCase):
    """A user has two startup files and either may hold an export. Judging ownership from
    one collapsed value and then deleting every matching line takes a foreign endpoint
    away with ours, or leaves ours behind."""

    OURS = "https://tenant.getunbound.ai"
    THEIRS = "https://llm.acme-corp.internal"

    def setUp(self):
        self.home = _home_with_config(gateway_url=self.OURS)
        self.patcher = patch.object(setup.platform, "system", lambda: "Darwin")
        self.patcher.start()
        self.addCleanup(self.patcher.stop)

    def _write(self, name, *lines):
        (self.home / name).write_text("".join(line + "\n" for line in lines))

    def _remove(self):
        return setup._remove_env_var_lines_for_user(
            None, self.home, "ANTHROPIC_BASE_URL",
            lambda value: setup._is_unbound_base_url(value, self.home))

    def _lines(self, name):
        return (self.home / name).read_text().splitlines()

    def test_ours_goes_and_theirs_stays_when_they_share_a_file(self):
        self._write(".zprofile",
                    'export ANTHROPIC_BASE_URL="%s"' % self.THEIRS,
                    'export ANTHROPIC_BASE_URL="%s"' % self.OURS)
        self.assertEqual(self._remove(), "cleared")
        self.assertEqual(self._lines(".zprofile"),
                         ['export ANTHROPIC_BASE_URL="%s"' % self.THEIRS])

    def test_theirs_in_the_other_file_survives(self):
        # the last export read wins the collapsed value, so ours is the one judged
        self._write(".zprofile", 'export ANTHROPIC_BASE_URL="%s"' % self.THEIRS)
        self._write(".bash_profile", 'export ANTHROPIC_BASE_URL="%s"' % self.OURS)
        self.assertEqual(self._remove(), "cleared")
        self.assertEqual(self._lines(".zprofile"),
                         ['export ANTHROPIC_BASE_URL="%s"' % self.THEIRS])
        self.assertEqual(self._lines(".bash_profile"), [])

    def test_ours_in_the_earlier_file_is_still_removed(self):
        # and here the collapsed value is theirs, which would have skipped ours entirely
        self._write(".zprofile", 'export ANTHROPIC_BASE_URL="%s"' % self.OURS)
        self._write(".bash_profile", 'export ANTHROPIC_BASE_URL="%s"' % self.THEIRS)
        self.assertEqual(self._remove(), "cleared")
        self.assertEqual(self._lines(".zprofile"), [])
        self.assertEqual(self._lines(".bash_profile"),
                         ['export ANTHROPIC_BASE_URL="%s"' % self.THEIRS])

    def test_only_a_foreign_export_is_left_untouched(self):
        self._write(".zprofile", 'export ANTHROPIC_BASE_URL="%s"' % self.THEIRS)
        self.assertEqual(self._remove(), "skipped")
        self.assertEqual(self._lines(".zprofile"),
                         ['export ANTHROPIC_BASE_URL="%s"' % self.THEIRS])

    def test_unrelated_lines_are_preserved(self):
        self._write(".zprofile",
                    "export PATH=/usr/local/bin:$PATH",
                    'export ANTHROPIC_BASE_URL="%s"' % self.OURS,
                    'export ANTHROPIC_AUTH_TOKEN="keep-me"')
        self.assertEqual(self._remove(), "cleared")
        self.assertEqual(self._lines(".zprofile"),
                         ["export PATH=/usr/local/bin:$PATH",
                          'export ANTHROPIC_AUTH_TOKEN="keep-me"'])

    def test_no_export_at_all(self):
        self._write(".zprofile", "export PATH=/usr/local/bin:$PATH")
        self.assertEqual(self._remove(), "not_found")

    def test_a_symlinked_rc_file_is_refused(self):
        target = Path(tempfile.mkdtemp()) / "elsewhere"
        target.write_text('export ANTHROPIC_BASE_URL="%s"\n' % self.OURS)
        (self.home / ".zprofile").symlink_to(target)
        self.assertEqual(self._remove(), "not_found")
        self.assertIn(self.OURS, target.read_text())


class TestBaseUrlGateNeedsOurKeyBesideIt(unittest.TestCase):
    def setUp(self):
        self.home = _home_with_config()
        for target, attr, value in (
                (setup.platform, "system", lambda: "Darwin"),
                # the privilege drop has its own tests; here it only has to not need root
                (setup, "_run_as_user", lambda _u, fn, *a, **k: fn(*a, **k))):
            patcher = patch.object(target, attr, value)
            patcher.start()
            self.addCleanup(patcher.stop)

    def test_a_foreign_endpoint_with_no_unbound_key_is_left_alone(self):
        (self.home / ".zprofile").write_text(
            'export ANTHROPIC_BASE_URL="https://llm.acme-corp.internal"\n')
        self.assertEqual(
            setup.remove_unbound_base_url_from_user("u", self.home), "not_found")
        self.assertIn("acme-corp", (self.home / ".zprofile").read_text())

    def test_our_pair_is_cleared(self):
        (self.home / ".zprofile").write_text(
            'export ANTHROPIC_BASE_URL="https://tenant.getunbound.ai"\n'
            'export UNBOUND_API_KEY="user-key"\n')
        self.assertEqual(
            setup.remove_unbound_base_url_from_user("u", self.home), "cleared")
        self.assertEqual((self.home / ".zprofile").read_text(),
                         'export UNBOUND_API_KEY="user-key"\n')


class TestWindowsMachineEnvIsOwnershipChecked(unittest.TestCase):
    """MDM writes the machine-wide environment on Windows, so an ownership check that only
    knows shell rc files answers None there and every device is skipped."""

    def setUp(self):
        self.patcher = patch.object(setup.platform, "system", lambda: "Windows")
        self.patcher.start()
        self.addCleanup(self.patcher.stop)
        self.home = _home_with_config()

    @staticmethod
    def _reg_output(value):
        return ("\nHKEY_LOCAL_MACHINE\\SYSTEM\\...\\Environment\n"
                "    ANTHROPIC_BASE_URL    REG_SZ    %s\n" % value)

    def _with_reg(self, value):
        class _Result:
            returncode = 0
            stdout = self._reg_output(value)
        return patch.object(setup.subprocess, "run", lambda *a, **k: _Result())

    def test_the_machine_value_is_what_ownership_is_judged_on(self):
        with self._with_reg("https://tenant.getunbound.ai"):
            self.assertEqual(
                setup._owned_env_value(self.home, "ANTHROPIC_BASE_URL"),
                "https://tenant.getunbound.ai")

    def test_a_foreign_machine_value_is_not_removed(self):
        removed = []
        with self._with_reg("https://llm.acme-corp.internal"), \
             patch.object(setup, "remove_env_var_on_windows_machine", removed.append):
            status = setup._remove_env_var_lines_for_user(
                None, self.home, "ANTHROPIC_BASE_URL",
                lambda value: setup._is_unbound_base_url(value, self.home))
        self.assertEqual(status, "skipped")
        self.assertEqual(removed, [])

    def test_our_machine_value_is_removed(self):
        removed = []
        with self._with_reg("https://tenant.getunbound.ai"), \
             patch.object(setup, "remove_env_var_on_windows_machine",
                          lambda var: (removed.append(var), "cleared")[1]):
            status = setup._remove_env_var_lines_for_user(
                None, self.home, "ANTHROPIC_BASE_URL",
                lambda value: setup._is_unbound_base_url(value, self.home))
        self.assertEqual(status, "cleared")
        self.assertEqual(removed, ["ANTHROPIC_BASE_URL"])

    def test_an_absent_machine_value_is_not_found(self):
        class _Result:
            returncode = 1
            stdout = ""
        with patch.object(setup.subprocess, "run", lambda *a, **k: _Result()):
            self.assertEqual(
                setup._remove_env_var_lines_for_user(
                    None, self.home, "ANTHROPIC_BASE_URL", lambda value: True),
                "not_found")


class TestKeyHelperIsReadAsItsOwner(unittest.TestCase):
    def test_a_helper_inside_a_home_resolves_to_that_user(self):
        home = Path(tempfile.mkdtemp())
        helper = home / ".claude" / "anthropic_key.sh"
        helper.parent.mkdir()
        helper.write_text('#!/bin/sh\necho "$UNBOUND_API_KEY"\n')
        with patch.object(setup, "get_all_user_homes", lambda: [("alice", home)]):
            self.assertEqual(setup._home_owner_of(helper), "alice")

    def test_a_system_path_has_no_owning_user(self):
        with patch.object(setup, "get_all_user_homes",
                          lambda: [("alice", Path(tempfile.mkdtemp()))]):
            self.assertIsNone(
                setup._home_owner_of(Path("/Library/Application Support/x.sh")))

    def test_the_owner_is_who_the_helper_is_read_as(self):
        home = Path(tempfile.mkdtemp())
        helper = home / ".claude" / "anthropic_key.sh"
        helper.parent.mkdir()
        helper.write_text('echo "$UNBOUND_API_KEY"\n')
        seen = []
        with patch.object(setup, "get_all_user_homes", lambda: [("alice", home)]), \
             patch.object(setup, "_read_user_file",
                          lambda username, path: (seen.append(username),
                                                  Path(path).read_text())[1]):
            self.assertTrue(setup._key_helper_file_is_ours(helper))
        self.assertEqual(seen, ["alice"])


class TestAnyUserKeyCheckReadsAsThatUser(unittest.TestCase):
    def test_each_users_config_is_read_under_their_own_name(self):
        home = _home_with_config(api_key="alice-key")
        seen = []
        with patch.object(setup, "get_all_user_homes", lambda: [("alice", home)]), \
             patch.object(setup, "_read_user_file",
                          lambda username, path: (seen.append(username),
                                                  Path(path).read_text())[1]):
            self.assertTrue(setup._is_unbound_api_key_any_user("alice-key"))
        self.assertEqual(seen, ["alice"])

    def test_a_foreign_credential_matches_nobody(self):
        home = _home_with_config(api_key="alice-key")
        with patch.object(setup, "get_all_user_homes", lambda: [("alice", home)]):
            self.assertFalse(setup._is_unbound_api_key_any_user("sk-ant-someone-elses"))


class TestRegExeIsNotTakenFromTheEnvironment(unittest.TestCase):
    def test_a_planted_system_root_does_not_move_reg_exe(self):
        with patch.dict(setup.os.environ, {"SystemRoot": r"C:\Users\mallory\evil"}):
            self.assertEqual(setup._reg_exe(), r"C:\Windows\System32\reg.exe")


class TestOwnershipIsDecidedOutsideThePrivilegeDrop(unittest.TestCase):
    """A second _run_as_user nested inside the first cannot call setgroups, so it returns
    None and every ownership question answers "not ours"."""

    def test_the_drop_is_never_reentered(self):
        home = _home_with_config(gateway_url="https://tenant.getunbound.ai")
        (home / ".zprofile").write_text(
            'export ANTHROPIC_BASE_URL="https://tenant.getunbound.ai"\n')
        depth = []
        deepest = []

        def _tracked(_username, fn, *args, **kwargs):
            depth.append(1)
            deepest.append(len(depth))
            try:
                return fn(*args, **kwargs)
            finally:
                depth.pop()

        with patch.object(setup.platform, "system", lambda: "Darwin"), \
             patch.object(setup, "_run_as_user", _tracked):
            status = setup._remove_env_var_lines_for_user(
                "alice", home, "ANTHROPIC_BASE_URL",
                lambda value: setup._is_unbound_base_url(value, home, "alice"))

        self.assertEqual(status, "cleared")
        self.assertTrue(deepest, "the privilege drop was never used")
        self.assertEqual(max(deepest), 1)
