"""
Tests for account identity in copilot/hooks/unbound.py.

The account is the GitHub login Copilot itself records on sign-in. The
installer's email is deliberately not used: it names the device's owner, not
the Copilot account, and reporting it would dress a signed-out machine as a
signed-in one.
"""

import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from tests.conftest import tool_module

unbound = tool_module("copilot/hooks")

SIGNED_IN = '// User settings\n{"lastLoggedInUser":{"host":"https://github.com","login":"octocat"}}'


class _IsolatedConfig(unittest.TestCase):
    """Point the hook at a temp config so it never reads the developer's own."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.config_path = Path(self._tmp.name) / "config.json"
        self._patch = patch.object(unbound, "_copilot_config_path",
                                   return_value=self.config_path)
        self._patch.start()
        self.addCleanup(self._patch.stop)

    def _write(self, body: str):
        self.config_path.write_text(body, encoding="utf-8")


class TestCopilotConfigPath(unittest.TestCase):
    def test_uses_the_relocated_copilot_home(self):
        with patch.dict(os.environ, {"COPILOT_HOME": "/tmp/custom-copilot"}):
            self.assertEqual(unbound._copilot_config_path(),
                             Path("/tmp/custom-copilot/config.json"))


class TestEmailDomain(unittest.TestCase):
    def test_returns_domain_for_normal_address(self):
        self.assertEqual(unbound._email_domain("alice@example.com"), "example.com")

    def test_a_login_has_no_domain(self):
        self.assertIsNone(unbound._email_domain("octocat"))

    def test_none_input_returns_none(self):
        self.assertIsNone(unbound._email_domain(None))


class TestCopilotLogin(_IsolatedConfig):
    def test_reads_the_login_past_the_jsonc_comment(self):
        """The file opens with // User settings, which json.loads alone rejects."""
        self._write(SIGNED_IN)
        self.assertEqual(unbound._copilot_login(), ("octocat", "https://github.com"))

    def test_plain_json_works_too(self):
        self._write('{"lastLoggedInUser":{"host":"https://github.com","login":"devuser"}}')
        self.assertEqual(unbound._copilot_login()[0], "devuser")

    def test_falls_back_to_the_logged_in_users_list(self):
        self._write('{"loggedInUsers":[{"host":"https://x.ghe.com","login":"ghe-user"}]}')
        self.assertEqual(unbound._copilot_login(), ("ghe-user", "https://x.ghe.com"))

    def test_signed_out_yields_nothing(self):
        self._write('// User settings\n{"appTipShown":true}')
        self.assertEqual(unbound._copilot_login(), (None, None))

    def test_a_missing_file_yields_nothing(self):
        self.assertEqual(unbound._copilot_login(), (None, None))

    def test_an_unreadable_file_is_logged(self):
        """Signed out and corrupt both report nothing, so the failure has to say so."""
        self._write("{not json")
        with patch.object(unbound, "log_error") as logged:
            self.assertEqual(unbound._copilot_login(), (None, None))
        self.assertEqual(logged.call_count, 1)


class TestReadAccountIdentity(_IsolatedConfig):
    def test_the_login_is_never_sent_as_an_email(self):
        """user_email becomes device.email, which provisions users by address."""
        self._write(SIGNED_IN)
        self.assertIsNone(unbound.read_account_identity()["user_email"])

    def test_exposes_the_login_without_calling_it_an_email(self):
        self._write(SIGNED_IN)
        identity = unbound.read_account_identity()
        self.assertEqual(identity["account_login"], "octocat")
        self.assertEqual(identity["account_host"], "https://github.com")

    def test_a_signed_in_seat_reports_its_auth_mode(self):
        self._write(SIGNED_IN)
        self.assertEqual(unbound.read_account_identity()["auth_mode"], "subscription")

    def test_org_and_plan_are_never_known(self):
        """A Copilot seat carries neither where the CLI can read it."""
        self._write(SIGNED_IN)
        identity = unbound.read_account_identity()
        self.assertIsNone(identity["org_id"])
        self.assertIsNone(identity["plan"])

    def test_a_login_carries_no_domain(self):
        self._write(SIGNED_IN)
        self.assertIsNone(unbound.read_account_identity()["email_domain"])

    def test_signed_out_reports_nothing_at_all(self):
        self._write('// User settings\n{"appTipShown":true}')
        identity = unbound.read_account_identity()
        self.assertIsNone(identity["user_email"])
        self.assertIsNone(identity["account_login"])
        self.assertIsNone(identity["account_host"])
        self.assertIsNone(identity["auth_mode"])

    def test_the_installer_email_is_not_used(self):
        """It names the device owner, not the Copilot account."""
        self._write('// User settings\n{"appTipShown":true}')
        with patch.object(unbound, "UNBOUND_CONFIG_PATH", Path("/nonexistent")):
            self.assertIsNone(unbound.read_account_identity()["user_email"])


class TestBuildAccountIdentity(_IsolatedConfig):
    def test_adds_device_serial(self):
        self._write(SIGNED_IN)
        with patch.object(unbound, "_device_serial", return_value="SERIAL1"):
            self.assertEqual(unbound.build_account_identity()["device_serial"], "SERIAL1")

    def test_omits_device_serial_when_unavailable(self):
        self._write(SIGNED_IN)
        with patch.object(unbound, "_device_serial", return_value=None):
            self.assertNotIn("device_serial", unbound.build_account_identity())

    def test_never_raises_when_the_serial_probe_fails(self):
        self._write(SIGNED_IN)
        with patch.object(unbound, "_device_serial", side_effect=OSError("boom")):
            self.assertEqual(unbound.build_account_identity()["account_login"], "octocat")

    def test_never_raises_when_the_identity_read_fails(self):
        with patch.object(unbound, "read_account_identity", side_effect=OSError("boom")):
            with patch.object(unbound, "_device_serial", return_value=None):
                self.assertEqual(unbound.build_account_identity(), {})


if __name__ == "__main__":
    unittest.main()
