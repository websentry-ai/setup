"""
Tests for account-identity helpers in copilot/hooks/unbound.py.

Covers:
  - _email_domain
  - read_account_identity  (~/.unbound/config.json is the only source)
  - build_account_identity
"""

import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from tests.conftest import tool_module

unbound = tool_module("copilot/hooks")


class _IsolatedConfig(unittest.TestCase):
    """Redirect unbound.UNBOUND_CONFIG_PATH at a temp file so read_account_identity
    never reads the developer's real ~/.unbound/config.json. UNBOUND_CONFIG_PATH is
    bound at import time, so we patch the module attribute directly."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.config_path = Path(self._tmp.name) / "config.json"
        self._patch = patch.object(unbound, "UNBOUND_CONFIG_PATH", self.config_path)
        self._patch.start()
        self.addCleanup(self._patch.stop)

    def _write_config(self, config: dict):
        self.config_path.write_text(json.dumps(config))


class TestEmailDomain(unittest.TestCase):
    def test_returns_domain_for_normal_address(self):
        self.assertEqual(unbound._email_domain("alice@example.com"), "example.com")

    def test_returns_lowercase(self):
        self.assertEqual(unbound._email_domain("Alice@Example.COM"), "example.com")

    def test_none_input_returns_none(self):
        self.assertIsNone(unbound._email_domain(None))

    def test_no_at_sign_returns_none(self):
        self.assertIsNone(unbound._email_domain("not-an-address"))

    def test_empty_domain_after_at_returns_none(self):
        self.assertIsNone(unbound._email_domain("alice@"))


class TestReadAccountIdentity(_IsolatedConfig):
    def test_reads_email_from_config(self):
        self._write_config({"email": "dev@acme.com"})
        self.assertEqual(unbound.read_account_identity()["user_email"], "dev@acme.com")

    def test_derives_email_domain(self):
        self._write_config({"email": "dev@acme.com"})
        self.assertEqual(unbound.read_account_identity()["email_domain"], "acme.com")

    def test_org_plan_auth_mode_always_none(self):
        """The Copilot CLI exposes none of these; the gateway resolves the org
        from the API key instead."""
        self._write_config({"email": "dev@acme.com"})
        identity = unbound.read_account_identity()
        self.assertIsNone(identity["org_id"])
        self.assertIsNone(identity["plan"])
        self.assertIsNone(identity["auth_mode"])

    def test_missing_config_returns_all_nulls(self):
        identity = unbound.read_account_identity()
        self.assertIsNone(identity["user_email"])
        self.assertIsNone(identity["email_domain"])

    def test_config_without_email_field_returns_none(self):
        self._write_config({"org_name": "acme"})
        self.assertIsNone(unbound.read_account_identity()["user_email"])

    def test_blank_email_returns_none(self):
        self._write_config({"email": "   "})
        self.assertIsNone(unbound.read_account_identity()["user_email"])

    def test_corrupt_config_is_failsafe_none(self):
        self.config_path.write_text("{not json")
        self.assertIsNone(unbound.read_account_identity()["user_email"])


class TestBuildAccountIdentity(_IsolatedConfig):
    def test_adds_device_serial(self):
        self._write_config({"email": "dev@acme.com"})
        with patch.object(unbound, "_device_serial", return_value="SERIAL1"):
            self.assertEqual(unbound.build_account_identity()["device_serial"], "SERIAL1")

    def test_omits_device_serial_when_unavailable(self):
        self._write_config({"email": "dev@acme.com"})
        with patch.object(unbound, "_device_serial", return_value=None):
            self.assertNotIn("device_serial", unbound.build_account_identity())

    def test_never_raises_when_identity_read_fails(self):
        with patch.object(unbound, "read_account_identity", side_effect=OSError("boom")):
            with patch.object(unbound, "_device_serial", return_value=None):
                self.assertEqual(unbound.build_account_identity(), {})

    def test_never_raises_when_serial_probe_fails(self):
        self._write_config({"email": "dev@acme.com"})
        with patch.object(unbound, "_device_serial", side_effect=OSError("boom")):
            self.assertEqual(
                unbound.build_account_identity()["user_email"], "dev@acme.com"
            )


if __name__ == "__main__":
    unittest.main()
