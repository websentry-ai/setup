"""
Tests for account-identity helpers in augment/hooks/unbound.py.

Covers:
  - _email_domain
  - read_account_identity  (context.userEmail + ~/.unbound/config.json fallback)
  - build_account_identity
"""

import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import unbound


class _IsolatedConfig(unittest.TestCase):
    """Redirect unbound.UNBOUND_CONFIG_PATH at a temp file so the email fallback
    in read_account_identity never reads the developer's real
    ~/.unbound/config.json. UNBOUND_CONFIG_PATH is bound at import time, so we
    patch the module attribute directly (patching Path.home() would not reach
    it)."""

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
        self.assertEqual(unbound._email_domain("BOB@Corp.COM"), "corp.com")

    def test_strips_whitespace_in_domain(self):
        # whitespace after @ is stripped
        self.assertEqual(unbound._email_domain("x@ company.io "), "company.io")

    def test_none_input_returns_none(self):
        self.assertIsNone(unbound._email_domain(None))

    def test_empty_string_returns_none(self):
        self.assertIsNone(unbound._email_domain(""))

    def test_no_at_sign_returns_none(self):
        self.assertIsNone(unbound._email_domain("notanemail"))

    def test_empty_domain_after_at_returns_none(self):
        # "user@" → domain portion is "" → should be None
        self.assertIsNone(unbound._email_domain("user@"))


class TestReadAccountIdentity(_IsolatedConfig):
    """Auggie 0.30.0 does NOT deliver context.userEmail (the includeUserContext
    metadata flag is intentionally not seeded), so the email is normally read
    from the `email` field the installer writes into ~/.unbound/config.json.
    context.userEmail is still honored when present, for forward-compat with a
    future Auggie. There is no other on-disk account record, so
    org/plan/auth_mode are always None. The base class isolates the config path
    so no real file leaks in."""

    # --- context.userEmail still wins when present (forward-compat) ---------
    def test_reads_email_from_context(self):
        event = {"context": {"userEmail": "alice@example.com"}}
        result = unbound.read_account_identity(event)
        self.assertEqual(result["user_email"], "alice@example.com")

    def test_derives_email_domain_from_context(self):
        event = {"context": {"userEmail": "alice@example.com"}}
        result = unbound.read_account_identity(event)
        self.assertEqual(result["email_domain"], "example.com")

    def test_context_email_takes_precedence_over_config(self):
        """When BOTH are present, the injected context.userEmail wins (a future
        Auggie's live value beats the installer's stored fallback)."""
        self._write_config({"email": "stored@config.com"})
        event = {"context": {"userEmail": "live@context.com"}}
        result = unbound.read_account_identity(event)
        self.assertEqual(result["user_email"], "live@context.com")
        self.assertEqual(result["email_domain"], "context.com")

    def test_org_plan_auth_mode_always_none(self):
        event = {"context": {"userEmail": "alice@example.com"}}
        result = unbound.read_account_identity(event)
        self.assertIsNone(result["org_id"])
        self.assertIsNone(result["plan"])
        self.assertIsNone(result["auth_mode"])

    # --- config.json fallback when context is absent (the Auggie 0.30.0 path) -
    def test_falls_back_to_config_email_when_no_context(self):
        """No context (the real Auggie 0.30.0 event shape) -> email comes from
        ~/.unbound/config.json."""
        self._write_config({"api_key": "sk-x", "email": "bob@corp.io"})
        result = unbound.read_account_identity({})
        self.assertEqual(result["user_email"], "bob@corp.io")
        self.assertEqual(result["email_domain"], "corp.io")

    def test_config_fallback_when_context_email_blank(self):
        """A blank context.userEmail falls through to the config fallback."""
        self._write_config({"email": "carol@corp.io"})
        result = unbound.read_account_identity({"context": {"userEmail": "   "}})
        self.assertEqual(result["user_email"], "carol@corp.io")

    def test_blank_email_and_no_config_is_none(self):
        """Blank context email + no config file -> None (no real file leaks)."""
        event = {"context": {"userEmail": "   "}}
        result = unbound.read_account_identity(event)
        self.assertIsNone(result["user_email"])
        self.assertIsNone(result["email_domain"])

    def test_no_context_and_no_config_returns_all_nulls(self):
        """Neither context NOR config present -> every field None."""
        result = unbound.read_account_identity({})
        self.assertIsNone(result["org_id"])
        self.assertIsNone(result["plan"])
        self.assertIsNone(result["auth_mode"])
        self.assertIsNone(result["user_email"])
        self.assertIsNone(result["email_domain"])

    def test_config_without_email_field_returns_none(self):
        """A config.json that has no `email` key -> user_email None."""
        self._write_config({"api_key": "sk-only"})
        result = unbound.read_account_identity({})
        self.assertIsNone(result["user_email"])

    def test_corrupt_config_is_failsafe_none(self):
        """An unparseable config.json never raises -> user_email None."""
        self.config_path.write_text("{ not json")
        result = unbound.read_account_identity({})
        self.assertIsNone(result["user_email"])

    def test_none_event_falls_back_to_config(self):
        self._write_config({"email": "dave@corp.io"})
        result = unbound.read_account_identity(None)
        self.assertEqual(result["user_email"], "dave@corp.io")

    def test_none_event_and_no_config_returns_none(self):
        result = unbound.read_account_identity(None)
        self.assertIsNone(result["user_email"])

    def test_non_dict_context_falls_back_to_config(self):
        self._write_config({"email": "erin@corp.io"})
        result = unbound.read_account_identity({"context": "not-a-dict"})
        self.assertIsInstance(result, dict)
        self.assertEqual(result["user_email"], "erin@corp.io")

    def test_returns_dict_not_raise_on_garbage(self):
        try:
            result = unbound.read_account_identity({"context": {"userEmail": None}})
        except Exception as exc:
            self.fail(f"read_account_identity raised {exc!r}")
        self.assertIsNone(result["user_email"])


class TestBuildAccountIdentity(_IsolatedConfig):
    """build_account_identity() adds the device serial to read_account_identity.
    Inherits _IsolatedConfig so the email fallback can't read the real
    ~/.unbound/config.json."""

    def test_returns_full_identity(self):
        event = {"context": {"userEmail": "user@corp.com"}}
        # probe=False (default) reads serial cache only; mock it to None so the
        # test is deterministic regardless of host.
        with patch.object(unbound, "_device_serial", return_value=None):
            result = unbound.build_account_identity(event)
        self.assertEqual(result["user_email"], "user@corp.com")
        self.assertEqual(result["email_domain"], "corp.com")
        self.assertIsNone(result["org_id"])
        self.assertIsNone(result["plan"])
        self.assertIsNone(result["auth_mode"])

    def test_adds_device_serial_when_available(self):
        with patch.object(unbound, "_device_serial", return_value="SERIAL123"):
            result = unbound.build_account_identity({"context": {"userEmail": "a@b.com"}})
        self.assertEqual(result["device_serial"], "SERIAL123")

    def test_never_raises_on_bad_event(self):
        with patch.object(unbound, "_device_serial", return_value=None):
            result = unbound.build_account_identity("not-a-dict")
        self.assertIsInstance(result, dict)


if __name__ == "__main__":
    unittest.main()
