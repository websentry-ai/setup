"""
Tests for account-identity helpers in augment/hooks/unbound.py.

Covers:
  - _email_domain
  - read_account_identity  (context.userEmail variants)
  - build_account_identity
"""

import unittest
from unittest.mock import patch

import unbound


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


class TestReadAccountIdentity(unittest.TestCase):
    """Augment injects the signed-in user's email as context.userEmail on hooks
    whose matcher enables includeUserContext. There is no on-disk account
    record, so org/plan/auth_mode are always None."""

    def test_reads_email_from_context(self):
        event = {"context": {"userEmail": "alice@example.com"}}
        result = unbound.read_account_identity(event)
        self.assertEqual(result["user_email"], "alice@example.com")

    def test_derives_email_domain_from_context(self):
        event = {"context": {"userEmail": "alice@example.com"}}
        result = unbound.read_account_identity(event)
        self.assertEqual(result["email_domain"], "example.com")

    def test_org_plan_auth_mode_always_none(self):
        event = {"context": {"userEmail": "alice@example.com"}}
        result = unbound.read_account_identity(event)
        self.assertIsNone(result["org_id"])
        self.assertIsNone(result["plan"])
        self.assertIsNone(result["auth_mode"])

    def test_blank_email_is_normalized_to_none(self):
        event = {"context": {"userEmail": "   "}}
        result = unbound.read_account_identity(event)
        self.assertIsNone(result["user_email"])
        self.assertIsNone(result["email_domain"])

    def test_no_context_returns_all_nulls(self):
        result = unbound.read_account_identity({})
        self.assertIsNone(result["org_id"])
        self.assertIsNone(result["plan"])
        self.assertIsNone(result["auth_mode"])
        self.assertIsNone(result["user_email"])
        self.assertIsNone(result["email_domain"])

    def test_none_event_returns_all_nulls(self):
        result = unbound.read_account_identity(None)
        self.assertIsNone(result["user_email"])

    def test_non_dict_context_does_not_raise(self):
        result = unbound.read_account_identity({"context": "not-a-dict"})
        self.assertIsInstance(result, dict)
        self.assertIsNone(result["user_email"])

    def test_returns_dict_not_raise_on_garbage(self):
        try:
            result = unbound.read_account_identity({"context": {"userEmail": None}})
        except Exception as exc:
            self.fail(f"read_account_identity raised {exc!r}")
        self.assertIsNone(result["user_email"])


class TestBuildAccountIdentity(unittest.TestCase):
    """build_account_identity() adds the device serial to read_account_identity."""

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
