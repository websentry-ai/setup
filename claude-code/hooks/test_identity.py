"""
Tests for account-identity helpers in claude-code/hooks/unbound.py.

Covers:
  - _email_domain
  - read_account_identity  (CLAUDE_MCP_CONFIG_PATH variants)
"""

import json
import tempfile
import unittest
from pathlib import Path
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
    """Test read_account_identity() against a mocked CLAUDE_MCP_CONFIG_PATH."""

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.claude_json = self.tmp / ".claude.json"
        self._patcher = patch.object(unbound, "CLAUDE_MCP_CONFIG_PATH", self.claude_json)
        self._patcher.start()
        self.addCleanup(self._patcher.stop)

    def _write_config(self, data):
        self.claude_json.write_text(json.dumps(data), encoding="utf-8")

    # --- happy path: oauthAccount present ---

    def test_returns_org_id_from_oauth_account(self):
        self._write_config({
            "oauthAccount": {
                "organizationUuid": "org-abc-123",
                "emailAddress": "alice@example.com",
            }
        })
        result = unbound.read_account_identity()
        self.assertEqual(result["org_id"], "org-abc-123")

    def test_returns_email_domain_from_oauth_account(self):
        self._write_config({
            "oauthAccount": {
                "organizationUuid": "org-abc-123",
                "emailAddress": "alice@example.com",
            }
        })
        result = unbound.read_account_identity()
        self.assertEqual(result["email_domain"], "example.com")

    def test_auth_mode_is_subscription_for_oauth(self):
        self._write_config({
            "oauthAccount": {
                "organizationUuid": "org-abc-123",
                "emailAddress": "alice@example.com",
            }
        })
        result = unbound.read_account_identity()
        self.assertEqual(result["auth_mode"], "subscription")

    def test_plan_is_always_none(self):
        self._write_config({
            "oauthAccount": {
                "organizationUuid": "org-abc-123",
                "emailAddress": "alice@example.com",
            }
        })
        result = unbound.read_account_identity()
        self.assertIsNone(result["plan"])

    def test_org_id_none_when_uuid_missing_from_oauth(self):
        self._write_config({
            "oauthAccount": {
                "emailAddress": "alice@example.com",
            }
        })
        result = unbound.read_account_identity()
        self.assertIsNone(result["org_id"])

    def test_email_domain_none_when_email_missing_from_oauth(self):
        self._write_config({
            "oauthAccount": {
                "organizationUuid": "org-abc-123",
            }
        })
        result = unbound.read_account_identity()
        self.assertIsNone(result["email_domain"])

    # --- api_key path: no oauthAccount ---

    def test_auth_mode_api_key_when_anthropic_env_set(self):
        self._write_config({})
        with patch.dict("os.environ", {"ANTHROPIC_API_KEY": "sk-test-key"}):
            result = unbound.read_account_identity()
        self.assertEqual(result["auth_mode"], "api_key")

    def test_auth_mode_api_key_when_custom_api_key_approved(self):
        self._write_config({
            "customApiKeyResponses": {"approved": True}
        })
        with patch.dict("os.environ", {}, clear=False):
            # Ensure ANTHROPIC_API_KEY is unset for this test
            env_patcher = patch.dict("os.environ", {"ANTHROPIC_API_KEY": ""})
            env_patcher.start()
            try:
                # Remove from environ entirely
                import os
                old = os.environ.pop("ANTHROPIC_API_KEY", None)
                result = unbound.read_account_identity()
                if old is not None:
                    os.environ["ANTHROPIC_API_KEY"] = old
            finally:
                env_patcher.stop()
        self.assertEqual(result["auth_mode"], "api_key")

    # --- missing file ---

    def test_missing_file_returns_all_nulls(self):
        # claude_json was never written
        result = unbound.read_account_identity()
        self.assertIsNone(result["org_id"])
        self.assertIsNone(result["plan"])
        self.assertIsNone(result["auth_mode"])
        self.assertIsNone(result["email_domain"])

    def test_missing_file_does_not_raise(self):
        # Should return a dict, not raise
        result = unbound.read_account_identity()
        self.assertIsInstance(result, dict)

    # --- malformed file ---

    def test_malformed_json_returns_all_nulls(self):
        self.claude_json.write_text("{not valid json}", encoding="utf-8")
        result = unbound.read_account_identity()
        self.assertIsNone(result["org_id"])
        self.assertIsNone(result["auth_mode"])

    def test_malformed_json_does_not_raise(self):
        self.claude_json.write_text("{not valid json}", encoding="utf-8")
        try:
            unbound.read_account_identity()
        except Exception as exc:
            self.fail(f"read_account_identity raised {exc!r} on malformed JSON")

    def test_null_oauth_account_field_returns_nulls(self):
        self._write_config({"oauthAccount": None})
        result = unbound.read_account_identity()
        self.assertIsNone(result["org_id"])
        self.assertIsNone(result["auth_mode"])


class TestBuildAccountIdentity(unittest.TestCase):
    """build_account_identity() returns the full identity every call."""

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.claude_json = self.tmp / ".claude.json"
        self._patcher = patch.object(unbound, "CLAUDE_MCP_CONFIG_PATH", self.claude_json)
        self._patcher.start()
        self.addCleanup(self._patcher.stop)

    def _write_config(self, data):
        self.claude_json.write_text(json.dumps(data), encoding="utf-8")

    def test_returns_full_identity(self):
        self._write_config({
            "oauthAccount": {
                "organizationUuid": "org-111",
                "emailAddress": "user@corp.com",
            }
        })
        result = unbound.build_account_identity()
        self.assertEqual(result["org_id"], "org-111")
        self.assertEqual(result["email_domain"], "corp.com")
        self.assertEqual(result["auth_mode"], "subscription")
        self.assertIsNone(result["plan"])

    def test_keys_limited_to_identity_fields(self):
        self._write_config({})
        result = unbound.build_account_identity()
        self.assertEqual(
            set(result.keys()), {"org_id", "plan", "auth_mode", "email_domain"}
        )


if __name__ == "__main__":
    unittest.main()
