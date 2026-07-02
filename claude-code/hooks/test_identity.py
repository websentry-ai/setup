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
        # Isolate from the real Claude Desktop dir so the desktop-email fallback
        # finds nothing unless a test explicitly populates self.tmp.
        self._desktop_patcher = patch.object(
            unbound, "_claude_desktop_support_dirs", return_value=[self.tmp]
        )
        self._desktop_patcher.start()
        self.addCleanup(self._desktop_patcher.stop)

    def _write_config(self, data):
        self.claude_json.write_text(json.dumps(data), encoding="utf-8")

    def _write_desktop_session(self, oauth, name="s1"):
        session = (self.tmp / "local-agent-mode-sessions" / "acct" / "org"
                   / f"local_{name}" / ".claude" / ".claude.json")
        session.parent.mkdir(parents=True, exist_ok=True)
        session.write_text(json.dumps({"oauthAccount": oauth}), encoding="utf-8")
        return session

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

    def test_plan_from_organization_type(self):
        self._write_config({
            "oauthAccount": {
                "organizationUuid": "org-abc-123",
                "emailAddress": "alice@example.com",
                "organizationType": "claude_max",
            }
        })
        result = unbound.read_account_identity()
        self.assertEqual(result["plan"], "claude_max")

    def test_plan_raw_value_not_normalized(self):
        self._write_config({
            "oauthAccount": {
                "organizationUuid": "org-abc-123",
                "organizationType": "claude_enterprise",
            }
        })
        result = unbound.read_account_identity()
        self.assertEqual(result["plan"], "claude_enterprise")

    def test_plan_none_when_organization_type_missing(self):
        self._write_config({
            "oauthAccount": {
                "organizationUuid": "org-abc-123",
                "emailAddress": "alice@example.com",
            }
        })
        result = unbound.read_account_identity()
        self.assertIsNone(result["plan"])

    def test_plan_none_in_api_key_mode(self):
        self._write_config({})
        with patch.dict("os.environ", {"ANTHROPIC_API_KEY": "sk-test-key"}):
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

    # --- Team/SSO Claude Desktop fallback ---

    def test_falls_back_to_desktop_email_when_no_oauth(self):
        # ~/.claude.json has no oauthAccount (Team/SSO desktop case)
        self._write_config({"someKey": True})
        self._write_desktop_session({"emailAddress": "team@corp.com"})
        result = unbound.read_account_identity()
        self.assertEqual(result["user_email"], "team@corp.com")
        self.assertEqual(result["email_domain"], "corp.com")

    def test_primary_oauth_email_wins_over_desktop_fallback(self):
        self._write_config({"oauthAccount": {"emailAddress": "primary@corp.com"}})
        self._write_desktop_session({"emailAddress": "stale@corp.com"})
        result = unbound.read_account_identity()
        self.assertEqual(result["user_email"], "primary@corp.com")

    def test_blank_when_no_oauth_and_no_desktop_session(self):
        self._write_config({"someKey": True})
        result = unbound.read_account_identity()
        self.assertIsNone(result["user_email"])
        self.assertIsNone(result["email_domain"])

    def test_whitespace_primary_email_falls_back_to_desktop(self):
        # a whitespace-only primary email must not block the fallback
        self._write_config({"oauthAccount": {"emailAddress": "   "}})
        self._write_desktop_session({"emailAddress": "team@corp.com"})
        result = unbound.read_account_identity()
        self.assertEqual(result["user_email"], "team@corp.com")


class TestBuildAccountIdentity(unittest.TestCase):
    """build_account_identity() returns the full identity every call."""

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.claude_json = self.tmp / ".claude.json"
        self._patcher = patch.object(unbound, "CLAUDE_MCP_CONFIG_PATH", self.claude_json)
        self._patcher.start()
        self.addCleanup(self._patcher.stop)
        # Isolate from the real machine: no desktop sessions, no device serial,
        # so key-set assertions are deterministic across hosts.
        for name, val in (("_claude_desktop_support_dirs", [self.tmp]),
                          ("_device_serial", None)):
            p = patch.object(unbound, name, return_value=val)
            p.start()
            self.addCleanup(p.stop)

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
        # device_serial is omitted when unavailable (patched to None in setUp);
        # user_email is always present.
        self._write_config({})
        result = unbound.build_account_identity()
        self.assertEqual(
            set(result.keys()),
            {"org_id", "plan", "auth_mode", "user_email", "email_domain"},
        )


class TestClaudeDesktopSupportDirs(unittest.TestCase):
    def test_darwin_path(self):
        with patch.object(unbound.platform, "system", return_value="Darwin"):
            dirs = unbound._claude_desktop_support_dirs()
        self.assertEqual(
            dirs, [Path.home() / "Library" / "Application Support" / "Claude"]
        )

    def test_linux_path(self):
        with patch.object(unbound.platform, "system", return_value="Linux"):
            dirs = unbound._claude_desktop_support_dirs()
        self.assertEqual(dirs, [Path.home() / ".config" / "Claude"])

    def test_windows_path_with_appdata(self):
        with patch.object(unbound.platform, "system", return_value="Windows"), \
             patch.dict("os.environ", {"APPDATA": r"C:\Users\t\AppData\Roaming"}):
            dirs = unbound._claude_desktop_support_dirs()
        self.assertEqual([str(d) for d in dirs], [str(Path(r"C:\Users\t\AppData\Roaming") / "Claude")])

    def test_windows_path_without_appdata_returns_empty(self):
        with patch.object(unbound.platform, "system", return_value="Windows"):
            env = {k: v for k, v in __import__("os").environ.items() if k != "APPDATA"}
            with patch.dict("os.environ", env, clear=True):
                dirs = unbound._claude_desktop_support_dirs()
        self.assertEqual(dirs, [])


class TestDesktopSessionEmail(unittest.TestCase):
    """_desktop_session_email(): returns the email only when all sessions agree;
    disagreement or any failure yields None (blank over wrong). Fail-open."""

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self._patcher = patch.object(
            unbound, "_claude_desktop_support_dirs", return_value=[self.tmp]
        )
        self._patcher.start()
        self.addCleanup(self._patcher.stop)

    def _session(self, name, payload, mtime):
        import os
        p = (self.tmp / "local-agent-mode-sessions" / "acct" / "org"
             / f"local_{name}" / ".claude" / ".claude.json")
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(payload, encoding="utf-8")
        os.utime(p, (mtime, mtime))
        return p

    def test_returns_none_when_no_sessions(self):
        self.assertIsNone(unbound._desktop_session_email())

    def test_missing_base_dir_returns_none(self):
        with patch.object(unbound, "_claude_desktop_support_dirs",
                          return_value=[self.tmp / "nope"]):
            self.assertIsNone(unbound._desktop_session_email())

    def test_returns_email_when_all_sessions_agree(self):
        # same address across sessions (common: one email spanning Max + Team orgs)
        self._session("a", json.dumps({"oauthAccount": {"emailAddress": "user@corp.com"}}), 1000)
        self._session("b", json.dumps({"oauthAccount": {"emailAddress": "User@Corp.com"}}), 2000)
        self.assertEqual(unbound._desktop_session_email(), "User@Corp.com")

    def test_returns_none_when_sessions_disagree(self):
        # two different accounts on disk → cannot tell which is active → blank over wrong
        self._session("old", json.dumps({"oauthAccount": {"emailAddress": "old@corp.com"}}), 1000)
        self._session("new", json.dumps({"oauthAccount": {"emailAddress": "new@corp.com"}}), 2000)
        self.assertIsNone(unbound._desktop_session_email())

    def test_ignores_sessions_without_email_when_others_agree(self):
        self._session("hasemail", json.dumps({"oauthAccount": {"emailAddress": "found@corp.com"}}), 1000)
        self._session("noemail", json.dumps({"oauthAccount": {}}), 2000)
        self._session("nooauth", json.dumps({"something": True}), 3000)
        self.assertEqual(unbound._desktop_session_email(), "found@corp.com")

    def test_blank_email_is_ignored(self):
        self._session("blank", json.dumps({"oauthAccount": {"emailAddress": "  "}}), 2000)
        self.assertIsNone(unbound._desktop_session_email())

    def test_non_string_email_is_ignored(self):
        self._session("weird", json.dumps({"oauthAccount": {"emailAddress": 12345}}), 2000)
        self.assertIsNone(unbound._desktop_session_email())

    def test_oversized_session_file_is_skipped(self):
        big = "x" * (unbound._DESKTOP_SESSION_MAX_BYTES + 10)
        self._session("big", json.dumps({"oauthAccount": {"emailAddress": "big@corp.com"}, "pad": big}), 2000)
        self.assertIsNone(unbound._desktop_session_email())

    def test_never_raises_on_malformed_json(self):
        self._session("bad", "{not json", 2000)
        try:
            self.assertIsNone(unbound._desktop_session_email())
        except Exception as exc:
            self.fail(f"_desktop_session_email raised {exc!r}")


if __name__ == "__main__":
    unittest.main()
