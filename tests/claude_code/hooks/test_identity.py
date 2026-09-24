"""
Tests for account-identity helpers in claude-code/hooks/unbound.py.

Covers:
  - _email_domain
  - read_account_identity  (CLAUDE_MCP_CONFIG_PATH and Cowork session variants)
"""

import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from tests.conftest import tool_module

unbound = tool_module("claude-code/hooks")
# Taken before any fixture redirects it.
REAL_MANAGED_SETTINGS_DIRS = unbound.MANAGED_SETTINGS_DIRS
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

    def test_auth_mode_subscription_when_oauth_omits_email(self):
        # oauthAccount present but no emailAddress must still yield auth_mode
        self._write_config({"oauthAccount": {"organizationUuid": "org-x"}})
        result = unbound.read_account_identity()
        self.assertEqual(result["auth_mode"], "subscription")
        self.assertEqual(result["org_id"], "org-x")
        self.assertIsNone(result["user_email"])


class TestGatewayHostAsTheAccount(unittest.TestCase):
    """Claude Code run through a company gateway has no Anthropic sign-in, so the
    endpoint it talks to stands in as the account's org."""

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.claude_json = self.tmp / ".claude.json"
        for target, value in (("CLAUDE_MCP_CONFIG_PATH", self.claude_json),
                              ("USER_SETTINGS_PATH", self.tmp / "settings.json"),
                              ("MANAGED_SETTINGS_DIRS", (self.tmp,))):
            p = patch.object(unbound, target, value)
            p.start()
            self.addCleanup(p.stop)
        p = patch.object(unbound, "_claude_desktop_support_dirs", return_value=[self.tmp])
        p.start()
        self.addCleanup(p.stop)
        self.claude_json.write_text("{}", encoding="utf-8")

    def _settings(self, name, base_url):
        path = self.tmp / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps({"env": {"ANTHROPIC_BASE_URL": base_url}}), encoding="utf-8")

    def test_the_env_base_url_host_is_the_org(self):
        with patch.dict(os.environ, {"ANTHROPIC_BASE_URL": "https://llm.acme.internal/v1/anthropic"}):
            identity = unbound.read_account_identity()
        self.assertEqual(identity["org_id"], "llm.acme.internal")
        self.assertIsNone(identity["user_email"])

    def test_managed_settings_supply_it_when_the_env_does_not(self):
        self._settings("managed-settings.json", "https://gateway.acme.com")
        self.assertEqual(unbound.read_account_identity()["org_id"], "gateway.acme.com")

    def test_the_user_settings_are_the_last_resort(self):
        self._settings("settings.json", "https://llm.acme.com:8080/proxy")
        self.assertEqual(unbound.read_account_identity()["org_id"], "llm.acme.com")

    def test_unbounds_own_gateway_is_not_an_account(self):
        """Our gateway installers point every customer's Claude Code at it."""
        for url in ("https://api.getunbound.ai", "https://zendesk-gateway.getunbound.ai/v1"):
            with patch.dict(os.environ, {"ANTHROPIC_BASE_URL": url}):
                self.assertIsNone(unbound.read_account_identity()["org_id"], url)

    def test_the_hooks_own_tenant_gateway_is_not_an_account(self):
        with patch.object(unbound, "UNBOUND_GATEWAY_URL", "https://gw.tenant.example"), \
                patch.dict(os.environ, {"ANTHROPIC_BASE_URL": "https://gw.tenant.example/anthropic"}):
            self.assertIsNone(unbound.read_account_identity()["org_id"])

    def test_a_loopback_proxy_is_not_an_account(self):
        for url in ("http://localhost:4000", "http://127.0.0.1:8080"):
            with patch.dict(os.environ, {"ANTHROPIC_BASE_URL": url}):
                self.assertIsNone(unbound.read_account_identity()["org_id"], url)

    def test_the_env_wins_without_reading_any_settings_file(self):
        """build_account_identity runs on the latency-critical pre-tool path."""
        with patch.object(unbound, "_settings_base_url", side_effect=AssertionError("read")), \
                patch.dict(os.environ, {"ANTHROPIC_BASE_URL": "https://llm.acme.internal"}):
            self.assertEqual(unbound._gateway_host(), "llm.acme.internal")

    def test_an_unbound_env_url_is_not_overridden_by_stale_settings(self):
        """Claude Code uses the env value, so a settings file must not replace it."""
        self._settings("settings.json", "https://llm.acme.com")
        with patch.dict(os.environ, {"ANTHROPIC_BASE_URL": "https://api.getunbound.ai"}):
            self.assertIsNone(unbound.read_account_identity()["org_id"])

    def test_only_the_host_is_kept(self):
        with patch.dict(os.environ, {"ANTHROPIC_BASE_URL": "https://user:secret@llm.acme.com:8443/path?key=abc"}):
            self.assertEqual(unbound.read_account_identity()["org_id"], "llm.acme.com")

    def test_a_signed_in_account_keeps_its_own_org(self):
        self.claude_json.write_text(json.dumps({"oauthAccount": {
            "organizationUuid": "org-abc", "emailAddress": "dev@acme.com"}}), encoding="utf-8")
        with patch.dict(os.environ, {"ANTHROPIC_BASE_URL": "https://llm.acme.internal"}):
            self.assertEqual(unbound.read_account_identity()["org_id"], "org-abc")

    def test_no_base_url_anywhere_means_no_org(self):
        self.assertIsNone(unbound.read_account_identity()["org_id"])

    def test_an_auth_token_marks_it_an_api_key_setup(self):
        with patch.dict(os.environ, {"ANTHROPIC_AUTH_TOKEN": "t", "ANTHROPIC_BASE_URL": "https://llm.acme.internal"}):
            self.assertEqual(unbound.read_account_identity()["auth_mode"], "api_key")

    def test_a_managed_drop_in_is_read(self):
        """The MDM install writes managed-settings.d/unbound.json, not the base file."""
        self._settings("managed-settings.d/unbound.json", "https://gateway.acme.com")
        self.assertEqual(unbound.read_account_identity()["org_id"], "gateway.acme.com")

    def test_a_drop_in_overrides_the_base_managed_file(self):
        self._settings("managed-settings.json", "https://old.acme.com")
        self._settings("managed-settings.d/50-gateway.json", "https://new.acme.com")
        self.assertEqual(unbound.read_account_identity()["org_id"], "new.acme.com")

    def test_only_this_oss_managed_dir_is_read(self):
        """Another OS's path would resolve against the working directory."""
        self.assertEqual(len(REAL_MANAGED_SETTINGS_DIRS), 1)
        self.assertTrue(REAL_MANAGED_SETTINGS_DIRS[0].is_absolute())

    def test_each_os_gets_the_installers_managed_dir(self):
        for system, expected in (("Darwin", "/Library/Application Support/ClaudeCode"),
                                 ("Linux", "/etc/claude-code")):
            with patch.object(unbound.platform, "system", return_value=system):
                self.assertEqual(unbound._managed_settings_dirs(), (Path(expected),))
        with patch.object(unbound.platform, "system", return_value="Windows"), \
                patch.dict(os.environ, {"ProgramFiles": r"D:\Apps"}):
            (windows,) = unbound._managed_settings_dirs()
        self.assertIn("Apps", str(windows))
        self.assertTrue(str(windows).endswith("ClaudeCode"))
        self.assertNotIn("ProgramData", str(windows))

    def test_a_corrupt_settings_file_is_skipped(self):
        (self.tmp / "managed-settings.json").write_text("{not json", encoding="utf-8")
        self._settings("settings.json", "https://gateway.acme.com")
        self.assertEqual(unbound.read_account_identity()["org_id"], "gateway.acme.com")


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

    def test_oversized_session_forces_blank(self):
        big = "x" * (unbound._DESKTOP_SESSION_MAX_BYTES + 10)
        self._session("big", json.dumps({"oauthAccount": {"emailAddress": "big@corp.com"}, "pad": big}), 2000)
        self.assertIsNone(unbound._desktop_session_email())

    def test_oversized_newer_session_forces_blank_not_stale(self):
        # newest session is oversized (unverifiable) -> must NOT fall through to an
        # older readable session's possibly-stale email
        big = "x" * (unbound._DESKTOP_SESSION_MAX_BYTES + 10)
        self._session("old", json.dumps({"oauthAccount": {"emailAddress": "old@corp.com"}}), 1000)
        self._session("new", json.dumps({"oauthAccount": {"emailAddress": "new@corp.com"}, "pad": big}), 2000)
        self.assertIsNone(unbound._desktop_session_email())

    def test_unreadable_newer_session_forces_blank_not_stale(self):
        # malformed newest session is a blind spot -> blank over a stale older email
        self._session("old", json.dumps({"oauthAccount": {"emailAddress": "old@corp.com"}}), 1000)
        self._session("new", "{not json", 2000)
        self.assertIsNone(unbound._desktop_session_email())

    def test_never_raises_on_malformed_json(self):
        self._session("bad", "{not json", 2000)
        try:
            self.assertIsNone(unbound._desktop_session_email())
        except Exception as exc:
            self.fail(f"_desktop_session_email raised {exc!r}")

    def test_glob_traversal_error_in_one_base_does_not_abort_scan(self):
        # a base whose glob raises mid-traversal must not kill the whole scan
        class _Raising:
            def glob(self, pattern):
                raise PermissionError("boom")

        class _BadBase:
            def __truediv__(self, other):
                return _Raising()

        self._session("ok", json.dumps({"oauthAccount": {"emailAddress": "ok@corp.com"}}), 2000)
        with patch.object(unbound, "_claude_desktop_support_dirs",
                          return_value=[_BadBase(), self.tmp]):
            self.assertEqual(unbound._desktop_session_email(), "ok@corp.com")


class TestDesktopSessionIdentity(unittest.TestCase):
    """_desktop_session_dir / _desktop_session_identity: a Cowork run reports the
    organization of the session it belongs to, taken from the session path."""

    ACCT = "cde7482a-446f-43c9-91b3-f480675a45c4"
    ORG = "3e9f466f-645a-44fe-af6f-4f8259823234"

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self._patcher = patch.object(
            unbound, "_claude_desktop_support_dirs", return_value=[self.tmp]
        )
        self._patcher.start()
        self.addCleanup(self._patcher.stop)
        # resolve(): on macOS the temp dir is a /var -> /private/var symlink and
        # the helper resolves before comparing.
        self.session = (self.tmp / "local-agent-mode-sessions" / self.ACCT
                        / self.ORG / "local_abc").resolve()

    def _config(self, oauth, session=None):
        p = (session or self.session) / ".claude" / ".claude.json"
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(json.dumps({"oauthAccount": oauth}), encoding="utf-8")
        return p

    def _oauth(self, **over):
        payload = {
            "accountUuid": self.ACCT,
            "organizationUuid": self.ORG,
            "emailAddress": "user@corp.com",
            "organizationType": "claude_enterprise",
        }
        payload.update(over)
        return payload

    def test_session_dir_from_cwd(self):
        event = {"cwd": str(self.session / "outputs")}
        self.assertEqual(unbound._desktop_session_dir(event), self.session)

    def test_session_dir_from_transcript_path(self):
        event = {"transcript_path": str(self.session / ".claude" / "projects" / "p" / "t.jsonl")}
        self.assertEqual(unbound._desktop_session_dir(event), self.session)

    def test_session_dir_from_the_session_root_itself(self):
        self.assertEqual(unbound._desktop_session_dir({"cwd": str(self.session)}), self.session)

    def test_session_dir_none_for_a_plain_repo_cwd(self):
        self.assertIsNone(unbound._desktop_session_dir({"cwd": "/Users/dev/repo"}))

    def test_session_dir_none_for_a_tree_outside_the_support_dir(self):
        # A planted tree elsewhere on disk is not this user's Claude Desktop.
        outside = Path(tempfile.mkdtemp()) / "local-agent-mode-sessions" / "a" / "b" / "local_c"
        self.assertIsNone(unbound._desktop_session_dir({"cwd": str(outside)}))

    def test_session_dir_none_without_a_local_session_segment(self):
        stray = self.tmp / "local-agent-mode-sessions" / self.ACCT / self.ORG / "cowork_plugins"
        self.assertIsNone(unbound._desktop_session_dir({"cwd": str(stray)}))

    def test_session_dir_none_for_a_non_dict_event(self):
        self.assertIsNone(unbound._desktop_session_dir("not-a-dict"))
        self.assertIsNone(unbound._desktop_session_dir(None))

    def test_identity_is_the_path_organization_only(self):
        # The config is never read: it lives inside the sandbox, so an agent
        # running there could name any email or plan it liked.
        self._config(self._oauth())
        self.assertEqual(
            unbound._desktop_session_identity({"cwd": str(self.session)}),
            {"org_id": self.ORG, "auth_mode": "subscription"},
        )

    def test_org_id_survives_a_missing_config(self):
        self.assertEqual(
            unbound._desktop_session_identity({"cwd": str(self.session)}),
            {"org_id": self.ORG, "auth_mode": "subscription"},
        )

    def test_a_rewritten_config_cannot_change_the_reported_identity(self):
        # The sandbox-writable config claims an approved-looking domain and a
        # different plan; neither reaches the gate.
        self._config(self._oauth(emailAddress="ceo@approved-corp.com",
                                 organizationType="claude_enterprise"))
        identity = unbound._desktop_session_identity({"cwd": str(self.session)})
        self.assertEqual(identity, {"org_id": self.ORG, "auth_mode": "subscription"})
        self.assertNotIn("user_email", identity)
        self.assertNotIn("plan", identity)

    def test_malformed_config_keeps_the_path_org(self):
        p = self.session / ".claude" / ".claude.json"
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text("{not json", encoding="utf-8")
        self.assertEqual(
            unbound._desktop_session_identity({"cwd": str(self.session)}),
            {"org_id": self.ORG, "auth_mode": "subscription"},
        )

    def test_no_session_returns_empty(self):
        self.assertEqual(unbound._desktop_session_identity({"cwd": "/tmp"}), {})

    def test_never_raises(self):
        for event in (None, "x", {}, {"cwd": None}, {"cwd": 5}, {"transcript_path": []}):
            try:
                unbound._desktop_session_identity(event)
            except Exception as exc:
                self.fail(f"_desktop_session_identity raised {exc!r} for {event!r}")


class TestReadAccountIdentityForCowork(unittest.TestCase):
    """read_account_identity(event): the Cowork session wins over ~/.claude.json,
    which describes the CLI's account and not the session's."""

    ORG = "7b274105-463a-431c-b894-cc97cf580b2b"

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.session = (self.tmp / "local-agent-mode-sessions" / "acct"
                        / self.ORG / "local_abc")
        cfg = self.session / ".claude" / ".claude.json"
        cfg.parent.mkdir(parents=True, exist_ok=True)
        cfg.write_text(json.dumps({"oauthAccount": {
            "organizationUuid": self.ORG,
            "emailAddress": "dev@corp.com",
            "organizationType": "claude_enterprise",
        }}), encoding="utf-8")
        p = patch.object(unbound, "_claude_desktop_support_dirs", return_value=[self.tmp])
        p.start()
        self.addCleanup(p.stop)
        self.event = {"cwd": str(self.session / "outputs")}

    def _home_config(self, payload):
        p = self.tmp / "home.claude.json"
        p.write_text(json.dumps(payload), encoding="utf-8")
        return patch.object(unbound, "CLAUDE_MCP_CONFIG_PATH", p)

    def test_cowork_reports_its_own_org(self):
        # The Desktop-only case: ~/.claude.json never gets oauthAccount, so this
        # is the whole of WEB-5650's false ORG_NOT_APPROVED refusals. The email
        # comes from the all-sessions-agree scan, not from this session's own
        # config, and the plan is not reported at all.
        with self._home_config({}):
            self.assertEqual(unbound.read_account_identity(self.event), {
                "org_id": self.ORG, "plan": None,
                "auth_mode": "subscription", "user_email": None,
                "email_domain": None,
            })

    def test_cowork_session_wins_over_a_different_cli_account(self):
        with self._home_config({"oauthAccount": {
            "organizationUuid": "personal-org", "emailAddress": "me@gmail.com",
            "organizationType": "claude_max",
        }}):
            result = unbound.read_account_identity(self.event)
        self.assertEqual(result["org_id"], self.ORG)
        self.assertIsNone(result["plan"])
        self.assertIsNone(result["user_email"])

    def test_cowork_never_takes_an_email_from_the_agree_scan(self):
        # The scan reads the same sandbox-writable session configs, and a machine
        # with one session agrees with itself, so a rewritten address would pass
        # the agreement rule unchallenged.
        with self._home_config({}):
            self.assertIsNone(unbound.read_account_identity(self.event)["user_email"])

    def test_cli_email_never_pairs_with_a_cowork_organization(self):
        # The gate admits a request on an organization OR a domain match, so
        # carrying the CLI account's approved domain beside this session's
        # unapproved organization would let the session through.
        import shutil
        shutil.rmtree(self.session / ".claude")
        with self._home_config({"oauthAccount": {
            "organizationUuid": "personal-org",
            "emailAddress": "ceo@approved-corp.com",
            "organizationType": "claude_enterprise",
        }}):
            result = unbound.read_account_identity(self.event)
        self.assertEqual(result["org_id"], self.ORG)
        self.assertIsNone(result["user_email"])
        self.assertIsNone(result["email_domain"])
        self.assertIsNone(result["plan"])

    def test_claude_code_run_is_unaffected(self):
        with self._home_config({"oauthAccount": {
            "organizationUuid": "personal-org", "emailAddress": "me@gmail.com",
            "organizationType": "claude_max",
        }}):
            self.assertEqual(unbound.read_account_identity({"cwd": "/Users/dev/repo"}), {
                "org_id": "personal-org", "plan": "claude_max",
                "auth_mode": "subscription", "user_email": "me@gmail.com",
                "email_domain": "gmail.com",
            })

    def test_no_event_is_unaffected(self):
        with self._home_config({"oauthAccount": {
            "organizationUuid": "personal-org", "emailAddress": "me@gmail.com",
        }}):
            self.assertEqual(unbound.read_account_identity()["org_id"], "personal-org")



if __name__ == "__main__":
    unittest.main()
