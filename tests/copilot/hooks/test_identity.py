"""
Tests for account identity in copilot/hooks/unbound.py.

The account is the GitHub login Copilot itself records on sign-in. The
installer's email is deliberately not used: it names the device's owner, not
the Copilot account, and reporting it would dress a signed-out machine as a
signed-in one.
"""

import json
import os
import sqlite3
import tempfile
import unittest
import unittest.mock
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
        self.vscode_dirs = [Path(self._tmp.name) / "Code" / "User",
                            Path(self._tmp.name) / "Code - Insiders" / "User"]
        vscode = patch.object(unbound, "_vscode_user_dirs", return_value=self.vscode_dirs)
        vscode.start()
        self.addCleanup(vscode.stop)
        env = patch.dict(os.environ, {})
        env.start()
        self.addCleanup(env.stop)
        for var in unbound._COPILOT_CLI_TOKEN_VARS:
            os.environ.pop(var, None)
        self.credential = patch.object(unbound, "_copilot_cli_credential", return_value=None)
        self.credential.start()
        self.addCleanup(self.credential.stop)
        self.user_cache_path = Path(self._tmp.name) / "copilot-user-cache.json"
        user_cache = patch.object(unbound, "_copilot_user_cache_path", return_value=self.user_cache_path)
        user_cache.start()
        self.addCleanup(user_cache.stop)
        self._user_cache_entries = {}

    def _write(self, body: str):
        self.config_path.write_text(body, encoding="utf-8")

    def _user_cache(self, login, sku="copilot_for_business_seat_quota", orgs=("acme",), at="2026-09-30T04:16:13.733Z"):
        """Add one GitHub copilot_internal/user answer to Copilot's user cache, the way Copilot writes it."""
        self._user_cache_entries["v1:%d" % len(self._user_cache_entries)] = {
            "schemaVersion": 1, "generation": "g", "retrievedAt": at,
            "response": {"login": login, "copilot_plan": "business", "access_type_sku": sku,
                         "organization_list": [{"id": 1, "login": o, "name": o.title()} for o in orgs]}}
        self.user_cache_path.write_text(
            "// Disposable cache for Copilot user responses, safe to delete. Managed automatically.\n"
            + json.dumps({"copilotUserCache": self._user_cache_entries}), encoding="utf-8")

    def _vscode(self, login="vs-user", sku="copilot_for_business_seat", orgs=None, install=0, mtime=None):
        """Write a VS Code globalStorage/state.vscdb the way VS Code keeps it."""
        path = self.vscode_dirs[install] / "globalStorage" / "state.vscdb"
        path.parent.mkdir(parents=True, exist_ok=True)
        chat = {"exp.github.copilot.organizationList": orgs or []}
        if sku is not None:
            chat["exp.github.copilot.sku"] = sku
        with sqlite3.connect(path) as db:
            db.execute("CREATE TABLE IF NOT EXISTS ItemTable (key TEXT UNIQUE ON CONFLICT REPLACE, value BLOB)")
            if login is not None:
                db.execute("INSERT INTO ItemTable VALUES (?, ?)", ("github.copilot-github", login))
            db.execute("INSERT INTO ItemTable VALUES (?, ?)", ("GitHub.copilot-chat", json.dumps(chat)))
        if mtime is not None:
            os.utime(path, (mtime, mtime))
        return path


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



class TestCopilotSeat(unittest.TestCase):
    """Plan and org come from GitHub, since Copilot keeps neither on disk."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        p = patch.object(unbound, "COPILOT_SEAT_CACHE_PATH", Path(self._tmp.name) / "seat.json")
        p.start()
        self.addCleanup(p.stop)

    def _seat(self, seat, login="octocat", host="https://github.com", probe=True):
        with patch.object(unbound, "_fetch_copilot_seat", return_value=seat) as fetch:
            return unbound._copilot_seat(login, host, probe), fetch

    def test_reads_the_plan_and_the_org(self):
        (plan, org), _ = self._seat({"login": "octocat", "copilot_plan": "business",
                                     "organization_login_list": ["zeta", "acme"]})
        self.assertEqual((plan, org), ("business", "acme"))

    def test_a_personal_seat_has_no_org(self):
        (plan, org), _ = self._seat({"login": "octocat", "copilot_plan": "individual",
                                     "organization_login_list": []})
        self.assertEqual((plan, org), ("individual", None))

    def test_another_accounts_seat_is_refused(self):
        """A gh login that is not Copilot's must not lend its plan."""
        result, _ = self._seat({"login": "someone-else", "copilot_plan": "enterprise"})
        self.assertEqual(result, (None, None))

    def test_the_pre_tool_path_never_calls_github(self):
        result, fetch = self._seat({"login": "octocat"}, probe=False)
        self.assertEqual(result, (None, None))
        fetch.assert_not_called()

    def test_a_cached_seat_is_served_without_a_call(self):
        self._seat({"login": "octocat", "copilot_plan": "business",
                    "organization_login_list": ["acme"]})
        result, fetch = self._seat(None, probe=False)
        self.assertEqual(result, ("business", "acme"))
        fetch.assert_not_called()

    def test_a_cache_for_another_login_is_ignored(self):
        self._seat({"login": "octocat", "copilot_plan": "business"})
        result, _ = self._seat(None, login="hubot", probe=False)
        self.assertEqual(result, (None, None))

    def test_a_miss_is_cached_so_the_next_turn_does_not_ask(self):
        self._seat({"login": "someone-else"})
        result, fetch = self._seat({"login": "octocat", "copilot_plan": "business"})
        self.assertEqual(result, (None, None))
        fetch.assert_not_called()

    def test_an_enterprise_server_host_is_not_asked(self):
        result, fetch = self._seat({"login": "octocat"}, host="https://acme.ghe.com")
        self.assertEqual(result, (None, None))
        fetch.assert_not_called()

    def test_an_unknown_host_is_not_asked(self):
        result, fetch = self._seat({"login": "octocat"}, host=None)
        self.assertEqual(result, (None, None))
        fetch.assert_not_called()

    def test_a_failed_call_reports_nothing(self):
        with patch.object(unbound, "_fetch_copilot_seat", side_effect=OSError("offline")):
            self.assertEqual(unbound._copilot_seat("octocat", "https://github.com", True),
                             (None, None))

    def test_the_identity_carries_the_seat(self):
        with patch.object(unbound, "read_account_identity",
                          return_value={"account_login": "octocat",
                                        "account_host": "https://github.com"}), \
                patch.object(unbound, "_copilot_seat", return_value=("business", "acme")), \
                patch.object(unbound, "_device_serial", return_value=None):
            identity = unbound.build_account_identity(probe=True)
        self.assertEqual((identity["plan"], identity["org_id"]), ("business", "acme"))


class TestVSCodeAccount(_IsolatedConfig):
    """VS Code keeps the account Copilot uses, with its plan, in globalStorage/state.vscdb."""

    def test_a_vscode_turn_reports_vscode_account_plan_and_org(self):
        self._write(SIGNED_IN)
        self._vscode(login="vs-user", sku="copilot_for_business_seat", orgs=["zeta", "acme"])
        identity = unbound.read_account_identity(surface="vscode")
        self.assertEqual((identity["account_login"], identity["account_host"], identity["plan"], identity["org_id"]),
                         ("vs-user", "https://github.com", "copilot_for_business_seat", "acme"))

    def test_a_personal_seat_has_no_org(self):
        self._vscode(sku="free_educational_quota", orgs=[])
        identity = unbound.read_account_identity(surface="vscode")
        self.assertEqual((identity["plan"], identity["org_id"]), ("free_educational_quota", None))

    def test_a_login_left_behind_by_a_sign_out_is_not_an_account(self):
        """Signing out clears the plan but leaves the preferred-account key."""
        self._vscode(login="gone-user", sku=None)
        self.assertIsNone(unbound.read_account_identity(surface="vscode")["account_login"])

    def test_a_vscode_turn_never_borrows_the_cli_sign_in(self):
        self._write(SIGNED_IN)
        self._vscode(sku=None)
        self.assertIsNone(unbound.read_account_identity(surface="vscode")["account_login"])

    def test_a_cli_turn_keeps_the_cli_account(self):
        self._write(SIGNED_IN)
        self._vscode(login="vs-user")
        identity = unbound.read_account_identity(surface="cli")
        self.assertEqual((identity["account_login"], identity["plan"]), ("octocat", None))

    def test_an_unlabelled_turn_never_reads_vscode(self):
        self._vscode(login="vs-user")
        self.assertIsNone(unbound.read_account_identity()["account_login"])

    def test_a_signed_out_newest_install_does_not_fall_back_to_an_older_one(self):
        self._vscode(login="old-user", install=0, mtime=1_000)
        self._vscode(login="gone-user", sku=None, install=1, mtime=2_000)
        self.assertIsNone(unbound.read_account_identity(surface="vscode")["account_login"])

    def test_an_install_without_copilot_is_skipped(self):
        self._vscode(login="stable-user", install=0, mtime=1_000)
        self._vscode(login=None, sku=None, install=1, mtime=2_000)
        self.assertEqual(unbound.read_account_identity(surface="vscode")["account_login"], "stable-user")

    def test_a_turn_reads_the_install_its_transcript_came_from(self):
        self._vscode(login="stable-user", install=0, mtime=1_000)
        self._vscode(login="insiders-user", install=1, mtime=2_000)
        transcript = str(self.vscode_dirs[0] / "workspaceStorage" / "abc" / "GitHub.copilot-chat" / "transcripts" / "s.jsonl")
        identity = unbound.read_account_identity(surface="vscode", transcript_path=transcript)
        self.assertEqual(identity["account_login"], "stable-user")

    def test_a_turn_from_a_signed_out_install_reports_no_one(self):
        self._vscode(login="gone-user", sku=None, install=0, mtime=1_000)
        self._vscode(login="insiders-user", install=1, mtime=2_000)
        transcript = str(self.vscode_dirs[0] / "workspaceStorage" / "abc" / "GitHub.copilot-chat" / "transcripts" / "s.jsonl")
        self.assertIsNone(unbound.read_account_identity(surface="vscode", transcript_path=transcript)["account_login"])

    def test_the_most_recently_used_install_wins(self):
        self._vscode(login="stable-user", install=0, mtime=1_000)
        self._vscode(login="insiders-user", install=1, mtime=2_000)
        self.assertEqual(unbound.read_account_identity(surface="vscode")["account_login"], "insiders-user")

    def test_an_unreadable_database_is_logged_and_names_no_one(self):
        path = self.vscode_dirs[0] / "globalStorage" / "state.vscdb"
        path.parent.mkdir(parents=True)
        path.write_bytes(b"not a database")
        with patch.object(unbound, "log_error") as logged:
            self.assertIsNone(unbound.read_account_identity(surface="vscode")["account_login"])
        self.assertEqual(logged.call_count, 1)

    def test_github_is_not_asked_when_vscode_names_the_plan(self):
        self._vscode(login="vs-user", sku="copilot_for_business_seat", orgs=["acme"])
        with patch.object(unbound, "_copilot_seat") as seat, \
                patch.object(unbound, "_device_serial", return_value=None):
            identity = unbound.build_account_identity(probe=True, surface="vscode")
        seat.assert_not_called()
        self.assertEqual((identity["plan"], identity["org_id"]), ("copilot_for_business_seat", "acme"))

    def test_github_fills_only_what_the_disk_left_blank(self):
        self._write(SIGNED_IN)
        with patch.object(unbound, "read_account_identity",
                          return_value={"account_login": "octocat", "account_host": "https://github.com",
                                        "plan": None, "org_id": "disk-org"}), \
                patch.object(unbound, "_copilot_seat", return_value=("business", "api-org")), \
                patch.object(unbound, "_device_serial", return_value=None):
            identity = unbound.build_account_identity(probe=True)
        self.assertEqual((identity["plan"], identity["org_id"]), ("business", "disk-org"))


class TestCopilotCliAccount(_IsolatedConfig):
    """The CLI's config names who signed in last; the credential store says who is signed in now."""

    def _cli(self, credential):
        with patch.object(unbound, "_copilot_cli_credential", return_value=credential) as check:
            return unbound.read_account_identity(surface="cli")["account_login"], check

    def test_a_stored_credential_confirms_the_config_login(self):
        self._write(SIGNED_IN)
        login, check = self._cli(True)
        self.assertEqual(login, "octocat")
        check.assert_called_once_with("https://github.com:octocat")

    def test_a_config_login_without_its_credential_is_signed_out(self):
        self._write(SIGNED_IN)
        self.assertIsNone(self._cli(False)[0])

    def test_an_unanswerable_store_keeps_the_config_login(self):
        self._write(SIGNED_IN)
        self.assertEqual(self._cli(None)[0], "octocat")

    def test_an_env_token_overrides_the_stored_sign_in(self):
        self._write(SIGNED_IN)
        for var in unbound._COPILOT_CLI_TOKEN_VARS:
            with self.subTest(var=var), patch.dict(os.environ, {var: "x"}):
                self.assertIsNone(self._cli(True)[0])

    def test_a_cloud_turn_is_not_checked(self):
        self._write(SIGNED_IN)
        with patch.object(unbound, "_copilot_cli_credential", return_value=False) as check:
            self.assertEqual(unbound.read_account_identity(surface="cloud")["account_login"], "octocat")
        check.assert_not_called()


class TestCopilotCliCredential(unittest.TestCase):
    """Only the entry's label is looked up; the secret is never read."""

    def setUp(self):
        unbound._copilot_cli_credential.cache_clear()
        self.addCleanup(unbound._copilot_cli_credential.cache_clear)

    def _mac(self, returncode):
        unbound._copilot_cli_credential.cache_clear()
        result = unittest.mock.Mock(returncode=returncode)
        with patch.object(unbound.platform, "system", return_value="Darwin"), \
                patch.object(unbound.subprocess, "run", return_value=result) as run:
            return unbound._copilot_cli_credential("https://github.com:octocat"), run.call_args[0][0]

    def test_macos_found_missing_and_unknown(self):
        self.assertIs(self._mac(0)[0], True)
        self.assertIs(self._mac(44)[0], False)
        self.assertIsNone(self._mac(51)[0])

    def test_macos_asks_for_the_label_only(self):
        _, argv = self._mac(0)
        self.assertEqual(argv, ["/usr/bin/security", "find-generic-password", "-s", "copilot-cli",
                                "-a", "https://github.com:octocat"])

    def _windows(self, stdout, returncode=0):
        unbound._copilot_cli_credential.cache_clear()
        result = unittest.mock.Mock(returncode=returncode, stdout=stdout)
        with patch.object(unbound.platform, "system", return_value="Windows"), \
                patch.object(unbound, "_is_windows", return_value=True), \
                patch.object(unbound, "_windows_system32_path", return_value="cmdkey.exe"), \
                patch.object(unbound.subprocess, "run", return_value=result):
            return unbound._copilot_cli_credential("https://github.com:octocat")

    def test_windows_matches_either_target_layout(self):
        for target in ("LegacyGeneric:target=https://github.com:octocat.copilot-cli",
                       "LegacyGeneric:target=copilot-cli/https://github.com:OctoCat"):
            with self.subTest(target=target):
                self.assertIs(self._windows("    Target: %s\n    Type: Generic\n" % target), True)

    def test_windows_a_longer_login_is_not_a_match(self):
        self.assertIs(self._windows("    Target: LegacyGeneric:target=https://github.com:octocat2.copilot-cli\n"), False)

    def test_a_repeat_check_in_one_run_spawns_no_second_process(self):
        with patch.object(unbound.platform, "system", return_value="Darwin"), \
                patch.object(unbound.subprocess, "run", return_value=unittest.mock.Mock(returncode=0)) as run:
            unbound._copilot_cli_credential("https://github.com:octocat")
            unbound._copilot_cli_credential("https://github.com:octocat")
        self.assertEqual(run.call_count, 1)

    def test_windows_other_copilot_entries_mean_signed_out(self):
        self.assertIs(self._windows("    Target: LegacyGeneric:target=https://github.com:someone.copilot-cli\n"), False)

    def test_windows_without_any_copilot_entry_cannot_say(self):
        self.assertIsNone(self._windows("    Target: LegacyGeneric:target=git:https://github.com\n"))

    def test_windows_cmdkey_failure_cannot_say(self):
        self.assertIsNone(self._windows("", returncode=1))

    def test_linux_cannot_say(self):
        with patch.object(unbound.platform, "system", return_value="Linux"), \
                patch.object(unbound, "_is_windows", return_value=False):
            self.assertIsNone(unbound._copilot_cli_credential("https://github.com:octocat"))


class TestCopilotUserCache(_IsolatedConfig):
    """Copilot caches GitHub's answer about each signed-in login; plan and org come from there."""

    def test_a_cli_turn_gets_plan_and_org_name_for_its_login(self):
        self._write(SIGNED_IN)
        self._user_cache("octocat", sku="copilot_for_business_seat_quota", orgs=["zeta", "acme"])
        identity = unbound.read_account_identity(surface="cli")
        self.assertEqual((identity["account_login"], identity["plan"], identity["org_id"]),
                         ("octocat", "copilot_for_business_seat_quota", "acme"))

    def test_the_newest_answer_for_the_login_wins(self):
        self._write(SIGNED_IN)
        self._user_cache("octocat", sku="free_limited_copilot", orgs=[], at="2026-09-01T00:00:00Z")
        self._user_cache("octocat", sku="copilot_for_business_seat_quota", orgs=["acme"], at="2026-09-30T00:00:00Z")
        self.assertEqual(unbound.read_account_identity(surface="cli")["plan"], "copilot_for_business_seat_quota")

    def test_another_logins_answer_is_ignored(self):
        self._write(SIGNED_IN)
        self._user_cache("someone-else")
        identity = unbound.read_account_identity(surface="cli")
        self.assertEqual((identity["plan"], identity["org_id"]), (None, None))

    def test_a_personal_seat_has_a_plan_and_no_org(self):
        self._write(SIGNED_IN)
        self._user_cache("OctoCat", sku="free_educational_quota", orgs=[])
        identity = unbound.read_account_identity(surface="cli")
        self.assertEqual((identity["plan"], identity["org_id"]), ("free_educational_quota", None))

    def test_without_a_cache_entry_the_cli_borrows_vscode_signed_in_as_the_same_login(self):
        self._write(SIGNED_IN)
        self._vscode(login="octocat", sku="copilot_for_business_seat_quota", orgs=["opaque-org"])
        identity = unbound.read_account_identity(surface="cli")
        self.assertEqual((identity["plan"], identity["org_id"]), ("copilot_for_business_seat_quota", "opaque-org"))

    def test_the_cli_never_borrows_vscode_signed_in_as_another_login(self):
        self._write(SIGNED_IN)
        self._vscode(login="vs-user")
        identity = unbound.read_account_identity(surface="cli")
        self.assertEqual((identity["plan"], identity["org_id"]), (None, None))

    def test_a_vscode_turn_reports_the_org_name_when_the_cache_has_it(self):
        self._vscode(login="vs-user", orgs=["3d1901ce21d7ca4bb9dd9818d628f3b5"])
        self._user_cache("vs-user", orgs=["acme"])
        self.assertEqual(unbound.read_account_identity(surface="vscode")["org_id"], "acme")

    def test_a_vscode_turn_keeps_the_opaque_org_without_a_cache_entry(self):
        self._vscode(login="vs-user", orgs=["3d1901ce21d7ca4bb9dd9818d628f3b5"])
        self.assertEqual(unbound.read_account_identity(surface="vscode")["org_id"], "3d1901ce21d7ca4bb9dd9818d628f3b5")

    def test_an_unreadable_cache_is_logged_and_adds_nothing(self):
        self._write(SIGNED_IN)
        self.user_cache_path.write_text("{not json", encoding="utf-8")
        with patch.object(unbound, "log_error") as logged:
            self.assertIsNone(unbound.read_account_identity(surface="cli")["plan"])
        self.assertEqual(logged.call_count, 1)

    def test_the_seat_lookup_is_skipped_when_the_cache_names_the_plan(self):
        self._write(SIGNED_IN)
        self._user_cache("octocat")
        with patch.object(unbound, "_copilot_seat") as seat, patch.object(unbound, "_device_serial", return_value=None):
            unbound.build_account_identity(probe=True, surface="cli")
        seat.assert_not_called()


class TestCopilotUserCachePath(unittest.TestCase):
    def test_macos(self):
        with patch.object(unbound, "_is_windows", return_value=False), \
                patch.object(unbound.platform, "system", return_value="Darwin"):
            self.assertEqual(unbound._copilot_user_cache_path(),
                             Path.home() / "Library" / "Caches" / "copilot" / "copilot-user-cache.json")

    def test_linux_honours_xdg_cache_home(self):
        with patch.object(unbound, "_is_windows", return_value=False), \
                patch.object(unbound.platform, "system", return_value="Linux"), \
                patch.dict(os.environ, {"XDG_CACHE_HOME": "/tmp/xdg"}):
            self.assertEqual(unbound._copilot_user_cache_path(), Path("/tmp/xdg/copilot/copilot-user-cache.json"))


if __name__ == "__main__":
    unittest.main()
