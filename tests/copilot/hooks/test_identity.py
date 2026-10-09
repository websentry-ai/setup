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
import time
from datetime import datetime, timezone
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
        self.vscode_dirs = [Path(self._tmp.name) / "Code" / "User",
                            Path(self._tmp.name) / "Code - Insiders" / "User"]
        vscode = patch.object(unbound, "_vscode_user_dirs", return_value=self.vscode_dirs)
        vscode.start()
        self.addCleanup(vscode.stop)
        env = patch.dict(os.environ, {})
        env.start()
        self.addCleanup(env.stop)
        self.user_cache_path = Path(self._tmp.name) / "copilot-user-cache.json"
        user_cache = patch.object(unbound, "_copilot_user_cache_path", return_value=self.user_cache_path)
        user_cache.start()
        self.addCleanup(user_cache.stop)
        self._user_cache_entries = {}

    def _write(self, body: str):
        self.config_path.write_text(body, encoding="utf-8")

    def _user_cache(self, login, sku="copilot_for_business_seat_quota", orgs=(101,), age_days=0):
        """Add one GitHub copilot_internal/user answer to Copilot's user cache, the way Copilot writes it."""
        self._user_cache_entries["v1:%d" % len(self._user_cache_entries)] = {
            "schemaVersion": 1, "generation": "g",
            "retrievedAt": datetime.fromtimestamp(time.time() - age_days * 86400, timezone.utc)
            .strftime("%Y-%m-%dT%H:%M:%S.000Z"),
            "response": {"login": login, "copilot_plan": "business", "access_type_sku": sku,
                         "organization_list": [{"id": o, "login": "org%d" % o, "name": "Org %d" % o} for o in orgs]}}
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
                                     "organization_list": [{"id": 202, "login": "zeta"}, {"id": 101, "login": "acme"}]})
        self.assertEqual((plan, org), ("business", "101"))

    def test_the_org_is_one_that_grants_the_seat(self):
        (_, org), _ = self._seat({"login": "octocat", "access_type_sku": "copilot_for_business_seat_quota",
                                  "organization_login_list": ["acme"],
                                  "organization_list": [{"id": 5, "login": "hobby"}, {"id": 101, "login": "acme"}]})
        self.assertEqual(org, "101")

    def test_a_seat_no_org_grants_has_no_org(self):
        (_, org), _ = self._seat({"login": "octocat", "access_type_sku": "copilot_individual",
                                  "organization_login_list": [],
                                  "organization_list": [{"id": 5, "login": "hobby"}]})
        self.assertIsNone(org)

    def test_the_plan_is_the_sku_when_github_sends_one(self):
        (plan, _), _ = self._seat({"login": "octocat", "copilot_plan": "business",
                                   "access_type_sku": "copilot_for_business_seat_quota"})
        self.assertEqual(plan, "copilot_for_business_seat_quota")

    def test_a_personal_seat_has_no_org(self):
        (plan, org), _ = self._seat({"login": "octocat", "copilot_plan": "individual",
                                     "organization_list": []})
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
                    "organization_list": [{"id": 101, "login": "acme"}]})
        result, fetch = self._seat(None, probe=False)
        self.assertEqual(result, ("business", "101"))
        fetch.assert_not_called()

    def test_a_seat_cached_before_the_sku_change_is_asked_again(self):
        """Entries written before plans became skus hold 'business'; they must not outlive the change."""
        COPILOT = unbound.COPILOT_SEAT_CACHE_PATH
        COPILOT.write_text(json.dumps({"login": "octocat", "plan": "business", "org": "acme", "at": __import__("time").time()}))
        (plan, _), fetch = self._seat({"login": "octocat", "access_type_sku": "copilot_for_business_seat_quota"})
        self.assertEqual(plan, "copilot_for_business_seat_quota")
        fetch.assert_called_once()

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
        self._vscode(login="vs-user", sku="copilot_for_business_seat")
        self._user_cache("vs-user", sku="copilot_for_business_seat", orgs=[202, 101])
        identity = unbound.read_account_identity(surface="vscode")
        self.assertEqual((identity["account_login"], identity["account_host"], identity["plan"], identity["org_id"]),
                         ("vs-user", "https://github.com", "copilot_for_business_seat", "101"))
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

    def test_github_fills_the_org_when_the_disk_has_only_the_plan(self):
        self._vscode(login="vs-user", sku="copilot_for_business_seat")
        with patch.object(unbound, "_copilot_seat", return_value=("copilot_for_business_seat", "101")) as seat, \
                patch.object(unbound, "_device_serial", return_value=None):
            identity = unbound.build_account_identity(probe=True, surface="vscode")
        seat.assert_called_once()
        self.assertEqual((identity["plan"], identity["org_id"]), ("copilot_for_business_seat", "101"))

    def test_an_older_seats_org_never_joins_the_current_plan(self):
        """A personal plan has no org; a cached business seat for the same login must not lend it one."""
        self._vscode(login="vs-user", sku="free_educational_quota")
        with patch.object(unbound, "_copilot_seat", return_value=("copilot_for_business_seat_quota", "303")), \
                patch.object(unbound, "_device_serial", return_value=None):
            identity = unbound.build_account_identity(probe=True, surface="vscode")
        self.assertEqual((identity["plan"], identity["org_id"]), ("free_educational_quota", None))

    def test_github_is_not_asked_when_vscode_names_the_plan(self):
        self._vscode(login="vs-user", sku="copilot_for_business_seat")
        self._user_cache("vs-user", sku="copilot_for_business_seat", orgs=[101])
        with patch.object(unbound, "_copilot_seat") as seat, \
                patch.object(unbound, "_device_serial", return_value=None):
            identity = unbound.build_account_identity(probe=True, surface="vscode")
        seat.assert_not_called()
        self.assertEqual((identity["plan"], identity["org_id"]), ("copilot_for_business_seat", "101"))
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
    def test_a_cli_turn_reports_the_config_login(self):
        self._write(SIGNED_IN)
        self.assertEqual(unbound.read_account_identity(surface="cli")["account_login"], "octocat")

    def test_an_env_token_does_not_hide_the_config_login(self):
        self._write(SIGNED_IN)
        with patch.dict(os.environ, {"GH_TOKEN": "x"}):
            self.assertEqual(unbound.read_account_identity(surface="cli")["account_login"], "octocat")

class TestCopilotUserCache(_IsolatedConfig):
    """Copilot caches GitHub's answer about each signed-in login; plan and org come from there."""

    def test_a_cli_turn_gets_plan_and_org_name_for_its_login(self):
        self._write(SIGNED_IN)
        self._user_cache("octocat", sku="copilot_for_business_seat_quota", orgs=[202, 101])
        identity = unbound.read_account_identity(surface="cli")
        self.assertEqual((identity["account_login"], identity["plan"], identity["org_id"]),
                         ("octocat", "copilot_for_business_seat_quota", "101"))

    def test_the_newest_answer_for_the_login_wins(self):
        self._write(SIGNED_IN)
        self._user_cache("octocat", sku="free_limited_copilot", orgs=[], age_days=3)
        self._user_cache("octocat", sku="copilot_for_business_seat_quota", orgs=[101], age_days=1)
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
        self._vscode(login="octocat", sku="copilot_for_business_seat_quota")
        identity = unbound.read_account_identity(surface="cli")
        self.assertEqual((identity["plan"], identity["org_id"]), ("copilot_for_business_seat_quota", None))
    def test_the_cli_never_borrows_vscode_signed_in_as_another_login(self):
        self._write(SIGNED_IN)
        self._vscode(login="vs-user")
        identity = unbound.read_account_identity(surface="cli")
        self.assertEqual((identity["plan"], identity["org_id"]), (None, None))

    def test_both_surfaces_send_the_same_numeric_org_id(self):
        self._write(SIGNED_IN)
        self._vscode(login="octocat", sku="copilot_for_business_seat_quota", orgs=["3d1901ce21d7ca4bb9dd9818d628f3b5"])
        self._user_cache("octocat", orgs=[131423224])
        self.assertEqual(unbound.read_account_identity(surface="vscode")["org_id"], "131423224")
        self.assertEqual(unbound.read_account_identity(surface="cli")["org_id"], "131423224")
    def test_a_vscode_turn_never_sends_vscodes_opaque_org(self):
        self._vscode(login="vs-user", orgs=["3d1901ce21d7ca4bb9dd9818d628f3b5"])
        self.assertIsNone(unbound.read_account_identity(surface="vscode")["org_id"])
    def test_an_enterprise_host_cli_borrows_nothing(self):
        self._write('{"lastLoggedInUser":{"host":"https://acme.ghe.com","login":"octocat"}}')
        self._user_cache("octocat")
        self._vscode(login="octocat")
        identity = unbound.read_account_identity(surface="cli")
        self.assertEqual((identity["account_login"], identity["plan"], identity["org_id"]), ("octocat", None, None))

    def test_an_answer_older_than_a_week_is_ignored(self):
        """A seat cached before an employer change must not name the new employer's org."""
        self._write(SIGNED_IN)
        self._user_cache("octocat", orgs=[303], age_days=8)
        identity = unbound.read_account_identity(surface="cli")
        self.assertEqual((identity["plan"], identity["org_id"]), (None, None))

    def test_a_stale_answer_lets_the_seat_lookup_run(self):
        self._write(SIGNED_IN)
        self._user_cache("octocat", age_days=30)
        with patch.object(unbound, "_copilot_seat", return_value=("copilot_for_business_seat_quota", "new-employer")) as seat, \
                patch.object(unbound, "_device_serial", return_value=None):
            identity = unbound.build_account_identity(probe=True, surface="cli")
        seat.assert_called_once()
        self.assertEqual(identity["org_id"], "new-employer")

    def test_a_cached_seat_with_another_plan_gives_a_vscode_turn_no_org(self):
        """A user who moved to a personal seat must not keep the former business seat's org."""
        self._vscode(login="vs-user", sku="free_educational_quota")
        self._user_cache("vs-user", sku="copilot_for_business_seat_quota", orgs=[303])
        identity = unbound.read_account_identity(surface="vscode")
        self.assertEqual((identity["plan"], identity["org_id"]), ("free_educational_quota", None))

    def test_a_stale_cache_gives_a_vscode_turn_no_org(self):
        self._vscode(login="vs-user", sku="copilot_for_business_seat_quota")
        self._user_cache("vs-user", orgs=[303], age_days=8)
        self.assertIsNone(unbound.read_account_identity(surface="vscode")["org_id"])
    def test_a_planless_cache_org_is_not_paired_with_a_borrowed_plan(self):
        self._write(SIGNED_IN)
        self._user_cache("octocat", sku="", orgs=[303])
        self._vscode(login="octocat", sku="copilot_for_business_seat_quota")
        identity = unbound.read_account_identity(surface="cli")
        self.assertEqual((identity["plan"], identity["org_id"]), ("copilot_for_business_seat_quota", None))
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


class TestCopilotNoAccountReason(_IsolatedConfig):
    """A turn with no account says why."""

    def _reason(self, surface):
        return unbound.read_account_identity(surface=surface)["account_reason"]

    def test_vscode_not_installed(self):
        self.assertEqual(self._reason("vscode"), "vscode_not_found")

    def test_vscode_signed_out(self):
        self._vscode(login="gone-user", sku=None)
        self.assertEqual(self._reason("vscode"), "vscode_signed_out")

    def test_vscode_never_signed_in_to_copilot(self):
        self._vscode(login=None, sku=None)
        self.assertEqual(self._reason("vscode"), "vscode_no_copilot_login")

    def test_a_signed_out_older_install_is_found_past_a_newer_one_without_copilot(self):
        self._vscode(login="gone-user", sku=None, install=0, mtime=1_000)
        self._vscode(login=None, sku=None, install=1, mtime=2_000)
        self.assertEqual(self._reason("vscode"), "vscode_signed_out")

    def test_vscode_unreadable(self):
        path = self.vscode_dirs[0] / "globalStorage" / "state.vscdb"
        path.parent.mkdir(parents=True)
        path.write_bytes(b"not a database")
        with patch.object(unbound, "log_error"):
            self.assertEqual(self._reason("vscode"), "vscode_unreadable")

    def test_cli_without_a_login(self):
        with patch.dict(os.environ, {}):
            for var in ("COPILOT_GITHUB_TOKEN", "GH_TOKEN", "GITHUB_TOKEN"):
                os.environ.pop(var, None)
            self.assertEqual(self._reason("cli"), "cli_no_login")

    def test_cli_signed_in_by_an_env_token(self):
        with patch.dict(os.environ, {"GH_TOKEN": "x"}):
            self.assertEqual(self._reason("cli"), "env_token")

    def test_a_cloud_turn_has_its_own_reason(self):
        with patch.dict(os.environ, {"GITHUB_TOKEN": "x"}):
            self.assertEqual(self._reason("cloud"), "cloud_no_login")

    def test_a_signed_in_turn_has_no_reason(self):
        self._write(SIGNED_IN)
        self.assertNotIn("account_reason", unbound.read_account_identity(surface="cli"))


if __name__ == "__main__":
    unittest.main()
