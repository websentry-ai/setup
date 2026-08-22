"""
Each mode removes only what Unbound installed.

An org may already point Claude Code at their own gateway or at Bedrock, and may have
their own hooks and their own key helper. Installing or clearing Unbound leaves all of it
alone. Unbound writes exactly: ANTHROPIC_BASE_URL = the Unbound gateway, UNBOUND_API_KEY,
~/.claude/anthropic_key.sh containing `echo $UNBOUND_API_KEY`, the apiKeyHelper pointing
at it, and hooks running unbound.py.
"""

import importlib.util
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parent
OURS = "https://api.getunbound.ai"
THEIRS = "https://bedrock.acme-corp.internal"
OUR_HELPER = "echo $UNBOUND_API_KEY"


def _load(name, relative):
    spec = importlib.util.spec_from_file_location(name, ROOT / relative)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


HOOKS = _load("ub_hooks", "hooks/setup.py")
GATEWAY = _load("ub_gateway", "gateway/setup.py")
HOOKS_MDM = _load("ub_hooks_mdm", "hooks/mdm/setup.py")
GATEWAY_MDM = _load("ub_gateway_mdm", "gateway/mdm/setup.py")
ALL = [HOOKS, GATEWAY, HOOKS_MDM, GATEWAY_MDM]
USER_LEVEL = [HOOKS, GATEWAY]
MDM = [HOOKS_MDM, GATEWAY_MDM]


class TestBaseUrlIdentity(unittest.TestCase):
    def test_our_gateway_is_ours(self):
        for mod in ALL:
            self.assertTrue(mod._is_unbound_base_url(OURS), mod.__name__)
            self.assertTrue(mod._is_unbound_base_url(OURS + "/"), mod.__name__)

    def test_anything_else_is_not(self):
        for value in (THEIRS, "https://bedrock.us-east-1.amazonaws.com",
                      "https://api.anthropic.com", "https://evil.com#api.getunbound.ai",
                      "", None, 5):
            for mod in ALL:
                self.assertFalse(mod._is_unbound_base_url(value),
                                 "%s %r" % (mod.__name__, value))


class TestARecordedCustomGatewayIsOurs(unittest.TestCase):
    """An org running Unbound on their own --gateway-url still installed it through us.
    The URL we recorded for a user says which endpoint we pointed them at, so it
    authorises removing that user's export -- and only that."""

    CUSTOM = "https://unbound.acme-corp.internal"

    @staticmethod
    def _home(gateway_url=None):
        home = Path(tempfile.mkdtemp())
        (home / ".unbound").mkdir()
        body = {"api_key": "k"}
        if gateway_url:
            body["gateway_url"] = gateway_url
        (home / ".unbound" / "config.json").write_text(json.dumps(body))
        return home

    def test_user_level_accepts_the_recorded_gateway(self):
        home = self._home(self.CUSTOM)
        for mod in USER_LEVEL:
            with patch.object(mod.Path, "home", staticmethod(lambda: home)):
                self.assertTrue(mod._is_unbound_base_url(self.CUSTOM), mod.__name__)
                self.assertTrue(mod._is_unbound_base_url(self.CUSTOM + "/"), mod.__name__)

    def test_user_level_still_refuses_an_endpoint_nobody_recorded(self):
        home = self._home(self.CUSTOM)
        for mod in USER_LEVEL:
            with patch.object(mod.Path, "home", staticmethod(lambda: home)):
                self.assertFalse(mod._is_unbound_base_url(THEIRS), mod.__name__)

    def test_no_record_falls_back_to_the_default_gateway_only(self):
        home = self._home(None)
        for mod in USER_LEVEL:
            with patch.object(mod.Path, "home", staticmethod(lambda: home)):
                self.assertTrue(mod._is_unbound_base_url(OURS), mod.__name__)
                self.assertFalse(mod._is_unbound_base_url(self.CUSTOM), mod.__name__)

    def test_the_record_read_is_whatever_is_on_disk_at_that_moment(self):
        # the install rewrites gateway_url later in the run; the removal has to read the
        # record the *previous* install left, so it must run before that rewrite
        home = self._home(self.CUSTOM)
        config = home / ".unbound" / "config.json"
        for mod in USER_LEVEL:
            with patch.object(mod.Path, "home", staticmethod(lambda: home)):
                self.assertTrue(mod._is_unbound_base_url(self.CUSTOM), mod.__name__)
                config.write_text(json.dumps({"api_key": "k", "gateway_url": OURS}))
                self.assertFalse(mod._is_unbound_base_url(self.CUSTOM), mod.__name__)
                config.write_text(json.dumps({"api_key": "k",
                                              "gateway_url": self.CUSTOM}))

    def test_a_corrupt_record_is_not_a_match(self):
        home = Path(tempfile.mkdtemp())
        (home / ".unbound").mkdir()
        (home / ".unbound" / "config.json").write_text("{not json")
        for mod in USER_LEVEL:
            with patch.object(mod.Path, "home", staticmethod(lambda: home)):
                self.assertFalse(mod._is_unbound_base_url(self.CUSTOM), mod.__name__)
                self.assertTrue(mod._is_unbound_base_url(OURS), mod.__name__)

    def test_a_windows_device_with_no_user_profiles_does_not_crash(self):
        # get_all_user_homes() falls back to a single (None, None) entry on Windows;
        # dereferencing that home aborted clear before the machine-wide state came out
        for mod in MDM:
            self.assertEqual(mod._recorded_gateway_url_for_user(None, None), "")
            matcher = mod._unbound_base_url_matcher(None, None)
            self.assertTrue(matcher(OURS), mod.__name__)
            self.assertFalse(matcher(THEIRS), mod.__name__)

    def test_on_windows_a_users_record_cannot_authorise_the_machine_wide_delete(self):
        # remove_env_var_from_user deletes HKLM on Windows, which the device shares, so a
        # config any account can write must not decide it -- otherwise a local user sets
        # gateway_url to the org endpoint and the next privileged clear removes it
        home = self._home(THEIRS)
        managed = Path(tempfile.mkdtemp())
        for mod in MDM:
            with patch.object(mod.platform, "system", lambda: "Windows"), \
                 patch.object(mod, "get_managed_settings_dir", lambda: managed), \
                 patch.object(mod, "_run_as_user", lambda _u, fn, *a, **k: fn(*a, **k)):
                matcher = mod._unbound_base_url_matcher("mallory", home)
            self.assertFalse(matcher(THEIRS), mod.__name__)
            self.assertTrue(matcher(OURS), mod.__name__)

    def test_on_unix_the_same_record_does_decide_that_users_own_rc(self):
        home = self._home(self.CUSTOM)
        managed = Path(tempfile.mkdtemp())
        for mod in MDM:
            with patch.object(mod.platform, "system", lambda: "Darwin"), \
                 patch.object(mod, "get_managed_settings_dir", lambda: managed), \
                 patch.object(mod, "_run_as_user", lambda _u, fn, *a, **k: fn(*a, **k)):
                matcher = mod._unbound_base_url_matcher("alice", home)
            self.assertTrue(matcher(self.CUSTOM), mod.__name__)

    def test_windows_still_recognises_a_custom_route_from_our_drop_in(self):
        home = self._home(THEIRS)
        managed = Path(tempfile.mkdtemp())
        (managed / "managed-settings.d").mkdir(parents=True)
        (managed / "managed-settings.d" / "unbound.json").write_text(json.dumps(
            {"env": {"ANTHROPIC_BASE_URL": self.CUSTOM}}))
        for mod in MDM:
            with patch.object(mod.platform, "system", lambda: "Windows"), \
                 patch.object(mod, "get_managed_settings_dir", lambda: managed), \
                 patch.object(mod, "_run_as_user", lambda _u, fn, *a, **k: fn(*a, **k)):
                matcher = mod._unbound_base_url_matcher("mallory", home)
            self.assertTrue(matcher(self.CUSTOM), mod.__name__)
            self.assertFalse(matcher(THEIRS), mod.__name__)

    def _flat(self, content):
        managed = Path(tempfile.mkdtemp())
        (managed / "managed-settings.json").write_text(json.dumps(content))
        for mod in MDM:
            with patch.object(mod, "get_managed_settings_dir", lambda: managed):
                yield mod, mod._unbound_base_url_matcher(None, None)

    def test_the_flat_fallback_counts_when_it_is_exactly_what_we_write(self):
        # the install replaces that whole file, so this shape is unambiguously ours
        for mod, matcher in self._flat(
                {"env": {"ANTHROPIC_AUTH_TOKEN": "t", "ANTHROPIC_BASE_URL": self.CUSTOM}}):
            self.assertTrue(matcher(self.CUSTOM), mod.__name__)

    def test_an_administrators_flat_file_stays_theirs(self):
        # any other top-level key means they wrote it, so the URL in it is not our record
        for mod, matcher in self._flat(
                {"permissions": {"allow": []},
                 "env": {"ANTHROPIC_AUTH_TOKEN": "t", "ANTHROPIC_BASE_URL": self.CUSTOM}}):
            self.assertFalse(matcher(self.CUSTOM), mod.__name__)

    def test_an_extra_env_key_also_means_theirs(self):
        for mod, matcher in self._flat(
                {"env": {"ANTHROPIC_AUTH_TOKEN": "t", "ANTHROPIC_BASE_URL": self.CUSTOM,
                         "HTTPS_PROXY": "http://corp:3128"}}):
            self.assertFalse(matcher(self.CUSTOM), mod.__name__)

    def test_the_drop_in_wins_over_the_flat_file(self):
        managed = Path(tempfile.mkdtemp())
        (managed / "managed-settings.d").mkdir(parents=True)
        (managed / "managed-settings.d" / "unbound.json").write_text(json.dumps(
            {"env": {"ANTHROPIC_BASE_URL": self.CUSTOM}}))
        (managed / "managed-settings.json").write_text(json.dumps(
            {"env": {"ANTHROPIC_AUTH_TOKEN": "t", "ANTHROPIC_BASE_URL": THEIRS}}))
        for mod in MDM:
            with patch.object(mod, "get_managed_settings_dir", lambda: managed):
                matcher = mod._unbound_base_url_matcher(None, None)
            self.assertTrue(matcher(self.CUSTOM), mod.__name__)

    def test_the_machine_wide_route_is_recognised_from_our_own_drop_in(self):
        # a Windows MDM device with no user profiles has no per-account record; the
        # drop-in this setup writes is device-level state nothing else writes
        managed = Path(tempfile.mkdtemp())
        (managed / "managed-settings.d").mkdir(parents=True)
        (managed / "managed-settings.d" / "unbound.json").write_text(json.dumps(
            {"env": {"ANTHROPIC_BASE_URL": self.CUSTOM, "ANTHROPIC_AUTH_TOKEN": "t"}}))
        for mod in MDM:
            with patch.object(mod, "get_managed_settings_dir", lambda: managed):
                matcher = mod._unbound_base_url_matcher(None, None)
            self.assertTrue(matcher(self.CUSTOM), mod.__name__)
            self.assertTrue(matcher(OURS), mod.__name__)
            self.assertFalse(matcher(THEIRS), mod.__name__)

    def test_no_drop_in_leaves_the_default_gateway_only(self):
        managed = Path(tempfile.mkdtemp())
        for mod in MDM:
            with patch.object(mod, "get_managed_settings_dir", lambda: managed):
                matcher = mod._unbound_base_url_matcher(None, None)
            self.assertTrue(matcher(OURS), mod.__name__)
            self.assertFalse(matcher(self.CUSTOM), mod.__name__)

    def test_a_malformed_drop_in_does_not_raise(self):
        managed = Path(tempfile.mkdtemp())
        (managed / "managed-settings.d").mkdir(parents=True)
        target = managed / "managed-settings.d" / "unbound.json"
        for junk in ("[]", "not json", "", "null", '{"env": 5}', '{"env": {}}',
                     '{"env": {"ANTHROPIC_BASE_URL": 5}}'):
            target.write_text(junk)
            for mod in MDM:
                with patch.object(mod, "get_managed_settings_dir", lambda: managed):
                    matcher = mod._unbound_base_url_matcher(None, None)
                self.assertTrue(matcher(OURS), "%s %r" % (mod.__name__, junk))
                self.assertFalse(matcher(self.CUSTOM), "%s %r" % (mod.__name__, junk))

    def test_mdm_matches_it_for_that_user(self):
        home = self._home(self.CUSTOM)
        for mod in MDM:
            with patch.object(mod, "_run_as_user", lambda _u, fn, *a, **k: fn(*a, **k)):
                matcher = mod._unbound_base_url_matcher("alice", home)
            self.assertTrue(matcher(self.CUSTOM), mod.__name__)
            self.assertTrue(matcher(OURS), mod.__name__)
            self.assertFalse(matcher(THEIRS), mod.__name__)

    def test_one_users_record_does_not_reach_the_system_wide_check(self):
        # this is the boundary: a local account writing our URL into their own config
        # must not authorise deleting anything from shared managed settings
        home = self._home(self.CUSTOM)
        for mod in MDM:
            with patch.object(mod, "get_all_user_homes", lambda: [("mallory", home)]), \
                 patch.object(mod, "_run_as_user", lambda _u, fn, *a, **k: fn(*a, **k)):
                self.assertFalse(mod._is_unbound_base_url(self.CUSTOM), mod.__name__)

    def test_the_managed_env_block_still_ignores_a_users_record(self):
        home = self._home(self.CUSTOM)
        managed = Path(tempfile.mkdtemp())
        # an extra key makes it unmistakably the administrator's file, so the only thing
        # that could authorise clearing it is mallory's record -- which must not
        (managed / "managed-settings.json").write_text(json.dumps(
            {"permissions": {"allow": []},
             "env": {"ANTHROPIC_BASE_URL": self.CUSTOM, "ANTHROPIC_AUTH_TOKEN": "t"}}))
        with patch.object(GATEWAY_MDM, "get_managed_settings_dir", lambda: managed), \
             patch.object(GATEWAY_MDM, "get_all_user_homes", lambda: [("mallory", home)]):
            GATEWAY_MDM.clear_managed_settings()
        env = json.loads((managed / "managed-settings.json").read_text())["env"]
        self.assertEqual(env, {"ANTHROPIC_BASE_URL": self.CUSTOM,
                               "ANTHROPIC_AUTH_TOKEN": "t"})


class TestTheOwnershipCheckNeverRaises(unittest.TestCase):
    """This runs on the install path, where anything that raises aborts the setup. A
    config that is not a JSON object is the case that bites: .get() on a list raises
    AttributeError, which is neither OSError nor ValueError."""

    MALFORMED = ['{"gateway_url": null}', '{"gateway_url": 5}', '{"gateway_url": ""}',
                 '{"gateway_url": "  "}', '{}', 'not json', '', '[]', '[1,2,3]',
                 '"a string"', '123', 'null', 'true']
    HOSTILE = [None, "", " ", "/", "https://", 5, [], {}, "\x00", "a" * 10000,
               "https://evil.com#api.getunbound.ai"]

    def test_user_level_survives_any_config_and_any_value(self):
        for cfg in self.MALFORMED:
            home = Path(tempfile.mkdtemp())
            (home / ".unbound").mkdir()
            (home / ".unbound" / "config.json").write_text(cfg)
            for mod in USER_LEVEL:
                with patch.object(mod.Path, "home", staticmethod(lambda h=home: h)):
                    for value in self.HOSTILE:
                        self.assertFalse(mod._is_unbound_base_url(value),
                                         "%s %r %r" % (mod.__name__, cfg, value))

    def test_mdm_survives_any_config_and_any_value(self):
        for cfg in self.MALFORMED:
            home = Path(tempfile.mkdtemp())
            (home / ".unbound").mkdir()
            (home / ".unbound" / "config.json").write_text(cfg)
            for mod in MDM:
                with patch.object(mod, "_run_as_user",
                                  lambda _u, fn, *a, **k: fn(*a, **k)):
                    matcher = mod._unbound_base_url_matcher("alice", home)
                for value in self.HOSTILE:
                    self.assertFalse(matcher(value),
                                     "%s %r %r" % (mod.__name__, cfg, value))

    def test_a_malformed_config_still_leaves_the_default_recognised(self):
        home = Path(tempfile.mkdtemp())
        (home / ".unbound").mkdir()
        (home / ".unbound" / "config.json").write_text("[1,2,3]")
        for mod in USER_LEVEL:
            with patch.object(mod.Path, "home", staticmethod(lambda: home)):
                self.assertTrue(mod._is_unbound_base_url(OURS), mod.__name__)


class TestEnvRemovalKeepsTheirs(unittest.TestCase):
    """export ANTHROPIC_BASE_URL goes only where it holds our gateway."""

    def _rc(self, *lines):
        rc = Path(tempfile.mkdtemp()) / ".bashrc"
        rc.write_text("".join(line + "\n" for line in lines))
        return rc

    def _remove_user_level(self, mod, rc):
        with patch.object(mod, "get_shell_rc_file", lambda: rc), \
             patch.object(mod.platform, "system", lambda: "Darwin"):
            return mod.remove_env_var("ANTHROPIC_BASE_URL", mod._is_unbound_base_url)[0]

    def test_their_endpoint_survives(self):
        for mod in USER_LEVEL:
            rc = self._rc('export ANTHROPIC_BASE_URL="%s"' % THEIRS)
            self.assertEqual(self._remove_user_level(mod, rc), "not_found")
            self.assertIn(THEIRS, rc.read_text())

    def test_ours_goes_and_theirs_stays_side_by_side(self):
        for mod in USER_LEVEL:
            rc = self._rc('export ANTHROPIC_BASE_URL="%s"' % THEIRS,
                          'export ANTHROPIC_BASE_URL="%s"' % OURS,
                          "export CLAUDE_CODE_USE_BEDROCK=1")
            self.assertEqual(self._remove_user_level(mod, rc), "cleared")
            text = rc.read_text()
            self.assertIn(THEIRS, text)
            self.assertNotIn(OURS, text)
            self.assertIn("CLAUDE_CODE_USE_BEDROCK", text)

    def test_the_same_holds_per_user_under_mdm(self):
        for mod in MDM:
            home = Path(tempfile.mkdtemp())
            (home / ".zprofile").write_text(
                'export ANTHROPIC_BASE_URL="%s"\nexport ANTHROPIC_BASE_URL="%s"\n'
                % (THEIRS, OURS))
            with patch.object(mod.platform, "system", lambda: "Darwin"), \
                 patch.object(mod, "_run_as_user", lambda _u, fn, *a, **k: fn(*a, **k)):
                status = mod.remove_env_var_from_user(
                    "alice", home, "ANTHROPIC_BASE_URL", mod._is_unbound_base_url)
            self.assertEqual(status, "cleared", mod.__name__)
            text = (home / ".zprofile").read_text()
            self.assertIn(THEIRS, text)
            self.assertNotIn(OURS, text)

    def test_the_api_key_is_still_removed_by_name(self):
        # UNBOUND_API_KEY is written by nothing but us, so it needs no value check
        for mod in USER_LEVEL:
            rc = self._rc('export UNBOUND_API_KEY="k"')
            with patch.object(mod, "get_shell_rc_file", lambda: rc), \
                 patch.object(mod.platform, "system", lambda: "Darwin"):
                self.assertEqual(mod.remove_env_var("UNBOUND_API_KEY")[0], "cleared")


class TestKeyHelperRemovalKeepsTheirs(unittest.TestCase):
    """~/.claude/anthropic_key.sh goes only when it is the script we wrote."""

    def _home_with_helper(self, body):
        home = Path(tempfile.mkdtemp())
        (home / ".claude").mkdir()
        (home / ".claude" / "anthropic_key.sh").write_text(body)
        return home

    def test_hooks_install_keeps_a_foreign_helper(self):
        home = self._home_with_helper("aws bedrock get-token")
        with patch.object(HOOKS.Path, "home", staticmethod(lambda: home)):
            HOOKS.remove_gateway_artifacts()
        self.assertTrue((home / ".claude" / "anthropic_key.sh").exists())

    def test_a_trailing_newline_does_not_disown_ours(self):
        home = self._home_with_helper(OUR_HELPER + "\n")
        with patch.object(HOOKS.Path, "home", staticmethod(lambda: home)):
            HOOKS.remove_gateway_artifacts()
        self.assertFalse((home / ".claude" / "anthropic_key.sh").exists())

    def test_body_identity_agrees_across_the_mdm_trees(self):
        for mod in MDM:
            self.assertTrue(mod._is_unbound_key_helper_body(OUR_HELPER))
            self.assertTrue(mod._is_unbound_key_helper_body(OUR_HELPER + "\n"))
            self.assertFalse(mod._is_unbound_key_helper_body("aws bedrock get-token"))
            self.assertFalse(mod._is_unbound_key_helper_body(None))


class TestApiKeyHelperSetting(unittest.TestCase):
    def test_gateway_clear_keeps_a_foreign_setting(self):
        home = Path(tempfile.mkdtemp())
        (home / ".claude").mkdir()
        settings = home / ".claude" / "settings.json"
        settings.write_text(json.dumps({"apiKeyHelper": "~/.claude/bedrock_key.sh"}))
        with patch.object(GATEWAY.Path, "home", staticmethod(lambda: home)):
            self.assertEqual(GATEWAY.remove_api_key_helper_setting(), "not_found")
        self.assertIn("bedrock_key.sh", settings.read_text())

    def test_gateway_clear_removes_our_setting(self):
        home = Path(tempfile.mkdtemp())
        (home / ".claude").mkdir()
        settings = home / ".claude" / "settings.json"
        settings.write_text(json.dumps({"apiKeyHelper": "~/.claude/anthropic_key.sh",
                                        "model": "opus"}))
        with patch.object(GATEWAY.Path, "home", staticmethod(lambda: home)):
            self.assertEqual(GATEWAY.remove_api_key_helper_setting(), "cleared")
        self.assertEqual(json.loads(settings.read_text()), {"model": "opus"})

    def test_the_managed_check_only_matches_the_managed_path(self):
        # the managed settings file names the managed script; a per-user path there is
        # somebody else's business
        managed = Path(tempfile.mkdtemp())
        (managed / "anthropic_key.sh").write_text(OUR_HELPER)
        for mod in MDM:
            self.assertTrue(mod._is_unbound_key_helper_setting(
                str(managed / "anthropic_key.sh"), managed))
            self.assertFalse(mod._is_unbound_key_helper_setting(
                "~/.claude/anthropic_key.sh", managed))
            self.assertFalse(mod._is_unbound_key_helper_setting(
                "~/.claude/bedrock_key.sh", managed))


class TestHooksInstallKeepsTheirApiKeyHelper(unittest.TestCase):
    """The mirror of the gateway case: installing hooks drops the gateway's key helper
    setting, not an org's own."""

    def _install_strip(self, value):
        home = Path(tempfile.mkdtemp())
        with patch.object(HOOKS.Path, "home", staticmethod(lambda: home)):
            return HOOKS._is_unbound_key_helper_setting(value)

    def test_their_helper_setting_is_not_ours(self):
        self.assertFalse(self._install_strip("~/.claude/bedrock_key.sh"))
        self.assertFalse(self._install_strip("/usr/local/bin/get-token"))
        self.assertFalse(self._install_strip(None))

    def test_the_setting_the_gateway_writes_is_ours(self):
        self.assertTrue(self._install_strip("~/.claude/anthropic_key.sh"))


class TestTheSettingIsJudgedByTheScriptItNames(unittest.TestCase):
    """~/.claude/anthropic_key.sh is a name an org could pick for their own helper. The
    path alone must not decide, or their file survives while the setting pointing at it
    is deleted -- which breaks their auth just as thoroughly."""

    def _home(self, body=None):
        home = Path(tempfile.mkdtemp())
        (home / ".claude").mkdir()
        if body is not None:
            (home / ".claude" / "anthropic_key.sh").write_text(body)
        return home

    def _judge(self, mod, home):
        with patch.object(mod.Path, "home", staticmethod(lambda: home)):
            return mod._is_unbound_key_helper_setting("~/.claude/anthropic_key.sh")

    def test_their_script_at_our_path_makes_the_setting_theirs(self):
        home = self._home("aws bedrock get-token --profile prod")
        for mod in USER_LEVEL:
            self.assertFalse(self._judge(mod, home), mod.__name__)

    def test_our_script_makes_the_setting_ours(self):
        home = self._home(OUR_HELPER)
        for mod in USER_LEVEL:
            self.assertTrue(self._judge(mod, home), mod.__name__)

    def test_nothing_there_reads_as_ours_already_removed(self):
        home = self._home(None)
        for mod in USER_LEVEL:
            self.assertTrue(self._judge(mod, home), mod.__name__)

    def test_the_managed_helper_is_judged_the_same_way(self):
        managed = Path(tempfile.mkdtemp())
        value = str(managed / "anthropic_key.sh")
        for mod in MDM:
            (managed / "anthropic_key.sh").write_text("aws bedrock get-token")
            self.assertFalse(mod._is_unbound_key_helper_setting(value, managed))
            (managed / "anthropic_key.sh").write_text(OUR_HELPER)
            self.assertTrue(mod._is_unbound_key_helper_setting(value, managed))
            self.assertFalse(mod._is_unbound_key_helper_setting(
                str(managed / "acme_key.sh"), managed))


class TestTheInstallOrderHoldsTheSettingCheckUp(unittest.TestCase):
    """The install removes our helper file first, then strips the setting. The strip
    reads "nothing there" as our own removal having just run, so reordering the two would
    start deleting a dangling setting that belongs to somebody else."""

    def _install(self, body):
        home = Path(tempfile.mkdtemp())
        (home / ".claude").mkdir()
        (home / ".claude" / "anthropic_key.sh").write_text(body)
        with patch.object(HOOKS.Path, "home", staticmethod(lambda: home)):
            HOOKS.remove_gateway_artifacts()
            ours = HOOKS._is_unbound_key_helper_setting("~/.claude/anthropic_key.sh")
        return (home / ".claude" / "anthropic_key.sh").exists(), ours

    def test_our_helper_leaves_and_the_setting_follows_it(self):
        exists, setting_is_ours = self._install(OUR_HELPER)
        self.assertFalse(exists)
        self.assertTrue(setting_is_ours)

    def test_their_helper_stays_and_so_does_the_setting(self):
        exists, setting_is_ours = self._install("aws bedrock get-token --profile prod")
        self.assertTrue(exists)
        self.assertFalse(setting_is_ours)


class TestBodyCheckFailsOpen(unittest.TestCase):
    """A helper we cannot decode is not ours, and must not raise -- setup sits between
    the user and their editor."""

    def test_a_binary_helper_is_not_ours(self):
        path = Path(tempfile.mkdtemp()) / "anthropic_key.sh"
        path.write_bytes(b"\x89PNG\r\n\x1a\n\xff\xfe")
        for mod in USER_LEVEL:
            self.assertFalse(mod._is_unbound_key_helper_file(path))
        for mod in MDM:
            self.assertIsNone(mod._read_text_or_none(path))

    def test_a_missing_helper_is_not_ours(self):
        path = Path(tempfile.mkdtemp()) / "nope.sh"
        for mod in USER_LEVEL:
            self.assertFalse(mod._is_unbound_key_helper_file(path))


class TestGatewayInstallKeepsTheirHooks(unittest.TestCase):
    """Installing the gateway drops the Unbound hook, not the user's own."""

    THEIRS = {"matcher": "Bash",
              "hooks": [{"type": "command", "command": "/usr/local/bin/audit.sh"}]}

    @staticmethod
    def _ours(command):
        return {"matcher": "*", "hooks": [{"type": "command", "command": command}]}

    def setUp(self):
        self.home = Path(tempfile.mkdtemp())
        self.our_cmd = str(self.home / ".claude" / "hooks" / "unbound.py")
        patcher = patch.object(GATEWAY.Path, "home", staticmethod(lambda: self.home))
        patcher.start()
        self.addCleanup(patcher.stop)

    def test_their_hook_survives_and_ours_goes(self):
        settings = {"hooks": {"PreToolUse": [self.THEIRS, self._ours(self.our_cmd)]}}
        GATEWAY._strip_unbound_hooks(settings)
        self.assertEqual(settings["hooks"], {"PreToolUse": [self.THEIRS]})

    def test_the_block_goes_when_only_ours_was_there(self):
        settings = {"hooks": {"PreToolUse": [self._ours(self.our_cmd)],
                              "Stop": [self._ours(self.our_cmd)]}}
        GATEWAY._strip_unbound_hooks(settings)
        self.assertNotIn("hooks", settings)

    def test_the_launcher_form_the_windows_installer_writes_is_ours(self):
        # Windows registers `py -3 "<path>"`. The launcher and its flags are stripped and
        # the path compared through os.path.normcase/normpath, which is what makes the
        # separators that platform writes match; a substring match would not.
        cmd = 'py -3 "%s"' % self.our_cmd
        settings = {"hooks": {"Stop": [self._ours(cmd)]}}
        GATEWAY._strip_unbound_hooks(settings)
        self.assertNotIn("hooks", settings)

    def test_a_quoted_home_with_spaces_stays_one_token(self):
        # `py -3 "C:\Users\Jane Doe\..."` — shlex groups the quoted argument even with
        # posix=False, so the space in the home directory does not split the path
        import shlex as _shlex
        cmd = 'py -3 "C:\\Users\\Jane Doe\\.claude\\hooks\\unbound.py"'
        tokens = [t.strip().strip('"') for t in _shlex.split(cmd, posix=False)]
        self.assertEqual(tokens,
                         ["py", "-3", "C:\\Users\\Jane Doe\\.claude\\hooks\\unbound.py"])

    def test_a_native_path_with_spaces_is_matched(self):
        home = Path(tempfile.mkdtemp()) / "Jane Doe"
        home.mkdir()
        cmd = 'python3 "%s"' % (home / ".claude" / "hooks" / "unbound.py")
        with patch.object(GATEWAY.Path, "home", staticmethod(lambda: home)):
            settings = {"hooks": {"Stop": [self._ours(cmd)]}}
            GATEWAY._strip_unbound_hooks(settings)
        self.assertNotIn("hooks", settings)

    def test_a_python_launcher_without_flags_is_ours(self):
        home = Path(tempfile.mkdtemp())
        cmd = 'python3 "%s"' % (home / ".claude" / "hooks" / "unbound.py")
        with patch.object(GATEWAY.Path, "home", staticmethod(lambda: home)):
            settings = {"hooks": {"Stop": [self._ours(cmd)]}}
            GATEWAY._strip_unbound_hooks(settings)
        self.assertNotIn("hooks", settings)

    def test_a_foreign_script_merely_named_unbound_is_not_ours(self):
        home = Path(tempfile.mkdtemp())
        cmd = 'python3 /opt/acme/unbound.py'
        with patch.object(GATEWAY.Path, "home", staticmethod(lambda: home)):
            settings = {"hooks": {"Stop": [self._ours(cmd)]}}
            GATEWAY._strip_unbound_hooks(settings)
        self.assertIn("hooks", settings)

    def test_the_binary_form_is_ours_too(self):
        settings = {"hooks": {"Stop": [
            self._ours("/opt/unbound/current/unbound-hook/unbound-hook hook")]}}
        GATEWAY._strip_unbound_hooks(settings)
        self.assertNotIn("hooks", settings)

    def test_no_hooks_at_all(self):
        settings = {"model": "opus"}
        GATEWAY._strip_unbound_hooks(settings)
        self.assertEqual(settings, {"model": "opus"})


class TestOurOwnDropInIsOursByConstruction(unittest.TestCase):
    """managed-settings.d/unbound.json is written by nothing but this setup, so a
    self-hosted gateway URL in it is still ours -- no value check could tell."""

    SELF_HOSTED = "https://ai.acme-corp.internal"

    def _clear(self, filename, parent, env, extra=None):
        managed = Path(tempfile.mkdtemp())
        target = managed / parent if parent else managed
        target.mkdir(parents=True, exist_ok=True)
        content = {"env": dict(env)}
        content.update(extra or {})
        (target / filename).write_text(json.dumps(content))
        with patch.object(GATEWAY_MDM, "get_managed_settings_dir", lambda: managed):
            GATEWAY_MDM.clear_managed_settings()
        path = target / filename
        return json.loads(path.read_text()).get("env", {}) if path.exists() else {}

    def test_a_self_hosted_gateway_in_our_drop_in_is_cleared(self):
        left = self._clear("unbound.json", "managed-settings.d",
                           {"ANTHROPIC_BASE_URL": self.SELF_HOSTED,
                            "ANTHROPIC_AUTH_TOKEN": "org-token"})
        self.assertEqual(left, {})

    def test_a_self_hosted_gateway_in_the_shared_file_is_left_alone(self):
        # that file is the administrator's, so a URL we do not recognise stays -- the
        # credential beside it is ours and comes out either way
        left = self._clear("managed-settings.json", None,
                           {"ANTHROPIC_BASE_URL": self.SELF_HOSTED,
                            "ANTHROPIC_AUTH_TOKEN": "org-token"},
                           extra={"permissions": {"allow": []}})
        self.assertEqual(left, {"ANTHROPIC_BASE_URL": self.SELF_HOSTED,
                                "ANTHROPIC_AUTH_TOKEN": "org-token"})

    def test_our_gateway_in_the_shared_file_is_cleared(self):
        left = self._clear("managed-settings.json", None,
                           {"ANTHROPIC_BASE_URL": OURS, "ANTHROPIC_AUTH_TOKEN": "t"})
        self.assertEqual(left, {})

    def test_the_drop_in_is_recognised_in_both_mdm_trees(self):
        managed = Path("/Library/Application Support/ClaudeCode")
        for mod in MDM:
            self.assertTrue(mod._is_our_dropin(
                managed / "managed-settings.d" / "unbound.json"))
            self.assertFalse(mod._is_our_dropin(managed / "managed-settings.json"))
            self.assertFalse(mod._is_our_dropin(
                managed / "managed-settings.d" / "acme.json"))
            self.assertFalse(mod._is_our_dropin(None))


class TestTheCredentialComesOutOfOurFiles(unittest.TestCase):
    """ANTHROPIC_AUTH_TOKEN is written beside a base URL, so the pair goes together and
    only out of a file this setup wrote. A token in the administrator's own file is their
    credential. Inside our file the URL may since have been repointed, and the token still
    comes out -- otherwise it is sent to whatever that URL now names."""

    THEIR_URL = "https://ai.acme-corp.internal"

    def _clear(self, content, filename="managed-settings.json", parent=None):
        managed = Path(tempfile.mkdtemp())
        target = managed / parent if parent else managed
        target.mkdir(parents=True, exist_ok=True)
        (target / filename).write_text(json.dumps(content))
        with patch.object(GATEWAY_MDM, "get_managed_settings_dir", lambda: managed):
            GATEWAY_MDM.clear_managed_settings()
        path = target / filename
        return json.loads(path.read_text()) if path.exists() else {}

    def test_our_drop_in_gives_up_the_token_even_after_a_repoint(self):
        left = self._clear({"env": {"ANTHROPIC_BASE_URL": self.THEIR_URL,
                                    "ANTHROPIC_AUTH_TOKEN": "org-token"}},
                           filename="unbound.json", parent="managed-settings.d")
        self.assertEqual(left, {})

    def test_our_flat_signature_gives_it_up_too(self):
        left = self._clear({"env": {"ANTHROPIC_BASE_URL": OURS,
                                    "ANTHROPIC_AUTH_TOKEN": "org-token"}})
        self.assertEqual(left, {})

    def test_an_orphaned_token_in_our_drop_in_goes(self):
        left = self._clear({"env": {"ANTHROPIC_AUTH_TOKEN": "org-token"}},
                           filename="unbound.json", parent="managed-settings.d")
        self.assertEqual(left, {})

    def test_an_administrators_token_is_not_ours_to_delete(self):
        content = {"permissions": {"allow": []},
                   "env": {"ANTHROPIC_BASE_URL": self.THEIR_URL,
                           "ANTHROPIC_AUTH_TOKEN": "org-token"}}
        self.assertEqual(self._clear(content), content)

    def test_nor_is_an_orphaned_one_in_their_file(self):
        content = {"permissions": {"allow": []},
                   "env": {"ANTHROPIC_AUTH_TOKEN": "org-token"}}
        self.assertEqual(self._clear(content), content)

    def test_but_our_pair_inside_their_file_still_goes(self):
        # setup wrote this pair into their file, so it is ours to take back out
        left = self._clear({"permissions": {"allow": []},
                            "env": {"ANTHROPIC_BASE_URL": OURS,
                                    "ANTHROPIC_AUTH_TOKEN": "org-token"}})
        self.assertEqual(left, {"permissions": {"allow": []}})


class TestTheWriterAndTheReaderAgree(unittest.TestCase):
    """Every tree writes `export VAR="value"`. If that format ever changes, the ownership
    check stops recognising our own export and the setup silently stops cleaning up."""

    def test_the_written_export_is_recognised(self):
        line = 'export ANTHROPIC_BASE_URL="%s"' % OURS
        for mod in ALL:
            value = mod._export_value(line, "export ANTHROPIC_BASE_URL=")
            self.assertTrue(mod._is_unbound_base_url(value), mod.__name__)

    def test_unquoted_and_single_quoted_forms_too(self):
        for line in ('export ANTHROPIC_BASE_URL=%s' % OURS,
                     "export ANTHROPIC_BASE_URL='%s'" % OURS,
                     '  export ANTHROPIC_BASE_URL="%s"  ' % OURS):
            for mod in ALL:
                value = mod._export_value(line, "export ANTHROPIC_BASE_URL=")
                self.assertTrue(mod._is_unbound_base_url(value), "%s %r" % (mod.__name__, line))

    def test_a_registry_value_round_trips(self):
        output = ("\nHKEY_LOCAL_MACHINE\\...\\Environment\n"
                  "    ANTHROPIC_BASE_URL    REG_SZ    %s\n" % OURS)
        for mod in ALL:
            self.assertTrue(mod._is_unbound_base_url(
                mod._registry_value(output, "ANTHROPIC_BASE_URL")), mod.__name__)

    def test_an_unreadable_registry_value_is_not_a_verdict(self):
        # "" would read as "not ours" and silently leave our own value behind
        for mod in ALL:
            self.assertIsNone(mod._registry_value("ERROR: cannot find", "ANTHROPIC_BASE_URL"))
            self.assertIsNone(mod._registry_value("", "ANTHROPIC_BASE_URL"))

    def test_a_registry_value_that_is_theirs_is_not_ours(self):
        output = "    ANTHROPIC_BASE_URL    REG_SZ    %s\n" % THEIRS
        for mod in ALL:
            self.assertFalse(mod._is_unbound_base_url(
                mod._registry_value(output, "ANTHROPIC_BASE_URL")), mod.__name__)

    def test_the_helper_setting_accepts_both_forms(self):
        home = Path(tempfile.mkdtemp())
        (home / ".claude").mkdir()
        (home / ".claude" / "anthropic_key.sh").write_text(OUR_HELPER)
        for mod in USER_LEVEL:
            with patch.object(mod.Path, "home", staticmethod(lambda: home)):
                self.assertTrue(mod._is_unbound_key_helper_setting(
                    "~/.claude/anthropic_key.sh"))
                self.assertTrue(mod._is_unbound_key_helper_setting(
                    str(home / ".claude" / "anthropic_key.sh")))
                self.assertFalse(mod._is_unbound_key_helper_setting(
                    str(home / ".claude" / "bedrock_key.sh")))


if __name__ == "__main__":
    unittest.main()
