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
    def _ours(command="~/.claude/hooks/unbound.py"):
        return {"matcher": "*", "hooks": [{"type": "command", "command": command}]}

    def test_their_hook_survives_and_ours_goes(self):
        settings = {"hooks": {"PreToolUse": [self.THEIRS, self._ours()]}}
        GATEWAY._strip_unbound_hooks(settings)
        self.assertEqual(settings["hooks"], {"PreToolUse": [self.THEIRS]})

    def test_the_block_goes_when_only_ours_was_there(self):
        settings = {"hooks": {"PreToolUse": [self._ours()], "Stop": [self._ours()]}}
        GATEWAY._strip_unbound_hooks(settings)
        self.assertNotIn("hooks", settings)

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

    def _clear(self, filename, parent, env):
        managed = Path(tempfile.mkdtemp())
        target = managed / parent if parent else managed
        target.mkdir(parents=True, exist_ok=True)
        (target / filename).write_text(json.dumps({"env": dict(env)}))
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
                            "ANTHROPIC_AUTH_TOKEN": "org-token"})
        self.assertEqual(left, {"ANTHROPIC_BASE_URL": self.SELF_HOSTED})

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


class TestTheCredentialAlwaysComesOut(unittest.TestCase):
    """ANTHROPIC_AUTH_TOKEN is a credential this setup wrote, and it is sent to whatever
    ANTHROPIC_BASE_URL currently names. Leaving it behind after a repoint hands our token
    to somebody else's endpoint."""

    THEIR_URL = "https://ai.acme-corp.internal"

    def _clear(self, env):
        managed = Path(tempfile.mkdtemp())
        managed.mkdir(parents=True, exist_ok=True)
        (managed / "managed-settings.json").write_text(json.dumps({"env": dict(env)}))
        with patch.object(GATEWAY_MDM, "get_managed_settings_dir", lambda: managed):
            GATEWAY_MDM.clear_managed_settings()
        path = managed / "managed-settings.json"
        return json.loads(path.read_text()).get("env", {}) if path.exists() else {}

    def test_the_token_goes_even_when_the_url_was_repointed(self):
        left = self._clear({"ANTHROPIC_BASE_URL": self.THEIR_URL,
                            "ANTHROPIC_AUTH_TOKEN": "org-token"})
        self.assertNotIn("ANTHROPIC_AUTH_TOKEN", left)

    def test_a_repointed_url_still_stays(self):
        left = self._clear({"ANTHROPIC_BASE_URL": self.THEIR_URL,
                            "ANTHROPIC_AUTH_TOKEN": "org-token"})
        self.assertEqual(left.get("ANTHROPIC_BASE_URL"), self.THEIR_URL)

    def test_an_orphaned_token_with_no_url_goes(self):
        self.assertEqual(self._clear({"ANTHROPIC_AUTH_TOKEN": "org-token"}), {})

    def test_the_whole_pair_goes_when_the_url_is_ours(self):
        self.assertEqual(
            self._clear({"ANTHROPIC_BASE_URL": OURS, "ANTHROPIC_AUTH_TOKEN": "t"}), {})


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
