"""
Tests that installing one Claude Code mode only removes the other mode's own artifacts.

Gateway and hooks cannot both drive Claude Code, so each setup clears the other. What it
must not clear is configuration somebody else put there: a custom ANTHROPIC_BASE_URL, an
apiKeyHelper pointing at their own script, or hooks they installed themselves.

Covers, on the hooks side:
  - _is_unbound_key_helper
  - _key_helper_file_is_ours
  - _is_unbound_base_url
  - remove_unbound_env_var
  - remove_gateway_artifacts
"""

import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import setup


class TestApiKeyHelperIdentity(unittest.TestCase):
    def test_the_form_the_gateway_writes(self):
        self.assertTrue(setup._is_unbound_key_helper("~/.claude/anthropic_key.sh"))

    def test_the_expanded_form(self):
        self.assertTrue(setup._is_unbound_key_helper(
            str(Path.home() / ".claude" / "anthropic_key.sh")))

    def test_someone_elses_helper(self):
        self.assertFalse(setup._is_unbound_key_helper("~/bin/my_own_key.sh"))

    def test_missing_or_wrong_type(self):
        self.assertFalse(setup._is_unbound_key_helper(None))
        self.assertFalse(setup._is_unbound_key_helper({"path": "x"}))


class TestKeyHelperFileIdentity(unittest.TestCase):
    def setUp(self):
        self.directory = Path(tempfile.mkdtemp())

    def test_the_script_the_gateway_wrote(self):
        path = self.directory / "anthropic_key.sh"
        path.write_text("echo $UNBOUND_API_KEY")
        self.assertTrue(setup._key_helper_file_is_ours(path))

    def test_a_script_of_the_same_name_holding_something_else(self):
        path = self.directory / "anthropic_key.sh"
        path.write_text("echo $MY_COMPANY_KEY")
        self.assertFalse(setup._key_helper_file_is_ours(path))

    def test_a_missing_file(self):
        self.assertFalse(setup._key_helper_file_is_ours(self.directory / "absent.sh"))


class TestBaseUrlIdentity(unittest.TestCase):
    def test_our_default_gateway(self):
        self.assertTrue(setup._is_unbound_base_url("https://api.getunbound.ai"))

    def test_a_trailing_slash_still_matches(self):
        self.assertTrue(setup._is_unbound_base_url("https://api.getunbound.ai/"))

    def test_another_host_of_ours(self):
        self.assertTrue(setup._is_unbound_base_url("https://eu.getunbound.ai"))

    def test_anthropic_itself_is_not_ours(self):
        self.assertFalse(setup._is_unbound_base_url("https://api.anthropic.com"))

    def test_a_customers_own_endpoint_is_not_ours(self):
        self.assertFalse(setup._is_unbound_base_url("https://llm.acme-corp.internal"))

    def test_a_lookalike_domain_is_not_ours(self):
        self.assertFalse(setup._is_unbound_base_url("https://getunbound.ai.evil.example"))

    def test_empty(self):
        self.assertFalse(setup._is_unbound_base_url(""))
        self.assertFalse(setup._is_unbound_base_url(None))


class TestGatewayEnvIsOurs(unittest.TestCase):
    """The Anthropic environment is only cleared when our gateway set it, which means our
    gateway URL alongside our API key. Either belonging to somebody else leaves both."""

    def _judge(self, base_url, api_key, recorded_key="unbound-key"):
        home = Path(tempfile.mkdtemp())
        (home / ".unbound").mkdir(parents=True)
        (home / ".unbound" / "config.json").write_text(json.dumps({
            "gateway_url": "https://api.getunbound.ai", "api_key": recorded_key}))
        values = {"ANTHROPIC_BASE_URL": base_url, "UNBOUND_API_KEY": api_key}
        with patch.object(setup.Path, "home", staticmethod(lambda: home)), \
             patch.object(setup, "_persisted_env_value", lambda n: values.get(n)):
            return setup._gateway_env_is_ours()

    def test_our_url_and_our_key(self):
        self.assertTrue(self._judge("https://api.getunbound.ai", "unbound-key"))

    def test_their_url_even_with_our_key_present(self):
        self.assertFalse(self._judge("https://llm.acme-corp.internal", "unbound-key"))

    def test_our_url_with_no_key_of_ours(self):
        # somebody pointing Claude Code at a URL on our host without our setup
        self.assertFalse(self._judge("https://api.getunbound.ai", None))

    def test_neither_is_ours(self):
        self.assertFalse(self._judge("https://llm.acme-corp.internal", None))

    def test_a_rotated_key_still_reads_as_ours(self):
        # a later run rewrites the recorded key; the leftovers are still ours to clear,
        # and refusing would strand Claude Code on our gateway with a dead credential
        self.assertTrue(self._judge("https://api.getunbound.ai", "older-key",
                                    recorded_key="newer-key"))


class TestGatewayArtifactRemoval(unittest.TestCase):
    def _run_with_helper(self, body):
        home = Path(tempfile.mkdtemp())
        (home / ".claude").mkdir(parents=True)
        helper = home / ".claude" / "anthropic_key.sh"
        if body is not None:
            helper.write_text(body)
        with patch.object(setup.Path, "home", staticmethod(lambda: home)):
            setup.remove_gateway_artifacts()
        return helper

    def test_our_helper_is_removed(self):
        helper = self._run_with_helper("echo $UNBOUND_API_KEY")
        self.assertFalse(helper.exists())

    def test_a_foreign_helper_survives(self):
        helper = self._run_with_helper("echo $MY_COMPANY_KEY")
        self.assertTrue(helper.exists())
        self.assertEqual(helper.read_text(), "echo $MY_COMPANY_KEY")

    def test_no_helper_at_all(self):
        helper = self._run_with_helper(None)
        self.assertFalse(helper.exists())


class TestHelperIdentityUsesBothPathAndBody(unittest.TestCase):
    """The path alone cannot decide: anthropic_key.sh is a name somebody could pick for
    their own helper, which this setup now leaves in place."""

    def _helper(self, body):
        home = Path(tempfile.mkdtemp())
        (home / ".claude").mkdir(parents=True)
        path = home / ".claude" / "anthropic_key.sh"
        if body is not None:
            path.write_text(body)
        return path

    def test_a_foreign_helper_at_our_path_is_not_ours(self):
        path = self._helper("echo $MY_COMPANY_KEY")
        self.assertFalse(setup._is_unbound_key_helper(str(path)))

    def test_our_helper_at_that_path_is_ours(self):
        path = self._helper("echo $UNBOUND_API_KEY")
        self.assertTrue(setup._is_unbound_key_helper(str(path)))

    def test_a_shebang_does_not_disown_a_real_install(self):
        path = self._helper("#!/bin/sh\necho $UNBOUND_API_KEY\n")
        self.assertTrue(setup._is_unbound_key_helper(str(path)))

    def test_a_dangling_pointer_at_our_path_is_ours_to_clear(self):
        path = self._helper(None)
        self.assertTrue(setup._is_unbound_key_helper(str(path)))

    def test_an_install_under_another_home_still_counts(self):
        self.assertTrue(
            setup._is_unbound_key_helper("/Users/someone/.claude/anthropic_key.sh"))

    def test_a_path_that_is_not_ours_at_all(self):
        self.assertFalse(setup._is_unbound_key_helper("~/bin/my_own_key.sh"))
        self.assertFalse(setup._is_unbound_key_helper("~/.claude/anthropic_key.sh.bak"))


class TestManagedEnvPairing(unittest.TestCase):
    """The gateway writes ANTHROPIC_AUTH_TOKEN and ANTHROPIC_BASE_URL together, so the
    URL identifies the pair. Taking the token from beside somebody else's URL would leave
    their endpoint with no credential."""

    @staticmethod
    def _strip(env):
        settings = {"env": dict(env)}
        block = settings["env"]
        if setup._is_unbound_base_url(block.get("ANTHROPIC_BASE_URL")):
            block.pop("ANTHROPIC_AUTH_TOKEN", None)
            block.pop("ANTHROPIC_BASE_URL", None)
        if not block:
            del settings["env"]
        return settings.get("env", {})

    def test_an_administrators_endpoint_and_credential_both_survive(self):
        out = self._strip({"ANTHROPIC_AUTH_TOKEN": "their-secret",
                           "ANTHROPIC_BASE_URL": "https://llm.acme-corp.internal"})
        self.assertEqual(out, {"ANTHROPIC_AUTH_TOKEN": "their-secret",
                               "ANTHROPIC_BASE_URL": "https://llm.acme-corp.internal"})

    def test_our_own_pair_is_removed_together(self):
        out = self._strip({"ANTHROPIC_AUTH_TOKEN": "unbound-key",
                           "ANTHROPIC_BASE_URL": "https://api.getunbound.ai"})
        self.assertEqual(out, {})

    def test_a_token_with_no_base_url_beside_it_is_left_alone(self):
        out = self._strip({"ANTHROPIC_AUTH_TOKEN": "lonely"})
        self.assertEqual(out, {"ANTHROPIC_AUTH_TOKEN": "lonely"})

    def test_unrelated_env_survives(self):
        out = self._strip({"ANTHROPIC_AUTH_TOKEN": "unbound-key",
                           "ANTHROPIC_BASE_URL": "https://api.getunbound.ai",
                           "HTTP_PROXY": "http://proxy:8080"})
        self.assertEqual(out, {"HTTP_PROXY": "http://proxy:8080"})


class TestUrlHostParsing(unittest.TestCase):
    """A backslash separates like a slash, so a host that only looks like ours is not."""

    def test_a_backslash_confused_lookalike(self):
        self.assertEqual(setup._url_host("https://evil.example\\.getunbound.ai"),
                         "evil.example")
        self.assertFalse(
            setup._is_unbound_base_url("https://evil.example\\.getunbound.ai"))

    def test_credentials_in_the_authority(self):
        self.assertEqual(setup._url_host("https://user:pw@api.getunbound.ai/v1"),
                         "api.getunbound.ai")

    def test_a_port(self):
        self.assertEqual(setup._url_host("https://api.getunbound.ai:8443"),
                         "api.getunbound.ai")


class TestPerLineEnvRemoval(unittest.TestCase):
    """A shell rc can hold more than one export of a name. Deciding from a single
    collapsed value would take somebody else's line away alongside ours."""

    def _rc(self, body):
        home = Path(tempfile.mkdtemp())
        rc = home / ".bashrc"
        rc.write_text(body)
        return home, rc

    def _remove(self, body):
        home, rc = self._rc(body)
        with patch.object(setup, "get_shell_rc_file", lambda: rc), \
             patch.object(setup.platform, "system", lambda: "Darwin"):
            status = setup._remove_env_var_lines(
                "ANTHROPIC_BASE_URL", setup._is_unbound_base_url)
        return status, rc.read_text()

    def test_only_our_line_goes(self):
        status, rest = self._remove(
            'export ANTHROPIC_BASE_URL="https://llm.acme-corp.internal"\n'
            'export ANTHROPIC_BASE_URL="https://api.getunbound.ai"\n')
        self.assertEqual(status, "cleared")
        self.assertIn("llm.acme-corp.internal", rest)
        self.assertNotIn("getunbound.ai", rest)

    def test_ours_first_theirs_last(self):
        status, rest = self._remove(
            'export ANTHROPIC_BASE_URL="https://api.getunbound.ai"\n'
            'export ANTHROPIC_BASE_URL="https://llm.acme-corp.internal"\n')
        self.assertEqual(status, "cleared")
        self.assertIn("llm.acme-corp.internal", rest)
        self.assertNotIn("getunbound.ai", rest)

    def test_only_a_foreign_line(self):
        status, rest = self._remove(
            'export ANTHROPIC_BASE_URL="https://llm.acme-corp.internal"\n')
        self.assertEqual(status, "skipped")
        self.assertIn("llm.acme-corp.internal", rest)

    def test_unrelated_lines_survive(self):
        status, rest = self._remove(
            'export PATH="$PATH:/opt/bin"\n'
            'export ANTHROPIC_BASE_URL="https://api.getunbound.ai"\n')
        self.assertEqual(status, "cleared")
        self.assertIn('export PATH="$PATH:/opt/bin"', rest)


if __name__ == "__main__":
    unittest.main()
