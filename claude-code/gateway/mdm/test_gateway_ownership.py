"""
Tests that the gateway MDM teardown removes only the Anthropic environment it wrote.

The base-URL check reads UNBOUND_API_KEY, so it has to run while that key is still
there. Covers:
  - _clear_env_var_across_users  (per-user gate, per-line removal, sweep order)
  - clear_setup                  (BASE_URL swept before API_KEY)
"""

import importlib.util
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

# Loaded by path: several trees in this repo have a module named `setup`, and importing
# it plainly makes whichever ran first win for all of them.
_spec = importlib.util.spec_from_file_location(
    "unbound_claude_gateway_mdm_setup", Path(__file__).resolve().parent / "setup.py")
setup = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(setup)

OURS = "https://tenant.getunbound.ai"
THEIRS = "https://llm.acme-corp.internal"


def _home(gateway_url=OURS, api_key="user-key"):
    home = Path(tempfile.mkdtemp())
    (home / ".unbound").mkdir()
    (home / ".unbound" / "config.json").write_text(
        json.dumps({"gateway_url": gateway_url, "api_key": api_key}))
    return home


class TestClearAcrossUsers(unittest.TestCase):
    def setUp(self):
        for target, attr, value in (
                (setup.platform, "system", lambda: "Darwin"),
                # the privilege drop has its own tests; here it only has to not need root
                (setup, "_run_as_user", lambda _u, fn, *a, **k: fn(*a, **k))):
            patcher = patch.object(target, attr, value)
            patcher.start()
            self.addCleanup(patcher.stop)

    def _sweep(self, var_name, home):
        return setup._clear_env_var_across_users(var_name, [("alice", home)])

    def test_our_pair_is_cleared(self):
        home = _home()
        (home / ".zprofile").write_text(
            'export ANTHROPIC_BASE_URL="%s"\nexport UNBOUND_API_KEY="user-key"\n' % OURS)
        self.assertEqual(self._sweep("ANTHROPIC_BASE_URL", home), (1, 0, 0))
        self.assertEqual((home / ".zprofile").read_text(),
                         'export UNBOUND_API_KEY="user-key"\n')

    def test_a_customers_endpoint_with_no_unbound_key_survives(self):
        home = _home()
        (home / ".zprofile").write_text('export ANTHROPIC_BASE_URL="%s"\n' % THEIRS)
        self.assertEqual(self._sweep("ANTHROPIC_BASE_URL", home), (0, 1, 0))
        self.assertIn(THEIRS, (home / ".zprofile").read_text())

    def test_a_customers_endpoint_beside_our_key_still_survives(self):
        # and it counts as nothing-to-clear, not as a teardown failure
        home = _home()
        (home / ".zprofile").write_text(
            'export ANTHROPIC_BASE_URL="%s"\nexport UNBOUND_API_KEY="user-key"\n' % THEIRS)
        self.assertEqual(self._sweep("ANTHROPIC_BASE_URL", home), (0, 1, 0))
        self.assertIn(THEIRS, (home / ".zprofile").read_text())

    def test_ours_and_theirs_together_leaves_only_theirs(self):
        home = _home()
        (home / ".zprofile").write_text(
            'export ANTHROPIC_BASE_URL="%s"\n'
            'export ANTHROPIC_BASE_URL="%s"\n'
            'export UNBOUND_API_KEY="user-key"\n' % (THEIRS, OURS))
        self.assertEqual(self._sweep("ANTHROPIC_BASE_URL", home), (1, 0, 0))
        text = (home / ".zprofile").read_text()
        self.assertIn(THEIRS, text)
        self.assertNotIn(OURS, text)


class TestSweepOrder(unittest.TestCase):
    """Clearing UNBOUND_API_KEY first would leave every base URL unjudged, and the device
    still routed at us after uninstall."""

    def test_base_url_is_swept_before_the_key(self):
        seen = []
        with patch.object(setup, "check_admin_privileges", lambda: True), \
             patch.object(setup, "get_all_user_homes", lambda: [("alice", _home())]), \
             patch.object(setup, "_clear_env_var_across_users",
                          lambda var, homes, label=None: (seen.append(var), (0, 0, 0))[1]):
            try:
                setup.clear_setup()
            except Exception:
                pass
        self.assertEqual(seen[:2], ["ANTHROPIC_BASE_URL", "UNBOUND_API_KEY"])


class TestManagedEnvBlock(unittest.TestCase):
    """The managed env pair goes only when it is the one this setup wrote. A self-hosted
    gateway is identified by the URL recorded for a user, not by our host name."""

    SELF_HOSTED = "https://ai.acme-corp.internal"

    def setUp(self):
        # the privilege drop has its own tests; here it only has to not need a real user
        patcher = patch.object(setup, "_run_as_user", lambda _u, fn, *a, **k: fn(*a, **k))
        patcher.start()
        self.addCleanup(patcher.stop)

    def _clear(self, env, homes):
        managed = Path(tempfile.mkdtemp())
        dropin = managed / "managed-settings.d"
        dropin.mkdir(parents=True)
        (dropin / "unbound.json").write_text(json.dumps({"env": env}))
        with patch.object(setup, "get_managed_settings_dir", lambda: managed), \
             patch.object(setup, "get_all_user_homes", lambda: homes):
            setup.clear_managed_settings()
        path = dropin / "unbound.json"
        return json.loads(path.read_text()).get("env", {}) if path.exists() else {}

    def test_our_self_hosted_pair_is_removed(self):
        homes = [("alice", _home(gateway_url=self.SELF_HOSTED, api_key="ub-key"))]
        left = self._clear({"ANTHROPIC_BASE_URL": self.SELF_HOSTED,
                            "ANTHROPIC_AUTH_TOKEN": "ub-key"}, homes)
        self.assertEqual(left, {})

    def test_an_administrators_own_pair_survives(self):
        homes = [("alice", _home(gateway_url=self.SELF_HOSTED, api_key="ub-key"))]
        env = {"ANTHROPIC_BASE_URL": "https://llm.someone-else.internal",
               "ANTHROPIC_AUTH_TOKEN": "their-token"}
        self.assertEqual(self._clear(env, homes), env)

    def test_unrelated_managed_env_survives(self):
        homes = [("alice", _home(gateway_url=self.SELF_HOSTED, api_key="ub-key"))]
        left = self._clear({"ANTHROPIC_BASE_URL": self.SELF_HOSTED,
                            "ANTHROPIC_AUTH_TOKEN": "ub-key",
                            "HTTPS_PROXY": "http://corp-proxy:3128"}, homes)
        self.assertEqual(left, {"HTTPS_PROXY": "http://corp-proxy:3128"})


class TestPerUserConfigRecordsTheGateway(unittest.TestCase):
    def test_the_gateway_url_is_written_beside_the_key(self):
        home = Path(tempfile.mkdtemp())
        with patch.object(setup, "_run_as_user", lambda _u, fn, *a, **k: fn(*a, **k)):
            setup.write_unbound_config_for_user(
                "alice", home, "ub-key", "https://ai.acme-corp.internal/")
        config = json.loads((home / ".unbound" / "config.json").read_text())
        self.assertEqual(config["api_key"], "ub-key")
        self.assertEqual(config["gateway_url"], "https://ai.acme-corp.internal")

    def test_no_gateway_url_leaves_the_key_alone(self):
        home = Path(tempfile.mkdtemp())
        with patch.object(setup, "_run_as_user", lambda _u, fn, *a, **k: fn(*a, **k)):
            setup.write_unbound_config_for_user("alice", home, "ub-key")
        config = json.loads((home / ".unbound" / "config.json").read_text())
        self.assertEqual(config, {"api_key": "ub-key"})


class TestOwnershipHelpersMatchTheHooksTree(unittest.TestCase):
    """Both MDM trees answer the same ownership questions; a fix in one that misses the
    other is how a device ends up with two different ideas of what belongs to us."""

    SHARED = ["_machine_env_value", "_owned_env_value", "_remove_env_var_lines_for_user",
              "_write_user_file", "_read_user_file", "_user_env_value", "_home_owner_of",
              "_key_helper_file_is_ours", "_is_unbound_api_key_any_user",
              "_is_unbound_base_url_any_user"]

    @staticmethod
    def _sources(path):
        import ast
        text = Path(path).read_text()
        lines = text.splitlines()
        return {node.name: "\n".join(lines[node.lineno - 1:node.end_lineno])
                for node in ast.parse(text).body
                if isinstance(node, ast.FunctionDef)}

    def test_every_shared_helper_is_byte_identical(self):
        here = Path(__file__).resolve().parent
        mine = self._sources(here / "setup.py")
        theirs = self._sources(here.parent.parent / "hooks" / "mdm" / "setup.py")
        for name in self.SHARED:
            self.assertIn(name, mine, name)
            self.assertIn(name, theirs, name)
            self.assertEqual(mine[name], theirs[name], "%s drifted across trees" % name)


if __name__ == "__main__":
    unittest.main()
