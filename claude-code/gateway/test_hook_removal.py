"""
Tests that gateway setup removes only the hooks Unbound installed.

Gateway and hooks cannot both drive Claude Code, so gateway setup clears our hook. A hook
somebody else installed is not this setup's to take away.

Covers:
  - _command_targets_unbound_hook
  - _strip_unbound_hooks
"""

import importlib.util
import unittest
from pathlib import Path

# Loaded by path under its own name: `setup` is also the module name of the hooks tree,
# and importing it plainly makes whichever ran first win for both.
_spec = importlib.util.spec_from_file_location(
    "unbound_gateway_setup", Path(__file__).resolve().parent / "setup.py")
setup = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(setup)

SCRIPT = Path.home() / ".claude" / "hooks" / "unbound.py"
OURS = {"command": "python3 %s" % SCRIPT}
THEIRS = {"command": "/usr/local/bin/their-hook"}


class TestCommandMatching(unittest.TestCase):
    def test_our_script(self):
        self.assertTrue(setup._command_targets_unbound_hook(OURS["command"], SCRIPT))

    def test_a_launcher_prefix_and_quoting(self):
        self.assertTrue(setup._command_targets_unbound_hook(
            'py -3 "%s" --flag' % SCRIPT, SCRIPT))

    def test_a_different_script_of_the_same_name(self):
        self.assertFalse(setup._command_targets_unbound_hook(
            "python3 /elsewhere/unbound.py", SCRIPT))

    def test_someone_elses_hook(self):
        self.assertFalse(setup._command_targets_unbound_hook(THEIRS["command"], SCRIPT))

    def test_empty_or_unparseable(self):
        self.assertFalse(setup._command_targets_unbound_hook("", SCRIPT))
        self.assertFalse(setup._command_targets_unbound_hook('unclosed "quote', SCRIPT))


class TestStripUnboundHooks(unittest.TestCase):
    def test_a_sibling_hook_survives(self):
        settings = {"hooks": {"PreToolUse": [{"hooks": [OURS, THEIRS]}]}}
        self.assertTrue(setup._strip_unbound_hooks(settings, SCRIPT))
        self.assertEqual(settings["hooks"]["PreToolUse"][0]["hooks"], [THEIRS])

    def test_an_event_that_was_only_ours_is_dropped(self):
        settings = {"hooks": {"Stop": [{"hooks": [OURS]}]}}
        setup._strip_unbound_hooks(settings, SCRIPT)
        self.assertNotIn("hooks", settings)

    def test_a_config_of_only_their_hooks_is_untouched(self):
        settings = {"hooks": {"PreToolUse": [{"hooks": [THEIRS]}]}}
        self.assertFalse(setup._strip_unbound_hooks(settings, SCRIPT))
        self.assertEqual(settings["hooks"]["PreToolUse"][0]["hooks"], [THEIRS])

    def test_a_non_list_event_is_left_as_it_is(self):
        settings = {"hooks": {"Odd": {"admin": "value"}}}
        setup._strip_unbound_hooks(settings, SCRIPT)
        self.assertEqual(settings["hooks"]["Odd"], {"admin": "value"})

    def test_unrelated_settings_are_untouched(self):
        settings = {"hooks": {"Stop": [{"hooks": [OURS]}]}, "model": "opus"}
        setup._strip_unbound_hooks(settings, SCRIPT)
        self.assertEqual(settings["model"], "opus")

    def test_no_hooks_key(self):
        self.assertFalse(setup._strip_unbound_hooks({}, SCRIPT))


if __name__ == "__main__":
    unittest.main()
