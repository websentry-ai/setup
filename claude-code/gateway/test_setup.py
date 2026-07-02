import importlib.util
import json
import os
import tempfile
import unittest
from unittest import mock
from pathlib import Path

_SPEC = importlib.util.spec_from_file_location(
    "gateway_setup", os.path.join(os.path.dirname(__file__), "setup.py")
)
gw = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(gw)


class TestResolveClaudeConfigDir(unittest.TestCase):

    def test_env_wins(self):
        with tempfile.TemporaryDirectory() as d:
            with mock.patch.dict(os.environ, {"CLAUDE_CONFIG_DIR": d}):
                self.assertEqual(gw._resolve_claude_config_dir(None), Path(d).resolve())

    def test_env_takes_precedence_over_arg(self):
        with tempfile.TemporaryDirectory() as d:
            with mock.patch.dict(os.environ, {"CLAUDE_CONFIG_DIR": d}):
                self.assertEqual(gw._resolve_claude_config_dir("/other/dir"), Path(d).resolve())

    def test_arg_used_when_env_absent(self):
        with mock.patch.dict(os.environ, {}, clear=False):
            os.environ.pop("CLAUDE_CONFIG_DIR", None)
            self.assertEqual(gw._resolve_claude_config_dir("/opt/cc"), Path("/opt/cc").resolve())

    def test_default_fallback(self):
        with mock.patch.dict(os.environ, {}, clear=False):
            os.environ.pop("CLAUDE_CONFIG_DIR", None)
            self.assertEqual(gw._resolve_claude_config_dir(None), Path.home() / ".claude")

    def test_blank_env_falls_back(self):
        with mock.patch.dict(os.environ, {"CLAUDE_CONFIG_DIR": "   "}):
            self.assertEqual(gw._resolve_claude_config_dir(None), Path.home() / ".claude")


class TestKeyHelperUnderConfigDir(unittest.TestCase):
    def test_custom_dir_writes_there_with_absolute_helper(self):
        with tempfile.TemporaryDirectory() as d:
            cc = Path(d) / "cc"
            gw.setup_claude_key_helper(cc)
            self.assertTrue((cc / "anthropic_key.sh").exists())
            settings = json.loads((cc / "settings.json").read_text())
            self.assertEqual(settings["apiKeyHelper"], str(cc / "anthropic_key.sh"))

    def test_default_dir_keeps_portable_helper(self):
        with tempfile.TemporaryDirectory() as home:
            with mock.patch.object(gw.Path, "home", staticmethod(lambda: Path(home))):
                default_dir = Path(home) / ".claude"
                gw.setup_claude_key_helper(default_dir)
                settings = json.loads((default_dir / "settings.json").read_text())
                self.assertEqual(settings["apiKeyHelper"], "~/.claude/anthropic_key.sh")

    def test_detect_install_state_honors_config_dir(self):
        with tempfile.TemporaryDirectory() as d:
            cc = Path(d) / "cc"
            self.assertEqual(gw.detect_install_state(cc), "fresh")
            gw.setup_claude_key_helper(cc)
            self.assertEqual(gw.detect_install_state(cc), "persisted")

    def test_apikeyhelper_portable_when_dir_equals_default_via_realpath(self):
        # Passing the default dir (even pre-resolution) must still yield the
        # portable ~/.claude form, not an absolute realpath.
        with tempfile.TemporaryDirectory() as home:
            with mock.patch.object(gw.Path, "home", staticmethod(lambda: Path(home))):
                gw.setup_claude_key_helper(Path(home) / ".claude")
                settings = json.loads((Path(home) / ".claude" / "settings.json").read_text())
                self.assertEqual(settings["apiKeyHelper"], "~/.claude/anthropic_key.sh")


class TestClearSweepsLegacyDir(unittest.TestCase):
    def test_clear_relocated_also_clears_default_claude(self):
        with tempfile.TemporaryDirectory() as home:
            home = Path(home)
            with mock.patch.object(gw.Path, "home", staticmethod(lambda: home)):
                legacy = home / ".claude"
                legacy.mkdir(parents=True)
                (legacy / "anthropic_key.sh").write_text("echo x")
                (legacy / "settings.json").write_text(json.dumps({"apiKeyHelper": "~/.claude/anthropic_key.sh"}))
                cc = home / "cc"
                gw.setup_claude_key_helper(cc)
                gw.clear_setup(cc)
                # active dir cleared
                self.assertFalse((cc / "anthropic_key.sh").exists())
                # legacy ~/.claude swept too
                self.assertFalse((legacy / "anthropic_key.sh").exists())
                self.assertNotIn("apiKeyHelper", json.loads((legacy / "settings.json").read_text()))

    def test_clear_default_dir_does_not_double_sweep(self):
        with tempfile.TemporaryDirectory() as home:
            home = Path(home)
            with mock.patch.object(gw.Path, "home", staticmethod(lambda: home)):
                gw.setup_claude_key_helper(home / ".claude")
                gw.clear_setup(home / ".claude")
                self.assertFalse((home / ".claude" / "anthropic_key.sh").exists())


if __name__ == "__main__":
    unittest.main()
