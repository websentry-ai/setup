import importlib.util
import json
import os
import tempfile
import unittest
from unittest import mock
from pathlib import Path

# Load gateway/setup.py under a unique module name so it can't collide with the
# hooks-mode setup.py when both test suites run in one pytest session.
_SPEC = importlib.util.spec_from_file_location(
    "gateway_setup", os.path.join(os.path.dirname(__file__), "setup.py")
)
gw = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(gw)


class TestResolveClaudeConfigDir(unittest.TestCase):
    """WEB-4882: gateway mode honors CLAUDE_CONFIG_DIR like the hooks installer."""

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
            # Relocated dir → absolute helper path so Claude resolves it under the active dir.
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


if __name__ == "__main__":
    unittest.main()
