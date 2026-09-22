"""Codex keeps config.toml and auth.json under CODEX_HOME; the hook reads them there."""

import importlib.util
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from tests.conftest import REPO


def _fresh_hook():
    # Paths are resolved at import, so each case loads its own copy.
    alias = "unbound_setup_tests.codex_home_probe"
    spec = importlib.util.spec_from_file_location(alias, REPO / "codex/hooks/unbound.py")
    module = importlib.util.module_from_spec(spec)
    sys.modules[alias] = module
    spec.loader.exec_module(module)
    return module


class TestCodexHome(unittest.TestCase):
    def test_mcp_config_is_read_from_codex_home(self):
        with tempfile.TemporaryDirectory() as home:
            Path(home, "config.toml").write_text(
                '[mcp_servers.context7]\ncommand = "npx"\nargs = ["-y", "@upstash/context7-mcp"]\n')
            with patch.dict(os.environ, {"CODEX_HOME": home}):
                hook = _fresh_hook()
            self.assertEqual(hook.CODEX_CONFIG_PATH, Path(home) / "config.toml")
            self.assertEqual(hook.CODEX_AUTH_PATH, Path(home) / "auth.json")
            cfg = hook._read_mcp_server_config("context7", hook.CODEX_CONFIG_PATH)
            self.assertEqual(cfg["command"], "npx")

    def test_defaults_to_dot_codex(self):
        env = {k: v for k, v in os.environ.items() if k != "CODEX_HOME"}
        with patch.dict(os.environ, env, clear=True):
            hook = _fresh_hook()
        self.assertEqual(hook.CODEX_CONFIG_PATH, Path.home() / ".codex" / "config.toml")


if __name__ == "__main__":
    unittest.main()
