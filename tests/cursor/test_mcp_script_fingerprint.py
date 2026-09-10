"""Local-script fingerprinting for cursor/unbound.py.

Drives the real chain the PreToolUse path uses: ~/.cursor/mcp.json ->
_read_mcp_server_config -> _augment_script_hash.
"""

import hashlib
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from tests.conftest import tool_module

unbound = tool_module("cursor")


class TestLocalScriptFingerprint(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self._tmp.name)
        self.config = self.dir / "mcp.json"
        self.script = self.dir / "build" / "index.js"
        self.script.parent.mkdir(parents=True, exist_ok=True)
        self.body = b"console.log('ctx')\n"
        self.script.write_bytes(self.body)
        self.sha = hashlib.sha256(self.body).hexdigest()

    def tearDown(self):
        self._tmp.cleanup()

    def _fingerprint(self, server_config):
        self.config.write_text(json.dumps({"mcpServers": {"ctx": server_config}}))
        cfg = unbound._read_mcp_server_config("ctx", self.config)
        return unbound._augment_script_hash(cfg, str(self.dir))

    def test_plain_script_argument_is_hashed(self):
        self.assertEqual(
            self._fingerprint({"command": "node", "args": [str(self.script)]})["scriptHash"],
            self.sha)

    def test_module_run_never_hashes_an_unrelated_file(self):
        notes = self.dir / "notes.py"
        notes.write_bytes(b"# private\n")
        self.assertNotIn("scriptHash", self._fingerprint(
            {"command": "python", "args": ["-m", "package", str(notes)]}))

    def test_windows_module_run_never_hashes_a_trailing_path(self):
        self.assertNotIn("scriptHash", self._fingerprint(
            {"command": "python", "args": ["-m", "package", r"C:\private\notes.py"]}))

    def test_preload_flag_makes_the_entrypoint_ambiguous(self):
        preload = self.dir / "build" / "preload.js"
        preload.write_bytes(b"// preload\n")
        self.assertNotIn("scriptHash", self._fingerprint({
            "command": "node", "args": ["-r", str(preload), str(self.script)],
        }))

    def test_script_symlink_to_a_non_script_is_not_hashed(self):
        secret = self.dir / "credentials"
        secret.write_bytes(b"aws_secret_access_key = 1\n")
        link = self.dir / "server.py"
        link.symlink_to(secret)
        self.assertNotIn("scriptHash", self._fingerprint(
            {"command": "python3", "args": [str(link)]}))

    def test_script_symlink_to_a_real_script_is_hashed(self):
        link = self.dir / "server.js"
        link.symlink_to(self.script)
        self.assertEqual(
            self._fingerprint({"command": "node", "args": [str(link)]})["scriptHash"],
            self.sha)

    def test_unreadable_script_is_diagnosed_not_swallowed(self):
        script = self.dir / "locked.py"
        script.write_bytes(b"print('secret-body')\n")
        script.chmod(0o000)
        try:
            with patch.object(unbound, "log_error") as log_error:
                cfg = self._fingerprint({"command": "python3", "args": [str(script)]})
        finally:
            script.chmod(0o600)
        self.assertNotIn("scriptHash", cfg)
        message, category = log_error.call_args.args[:2]
        self.assertEqual(category, "mcp_config")
        self.assertIn("PermissionError", message)
        self.assertNotIn("secret-body", message)


if __name__ == "__main__":
    unittest.main()
