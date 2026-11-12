"""Which MCP server the Cursor hook reports to the gateway.

Drives the real entrypoint (main() reading a beforeMCPExecution event on stdin).
The event shape is a capture from the Cursor CLI: the server's name arrives in
`mcp_server_name`, the stdio launch string in `command`, and there is no `cwd`.
"""

import io
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from tests.conftest import tool_module

unbound = tool_module("cursor")

FS = {"command": "npx", "args": ["-y", "@modelcontextprotocol/server-filesystem", "/data"]}
OTHER = {"command": "python3", "args": ["/opt/other_server.py"]}
LAUNCH = "npx -y @modelcontextprotocol/server-filesystem /data"


class CursorMcpIdentity(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        root = Path(self._tmp.name)
        self.user_config = root / "home" / ".cursor" / "mcp.json"
        self.workspace = root / "repo"
        self.workspace.mkdir()
        self._patchers = [
            patch.object(unbound, "CURSOR_MCP_CONFIG_PATH", self.user_config),
            patch.object(unbound, "get_api_key", lambda: "API_KEY"),
            patch.object(unbound, "_emit", lambda s: None),
            patch.object(unbound, "load_policy_cache", lambda: {"tools_to_check": [], "ts": 0}),
            patch.object(unbound, "is_cache_stale", lambda c: False),
            patch.object(unbound, "get_recent_user_prompts_for_session", lambda *a, **k: []),
            patch.object(unbound, "_is_approval_retry", lambda *a, **k: False),
            patch.object(unbound, "build_account_identity", lambda *a, **k: {}),
            patch.object(unbound, "report_error_to_gateway", lambda *a, **k: None),
            patch.object(unbound, "_dispatch_mcp_server_scan", lambda *a, **k: None),
        ]
        for p in self._patchers:
            p.start()

    def tearDown(self):
        for p in self._patchers:
            p.stop()
        self._tmp.cleanup()

    def _write(self, path, servers):
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps({"mcpServers": servers}))

    def _send(self, **overrides):
        event = {
            "hook_event_name": "beforeMCPExecution",
            "tool_name": "write_file",
            "tool_input": "{}",
            "mcp_server_name": "fsx",
            "command": LAUNCH,
            "workspace_roots": [str(self.workspace)],
            "conversation_id": "c1",
            "generation_id": "c1",
        }
        event.update(overrides)
        event = {k: v for k, v in event.items() if v is not None}
        sent = {}

        def fake_send(body, api_key):
            sent["md"] = body["pre_tool_use_data"]["metadata"]
            return {"decision": "allow"}

        with patch.object(unbound, "send_to_hook_api", fake_send), \
             patch.object(sys, "stdin", io.StringIO(json.dumps(event))):
            try:
                unbound.main()
            except SystemExit:
                pass
        md = sent.get("md", {})
        return md.get("mcp_server"), md.get("mcp_server_config")

    def test_stdio_server_in_user_config_is_named_and_resolved(self):
        self._write(self.user_config, {"fsx": FS})
        self.assertEqual(self._send(), ("fsx", FS))

    def test_stdio_server_in_workspace_config_is_resolved(self):
        self._write(self.workspace / ".cursor" / "mcp.json", {"fsx": FS})
        self.assertEqual(self._send(), ("fsx", FS))

    def test_workspace_config_beats_user_config(self):
        self._write(self.user_config, {"fsx": OTHER})
        self._write(self.workspace / ".cursor" / "mcp.json", {"fsx": FS})
        self.assertEqual(self._send(), ("fsx", FS))

    def test_each_workspace_root_is_searched(self):
        other_root = self.workspace.parent / "second"
        self._write(other_root / ".cursor" / "mcp.json", {"fsx": FS})
        self.assertEqual(
            self._send(workspace_roots=[str(self.workspace), str(other_root)]), ("fsx", FS))

    def test_remote_server_outside_any_config_is_identified_by_url(self):
        url = "https://mcp.example.com/mcp"
        self.assertEqual(
            self._send(command=None, url=url, mcp_server_url=url), ("fsx", {"url": url}))

    def test_older_cursor_without_a_server_name_keeps_the_command(self):
        # Before mcp_server_name existed the command was the only identifier sent.
        self._write(self.user_config, {"fsx": FS})
        self.assertEqual(self._send(mcp_server_name=None), (LAUNCH, None))

    def test_unknown_server_sends_the_name_without_config(self):
        self.assertEqual(self._send(), ("fsx", None))

    def test_secrets_in_the_config_are_not_sent(self):
        self._write(self.user_config, {"fsx": {**FS, "env": {"TOKEN": "s3cr3t"},
                                               "headers": {"Authorization": "Bearer x"}}})
        self.assertEqual(self._send(), ("fsx", FS))

    def test_relative_script_resolves_against_the_workspace(self):
        script = self.workspace / "server.js"
        script.write_bytes(b"console.log('x')\n")
        self._write(self.workspace / ".cursor" / "mcp.json",
                    {"fsx": {"command": "node", "args": ["server.js"]}})
        _, cfg = self._send(command="node server.js")
        self.assertIn("scriptHash", cfg)


if __name__ == "__main__":
    unittest.main()
