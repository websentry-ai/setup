"""The MCP server a Cursor beforeMCPExecution call names, and the config sent for it.

Drives main() with a real event on stdin and captures the request the gateway gets.
"""

import io
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from tests.conftest import tool_module

unbound = tool_module("cursor")

CTX7 = {"command": "npx", "args": ["-y", "@upstash/context7-mcp"]}


class TestCursorMcpServerIdentity(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self._tmp.name)
        self.project = self.dir / "project"
        (self.project / ".cursor").mkdir(parents=True)
        self.global_config = self.dir / "global-mcp.json"

    def tearDown(self):
        self._tmp.cleanup()

    def _run(self, event):
        sent = []
        stdin = io.StringIO(json.dumps({
            "hook_event_name": "beforeMCPExecution",
            "conversation_id": "c1",
            "generation_id": "g1",
            "tool_name": "resolve-library-id",
            "tool_input": {"libraryName": "react"},
            "workspace_roots": [str(self.project)],
            **event,
        }))
        with patch.object(unbound.sys, "stdin", stdin), \
                patch.object(unbound, "CURSOR_MCP_CONFIG_PATH", self.global_config), \
                patch.object(unbound, "SKILL_POLICY_STATE_ROOT", self.dir / "skills"), \
                patch.object(unbound, "get_api_key", return_value="k"), \
                patch.object(unbound, "send_to_hook_api",
                             side_effect=lambda body, key: sent.append(body) or {"decision": "allow"}), \
                patch("sys.stdout", new_callable=io.StringIO):
            unbound.main()
        self.assertEqual(len(sent), 1)
        return sent[0]["pre_tool_use_data"]["metadata"]

    def test_remote_server_is_checked_as_mcp_by_its_name_and_url(self):
        metadata = self._run({
            "mcp_server_name": "plugin-context7-context7",
            "url": "https://mcp.context7.com/mcp",
        })
        self.assertEqual(metadata["mcp_server"], "plugin-context7-context7")
        self.assertEqual(metadata["mcp_server_config"]["url"], "https://mcp.context7.com/mcp")

    def test_project_config_is_read_before_the_global_one(self):
        (self.project / ".cursor" / "mcp.json").write_text(json.dumps({"mcpServers": {"context7": CTX7}}))
        self.global_config.write_text(json.dumps({"mcpServers": {"context7": {"url": "https://other"}}}))
        metadata = self._run({"command": "context7", "mcp_server_name": "context7"})
        self.assertEqual(metadata["mcp_server"], "context7")
        self.assertEqual(metadata["mcp_server_config"]["command"], "npx")

    def test_global_config_still_applies_without_a_project_entry(self):
        self.global_config.write_text(json.dumps({"mcpServers": {"context7": CTX7}}))
        metadata = self._run({"command": "context7"})
        self.assertEqual(metadata["mcp_server_config"]["args"], CTX7["args"])


class TestCursorDeferredSkillContextKey(unittest.TestCase):
    def test_prompt_and_tool_call_share_the_pause_across_conversation_ids(self):
        # The Cursor CLI sends one conversation_id on the prompt and another on its tool calls.
        with tempfile.TemporaryDirectory() as tmp, \
                patch.object(unbound, "SKILL_POLICY_STATE_ROOT", Path(tmp)):
            unbound._defer_prompt_skill_context(
                {"conversation_id": "prompt-conv", "generation_id": "g1"},
                "Invoke /unbound-secure-sql before continuing.", "Loading skill.")
            response = unbound._with_deferred_skill_context(
                {"conversation_id": "tool-conv", "generation_id": "g1"}, {})
        self.assertEqual(response["permission"], "deny")
        self.assertEqual(response["user_message"], "Loading skill.")

    def test_another_generation_does_not_take_the_pause(self):
        with tempfile.TemporaryDirectory() as tmp, \
                patch.object(unbound, "SKILL_POLICY_STATE_ROOT", Path(tmp)):
            unbound._defer_prompt_skill_context(
                {"conversation_id": "c1", "generation_id": "g1"}, "Invoke /unbound-secure-sql.")
            response = unbound._with_deferred_skill_context(
                {"conversation_id": "c1", "generation_id": "g2"}, {})
        self.assertEqual(response, {})


if __name__ == "__main__":
    unittest.main()
