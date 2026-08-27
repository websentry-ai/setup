"""
Tests for turn scoping in copilot/hooks/unbound.py.

A prompt typed while Copilot is working joins the running turn, but where it lands
differs by surface: inside the open agent turn in the CLI, outside it in VS Code. The
turn is therefore defined as the prompts not yet reported, not by position. Covers:
  - build_exchange_from_transcript
  - get_forwarded_state / record_forwarded_tool_ids  (reported-prompt watermark)
"""

import json
import tempfile
import unittest
import unittest.mock
from pathlib import Path

from tests.conftest import tool_module

unbound = tool_module("copilot/hooks")
SESSION = "sess-1"


def _entry(entry_type, _id=None, **data):
    entry = {"type": entry_type, "data": data}
    if _id:
        entry["id"] = _id
    return entry


def _transcript(entries):
    path = Path(tempfile.mkdtemp()) / "events.jsonl"
    with open(path, "w", encoding="utf-8") as f:
        for entry in entries:
            f.write(json.dumps(entry) + "\n")
    return str(path)


def _tool(call_id):
    return [_entry("tool.execution_start", toolCallId=call_id, toolName="shell",
                   arguments={"command": "ls"}),
            _entry("tool.execution_complete", toolCallId=call_id, success=True,
                   result={"output": "ok"})]


def _user_text(exchange):
    return [m["content"] for m in (exchange or {}).get("messages", [])
            if m.get("role") == "user"]


class TestTurnIsTheUnreportedPrompts(unittest.TestCase):
    def test_powershell_is_not_reported_as_mcp(self):
        path = _transcript([
            _entry("user.message", _id="u1", content="check it"),
            _entry("tool.execution_start", toolCallId="call-a", toolName="powershell",
                   arguments={"command": "Get-ChildItem"}),
            _entry("tool.execution_complete", toolCallId="call-a", success=True,
                   result={"content": "file.txt"}),
            _entry("assistant.message", content="done"),
        ])

        exchange, _forwarded, _sig, _prompts = unbound.build_exchange_from_transcript(
            path, SESSION)

        tool_use = exchange["messages"][1]["tool_use"]
        self.assertEqual(tool_use[0]["type"], "afterShellExecution")
        self.assertEqual(tool_use[0]["command"], "Get-ChildItem")

    def test_write_powershell_is_reported_as_shell_input(self):
        path = _transcript([
            _entry("user.message", _id="u1", content="answer the prompt"),
            _entry("tool.execution_start", toolCallId="call-a", toolName="write_powershell",
                   arguments={"input": "yes"}),
            _entry("tool.execution_complete", toolCallId="call-a", success=True,
                   result={"content": "continued"}),
            _entry("assistant.message", content="done"),
        ])

        exchange, _forwarded, _sig, _prompts = unbound.build_exchange_from_transcript(
            path, SESSION)

        tool_use = exchange["messages"][1]["tool_use"]
        self.assertEqual(tool_use[0]["type"], "afterShellExecution")
        self.assertEqual(tool_use[0]["command"], "yes")

    def test_read_bash_is_not_emitted(self):
        path = _transcript([
            _entry("user.message", _id="u1", content="read output"),
            _entry("tool.execution_start", toolCallId="call-a", toolName="read_bash",
                   arguments={"sessionId": "1"}),
            _entry("tool.execution_complete", toolCallId="call-a", success=True,
                   result={"content": "done"}),
            _entry("assistant.message", content="done"),
        ])

        exchange, _forwarded, _sig, _prompts = unbound.build_exchange_from_transcript(
            path, SESSION)

        self.assertNotIn("tool_use", exchange["messages"][1])

    def test_configured_mcp_name_takes_precedence_over_native_suppression(self):
        mapped = unbound.map_copilot_tool(
            'read_bash',
            {'sessionId': '1'},
            'done',
            mcp_servers={'read_bash': {'command': 'fake-server'}},
        )

        self.assertEqual(mapped['type'], 'afterMCPExecution')
        self.assertEqual(mapped['server_name'], 'read_bash')

    def test_cli_agent_wrapper_is_not_emitted(self):
        path = _transcript([
            _entry("user.message", _id="u1", content="check agents"),
            _entry("tool.execution_start", toolCallId="call-a", toolName="list_agents",
                   arguments={}),
            _entry("tool.execution_complete", toolCallId="call-a", success=True,
                   result={"content": "none"}),
            _entry("assistant.message", content="done"),
        ])

        exchange, _forwarded, _sig, _prompts = unbound.build_exchange_from_transcript(
            path, SESSION)

        self.assertNotIn("tool_use", exchange["messages"][1])

    def test_editor_diagnostics_are_not_emitted(self):
        path = _transcript([
            _entry("user.message", _id="u1", content="check errors"),
            _entry("tool.execution_start", toolCallId="call-a", toolName="get_errors",
                   arguments={"filePaths": ["app.py"]}),
            _entry("tool.execution_complete", toolCallId="call-a", success=True,
                   result={"content": "no errors"}),
            _entry("assistant.message", content="done"),
        ])

        exchange, _forwarded, _sig, _prompts = unbound.build_exchange_from_transcript(
            path, SESSION)

        self.assertNotIn("tool_use", exchange["messages"][1])

    def test_unknown_copilot_tool_is_not_reported_as_mcp(self):
        path = _transcript([
            _entry("user.message", _id="u1", content="use it"),
            _entry("tool.execution_start", toolCallId="call-a",
                   toolName="new_copilot_builtin", arguments={"q": 1}),
            _entry("tool.execution_complete", toolCallId="call-a", success=True,
                   result={"content": "ok"}),
            _entry("assistant.message", content="done"),
        ])

        exchange, _forwarded, _sig, _prompts = unbound.build_exchange_from_transcript(
            path, SESSION)

        self.assertNotIn("tool_use", exchange["messages"][1])

    def test_configured_bare_mcp_tool_is_reported_with_its_server(self):
        path = _transcript([
            _entry("user.message", _id="u1", content="search github"),
            _entry("tool.execution_start", toolCallId="call-a",
                   toolName="github-mcp-server-search_code", arguments={"q": "needle"}),
            _entry("tool.execution_complete", toolCallId="call-a", success=True,
                   result={"content": "ok"}),
            _entry("assistant.message", content="done"),
        ])

        with unittest.mock.patch.object(
            unbound,
            "read_copilot_mcp_servers",
            return_value={"github-mcp-server": {"command": "github-mcp-server"}},
        ):
            exchange, _forwarded, _sig, _prompts = unbound.build_exchange_from_transcript(
                path, SESSION, cwd="/workspace")

        tool_use = exchange["messages"][1]["tool_use"]
        self.assertEqual(tool_use[0]["type"], "afterMCPExecution")
        self.assertEqual(tool_use[0]["server_name"], "github-mcp-server")

    def test_cli_shape_queued_prompt_inside_the_agent_turn(self):
        path = _transcript([
            _entry("user.message", _id="u1", content="first question"),
            _entry("assistant.turn_start"),
            _entry("assistant.message", content="let me look into that"),
            *_tool("call-a"),
            _entry("user.message", _id="u2", content="second question"),
            *_tool("call-b"),
            _entry("assistant.message", content="the answer"),
            _entry("assistant.turn_end"),
        ])
        exchange, forwarded, _sig, prompts = unbound.build_exchange_from_transcript(
            path, SESSION)
        self.assertEqual(_user_text(exchange), ["first question\n\nsecond question"])
        self.assertEqual(forwarded, {"call-a", "call-b"})
        self.assertEqual(prompts, {"u1", "u2"})

    def test_vscode_shape_queued_prompt_outside_the_agent_turn(self):
        path = _transcript([
            _entry("user.message", _id="u1", content="first question"),
            _entry("assistant.turn_start"),
            _entry("assistant.message", content="scanning"),
            _entry("assistant.turn_end"),
            _entry("user.message", _id="u2", content="second question"),
            _entry("assistant.turn_start"),
            *_tool("call-a"),
            _entry("assistant.message", content="the answer"),
            _entry("assistant.turn_end"),
        ])
        exchange, _forwarded, _sig, prompts = unbound.build_exchange_from_transcript(
            path, SESSION)
        self.assertEqual(_user_text(exchange), ["first question\n\nsecond question"])
        self.assertEqual(prompts, {"u1", "u2"})

    def test_an_already_reported_prompt_is_not_resent(self):
        path = _transcript([
            _entry("user.message", _id="u1", content="first question"),
            *_tool("call-a"),
            _entry("assistant.message", content="the first answer"),
            _entry("user.message", _id="u2", content="second question"),
            *_tool("call-b"),
            _entry("assistant.message", content="the second answer"),
        ])
        exchange, forwarded, _sig, prompts = unbound.build_exchange_from_transcript(
            path, SESSION, already_forwarded={"call-a"}, already_prompted={"u1"})
        self.assertEqual(_user_text(exchange), ["second question"])
        self.assertEqual(forwarded, {"call-b"})
        self.assertEqual(prompts, {"u2"})

    def test_nothing_new_yields_no_exchange(self):
        path = _transcript([
            _entry("user.message", _id="u1", content="first question"),
            _entry("assistant.message", content="the answer"),
        ])
        exchange, forwarded, sig, prompts = unbound.build_exchange_from_transcript(
            path, SESSION, already_prompted={"u1"})
        self.assertIsNone(exchange)
        self.assertEqual((forwarded, sig, prompts), (set(), None, set()))

    def test_an_entry_without_an_id_is_still_watermarked(self):
        # otherwise every later Stop re-selects it and re-uploads its text
        path = _transcript([
            _entry("user.message", content="no envelope id"),
            _entry("assistant.message", content="the answer"),
        ])
        exchange, _f, _s, prompts = unbound.build_exchange_from_transcript(path, SESSION)
        self.assertEqual(_user_text(exchange), ["no envelope id"])
        self.assertEqual(len(prompts), 1)
        again, _f2, _s2, _p2 = unbound.build_exchange_from_transcript(
            path, SESSION, already_prompted=prompts)
        self.assertIsNone(again)

    def test_two_id_less_entries_get_distinct_keys(self):
        path = _transcript([
            _entry("user.message", content="first"),
            _entry("user.message", content="second"),
            _entry("assistant.message", content="the answer"),
        ])
        _ex, _f, _s, prompts = unbound.build_exchange_from_transcript(path, SESSION)
        self.assertEqual(len(prompts), 2)

    def test_a_transcript_with_no_prompt_yields_nothing(self):
        path = _transcript([_entry("session.start", sessionId=SESSION)])
        exchange, forwarded, sig, prompts = unbound.build_exchange_from_transcript(
            path, SESSION)
        self.assertIsNone(exchange)
        self.assertEqual((forwarded, sig, prompts), (set(), None, set()))


class TestReportedPromptWatermark(unittest.TestCase):
    def test_state_round_trips_through_the_marker(self):
        logs = [{"timestamp": "2026-08-20T10:00:00Z",
                 "event": {"hook_event_name": unbound.FORWARDED_TOOLS_EVENT,
                           "session_id": SESSION,
                           "forwarded_tool_ids": ["call-a"],
                           "forwarded_prompt_ids": ["u1"],
                           "text_sig": "sig"}}]
        with unittest.mock.patch.object(unbound, "load_existing_logs", lambda: logs):
            tools, sig, prompts, _index = unbound.get_forwarded_state(SESSION)
        self.assertEqual(tools, {"call-a"})
        self.assertEqual(sig, "sig")
        self.assertEqual(prompts, {"u1"})

    def test_a_marker_without_prompt_ids_still_reads(self):
        logs = [{"timestamp": "2026-08-20T10:00:00Z",
                 "event": {"hook_event_name": unbound.FORWARDED_TOOLS_EVENT,
                           "session_id": SESSION,
                           "forwarded_tool_ids": ["call-a"]}}]
        with unittest.mock.patch.object(unbound, "load_existing_logs", lambda: logs):
            tools, _sig, prompts, _index = unbound.get_forwarded_state(SESSION)
        self.assertEqual(tools, {"call-a"})
        self.assertEqual(prompts, set())

    def test_prompt_ids_persist_across_stops(self):
        # without this the watermark is always empty and every Stop resends the whole
        # session's prompts, so a later turn carries the earlier turns' text
        logs = []
        with unittest.mock.patch.object(unbound, "load_existing_logs", lambda: list(logs)), \
             unittest.mock.patch.object(unbound, "save_logs",
                                        lambda x: (logs.clear(), logs.extend(x))):
            unbound.record_forwarded_tool_ids(SESSION, {"call-a"}, "sig1", {"u1"})
            unbound.record_forwarded_tool_ids(SESSION, {"call-b"}, "sig2", {"u2"})
            tools, _sig, prompts, _index = unbound.get_forwarded_state(SESSION)
        self.assertEqual(tools, {"call-a", "call-b"})
        self.assertEqual(prompts, {"u1", "u2"})

    def test_a_second_turn_does_not_carry_the_first(self):
        first = _transcript([
            _entry("user.message", _id="u1", content="first question"),
            _entry("assistant.message", content="the first answer"),
        ])
        _ex, _fwd, _sig, reported = unbound.build_exchange_from_transcript(first, SESSION)
        second = _transcript([
            _entry("user.message", _id="u1", content="first question"),
            _entry("assistant.message", content="the first answer"),
            _entry("user.message", _id="u2", content="second question"),
            _entry("assistant.message", content="the second answer"),
        ])
        exchange, _f, _s, _p = unbound.build_exchange_from_transcript(
            second, SESSION, already_prompted=reported)
        self.assertEqual(_user_text(exchange), ["second question"])

    def test_no_session_id_is_empty_state(self):
        self.assertEqual(unbound.get_forwarded_state(None), (set(), None, set(), 0))


if __name__ == "__main__":
    unittest.main()
