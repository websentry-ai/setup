"""
Tests for backfill token-usage collection in copilot/hooks/setup.py.

Copilot's transcripts carry no token counts, so the backfill client reads them from the
stores Copilot keeps them in and ships one usage dict per exchange. Covers:
  - _backfill_cli_usage      (CLI sqlite store, cache-inclusive input, grouped per turn)
  - _backfill_vscode_usage   (VS Code chat journal, finalised requests only)
  - _backfill_collect_session / _backfill_slice_session (payload + boundary-aligned slicing)
"""

import json
from datetime import datetime, timezone
import os
import sqlite3
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from tests.conftest import tool_module

setup = tool_module("copilot/hooks", "setup")

SESSION = "sess-backfill"
SCHEMA = """CREATE TABLE assistant_usage_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT, session_id TEXT, turn_index INTEGER, model TEXT,
    input_tokens INTEGER, output_tokens INTEGER, cache_read_tokens INTEGER,
    cache_write_tokens INTEGER, reasoning_tokens INTEGER, created_at TEXT)"""


def _cli_tree(tmpdir, rows, session=SESSION):
    """<copilot home>/session-state/<id>/events.jsonl, with the store beside session-state.
    The store is resolved from the transcript path, so MDM's per-user homes work too."""
    copilot = Path(tmpdir) / ".copilot"
    (copilot / "session-state" / session).mkdir(parents=True)
    transcript = copilot / "session-state" / session / "events.jsonl"
    transcript.write_text("", encoding="utf-8")
    conn = sqlite3.connect(str(copilot / "session-store.db"))
    conn.execute(SCHEMA)
    conn.executemany(
        "INSERT INTO assistant_usage_events (session_id, turn_index, input_tokens,"
        " output_tokens, cache_read_tokens, cache_write_tokens) VALUES (?,?,?,?,?,?)", rows)
    conn.commit()
    conn.close()
    return transcript


def _cli_usage(rows, session=SESSION):
    with tempfile.TemporaryDirectory() as tmpdir:
        return setup._backfill_cli_usage(_cli_tree(tmpdir, rows), session)


def _vscode_tree(tmpdir, session, lines):
    root = Path(tmpdir) / "ws" / "hash"
    (root / "chatSessions").mkdir(parents=True)
    (root / "GitHub.copilot-chat" / "transcripts").mkdir(parents=True)
    (root / "chatSessions" / (session + ".jsonl")).write_text(
        "\n".join(json.dumps(line) for line in lines), encoding="utf-8")
    transcript = root / "GitHub.copilot-chat" / "transcripts" / (session + ".jsonl")
    transcript.write_text("", encoding="utf-8")
    return transcript



BASE_MS = 1787893680000
TURN_MS = 10000          # turns start 10s apart
CLOSE_MS = 5000          # each turn closes 5s after its prompt


def _iso(ms):
    return datetime.fromtimestamp(ms / 1000.0, timezone.utc).isoformat().replace("+00:00", "Z")


def _turn_entries(count):
    """`count` turns, each closing before the next one opens. Requests are stamped inside
    a turn but BEFORE its prompt, the way VS Code really writes them."""
    entries = []
    for turn in range(count):
        start = BASE_MS + turn * TURN_MS
        entries.append({"type": "user.message", "timestamp": _iso(start),
                        "data": {"content": "prompt %d" % turn}})
        entries.append({"type": "assistant.message", "timestamp": _iso(start + CLOSE_MS),
                        "data": {"content": "reply %d" % turn}})
    return entries


def _turn_stamp(turn):
    # 400ms before its own prompt, matching the real journal
    return BASE_MS + turn * TURN_MS - 400


def _request(prompt=None, completion=None, elapsed=1234, turn=0):
    obj = {"timestamp": _turn_stamp(turn)}
    for key, value in (("promptTokens", prompt), ("completionTokens", completion),
                       ("elapsedMs", elapsed)):
        if value is not None:
            obj[key] = value
    return obj


class TestBackfillCliUsage(unittest.TestCase):
    def test_copilot_home_contains_cli_transcripts(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            copilot_home = Path(tmpdir) / "custom-copilot"
            transcript = copilot_home / "session-state" / SESSION / "events.jsonl"
            transcript.parent.mkdir(parents=True)
            transcript.write_text("{}\n", encoding="utf-8")
            with patch.dict(os.environ, {"COPILOT_HOME": str(copilot_home)}):
                found = list(setup._backfill_iter_transcripts(0))
        self.assertEqual(found, [transcript])

    def test_one_entry_per_turn_in_order(self):
        usage = _cli_usage([(SESSION, 0, 100, 5, 0, 0), (SESSION, 1, 200, 7, 0, 0)])
        self.assertEqual([u["input_tokens"] for u in usage], [100, 200])
        self.assertEqual([u["output_tokens"] for u in usage], [5, 7])

    def test_requests_within_a_turn_are_summed(self):
        usage = _cli_usage([(SESSION, 0, 100, 5, 0, 0), (SESSION, 0, 50, 3, 0, 0)])
        self.assertEqual(len(usage), 1)
        self.assertEqual((usage[0]["input_tokens"], usage[0]["output_tokens"]), (150, 8))

    def test_cache_tiers_come_out_of_input(self):
        # 26941 = 10 fresh + 0 read + 26931 write, the shape Copilot records
        usage = _cli_usage([(SESSION, 0, 26941, 274, 0, 26931)])
        self.assertEqual(usage[0], {"input_tokens": 10, "output_tokens": 274,
                                    "cache_read_input_tokens": 0,
                                    "cache_creation_input_tokens": 26931})

    def test_other_sessions_are_ignored(self):
        usage = _cli_usage([("other", 0, 9999, 1, 0, 0), (SESSION, 0, 7, 1, 0, 0)])
        self.assertEqual(usage[0]["input_tokens"], 7)

    def test_missing_store_is_empty(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            transcript = Path(tmpdir) / ".copilot" / "session-state" / SESSION / "events.jsonl"
            transcript.parent.mkdir(parents=True)
            transcript.write_text("", encoding="utf-8")
            self.assertEqual(setup._backfill_cli_usage(transcript, SESSION), [])

    def test_store_without_the_table_is_empty(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            copilot = Path(tmpdir) / ".copilot"
            (copilot / "session-state" / SESSION).mkdir(parents=True)
            transcript = copilot / "session-state" / SESSION / "events.jsonl"
            transcript.write_text("", encoding="utf-8")
            sqlite3.connect(str(copilot / "session-store.db")).close()
            self.assertEqual(setup._backfill_cli_usage(transcript, SESSION), [])

    def test_shallow_path_cannot_resolve_a_store(self):
        self.assertEqual(setup._backfill_cli_usage(Path("/events.jsonl"), SESSION), [])

    def test_each_home_resolves_its_own_store(self):
        # the MDM case: two users, two stores, no shared Path.home()
        with tempfile.TemporaryDirectory() as one, tempfile.TemporaryDirectory() as two:
            a = _cli_tree(one, [(SESSION, 0, 111, 1, 0, 0)])
            b = _cli_tree(two, [(SESSION, 0, 222, 2, 0, 0)])
            self.assertEqual(setup._backfill_cli_usage(a, SESSION)[0]["input_tokens"], 111)
            self.assertEqual(setup._backfill_cli_usage(b, SESSION)[0]["input_tokens"], 222)


class TestBackfillVscodeUsage(unittest.TestCase):
    def _usage(self, lines, turns=1):
        with tempfile.TemporaryDirectory() as tmpdir:
            transcript = _vscode_tree(tmpdir, SESSION, lines)
            return setup._backfill_vscode_usage(transcript, SESSION, _turn_entries(turns))

    def test_finalised_requests_are_reported_in_order(self):
        usage = self._usage([
            {"kind": 1, "v": {"requests": []}},
            {"kind": 2, "k": ["requests"], "v": [_request(100, 5, turn=0),
                                                 _request(200, 7, turn=1)]},
        ], turns=2)
        self.assertEqual([u["input_tokens"] for u in usage], [100, 200])

    def test_patches_win_over_the_streaming_values(self):
        usage = self._usage([
            {"kind": 1, "v": {"requests": []}},
            {"kind": 2, "k": ["requests"], "v": [_request(40369, 178, elapsed=None)]},
            {"kind": 2, "k": ["requests", "0", "completionTokens"], "v": 591},
            {"kind": 2, "k": ["requests", "0", "promptTokens"], "v": 44090},
            {"kind": 2, "k": ["requests", "0", "elapsedMs"], "v": 10980},
        ])
        self.assertEqual((usage[0]["input_tokens"], usage[0]["output_tokens"]), (44090, 591))

    def test_an_unfinished_request_leaves_only_its_own_turn_estimated(self):
        # counts appear mid-stream; without elapsedMs the request is not final. Its turn
        # reports nothing and is estimated, but the finished turns still report.
        usage = self._usage([
            {"kind": 1, "v": {"requests": []}},
            {"kind": 2, "k": ["requests"], "v": [_request(100, 5, turn=0),
                                                 _request(200, 7, elapsed=None, turn=1)]},
        ], turns=2)
        self.assertEqual(len(usage), 2)
        self.assertEqual(usage[0]["input_tokens"], 100)
        self.assertEqual(usage[1], {})

    def test_a_turn_sums_every_request_that_ran_inside_it(self):
        usage = self._usage([
            {"kind": 1, "v": {"requests": []}},
            {"kind": 2, "k": ["requests"], "v": [
                dict(_request(100, 5, turn=0)),
                dict(_request(30, 2, turn=0), **{"timestamp": _turn_stamp(0) + 100})]},
        ], turns=1)
        self.assertEqual((usage[0]["input_tokens"], usage[0]["output_tokens"]), (130, 7))

    def test_a_request_is_billed_to_its_own_turn_not_the_next(self):
        # The whole bug: fewer requests than turns, so position and turn disagree. The
        # journal holds only turn 1's request; turn 0 must stay estimated.
        usage = self._usage([
            {"kind": 1, "v": {"requests": []}},
            {"kind": 2, "k": ["requests"], "v": [_request(200, 7, turn=1)]},
        ], turns=2)
        self.assertEqual(usage[0], {})
        self.assertEqual(usage[1]["input_tokens"], 200)

    def test_an_undated_request_is_billed_to_no_turn(self):
        undated = _request(100, 5, turn=0)
        undated.pop("timestamp")
        usage = self._usage([
            {"kind": 1, "v": {"requests": []}},
            {"kind": 2, "k": ["requests"], "v": [undated]},
        ], turns=1)
        self.assertEqual(usage, [{}])

    def test_an_unreadable_stamp_never_aborts_the_run(self):
        # Fail open: a stamp without an offset takes the platform path, which raises OSError
        # on Windows for pre-epoch dates. One odd transcript must not kill the whole backfill.
        entries = _turn_entries(2)
        with patch.object(setup, "_backfill_epoch", side_effect=OSError("Invalid argument")):
            usage = self._usage([
                {"kind": 1, "v": {"requests": []}},
                {"kind": 2, "k": ["requests"], "v": [_request(100, 5, turn=0)]},
            ], turns=2)
            models = setup._backfill_vscode_models(Path("/tmp/x/y.jsonl"), SESSION, entries)
        self.assertEqual(usage, [])
        self.assertEqual(models, [])

    def test_turn_ceilings_never_decrease(self):
        # The scan takes the first ceiling a request fits under, so out-of-order transcript
        # stamps must not produce a window that reaches backwards.
        jumbled = [
            {"type": "user.message", "timestamp": _iso(BASE_MS + 30000), "data": {"content": "a"}},
            {"type": "assistant.message", "timestamp": _iso(BASE_MS + 40000), "data": {"content": "r"}},
            {"type": "user.message", "timestamp": _iso(BASE_MS + 10000), "data": {"content": "b"}},
            {"type": "assistant.message", "timestamp": _iso(BASE_MS + 5000), "data": {"content": "r"}},
            {"type": "user.message", "timestamp": _iso(BASE_MS + 60000), "data": {"content": "c"}},
        ]
        ceilings = setup._backfill_turn_ceilings(jumbled)
        self.assertEqual(len(ceilings), 3)
        self.assertTrue(all(ceilings[i] <= ceilings[i + 1] for i in range(len(ceilings) - 1)))

    def test_non_transcript_path_is_empty(self):
        self.assertEqual(
            setup._backfill_vscode_usage(Path("/tmp/x/y.jsonl"), SESSION, _turn_entries(1)), [])


class TestBackfillPayload(unittest.TestCase):
    def tearDown(self):
        setup._BACKFILL_HOOK_MODULE = None
        setup._BACKFILL_HOOK_PATH = None

    def test_installed_hook_resolves_a_configured_bare_mcp_call_end_to_end(self):
        entries = [
            {"type": "user.message", "data": {"content": "show issue"}},
            {"type": "assistant.message", "data": {"toolRequests": [{
                "toolCallId": "call-1",
                "name": "github-get_issue",
                "arguments": {"id": 1},
            }]}},
        ]
        with tempfile.TemporaryDirectory() as tmpdir:
            home = Path(tmpdir)
            hook_dir = home / ".copilot" / "hooks"
            hook_dir.mkdir(parents=True)
            source_hook = Path(__file__).resolve().parents[3] / "copilot" / "hooks" / "unbound.py"
            (hook_dir / "unbound.py").write_text(
                source_hook.read_text(encoding="utf-8"), encoding="utf-8"
            )
            (home / ".copilot" / "mcp-config.json").write_text(json.dumps({
                "mcpServers": {
                    "github": {"command": "npx", "args": ["github-mcp-server"]},
                },
            }), encoding="utf-8")
            transcript = home / ".copilot" / "session-state" / SESSION / "events.jsonl"
            transcript.parent.mkdir(parents=True)
            transcript.write_text(
                "\n".join(json.dumps(entry) for entry in entries), encoding="utf-8"
            )
            with patch.object(setup.Path, "home", return_value=home):
                session = setup._backfill_collect_session(transcript)

        self.assertEqual(session["mcp_tool_provenance"], {
            "call-1": {
                "tool_name": "github-get_issue",
                "server_name": "github",
                "mcp_tool_name": "get_issue",
                "mcp_server_config": {
                    "command": "npx",
                    "args": ["github-mcp-server"],
                },
            },
        })

    def test_installed_hook_uses_explicit_mcp_fields_without_local_config(self):
        entries = [
            {"type": "user.message", "data": {"content": "search code"}},
            {"type": "tool.execution_start", "data": {
                "toolCallId": "call-1",
                "toolName": "github-mcp-server-search_code",
                "arguments": {"query": "mcp"},
                "mcpServerName": "github-mcp-server",
                "mcpToolName": "search_code",
            }},
        ]
        with tempfile.TemporaryDirectory() as tmpdir:
            home = Path(tmpdir)
            hook_dir = home / ".copilot" / "hooks"
            hook_dir.mkdir(parents=True)
            source_hook = Path(__file__).resolve().parents[3] / "copilot" / "hooks" / "unbound.py"
            (hook_dir / "unbound.py").write_text(
                source_hook.read_text(encoding="utf-8"), encoding="utf-8"
            )
            transcript = home / ".copilot" / "session-state" / SESSION / "events.jsonl"
            transcript.parent.mkdir(parents=True)
            transcript.write_text(
                "\n".join(json.dumps(entry) for entry in entries), encoding="utf-8"
            )
            with patch.object(setup.Path, "home", return_value=home):
                session = setup._backfill_collect_session(transcript)

        self.assertEqual(session["mcp_tool_provenance"], {
            "call-1": {
                "tool_name": "github-mcp-server-search_code",
                "server_name": "github-mcp-server",
                "mcp_tool_name": "search_code",
            },
        })

    def test_collected_session_carries_positive_mcp_provenance(self):
        class HookModule:
            @staticmethod
            def read_copilot_mcp_servers(cwd):
                return {"github": {"command": "github-mcp-server"}}

            @staticmethod
            def map_copilot_tool(name, args, result, **_kwargs):
                if name == "github-get_issue":
                    return {
                        "type": "afterMCPExecution",
                        "tool_name": name,
                        "server_name": "github",
                        "mcp_tool_name": "get_issue",
                        "mcp_server_config": {"command": "github-mcp-server"},
                    }
                return None

        entries = [
            {"type": "user.message", "data": {"content": "show issue"}},
            {"type": "assistant.message", "data": {"toolRequests": [{
                "toolCallId": "call-1",
                "name": "github-get_issue",
                "arguments": {"id": 1},
            }]}},
        ]
        with tempfile.TemporaryDirectory() as tmpdir:
            transcript = Path(tmpdir) / "events.jsonl"
            transcript.write_text(
                "\n".join(json.dumps(entry) for entry in entries), encoding="utf-8"
            )
            with patch.object(setup, "_backfill_session_usage", lambda *a: []), patch.object(
                setup, "_backfill_load_hook_module", return_value=HookModule
            ):
                session = setup._backfill_collect_session(transcript)

        self.assertEqual(session["mcp_tool_provenance"], {
            "call-1": {
                "tool_name": "github-get_issue",
                "server_name": "github",
                "mcp_tool_name": "get_issue",
                "mcp_server_config": {"command": "github-mcp-server"},
            },
        })

    def test_collected_session_does_not_label_an_unresolved_tool_as_mcp(self):
        class HookModule:
            @staticmethod
            def read_copilot_mcp_servers(cwd):
                return {}

            @staticmethod
            def map_copilot_tool(name, args, result, **_kwargs):
                return None

        entries = [
            {"type": "user.message", "data": {"content": "use it"}},
            {"type": "assistant.message", "data": {"toolRequests": [{
                "toolCallId": "call-1",
                "name": "future_native_tool",
                "arguments": {},
            }]}},
        ]
        with tempfile.TemporaryDirectory() as tmpdir:
            transcript = Path(tmpdir) / "events.jsonl"
            transcript.write_text(
                "\n".join(json.dumps(entry) for entry in entries), encoding="utf-8"
            )
            with patch.object(setup, "_backfill_session_usage", lambda *a: []), patch.object(
                setup, "_backfill_load_hook_module", return_value=HookModule
            ):
                session = setup._backfill_collect_session(transcript)

        self.assertNotIn("mcp_tool_provenance", session)

    def test_usage_is_omitted_when_there_is_none(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            transcript = Path(tmpdir) / "events.jsonl"
            transcript.write_text(json.dumps(
                {"type": "user.message", "data": {"content": "hi"}}) + "\n", encoding="utf-8")
            with patch.object(setup, "_backfill_session_usage", lambda *a: []):
                session = setup._backfill_collect_session(transcript)
        self.assertNotIn("usage", session)

    def test_slices_cut_usage_on_the_same_boundaries_as_entries(self):
        entries = []
        for turn in range(3):
            entries.append({"type": "user.message", "data": {"content": "prompt %d" % turn}})
            entries.append({"type": "assistant.message", "data": {"content": "x" * 400}})
        usage = [{"input_tokens": n, "output_tokens": 0, "cache_read_input_tokens": 0,
                  "cache_creation_input_tokens": 0} for n in (11, 22, 33)]
        session = {"session_id": SESSION, "entries": entries, "usage": usage}
        slices = list(setup._backfill_slice_session(session, 900))
        rebuilt = []
        for chunk in slices:
            rebuilt.extend(chunk.get("usage") or [])
        self.assertGreater(len(slices), 1)
        self.assertEqual(rebuilt, usage)

    def test_a_session_that_fits_is_yielded_whole_with_its_usage(self):
        session = {"session_id": SESSION,
                   "entries": [{"type": "user.message", "data": {"content": "hi"}}],
                   "usage": [{"input_tokens": 5, "output_tokens": 1,
                              "cache_read_input_tokens": 0, "cache_creation_input_tokens": 0}]}
        slices = list(setup._backfill_slice_session(session, 1_000_000))
        self.assertEqual(len(slices), 1)
        self.assertEqual(slices[0]["usage"], session["usage"])

    def test_slices_only_carry_provenance_for_calls_in_that_slice(self):
        entries = []
        provenance = {}
        for turn in range(3):
            call_id = "call-%d" % turn
            tool_name = "server-tool-%d" % turn
            entries.extend([
                {"type": "user.message", "data": {"content": "prompt %d" % turn}},
                {"type": "assistant.message", "data": {
                    "content": "x" * 400,
                    "toolRequests": [{"toolCallId": call_id, "name": tool_name}],
                }},
            ])
            provenance[call_id] = {
                "tool_name": tool_name,
                "server_name": "server",
                "mcp_tool_name": "tool-%d" % turn,
                "mcp_server_config": {"command": "npx", "args": ["server-mcp"]},
            }
        session = {
            "session_id": SESSION,
            "entries": entries,
            "mcp_tool_provenance": provenance,
        }

        slices = list(setup._backfill_slice_session(session, 1100))

        self.assertGreater(len(slices), 1)
        rebuilt = {}
        for chunk in slices:
            chunk_call_ids = {
                request["toolCallId"]
                for entry in chunk["entries"]
                for request in (entry.get("data") or {}).get("toolRequests") or []
            }
            self.assertEqual(
                set((chunk.get("mcp_tool_provenance") or {}).keys()), chunk_call_ids
            )
            rebuilt.update(chunk.get("mcp_tool_provenance") or {})
        self.assertEqual(rebuilt, provenance)
