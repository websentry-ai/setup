"""
Tests for the Visual Studio Copilot Chat sweep in copilot/hooks/unbound.py.

Visual Studio exposes no hook surface, so its chat sessions are read off disk and shaped
into the sessions the Copilot backfill parser already walks. Each conversation is uploaded
in full, because the server refuses a session whose existing rows none of the incoming
records match.

Fixtures cover both generations: VS 2022 bodies carry `intent_content`, VS 2026 bodies drop
it and prepend a synthetic `# IDESTATE CONTEXT` user message to every turn.
"""

import json
import os
import struct
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from tests.conftest import tool_module

unbound = tool_module("copilot/hooks", "unbound")

SESSION = "6e9d771b-382f-4923-8a33-f2ff29e33b90"
OTHER = "9b3844f2-943e-441d-b428-17931a599bc1"
IDESTATE = "# IDESTATE CONTEXT\r\nUser's current development environment is: VS"


def _mp_str(value):
    raw = value.encode("utf-8")
    if len(raw) < 32:
        return bytes([0xA0 | len(raw)]) + raw
    return bytes([0xD9, len(raw)]) + raw


def _mp_map(pairs):
    out = bytes([0x80 | len(pairs)])
    for key, value in pairs:
        out += _mp_str(key) + value
    return out


def _mp_array(items):
    return bytes([0x90 | len(items)]) + b"".join(items)


def _mp_timestamp64(epoch_seconds):
    """The -1 extension in its 8-byte form, which is what Visual Studio writes."""
    return bytes([0xD7, 0xFF]) + struct.pack(">Q", int(epoch_seconds))


def _text_block(text):
    return _mp_array([bytes([0x03]), _mp_map([("Content", _mp_str(text))])])


def _prompt(text):
    return _mp_array([bytes([0x00]),
                      _mp_map([("MessageId", _mp_str("m-user")),
                               ("Content", _mp_array([_text_block(text)]))])])


def _reply(text, model="claude-haiku-4.5", timestamp=1789981892):
    return _mp_array([bytes([0x01]), _mp_map([
        ("MessageId", _mp_str("m-asst")),
        ("CorrelationId", _mp_str("corr-1")),
        ("Content", _mp_array([_text_block(text)])),
        ("Model", _mp_map([("Family", _mp_str(model))])),
        ("Quotas", _mp_array([_mp_map([("Timestamp", _mp_timestamp64(timestamp))])]))])])


def _session_file(root, blob, session=SESSION, solution="demo"):
    path = (Path(root) / solution / ".vs" / solution / "copilot-chat" / "0dbe1b56"
            / "sessions" / session)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(blob)
    return path


def _msg(role, content):
    return {"role": role, "content": content}


def _body(messages, model="claude-haiku-4.5"):
    """A VS 2026 request body: no intent_content, synthetic user message per turn."""
    return {"messages": messages, "model": model, "n": 1, "stream": True}


def _chat_log(root, entries, name="20260921_060332.912_VSGitHubCopilot.chat.log"):
    """`entries` is a list of ('session', body) or ('usage', dict) in log order."""
    d = Path(root) / "AppData" / "Local" / "Temp" / "VSGitHubCopilotLogs"
    d.mkdir(parents=True, exist_ok=True)
    lines = []
    for kind, value in entries:
        if kind == "session":
            lines.append("[2026-09-21 13:33:00.000 CopilotFunctionRegistry V] "
                         "[FunctionProviderWrapper.OnNext] SessionId=%s FunctionsCount=8" % value)
        elif kind == "empty-session":
            lines.append("[2026-09-21 13:33:00.000 CopilotFunctionRegistry V] "
                         "[FunctionProviderWrapper.OnNext] SessionId= FunctionsCount=1")
        elif kind == "usage":
            lines.append("[2026-09-21 13:33:06.000 Conversations V] [CopilotClient EventType(11)] "
                         + json.dumps([value]))
        else:
            lines.append("[2026-09-21 13:33:05.862 Conversations V] [CopilotClient EventType(9)] "
                         + json.dumps(value))
    path = d / name
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return path


def _usage(inp, out, cached=0):
    return {"InputTokenCount": inp, "OutputTokenCount": out, "CachedInputTokenCount": cached}


class MessagePackDecoding(unittest.TestCase):
    def test_decodes_the_shapes_visual_studio_writes(self):
        blob = _mp_map([("Content", _mp_array([_text_block("hello")]))])
        self.assertEqual(unbound._mp_unpack_all(blob)[0]["Content"][0][1]["Content"], "hello")

    def test_str8_survives(self):
        long_text = "x" * 40
        self.assertEqual(unbound._mp_unpack_all(_mp_map([("C", _mp_str(long_text))]))[0]["C"],
                         long_text)

    def test_unknown_code_raises_rather_than_returning_junk(self):
        with self.assertRaises(ValueError):
            unbound._mp_unpack_all(bytes([0xC1]))


class TurnPairing(unittest.TestCase):
    def test_role_zero_is_the_prompt_and_one_is_the_reply(self):
        turns = unbound._vs_session_turns(unbound._mp_unpack_all(_prompt("ask") + _reply("answer")))
        self.assertEqual(len(turns), 1)
        self.assertEqual(unbound._vs_block_text(turns[0][1]), "ask")

    def test_a_reply_with_no_text_is_still_running_and_withheld(self):
        blob = _prompt("ask") + _mp_array([bytes([0x01]), _mp_map([("Content", _mp_array([]))])])
        self.assertEqual(unbound._vs_session_turns(unbound._mp_unpack_all(blob)), [])


class ChatLogTurns(unittest.TestCase):
    def test_the_trailing_turn_is_withheld_until_it_settles(self):
        body = _body([_msg("user", "one"), _msg("assistant", "first"), _msg("user", "two")])
        self.assertEqual(unbound._vs_chat_log_turns(body), [(0, "one", "first")])

    def test_a_repeated_prompt_earlier_in_the_chat_is_not_dropped(self):
        # Filtering by text rather than position would delete the settled first "continue".
        body = _body([_msg("user", "continue"), _msg("assistant", "a"),
                      _msg("user", "continue"), _msg("assistant", "b"),
                      _msg("user", "continue")])
        self.assertEqual(unbound._vs_chat_log_turns(body),
                         [(0, "continue", "a"), (1, "continue", "b")])

    def test_the_synthetic_idestate_message_opens_no_turn(self):
        body = _body([_msg("user", IDESTATE), _msg("user", "real one"),
                      _msg("assistant", "answer"),
                      _msg("user", IDESTATE), _msg("user", "real two")])
        self.assertEqual(unbound._vs_chat_log_turns(body), [(0, "real one", "answer")])

    def test_tool_messages_do_not_break_pairing(self):
        body = _body([_msg("system", "sys"), _msg("user", "ask"), _msg("assistant", "part"),
                      _msg("tool", "output"), _msg("assistant", "more"), _msg("user", "next")])
        self.assertEqual(unbound._vs_chat_log_turns(body), [(0, "ask", "part\n\nmore")])


class UsageAttribution(unittest.TestCase):
    def test_a_turn_is_positioned_by_real_user_messages_only(self):
        body = _body([_msg("user", IDESTATE), _msg("user", "one"),
                      _msg("assistant", "a"), _msg("user", IDESTATE), _msg("user", "two")])
        self.assertEqual(unbound._vs_user_messages(body), ["one", "two"])

    def test_cached_tokens_come_out_of_input(self):
        line = "[CopilotClient EventType(11)] " + json.dumps([_usage(500, 20, cached=300)])
        self.assertEqual(unbound._vs_usage_from_line(line),
                         {"input_tokens": 200, "output_tokens": 20,
                          "cache_read_input_tokens": 300})

    def test_agent_mode_calls_for_one_turn_are_summed(self):
        into = {}
        unbound._vs_add_usage(into, {"input_tokens": 10, "output_tokens": 1,
                                     "cache_read_input_tokens": 0})
        unbound._vs_add_usage(into, {"input_tokens": 5, "output_tokens": 2,
                                     "cache_read_input_tokens": 3})
        self.assertEqual(into, {"input_tokens": 15, "output_tokens": 3,
                                "cache_read_input_tokens": 3})


class Collection(unittest.TestCase):
    def _collect(self, tmp, installed=True):
        with patch.object(unbound, "_is_windows", return_value=True), \
                patch.object(unbound, "_vs_installed", return_value=installed), \
                patch.object(unbound, "_vs_solution_roots", return_value=[Path(tmp)]), \
                patch.object(unbound.Path, "home", staticmethod(lambda: Path(tmp))):
            sessions, _, _ = unbound.collect_visual_studio_sessions(0)
        return sessions

    def test_a_turn_becomes_the_two_entries_the_parser_walks(self):
        with tempfile.TemporaryDirectory() as tmp:
            _session_file(tmp, _prompt("ask") + _reply("answer"))
            sessions = self._collect(tmp)

        self.assertEqual(len(sessions), 1)
        entries = sessions[0]["entries"]
        self.assertEqual([e["type"] for e in entries], ["user.message", "assistant.message"])
        self.assertEqual(entries[0]["data"]["content"], "ask")
        self.assertEqual(entries[1]["data"]["model"], "claude-haiku-4.5")
        self.assertEqual(sessions[0]["session_id"], SESSION)

    def test_the_entry_id_is_derived_so_both_sources_agree_on_it(self):
        # Without an id the server keys on prompt text, which cannot tell repeats apart.
        with tempfile.TemporaryDirectory() as tmp:
            _session_file(tmp, _prompt("ask") + _reply("answer"))
            from_store = self._collect(tmp)

        with tempfile.TemporaryDirectory() as tmp:
            _chat_log(tmp, [
                ("session", SESSION),
                ("body", _body([_msg("user", "ask"), _msg("assistant", "answer"),
                                _msg("user", "next")])),
            ])
            from_log = self._collect(tmp)

        self.assertEqual(from_store[0]["entries"][0]["id"],
                         from_log[0]["entries"][0]["id"])
        self.assertEqual(from_store[0]["entries"][0]["id"],
                         unbound._vs_turn_marker(SESSION, "ask", 0))

    def test_a_repeated_prompt_still_gets_a_distinct_id_per_turn(self):
        with tempfile.TemporaryDirectory() as tmp:
            _chat_log(tmp, [
                ("session", SESSION),
                ("body", _body([_msg("user", "continue"), _msg("assistant", "a"),
                                _msg("user", "continue"), _msg("assistant", "b"),
                                _msg("user", "continue")])),
            ])
            sessions = self._collect(tmp)

        ids = [e["id"] for e in sessions[0]["entries"] if e["type"] == "user.message"]
        self.assertEqual(len(ids), 2)
        self.assertEqual(len(set(ids)), 2)

    def test_the_turn_is_timed_from_its_reply_not_from_sweep_time(self):
        with tempfile.TemporaryDirectory() as tmp:
            _session_file(tmp, _prompt("ask") + _reply("answer", timestamp=1789981892))
            sessions = self._collect(tmp)
        self.assertEqual(sessions[0]["entries"][0]["timestamp"], "2026-09-21T09:11:32Z")

    def test_a_store_only_turn_carries_no_usage_so_the_key_is_dropped(self):
        with tempfile.TemporaryDirectory() as tmp:
            _session_file(tmp, _prompt("ask") + _reply("answer"))
            sessions = self._collect(tmp)
        self.assertNotIn("usage", sessions[0])

    def test_usage_lands_on_the_turn_that_earned_it(self):
        with tempfile.TemporaryDirectory() as tmp:
            _chat_log(tmp, [
                ("session", SESSION),
                ("body", _body([_msg("user", "one")])),
                ("usage", _usage(500, 20, cached=300)),
                ("body", _body([_msg("user", "one"), _msg("assistant", "a"),
                                _msg("user", "two")])),
                ("usage", _usage(80, 9)),
            ])
            sessions = self._collect(tmp)

        self.assertEqual(len(sessions), 1)
        self.assertEqual(sessions[0]["usage"],
                         [{"input_tokens": 200, "output_tokens": 20,
                           "cache_read_input_tokens": 300}])

    def test_two_turns_with_the_same_prompt_do_not_share_usage(self):
        # Keying usage on prompt text summed them and reported the total on both.
        with tempfile.TemporaryDirectory() as tmp:
            _chat_log(tmp, [
                ("session", SESSION),
                ("body", _body([_msg("user", "continue")])),
                ("usage", _usage(100, 5)),
                ("body", _body([_msg("user", "continue"), _msg("assistant", "a"),
                                _msg("user", "continue")])),
                ("usage", _usage(700, 9)),
                ("body", _body([_msg("user", "continue"), _msg("assistant", "a"),
                                _msg("user", "continue"), _msg("assistant", "b"),
                                _msg("user", "done")])),
            ])
            sessions = self._collect(tmp)

        usage = sessions[0]["usage"]
        self.assertEqual(usage[0]["input_tokens"], 100)
        self.assertEqual(usage[1]["input_tokens"], 700)

    def test_usage_stays_aligned_when_an_early_turn_has_none(self):
        with tempfile.TemporaryDirectory() as tmp:
            _chat_log(tmp, [
                ("session", SESSION),
                ("body", _body([_msg("user", "one")])),
                ("body", _body([_msg("user", "one"), _msg("assistant", "a"),
                                _msg("user", "two")])),
                ("usage", _usage(42, 7)),
                ("body", _body([_msg("user", "one"), _msg("assistant", "a"),
                                _msg("user", "two"), _msg("assistant", "b"),
                                _msg("user", "three")])),
            ])
            sessions = self._collect(tmp)

        usage = sessions[0]["usage"]
        self.assertEqual(usage[0], {})
        self.assertEqual(usage[1]["input_tokens"], 42)

    def test_each_chat_in_one_launch_stays_its_own_conversation(self):
        with tempfile.TemporaryDirectory() as tmp:
            _chat_log(tmp, [
                ("empty-session", None),
                ("session", SESSION),
                ("body", _body([_msg("user", "hello"), _msg("assistant", "a"),
                                _msg("user", "next")])),
                ("session", OTHER),
                ("body", _body([_msg("user", "hello"), _msg("assistant", "b"),
                                _msg("user", "next")])),
            ])
            sessions = self._collect(tmp)

        by_id = {s["session_id"]: s for s in sessions}
        self.assertEqual(set(by_id), {SESSION, OTHER})
        self.assertEqual(by_id[SESSION]["entries"][1]["data"]["content"], "a")
        self.assertEqual(by_id[OTHER]["entries"][1]["data"]["content"], "b")

    def test_the_same_turn_from_both_sources_is_collected_once(self):
        with tempfile.TemporaryDirectory() as tmp:
            _session_file(tmp, _prompt("ask") + _reply("answer"))
            _chat_log(tmp, [
                ("session", SESSION),
                ("body", _body([_msg("user", "ask"), _msg("assistant", "answer"),
                                _msg("user", "next")])),
            ])
            sessions = self._collect(tmp)

        self.assertEqual(len(sessions), 1)
        self.assertEqual(len(sessions[0]["entries"]), 2)

    def test_session_ids_from_the_two_sources_compare_case_insensitively(self):
        with tempfile.TemporaryDirectory() as tmp:
            _session_file(tmp, _prompt("ask") + _reply("answer"), session=SESSION.upper())
            _chat_log(tmp, [
                ("session", SESSION),
                ("body", _body([_msg("user", "ask"), _msg("assistant", "answer"),
                                _msg("user", "next")])),
            ])
            sessions = self._collect(tmp)
        self.assertEqual(len(sessions), 1)

    def test_a_corrupt_session_is_logged_and_skipped(self):
        with tempfile.TemporaryDirectory() as tmp:
            _session_file(tmp, b"\xc1not msgpack")
            with patch.object(unbound, "log_error") as logged:
                sessions = self._collect(tmp)
        self.assertEqual(sessions, [])
        logged.assert_called_once()

    def test_nothing_runs_when_visual_studio_is_not_installed(self):
        with tempfile.TemporaryDirectory() as tmp:
            _session_file(tmp, _prompt("ask") + _reply("answer"))
            self.assertEqual(self._collect(tmp, installed=False), [])

    def test_nothing_runs_off_windows(self):
        with patch.object(unbound, "_is_windows", return_value=False):
            self.assertEqual(unbound.collect_visual_studio_sessions(0), ([], False, None))


class LogReading(unittest.TestCase):
    def test_an_oversized_line_is_drained_rather_than_buffered(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "big.log"
            path.write_text("x" * (unbound._VS_MAX_LOG_LINE_CHARS + 50) + "\nsecond\n",
                            encoding="utf-8")
            with open(path, "r", encoding="utf-8") as handle:
                lines = list(unbound._vs_capped_lines(handle))
        self.assertTrue(all(len(l) <= unbound._VS_MAX_LOG_LINE_CHARS for l in lines))

    def test_the_line_count_is_bounded(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "many.log"
            path.write_text("a\n" * (unbound._VS_MAX_LOG_LINES + 100), encoding="utf-8")
            with open(path, "r", encoding="utf-8") as handle:
                self.assertEqual(len(list(unbound._vs_capped_lines(handle))),
                                 unbound._VS_MAX_LOG_LINES)


if __name__ == "__main__":
    unittest.main()


class TruncationAndOrdering(unittest.TestCase):
    """Two ways a sweep can quietly lose turns that the cutoff then hides forever."""

    def _collect(self, tmp):
        with patch.object(unbound, "_is_windows", return_value=True), \
                patch.object(unbound, "_vs_installed", return_value=True), \
                patch.object(unbound, "_vs_solution_roots", return_value=[Path(tmp)]), \
                patch.object(unbound.Path, "home", staticmethod(lambda: Path(tmp))):
            return unbound.collect_visual_studio_sessions(0)

    def test_a_capped_walk_is_reported_so_the_caller_holds_the_cutoff(self):
        with tempfile.TemporaryDirectory() as tmp:
            for n, name in enumerate(("alpha", "beta", "gamma")):
                _session_file(tmp, _prompt("ask %d" % n) + _reply("answer %d" % n),
                              session="%s-0000-0000-0000-00000000000%d" % (SESSION[:8], n),
                              solution=name)
            with patch.object(unbound, "_VS_MAX_SESSIONS_PER_RUN", 1), \
                    patch.object(unbound, "log_error"):
                sessions, truncated, _ = self._collect(tmp)

        self.assertEqual(len(sessions), 1)
        self.assertTrue(truncated, "a capped walk must tell the caller, or the cutoff "
                                   "advances past files it never read")

    def test_an_uncapped_walk_reports_no_truncation(self):
        with tempfile.TemporaryDirectory() as tmp:
            _session_file(tmp, _prompt("ask") + _reply("answer"))
            sessions, truncated, _ = self._collect(tmp)
        self.assertEqual(len(sessions), 1)
        self.assertFalse(truncated)

    def test_the_metered_copy_of_a_turn_wins_over_a_later_replay(self):
        # A restart replays the history; read newest-first, the replay wins and loses usage.
        with tempfile.TemporaryDirectory() as tmp:
            _chat_log(tmp, [
                ("session", SESSION),
                ("body", _body([_msg("user", "ask")])),
                ("usage", _usage(500, 20, cached=300)),
                ("body", _body([_msg("user", "ask"), _msg("assistant", "answer"),
                                _msg("user", "later")])),
            ], name="20260921_010101.000_VSGitHubCopilot.chat.log")
            _chat_log(tmp, [
                ("session", SESSION),
                ("body", _body([_msg("user", "ask"), _msg("assistant", "answer"),
                                _msg("user", "after restart")])),
            ], name="20260922_020202.000_VSGitHubCopilot.chat.log")
            sessions, _, _ = self._collect(tmp)

        self.assertEqual(len(sessions), 1)
        self.assertEqual(sessions[0]["usage"][0],
                         {"input_tokens": 200, "output_tokens": 20,
                          "cache_read_input_tokens": 300})


class MetadataAndResume(unittest.TestCase):
    """Three ways a sweep mis-reported or stalled, all flagged on #335."""

    def _collect(self, tmp):
        with patch.object(unbound, "_is_windows", return_value=True), \
                patch.object(unbound, "_vs_installed", return_value=True), \
                patch.object(unbound, "_vs_solution_roots", return_value=[Path(tmp)]), \
                patch.object(unbound.Path, "home", staticmethod(lambda: Path(tmp))):
            return unbound.collect_visual_studio_sessions(0)

    def test_a_turn_keeps_the_model_it_ran_on(self):
        # Reading the model off the request that replays a turn re-dates it to today.
        with tempfile.TemporaryDirectory() as tmp:
            _chat_log(tmp, [
                ("session", SESSION),
                ("body", _body([_msg("user", "first")], model="model-a")),
                ("body", _body([_msg("user", "first"), _msg("assistant", "a"),
                                _msg("user", "second")], model="model-b")),
                ("body", _body([_msg("user", "first"), _msg("assistant", "a"),
                                _msg("user", "second"), _msg("assistant", "b"),
                                _msg("user", "third")], model="model-c")),
            ])
            sessions, _, _ = self._collect(tmp)

        models = [e["data"]["model"] for e in sessions[0]["entries"]
                  if e["type"] == "assistant.message"]
        self.assertEqual(models, ["model-a", "model-b"])

    def test_the_last_finished_turn_keeps_its_logged_usage(self):
        # Its reply only exists in the .vs store, but its token counts are in the log.
        with tempfile.TemporaryDirectory() as tmp:
            _session_file(tmp, _prompt("ask") + _reply("answer"))
            _chat_log(tmp, [
                ("session", SESSION),
                ("body", _body([_msg("user", "ask")])),
                ("usage", _usage(900, 30, cached=400)),
            ])
            sessions, _, _ = self._collect(tmp)

        self.assertEqual(len(sessions), 1)
        self.assertEqual(sessions[0]["entries"][0]["data"]["content"], "ask")
        self.assertEqual(sessions[0]["usage"][0],
                         {"input_tokens": 500, "output_tokens": 30,
                          "cache_read_input_tokens": 400})

    def test_a_capped_walk_reports_where_to_resume(self):
        with tempfile.TemporaryDirectory() as tmp:
            for n, name in enumerate(("alpha", "beta", "gamma")):
                path = _session_file(tmp, _prompt("ask %d" % n) + _reply("answer %d" % n),
                                     session="%s-0000-0000-0000-00000000000%d" % (SESSION[:8], n),
                                     solution=name)
                os.utime(path, (1789900000 + n * 100, 1789900000 + n * 100))
            with patch.object(unbound, "_VS_MAX_SESSIONS_PER_RUN", 2), \
                    patch.object(unbound, "log_error"):
                sessions, truncated, resume_at = self._collect(tmp)

        self.assertEqual(len(sessions), 2)
        self.assertTrue(truncated)
        self.assertEqual(resume_at, 1789900100,
                         "must resume past the last file it finished, not repeat them")

    def test_the_store_walk_runs_oldest_first(self):
        with tempfile.TemporaryDirectory() as tmp:
            for n, name in enumerate(("newer", "older")):
                path = _session_file(tmp, _prompt("ask %d" % n) + _reply("answer %d" % n),
                                     session="%s-0000-0000-0000-00000000000%d" % (SESSION[:8], n),
                                     solution=name)
                os.utime(path, (1789900000 - n * 500, 1789900000 - n * 500))
            with patch.object(unbound, "_vs_solution_roots", return_value=[Path(tmp)]):
                mtimes = [m for m, _, _, _ in unbound._iter_vs_sessions(0)]
        self.assertEqual(mtimes, sorted(mtimes))


class SharedRootsAndHostileFiles(unittest.TestCase):
    """A sweep runs once per user, and not every path it could walk belongs to that user."""

    def _collect(self, home, roots=None):
        roots = [Path(home)] if roots is None else roots
        with patch.object(unbound, "_is_windows", return_value=True), \
                patch.object(unbound, "_vs_installed", return_value=True), \
                patch.object(unbound, "_vs_solution_roots", return_value=roots), \
                patch.object(unbound.Path, "home", staticmethod(lambda: Path(home))), \
                patch.object(unbound, "log_error"):
            return unbound.collect_visual_studio_sessions(0)

    def test_machine_wide_roots_are_not_walked(self):
        # A chat log the user can write is no proof of who owns what is found there.
        with tempfile.TemporaryDirectory() as home:
            with patch.object(unbound.Path, "home", staticmethod(lambda: Path(home))), \
                    patch.object(unbound.Path, "is_dir", lambda self: True):
                roots = [str(r) for r in unbound._vs_solution_roots()]
        self.assertTrue(all(str(home) in r for r in roots), roots)
        self.assertEqual(len(roots), 2)

    def test_a_home_root_session_is_collected(self):
        with tempfile.TemporaryDirectory() as home:
            _session_file(home, _prompt("ask") + _reply("answer"))
            sessions, _, _ = self._collect(home)
        self.assertEqual(len(sessions), 1)

    def test_a_session_symlinked_out_of_its_root_is_not_read(self):
        # The sweep runs with the installer's rights, not the planter's.
        with tempfile.TemporaryDirectory() as home, tempfile.TemporaryDirectory() as outside:
            secret = Path(outside) / "secret"
            secret.write_bytes(_prompt("stolen") + _reply("secret contents"))
            planted = _session_file(home, b"")
            planted.unlink()
            planted.symlink_to(secret)
            sessions, _, _ = self._collect(home)
        self.assertEqual(sessions, [])

    def test_a_walk_that_hits_its_budget_still_returns_what_it_found(self):
        # A bare return handed the caller None once this stopped being a generator.
        with tempfile.TemporaryDirectory() as home:
            _session_file(home, _prompt("ask") + _reply("answer"))
            with patch.object(unbound, "_VS_MAX_WALK_DIRS", 0), \
                    patch.object(unbound, "log_error"):
                sessions, truncated, _ = self._collect(home)
        self.assertEqual(sessions, [])
        self.assertTrue(truncated)

    def test_a_session_swapped_for_a_symlink_after_the_walk_is_not_read(self):
        # The walk clears a path, then sorts; the read happens later.
        with tempfile.TemporaryDirectory() as home, tempfile.TemporaryDirectory() as outside:
            secret = Path(outside) / "secret"
            secret.write_bytes(_prompt("stolen") + _reply("secret contents"))
            planted = _session_file(home, _prompt("ask") + _reply("answer"))
            real = unbound._iter_vs_sessions

            def swap(cutoff, budget=None):
                found = real(cutoff, budget)
                planted.unlink()
                planted.symlink_to(secret)
                return found

            with patch.object(unbound, "_iter_vs_sessions", swap):
                sessions, _, _ = self._collect(home)
        self.assertEqual(sessions, [])

    def test_a_session_swapped_for_another_real_file_after_the_walk_is_not_read(self):
        # Re-checking the path cannot catch this: the swapped-in file is inside the root.
        with tempfile.TemporaryDirectory() as home:
            planted = _session_file(home, _prompt("ask") + _reply("answer"))
            real = unbound._iter_vs_sessions

            def swap(cutoff, budget=None):
                found = real(cutoff, budget)
                planted.unlink()
                planted.write_bytes(_prompt("swapped in") + _reply("after the check"))
                return found

            with patch.object(unbound, "_iter_vs_sessions", swap), \
                    patch.object(unbound, "log_error"):
                sessions, _, _ = self._collect(home)
        self.assertEqual(sessions, [], "the handle must be checked, not the path")

    def test_a_chat_log_symlinked_out_of_its_root_is_not_read(self):
        with tempfile.TemporaryDirectory() as home, tempfile.TemporaryDirectory() as outside:
            secret = Path(outside) / "secret.log"
            secret.write_text("x\n", encoding="utf-8")
            planted = _chat_log(home, [])
            planted.unlink()
            planted.symlink_to(secret)
            with patch.object(unbound.Path, "home", staticmethod(lambda: Path(home))), \
                    patch.object(unbound, "log_error"):
                self.assertEqual(unbound._iter_vs_chat_logs(0), [])

    def test_a_nested_session_file_raises_instead_of_exhausting_the_stack(self):
        # RecursionError is not in the caller's except clause, so it would abort the walk.
        with tempfile.TemporaryDirectory() as home:
            _session_file(home, b"\x91" * 20000)
            sessions, _, _ = self._collect(home)
        self.assertEqual(sessions, [])


class TurnPositions(unittest.TestCase):
    """A turn's position is its own, not its rank among the turns that finished."""

    def _collect(self, home):
        with patch.object(unbound, "_is_windows", return_value=True), \
                patch.object(unbound, "_vs_installed", return_value=True), \
                patch.object(unbound, "_vs_solution_roots", return_value=[Path(home)]), \
                patch.object(unbound.Path, "home", staticmethod(lambda: Path(home))), \
                patch.object(unbound, "log_error"):
            return unbound.collect_visual_studio_sessions(0)

    def test_a_cancelled_first_turn_does_not_shift_the_usage_of_the_second(self):
        # VS keys usage by position among every prompt, so the cancelled turn holds slot 0.
        with tempfile.TemporaryDirectory() as home:
            _chat_log(home, [
                ("session", SESSION),
                ("body", _body([_msg("user", "cancelled"), _msg("assistant", ""),
                                _msg("user", "real one")])),
                ("usage", _usage(100, 5)),
                ("body", _body([_msg("user", "cancelled"), _msg("assistant", ""),
                                _msg("user", "real one"), _msg("assistant", "answer"),
                                _msg("user", "real two")])),
                ("usage", _usage(700, 40)),
            ])
            sessions, _, _ = self._collect(home)

        entries = sessions[0]["entries"]
        self.assertEqual(entries[0]["data"]["content"], "real one")
        self.assertEqual(entries[0]["id"], unbound._vs_turn_marker(SESSION, "real one", 1),
                         "the surviving turn keeps slot 1, so its id is stable across sweeps")
        self.assertEqual(len(sessions[0]["usage"]), 1)
        self.assertEqual(sessions[0]["usage"][0],
                         {"input_tokens": 100, "output_tokens": 5,
                          "cache_read_input_tokens": 0},
                         "the backend pairs usage[i] with exchange i, so no pad slots")

    def test_a_cancelled_turn_keeps_the_positions_of_the_turns_after_it(self):
        turns = unbound._vs_chat_log_turns(_body([
            _msg("user", "cancelled"), _msg("assistant", ""),
            _msg("user", "one"), _msg("assistant", "a"),
            _msg("user", "two"), _msg("assistant", "b"),
            _msg("user", "trailing")]))
        self.assertEqual(turns, [(1, "one", "a"), (2, "two", "b")])

    def test_the_store_numbers_a_textless_turn_the_same_way(self):
        blob = (_prompt("cancelled") + _mp_array([bytes([0x01]), _mp_map([("Content", _mp_array([]))])])
                + _prompt("one") + _reply("a"))
        turns = unbound._vs_session_turns(unbound._mp_unpack_all(blob))
        self.assertEqual([i for i, _, _ in turns], [1])


class LogRequestBudget(unittest.TestCase):
    def test_a_quiet_conversation_survives_a_busy_one_in_the_same_log(self):
        # A single tail of the log would drop A entirely once B outran it.
        entries = [("session", OTHER), ("body", _body([_msg("user", "from A"),
                                                       _msg("assistant", "a"),
                                                       _msg("user", "settle A")]))]
        entries.append(("session", SESSION))
        for n in range(unbound._VS_MAX_METADATA_REQUESTS + 5):
            entries.append(("body", _body([_msg("user", "B %d" % n)])))

        with tempfile.TemporaryDirectory() as home:
            path = _chat_log(home, entries)
            key = unbound._vs_file_key(path.stat())
            with patch.object(unbound, "log_error"):
                requests, _ = unbound._vs_chat_log_requests(path, path.parent.resolve(), key)

        kept = {r[4] for r in requests}
        self.assertIn(OTHER, kept, "the quiet conversation must not be dropped")
        self.assertLessEqual(sum(1 for r in requests if r[4] == SESSION),
                             unbound._VS_MAX_METADATA_REQUESTS)


class UsageSlotAlignment(unittest.TestCase):
    def test_every_usage_slot_lines_up_with_an_exchange(self):
        # Positions can skip a cancelled turn; the backend cannot.
        with tempfile.TemporaryDirectory() as home:
            _chat_log(home, [
                ("session", SESSION),
                ("body", _body([_msg("user", "cancelled"), _msg("assistant", ""),
                                _msg("user", "one")])),
                ("usage", _usage(100, 5)),
                ("body", _body([_msg("user", "cancelled"), _msg("assistant", ""),
                                _msg("user", "one"), _msg("assistant", "a"),
                                _msg("user", "two")])),
                ("usage", _usage(700, 40)),
                ("body", _body([_msg("user", "cancelled"), _msg("assistant", ""),
                                _msg("user", "one"), _msg("assistant", "a"),
                                _msg("user", "two"), _msg("assistant", "b"),
                                _msg("user", "three")])),
                ("usage", _usage(900, 60)),
            ])
            with patch.object(unbound, "_is_windows", return_value=True), \
                    patch.object(unbound, "_vs_installed", return_value=True), \
                    patch.object(unbound, "_vs_solution_roots", return_value=[Path(home)]), \
                    patch.object(unbound.Path, "home", staticmethod(lambda: Path(home))), \
                    patch.object(unbound, "log_error"):
                sessions, _, _ = unbound.collect_visual_studio_sessions(0)

        session = sessions[0]
        exchanges = [e for e in session["entries"] if e["type"] == "user.message"]
        self.assertEqual([e["data"]["content"] for e in exchanges], ["one", "two"])
        self.assertEqual(len(session["usage"]), len(exchanges))
        self.assertEqual([u["input_tokens"] for u in session["usage"]], [100, 700])

    def test_a_turn_recovered_late_still_lands_in_order(self):
        # The store is read after every log, so a turn only it holds arrives last.
        with tempfile.TemporaryDirectory() as home:
            _session_file(home, _prompt("first") + _reply("a") + _prompt("second") + _reply("b"))
            _chat_log(home, [
                ("session", SESSION),
                ("body", _body([_msg("user", "first"), _msg("assistant", "a"),
                                _msg("user", "second")])),
            ])
            with patch.object(unbound, "_is_windows", return_value=True), \
                    patch.object(unbound, "_vs_installed", return_value=True), \
                    patch.object(unbound, "_vs_solution_roots", return_value=[Path(home)]), \
                    patch.object(unbound.Path, "home", staticmethod(lambda: Path(home))), \
                    patch.object(unbound, "log_error"):
                sessions, _, _ = unbound.collect_visual_studio_sessions(0)

        prompts = [e["data"]["content"] for e in sessions[0]["entries"]
                   if e["type"] == "user.message"]
        self.assertEqual(prompts, ["first", "second"])


class LongChatLog(unittest.TestCase):
    def test_a_long_log_is_read_from_its_tail(self):
        # The head spends the budget on ancient requests; the file only grows.
        with tempfile.TemporaryDirectory() as home:
            entries = [("session", OTHER)]
            entries += [("body", _body([_msg("user", "ancient %d" % n)])) for n in range(200)]
            entries += [("session", SESSION),
                        ("body", _body([_msg("user", "recent"), _msg("assistant", "a"),
                                        _msg("user", "settle")]))]
            path = _chat_log(home, entries)
            key = unbound._vs_file_key(path.stat())
            raw = path.read_bytes()
            # A window opening mid-way through the line before the second marker.
            line_start = raw.rfind(b"\n", 0, raw.index(SESSION.encode())) + 1
            window = len(raw) - (line_start - 5)
            with patch.object(unbound, "_VS_MAX_LOG_BYTES", window), \
                    patch.object(unbound, "log_error"):
                requests, _ = unbound._vs_chat_log_requests(path, path.parent.resolve(), key)

        self.assertTrue(requests, "the tail must still yield the recent requests")
        self.assertEqual({r[4] for r in requests}, {SESSION},
                         "requests before the first marker in the window are not attributed")

    def test_a_short_log_is_read_whole(self):
        with tempfile.TemporaryDirectory() as home:
            path = _chat_log(home, [("session", SESSION),
                                    ("body", _body([_msg("user", "one")]))])
            key = unbound._vs_file_key(path.stat())
            with patch.object(unbound, "log_error"):
                requests, _ = unbound._vs_chat_log_requests(path, path.parent.resolve(), key)
        self.assertEqual(len(requests), 1)
        self.assertEqual(requests[0][4], SESSION)
