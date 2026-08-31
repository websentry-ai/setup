"""
Tests for per-turn identity and late completion in copilot/hooks/unbound.py.

Copilot writes a turn's tokens and its served model after that turn has already been
reported, so the numbers have to be sent again later. The second send must land on the
same row, which means a turn needs an id that does not change when its usage does.
"""

import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from tests.conftest import tool_module

unbound = tool_module("copilot/hooks", "unbound")

SESSION = "sess-turn-identity"


def _transcript(tmpdir, entries):
    path = Path(tmpdir) / "events.jsonl"
    path.write_text("\n".join(json.dumps(e) for e in entries), encoding="utf-8")
    return path


def _user(content, entry_id=None):
    entry = {"type": "user.message", "data": {"content": content}}
    if entry_id:
        entry["id"] = entry_id
    return entry


def _assistant(content):
    return {"type": "assistant.message", "data": {"content": content}}


class TestTurnRequestId(unittest.TestCase):
    def _id(self, user, assistant, occurrence=0, session=SESSION):
        digest = unbound.turn_content_digest(user, assistant)
        return unbound.build_turn_request_id(session, digest, occurrence)

    def test_same_turn_gets_the_same_id(self):
        # The whole point: re-sending a turn once its tokens land must address the row
        # the first send created.
        self.assertEqual(self._id("hi", "hello"), self._id("hi", "hello"))

    def test_usage_is_not_part_of_the_id(self):
        # The id is built from content alone, so tokens arriving later cannot change it.
        first = self._id("hi", "hello")
        self.assertEqual(first, self._id("hi", "hello"))

    def test_different_turns_get_different_ids(self):
        self.assertNotEqual(self._id("hi", "hello"), self._id("bye", "hello"))
        self.assertNotEqual(self._id("hi", "hello"), self._id("hi", "goodbye"))

    def test_a_repeated_turn_is_separated_by_occurrence(self):
        self.assertNotEqual(self._id("hi", "hello", 0), self._id("hi", "hello", 1))

    def test_sessions_do_not_collide(self):
        self.assertNotEqual(self._id("hi", "hello"), self._id("hi", "hello", session="other"))

    def test_a_prompt_cannot_forge_the_next_turns_digest(self):
        # NUL-joined, so "ab" + "" and "a" + "b" stay distinct.
        self.assertNotEqual(unbound.turn_content_digest("ab", ""),
                            unbound.turn_content_digest("a", "b"))

    def test_the_id_fits_the_request_id_column(self):
        self.assertEqual(len(self._id("hi", "hello")), 36)


class TestRebuildTurnContent(unittest.TestCase):
    def test_one_turn_is_rebuilt_and_the_next_prompt_ends_it(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            path = _transcript(tmpdir, [
                _user("first", "p1"), _assistant("reply one"),
                _user("second", "p2"), _assistant("reply two"),
            ])
            self.assertEqual(
                unbound.rebuild_turn_content(path, SESSION, "p1"), ("first", "reply one"))
            self.assertEqual(
                unbound.rebuild_turn_content(path, SESSION, "p2"), ("second", "reply two"))

    def test_multiple_assistant_messages_join(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            path = _transcript(tmpdir, [
                _user("q", "p1"), _assistant("one"), _assistant("two"),
            ])
            self.assertEqual(
                unbound.rebuild_turn_content(path, SESSION, "p1"), ("q", "one\n\ntwo"))

    def test_an_unknown_prompt_id_rebuilds_nothing(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            path = _transcript(tmpdir, [_user("q", "p1"), _assistant("a")])
            self.assertIsNone(unbound.rebuild_turn_content(path, SESSION, "gone"))

    def test_a_missing_transcript_rebuilds_nothing(self):
        self.assertIsNone(unbound.rebuild_turn_content("/nope/events.jsonl", SESSION, "p1"))
        self.assertIsNone(unbound.rebuild_turn_content(None, SESSION, "p1"))

    def test_an_entry_without_an_id_still_resolves(self):
        # Entries can arrive without an envelope id; the derived id has to match the one
        # the parser watermarked with, or the turn can never be rebuilt.
        with tempfile.TemporaryDirectory() as tmpdir:
            entries = [_user("no id here"), _assistant("reply")]
            path = _transcript(tmpdir, entries)
            derived = unbound.turn_prompt_id(entries[0], SESSION, 0, "no id here")
            self.assertEqual(
                unbound.rebuild_turn_content(path, SESSION, derived),
                ("no id here", "reply"))


class TestCompletePendingTurn(unittest.TestCase):
    def _run(self, pending, usage, model, entries=None, final=False, capture=None):
        sent = []
        entries = entries or [_user("q", "p1"), _assistant("a")]

        def _usage(*a, **k):
            if capture is not None:
                capture.update(k)
            return (usage, 0)

        with tempfile.TemporaryDirectory() as tmpdir:
            path = _transcript(tmpdir, entries)
            event = {"transcript_path": str(path)}
            with patch.object(unbound, "get_session_marker",
                              lambda k: {"pending_turn": pending}), \
                    patch.object(unbound, "get_turn_usage", _usage), \
                    patch.object(unbound, "_vscode_turn_model", lambda *a, **k: model), \
                    patch.object(unbound, "send_to_api",
                                 lambda ex, key: sent.append(ex) or True):
                settled = unbound.complete_pending_turn(event, "wm", "key", final=final)
        return settled, sent

    def _pending(self):
        return {"turn_request_id": "tid-1", "conversation_id": SESSION,
                "prompt_id": "p1", "since": None, "until": "2026-08-31T00:00:00Z"}

    def test_usage_that_lands_later_is_sent_under_the_original_id(self):
        settled, sent = self._run(self._pending(), {"input_tokens": 5}, None)
        self.assertTrue(settled)
        self.assertEqual(len(sent), 1)
        self.assertEqual(sent[0]["turn_request_id"], "tid-1")
        self.assertEqual(sent[0]["usage"], {"input_tokens": 5})
        self.assertEqual(sent[0]["messages"][0]["content"], "q")

    def test_a_model_alone_keeps_waiting_for_the_tokens(self):
        # VS Code can name the model before it has finished counting. Sending on the model
        # alone and clearing the slot would lose those tokens permanently.
        settled, sent = self._run(self._pending(), None, "claude-haiku-4.5")
        self.assertFalse(settled)
        self.assertEqual(sent, [])

    def test_session_end_sends_the_model_but_keeps_the_slot(self):
        # Last chance this session gets, so take what is there. Settled still means the
        # tokens are in, so the slot survives for anything that runs after.
        settled, sent = self._run(self._pending(), None, "claude-haiku-4.5", final=True)
        self.assertFalse(settled)
        self.assertEqual(sent[0]["model"], "claude-haiku-4.5")
        self.assertNotIn("usage", sent[0])

    def test_a_send_carrying_tokens_is_what_settles_the_turn(self):
        settled, sent = self._run(self._pending(), {"input_tokens": 5}, None)
        self.assertTrue(settled)
        self.assertEqual(sent[0]["usage"], {"input_tokens": 5})

    def test_tokens_arriving_after_a_model_still_complete_the_turn(self):
        # The slot survived the model-only round, so the later tokens land on the row.
        settled, sent = self._run(self._pending(), {"input_tokens": 5}, "claude-haiku-4.5")
        self.assertTrue(settled)
        self.assertEqual(sent[0]["usage"], {"input_tokens": 5})
        self.assertEqual(sent[0]["model"], "claude-haiku-4.5")

    def test_nothing_landed_means_nothing_sent(self):
        settled, sent = self._run(self._pending(), None, None)
        self.assertFalse(settled)
        self.assertEqual(sent, [])

    def test_no_pending_turn_is_a_no_op(self):
        self.assertEqual(self._run(None, {"input_tokens": 5}, None), (False, []))
        self.assertEqual(self._run({}, {"input_tokens": 5}, None), (False, []))

    def test_a_turn_gone_from_the_transcript_is_cleared_not_resent(self):
        # Otherwise the slot would hold a turn that can never be rebuilt and every later
        # Stop would retry it.
        pending = dict(self._pending(), prompt_id="vanished")
        settled, sent = self._run(pending, {"input_tokens": 5}, None)
        self.assertTrue(settled)
        self.assertEqual(sent, [])


if __name__ == "__main__":
    unittest.main()

    def test_session_end_waits_for_a_journal_that_has_not_been_written(self):
        # VS Code writes the journal lazily, sometimes only as the session closes. Mid
        # session an empty read means "a later Stop will get it"; at SessionEnd there is
        # no later Stop, so the read has to wait instead of giving up.
        capture = {}
        self._run(self._pending(), {"input_tokens": 5}, None, final=True, capture=capture)
        self.assertTrue(capture.get("wait_when_idle"))

    def test_mid_session_does_not_pay_for_the_wait(self):
        capture = {}
        self._run(self._pending(), {"input_tokens": 5}, None, final=False, capture=capture)
        self.assertFalse(capture.get("wait_when_idle"))
