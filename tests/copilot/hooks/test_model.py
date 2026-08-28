"""
Tests for per-request model capture in copilot/hooks/unbound.py.

The transcript the exchange is built from carries no model at all, so every VS Code row
otherwise reads 'auto'. VS Code records the model per request in its chat journal: the
selection when the prompt is sent, and the model that served it once the response lands.
"""

import json
import tempfile
import unittest
from pathlib import Path

from tests.conftest import tool_module

unbound = tool_module("copilot/hooks")

SESSION = "sess-model"


def _journal(tmpdir, lines, session=SESSION):
    root = Path(tmpdir) / "ws" / "hash"
    (root / "chatSessions").mkdir(parents=True)
    (root / "GitHub.copilot-chat" / "transcripts").mkdir(parents=True)
    (root / "chatSessions" / (session + ".jsonl")).write_text(
        "\n".join(json.dumps(line) for line in lines), encoding="utf-8")
    transcript = root / "GitHub.copilot-chat" / "transcripts" / (session + ".jsonl")
    transcript.write_text("", encoding="utf-8")
    return str(transcript)


def _request(selected=None, served=None, ts=1787893680000):
    obj = {"timestamp": ts}
    if selected is not None:
        obj["modelId"] = selected
    if served is not None:
        obj["result"] = {"metadata": {"toolCallRounds": [{"modelId": served}]}}
    return obj


class TestTurnModel(unittest.TestCase):
    # requests default to 12:00:00; the window runs from previous_stop to turn_end
    STOP = "2026-08-28T12:00:30.000Z"

    def _model(self, requests, session=SESSION, previous_stop=None, turn_end=None):
        with tempfile.TemporaryDirectory() as tmpdir:
            transcript = _journal(tmpdir, [{"kind": 1, "v": {"requests": []}},
                                           {"kind": 2, "k": ["requests"], "v": requests}],
                                  session=session)
            return unbound._vscode_turn_model(transcript, session, previous_stop,
                                              turn_end or self.STOP)

    def test_the_serving_model_wins_over_the_selection(self):
        # this is what makes an 'auto' pick report the model that actually ran
        self.assertEqual(
            self._model([_request(selected="copilot/auto", served="gpt-5.6-luna")]),
            "gpt-5.6-luna")

    def test_the_selection_is_used_before_the_response_lands(self):
        # modelId is set when the prompt is sent, so an explicit pick is always reported
        self.assertEqual(
            self._model([_request(selected="copilot/claude-haiku-4.5")]),
            "claude-haiku-4.5")

    def test_the_namespace_prefix_is_stripped(self):
        self.assertEqual(self._model([_request(selected="copilot/claude-sonnet-5")]),
                         "claude-sonnet-5")
        self.assertEqual(self._model([_request(selected="claude-sonnet-5")]),
                         "claude-sonnet-5")

    def test_an_auto_pick_with_no_served_model_yet_stays_auto(self):
        self.assertEqual(self._model([_request(selected="copilot/auto")]), "auto")

    def test_the_newest_request_is_the_one_reported(self):
        # a mid-session switch must not report the model of an earlier turn
        self.assertEqual(
            self._model([_request(selected="copilot/auto", served="gpt-5.6-luna"),
                         _request(selected="copilot/claude-haiku-4.5",
                                  served="claude-haiku-4.5"),
                         _request(selected="copilot/claude-sonnet-5",
                                  served="claude-sonnet-5")]),
            "claude-sonnet-5")

    def test_switching_back_reports_the_model_switched_back_to(self):
        self.assertEqual(
            self._model([_request(selected="copilot/claude-haiku-4.5",
                                  served="claude-haiku-4.5"),
                         _request(selected="copilot/auto", served="gpt-5.6-luna"),
                         _request(selected="copilot/claude-haiku-4.5",
                                  served="claude-haiku-4.5")]),
            "claude-haiku-4.5")

    def test_a_request_with_no_model_at_all_reports_nothing(self):
        self.assertIsNone(self._model([_request()]))

    def test_no_requests_reports_nothing(self):
        self.assertIsNone(self._model([]))

    def test_non_string_values_are_ignored(self):
        self.assertIsNone(self._model([_request(selected={"corrupt": 1})]))
        self.assertEqual(
            self._model([{"timestamp": 1, "modelId": "copilot/claude-haiku-4.5",
                          "result": {"metadata": {"toolCallRounds": [{"modelId": 12345}]}}}]),
            "claude-haiku-4.5")

    def test_a_queued_next_turn_does_not_steal_this_row(self):
        # a prompt queued while this turn runs already exists in the journal
        got = self._model(
            [_request(selected="copilot/claude-haiku-4.5", served="claude-haiku-4.5",
                      ts=1787918400000),                                     # 12:00:00, this turn
             _request(selected="copilot/claude-sonnet-5", ts=1787918460000)],  # 12:01:00, queued
            turn_end="2026-08-28T12:00:30.000Z")
        self.assertEqual(got, "claude-haiku-4.5")

    def test_the_previous_turn_is_never_reported_as_this_one(self):
        # the journal is written lazily, so this turn's request may not be there yet.
        # Reporting the previous turn's model would be a confidently wrong answer.
        got = self._model(
            [_request(selected="copilot/gpt-5.6-terra", served="gpt-5.6-terra",
                      ts=1787918400000)],                    # 12:00:00, the PREVIOUS turn
            previous_stop="2026-08-28T12:00:10.000Z",        # it ended before this turn began
            turn_end="2026-08-28T12:00:30.000Z")
        self.assertIsNone(got)

    def test_the_first_turn_has_no_lower_bound(self):
        got = self._model([_request(selected="copilot/claude-haiku-4.5", ts=1787918400000)],
                          previous_stop=None)
        self.assertEqual(got, "claude-haiku-4.5")

    def test_an_empty_window_reports_nothing(self):
        got = self._model([_request(selected="copilot/claude-haiku-4.5", ts=1787918400000)],
                          turn_end="2026-08-28T00:00:00.000Z")
        self.assertIsNone(got)

    def test_a_cli_transcript_has_no_vscode_store(self):
        self.assertIsNone(unbound._vscode_turn_model(
            "/h/.copilot/session-state/" + SESSION + "/events.jsonl", SESSION,
            None, self.STOP))

    def test_a_rejected_session_id_reports_nothing(self):
        # the id is joined into a path, so it goes through the same validation
        with tempfile.TemporaryDirectory() as tmpdir:
            transcript = _journal(tmpdir, [{"kind": 1, "v": {"requests": []}}])
            self.assertIsNone(unbound._vscode_turn_model(
                transcript, "../../../etc/passwd", None, self.STOP))
            self.assertIsNone(unbound._vscode_turn_model(transcript, "CON", None, self.STOP))
