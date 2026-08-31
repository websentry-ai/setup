"""
Tests for backfill model collection and the force-backfill flag in copilot/hooks/setup.py.

VS Code's transcripts carry no model at all, which is why backfilled rows read 'auto'.
The model lives in the chat journal beside them, so the client ships one name per
exchange. Covers:
  - _backfill_vscode_models   (servedBy over modelId, namespacing, gaps)
  - _backfill_session_models  (VS Code only; the CLI transcript already names its model)
  - _backfill_collect_session / _backfill_slice_session (payload + boundary-aligned slicing)
  - _backfill_force_epoch     (org-wide re-walk request)
"""

import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from tests.conftest import tool_module

setup = tool_module("copilot/hooks", "setup")

SESSION = "sess-models"


def _vscode_tree(tmpdir, session, lines):
    root = Path(tmpdir) / "ws" / "hash"
    (root / "chatSessions").mkdir(parents=True)
    (root / "GitHub.copilot-chat" / "transcripts").mkdir(parents=True)
    (root / "chatSessions" / (session + ".jsonl")).write_text(
        "\n".join(json.dumps(line) for line in lines), encoding="utf-8")
    transcript = root / "GitHub.copilot-chat" / "transcripts" / (session + ".jsonl")
    transcript.write_text("", encoding="utf-8")
    return transcript


def _request(served=None, selected=None):
    obj = {"timestamp": 1787893680000, "promptTokens": 10,
           "completionTokens": 2, "elapsedMs": 99}
    if served is not None:
        obj["servedBy"] = served
    if selected is not None:
        obj["modelId"] = selected
    return obj


class TestBackfillVscodeModels(unittest.TestCase):
    def _models(self, lines):
        with tempfile.TemporaryDirectory() as tmpdir:
            transcript = _vscode_tree(tmpdir, SESSION, lines)
            return setup._backfill_vscode_models(transcript, SESSION)

    def test_served_model_wins_over_the_selection(self):
        # An 'auto' selection is the whole problem: servedBy names what actually ran.
        models = self._models([
            {"kind": 1, "v": {"requests": []}},
            {"kind": 2, "k": ["requests"], "v": [
                _request(served="gpt-5.6-luna", selected="copilot/auto")]},
        ])
        self.assertEqual(models, ["gpt-5.6-luna"])

    def test_selection_is_used_when_nothing_served_yet(self):
        models = self._models([
            {"kind": 1, "v": {"requests": []}},
            {"kind": 2, "k": ["requests"], "v": [_request(selected="copilot/claude-haiku-4.5")]},
        ])
        self.assertEqual(models, ["claude-haiku-4.5"])

    def test_unnamespaced_selection_is_left_alone(self):
        models = self._models([
            {"kind": 1, "v": {"requests": []}},
            {"kind": 2, "k": ["requests"], "v": [_request(selected="claude-opus-5")]},
        ])
        self.assertEqual(models, ["claude-opus-5"])

    def test_a_gap_keeps_its_position(self):
        # Positions are what bind a model to an exchange, so an unknown one cannot shift
        # the others up.
        models = self._models([
            {"kind": 1, "v": {"requests": []}},
            {"kind": 2, "k": ["requests"], "v": [
                _request(), _request(served="claude-sonnet-5")]},
        ])
        self.assertEqual(models, ["", "claude-sonnet-5"])

    def test_a_patch_wins_over_the_streamed_selection(self):
        models = self._models([
            {"kind": 1, "v": {"requests": []}},
            {"kind": 2, "k": ["requests"], "v": [_request(selected="copilot/auto")]},
            {"kind": 2, "k": ["requests", "0", "servedBy"], "v": "claude-opus-5"},
        ])
        self.assertEqual(models, ["claude-opus-5"])

    def test_mid_session_switch_is_reported_per_request(self):
        models = self._models([
            {"kind": 1, "v": {"requests": []}},
            {"kind": 2, "k": ["requests"], "v": [
                _request(served="claude-haiku-4.5"), _request(served="claude-sonnet-5")]},
        ])
        self.assertEqual(models, ["claude-haiku-4.5", "claude-sonnet-5"])

    def test_non_transcript_path_is_empty(self):
        self.assertEqual(setup._backfill_vscode_models(Path("/tmp/x/y.jsonl"), SESSION), [])

    def test_cli_transcripts_report_nothing(self):
        # The CLI transcript records model_change and per-message models already.
        self.assertEqual(
            setup._backfill_session_models(Path("/tmp/x/events.jsonl"), SESSION), [])


class TestBackfillModelsPayload(unittest.TestCase):
    def _collect(self, models):
        with tempfile.TemporaryDirectory() as tmpdir:
            transcript = Path(tmpdir) / "events.jsonl"
            transcript.write_text(json.dumps(
                {"type": "user.message", "data": {"content": "hi"}}) + "\n", encoding="utf-8")
            with patch.object(setup, "_backfill_session_usage", lambda *a: []), \
                    patch.object(setup, "_backfill_session_models", lambda *a: models):
                return setup._backfill_collect_session(transcript)

    def test_models_ride_along_when_any_are_known(self):
        self.assertEqual(self._collect(["claude-opus-5"])["models"], ["claude-opus-5"])

    def test_models_are_omitted_when_none_are_known(self):
        self.assertNotIn("models", self._collect(["", ""]))
        self.assertNotIn("models", self._collect([]))

    def test_slices_cut_models_on_the_same_boundaries_as_entries(self):
        # A split session re-bases record_index, so models must cut where entries do or
        # the second slice would report the first slice's models.
        entries = []
        for turn in range(3):
            entries.append({"type": "user.message", "data": {"content": "prompt %d" % turn}})
            entries.append({"type": "assistant.message", "data": {"content": "x" * 400}})
        session = {"session_id": SESSION, "entries": entries,
                   "models": ["m0", "m1", "m2"]}
        slices = list(setup._backfill_slice_session(session, 900))
        self.assertGreater(len(slices), 1)
        rebuilt = []
        for part in slices:
            rebuilt.extend(part.get("models", []))
        self.assertEqual(rebuilt, ["m0", "m1", "m2"])
        for part in slices:
            base = part["record_index_base"]
            self.assertEqual(part.get("models", []),
                             ["m0", "m1", "m2"][base:base + len(part.get("models", []))])


class TestBackfillForceEpoch(unittest.TestCase):
    def _epoch(self, code, payload):
        body = json.dumps(payload).encode("utf-8") if payload is not None else b"not json"
        with patch.object(setup, "_backfill_http_request", lambda *a, **k: (code, body)):
            return setup._backfill_force_epoch("key", "https://backend")

    def test_a_requested_time_is_returned(self):
        self.assertEqual(self._epoch(200, {"force_backfill_requested_epoch": 1787893680.5}),
                         1787893680.5)

    def test_no_outstanding_request_is_none(self):
        self.assertIsNone(self._epoch(200, {"force_backfill_requested_epoch": None}))
        self.assertIsNone(self._epoch(200, {}))

    def test_a_bogus_value_never_forces(self):
        # bool is an int subclass, so True would otherwise read as epoch 1.
        self.assertIsNone(self._epoch(200, {"force_backfill_requested_epoch": True}))
        self.assertIsNone(self._epoch(200, {"force_backfill_requested_epoch": "yesterday"}))

    def test_a_failed_call_never_forces(self):
        self.assertIsNone(self._epoch(500, {"force_backfill_requested_epoch": 1787893680}))
        self.assertIsNone(self._epoch(0, {"force_backfill_requested_epoch": 1787893680}))
        self.assertIsNone(self._epoch(200, None))


if __name__ == "__main__":
    unittest.main()
