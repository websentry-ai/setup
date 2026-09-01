"""
Tests for backfill model collection and the force-backfill flag in copilot/hooks/setup.py.

VS Code's transcripts carry no model at all, which is why backfilled rows read 'auto'.
The model lives in the chat journal beside them, so the client ships one name per
exchange. Covers:
  - _backfill_vscode_models   (servedBy over modelId, namespacing, gaps)
  - _backfill_session_models  (VS Code only; the CLI transcript already names its model)
  - _backfill_collect_session / _backfill_slice_session (payload + boundary-aligned slicing)
  - _backfill_force_config    (org-wide re-walk request + its window)
"""

import json
from datetime import datetime, timezone
import tempfile
import time
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


BASE_MS = 1787893680000
TURN_MS = 10000
CLOSE_MS = 5000


def _iso(ms):
    return datetime.fromtimestamp(ms / 1000.0, timezone.utc).isoformat().replace("+00:00", "Z")


def _turn_entries(count):
    """`count` turns, each closing before the next opens."""
    entries = []
    for turn in range(count):
        start = BASE_MS + turn * TURN_MS
        entries.append({"type": "user.message", "timestamp": _iso(start),
                        "data": {"content": "prompt %d" % turn}})
        entries.append({"type": "assistant.message", "timestamp": _iso(start + CLOSE_MS),
                        "data": {"content": "reply %d" % turn}})
    return entries


def _request(served=None, selected=None, turn=0):
    obj = {"timestamp": BASE_MS + turn * TURN_MS - 400, "promptTokens": 10,
           "completionTokens": 2, "elapsedMs": 99}
    if served is not None:
        obj["servedBy"] = served
    if selected is not None:
        obj["modelId"] = selected
    return obj


class TestBackfillVscodeModels(unittest.TestCase):
    def _models(self, lines, turns=1):
        with tempfile.TemporaryDirectory() as tmpdir:
            transcript = _vscode_tree(tmpdir, SESSION, lines)
            return setup._backfill_vscode_models(transcript, SESSION, _turn_entries(turns))

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
                _request(turn=0), _request(served="claude-sonnet-5", turn=1)]},
        ], turns=2)
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
                _request(served="claude-haiku-4.5", turn=0),
                _request(served="claude-sonnet-5", turn=1)]},
        ], turns=2)
        self.assertEqual(models, ["claude-haiku-4.5", "claude-sonnet-5"])

    def test_a_model_is_billed_to_its_own_turn_not_the_next(self):
        # Fewer requests than turns: position and turn disagree, and the turn wins.
        models = self._models([
            {"kind": 1, "v": {"requests": []}},
            {"kind": 2, "k": ["requests"], "v": [_request(served="gpt-5-mini", turn=1)]},
        ], turns=2)
        self.assertEqual(models, ["", "gpt-5-mini"])

    def test_a_mid_turn_switch_reports_the_turns_last_model(self):
        # The live collector reads the turn's last request; the re-walk must agree or the
        # same turn is costed under two different models.
        models = self._models([
            {"kind": 1, "v": {"requests": []}},
            {"kind": 2, "k": ["requests"], "v": [
                _request(served="claude-haiku-4.5", turn=0),
                dict(_request(served="gpt-5-mini", turn=0),
                     **{"timestamp": BASE_MS - 400 + 100})]},
        ], turns=1)
        self.assertEqual(models, ["gpt-5-mini"])

    def test_non_transcript_path_is_empty(self):
        self.assertEqual(
            setup._backfill_vscode_models(Path("/tmp/x/y.jsonl"), SESSION, _turn_entries(1)), [])

    def test_cli_transcripts_report_nothing(self):
        # The CLI transcript records model_change and per-message models already.
        self.assertEqual(
            setup._backfill_session_models(Path("/tmp/x/events.jsonl"), SESSION, []), [])


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


class TestBackfillForceConfig(unittest.TestCase):
    def _config(self, code, payload):
        body = json.dumps(payload).encode("utf-8") if payload is not None else b"not json"
        with patch.object(setup, "_backfill_http_request", lambda *a, **k: (code, body)):
            return setup._backfill_force_config("key", "https://backend")

    def _epoch(self, code, payload):
        return self._config(code, payload)[0]

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

    def test_a_window_rides_with_the_request(self):
        self.assertEqual(
            self._config(200, {"force_backfill_requested_epoch": 1787893680,
                               "force_backfill_days": 45}),
            (1787893680.0, 45))

    def test_no_window_leaves_the_installer_default(self):
        # None, not 30: the caller owns the default, so an old backend behaves as before.
        for payload in ({"force_backfill_requested_epoch": 1787893680},
                        {"force_backfill_requested_epoch": 1787893680,
                         "force_backfill_days": None}):
            self.assertIsNone(self._config(200, payload)[1], payload)

    def test_an_unusable_window_is_ignored(self):
        # bool is an int subclass; 0 and negatives would reach back to the epoch.
        for bad in (True, False, 0, -5, "45", 45.5, [45], {"days": 45}):
            self.assertIsNone(
                self._config(200, {"force_backfill_requested_epoch": 1787893680,
                                   "force_backfill_days": bad})[1], bad)

    def test_a_window_without_a_request_is_never_returned(self):
        self.assertEqual(self._config(200, {"force_backfill_days": 45}), (None, None))


if __name__ == "__main__":
    unittest.main()


class TestForceWindow(unittest.TestCase):
    """How far back a forced re-walk reaches on a user-scope install. Without the org's
    window it cannot pass 30 days, so history an earlier backfill already reached is
    dropped and never revisited."""

    def _forced_cutoff(self, force_days):
        """The mtime floor a forced run actually walks from."""
        seen = {}

        def _capture(cutoff_mtime):
            seen["cutoff"] = cutoff_mtime
            return iter(())

        with patch.object(setup, "_copilot_home", lambda: Path("/tmp/nope")), \
                patch.object(setup, "_backfill_read_cutoff", lambda home: 0.0), \
                patch.object(setup, "_backfill_force_config",
                             lambda *a: (1e12, force_days)), \
                patch.object(setup, "_backfill_iter_transcripts", _capture), \
                patch.object(setup, "_backfill_write_cutoff", lambda *a: None):
            setup.run_backfill("key", "https://backend")
        return seen["cutoff"]

    def test_the_window_widens_the_walk(self):
        reach = time.time() - self._forced_cutoff(45)
        self.assertAlmostEqual(reach / 86400, 45, delta=1)

    def test_no_window_keeps_the_installer_default(self):
        reach = time.time() - self._forced_cutoff(None)
        self.assertAlmostEqual(reach / 86400, setup.BACKFILL_MAX_AGE_DAYS, delta=1)
