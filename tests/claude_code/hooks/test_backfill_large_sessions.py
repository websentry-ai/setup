"""Transcripts over one chunk are read and sent a slice at a time, up to the 1 GiB cap: cut exactly where a
transcript read whole is cut, resumed inside the file by the next MDM run, paced, and never held whole."""

import io
import json
import os
import tempfile
import time
import tracemalloc
import unittest
from contextlib import ExitStack, redirect_stdout
from pathlib import Path
from unittest.mock import patch

from tests.conftest import tool_module

mdm = tool_module("claude-code/hooks/mdm", "setup")
setup = tool_module("claude-code/hooks", "setup")
UPLOADERS = (mdm, setup)
SID = "11111111-2222-3333-4444-555555555555"


def _at(minute, second=0):
    return f"2026-09-01T10:{minute:02d}:{second:02d}.000Z"


def _write_transcript(path: Path, sizes, preamble=True):
    """A transcript of one exchange per size: a real prompt, then replies padded to about that many bytes."""
    lines = [{"type": "summary", "sessionId": SID, "summary": "s"}] if preamble else []
    for n, size in enumerate(sizes):
        lines.append({"type": "user", "sessionId": SID, "timestamp": _at(n), "isSidechain": False,
                      "message": {"role": "user", "content": f"ask {n}"}})
        for k in range(3):
            lines.append({"type": "assistant", "sessionId": SID, "timestamp": _at(n, 10 + k),
                          "message": {"id": f"msg_{n}_{k}", "role": "assistant", "content": "x" * (size // 3),
                                      "usage": {"input_tokens": 1, "output_tokens": 2}}})
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("".join(json.dumps(line) + "\n" for line in lines))
    return lines


def _subagents(count):
    """Subagent replies spread over the exchanges, one before them all, one after them all, and one with no time."""
    records = [{"type": "assistant", "timestamp": _at(n, 30), "isSidechain": True,
                "message": {"id": f"agent_{n}", "usage": {"output_tokens": n}}} for n in range(count)]
    records.append({"type": "assistant", "timestamp": "2026-09-01T09:00:00.000Z", "isSidechain": True,
                    "message": {"id": "agent_early", "usage": {"output_tokens": 1}}})
    records.append({"type": "assistant", "timestamp": "2026-09-01T23:00:00.000Z", "isSidechain": True,
                    "message": {"id": "agent_late", "usage": {"output_tokens": 1}}})
    records.append({"type": "assistant", "timestamp": None, "isSidechain": True,
                    "message": {"id": "agent_untimed", "usage": {"output_tokens": 1}}})
    return records


def _streamed(up, head, max_bytes):
    """Every slice _backfill_read_slice cuts, each from the resume point the one before returned."""
    pieces, resume = [], None
    while True:
        piece, resume = up._backfill_read_slice(head, resume, max_bytes)
        if piece:
            pieces.append(piece)
        if resume is None:
            return pieces


def _prompts(pieces):
    return [e["message"]["content"] for p in pieces for e in p["entries"]
            if e.get("type") == "user" and isinstance(e.get("message"), dict)]


class SliceReaderTestCase(unittest.TestCase):

    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.path = Path(tmp.name) / "projects" / "p" / f"{SID}.jsonl"

    def _head(self, records=()):
        head = {"session_id": SID, "transcript_path": str(self.path), "user_email": "a@b.co"}
        if records:
            head["subagents"] = list(records)
        return head

    def test_slices_match_a_transcript_read_whole_with_each_subagent_reply_once(self):
        sizes = [900, 2500, 300, 4000, 1200, 700, 3300, 150, 2000, 600, 2800, 1000]
        _write_transcript(self.path, sizes)
        records = _subagents(len(sizes))
        for up in UPLOADERS:
            for max_bytes in (9000, 14000, 30000):
                with self.subTest(up.__name__, max_bytes=max_bytes):
                    whole = dict(up._backfill_collect_session(self.path), subagents=records, user_email="a@b.co")
                    expected = list(up._backfill_slice_session(whole, max_bytes))
                    pieces = _streamed(up, self._head(records), max_bytes)
                    self.assertGreater(len(pieces), 1)
                    self.assertEqual(pieces, expected)
                    self.assertTrue(all(len(json.dumps(p).encode()) <= max_bytes for p in pieces))
                    sent = [r["message"]["id"] for p in pieces for r in p["subagents"]]
                    self.assertEqual(sorted(sent), sorted(r["message"]["id"] for r in records))

    def test_every_slice_size_byte_by_byte_cuts_where_the_whole_file_slicer_cuts(self):
        # One byte apart across more than an exchange, so some cut lands on each side of every budget edge.
        _write_transcript(self.path, [300, 900, 200, 1500, 400, 1100])
        records = _subagents(6)
        for up in UPLOADERS:
            whole = dict(up._backfill_collect_session(self.path), subagents=records, user_email="a@b.co")
            mismatched = [m for m in range(3000, 5200)
                          if _streamed(up, self._head(records), m) != list(up._backfill_slice_session(whole, m))]
            self.assertEqual(mismatched, [], up.__name__)

    def test_the_entry_cap_cuts_where_the_whole_file_slicer_cuts(self):
        _write_transcript(self.path, [100] * 20)
        for up in UPLOADERS:
            with self.subTest(up.__name__), patch.object(up, "BACKFILL_MAX_ENTRIES_PER_SLICE", 9):
                whole = dict(up._backfill_collect_session(self.path), user_email="a@b.co")
                pieces = _streamed(up, self._head(), 10 ** 6)
                self.assertEqual(pieces, list(up._backfill_slice_session(whole, 10 ** 6)))
                self.assertTrue(all(len(p["entries"]) <= 9 for p in pieces))

    def test_an_exchange_too_big_for_any_slice_is_skipped_and_the_rest_still_goes(self):
        _write_transcript(self.path, [500, 500, 50000, 500, 500])
        for up in UPLOADERS:
            with self.subTest(up.__name__):
                pieces = _streamed(up, self._head(), 4000)
                self.assertEqual(_prompts(pieces), ["ask 0", "ask 1", "ask 3", "ask 4"])
                # The skipped exchange's prompt still counts, so later turns keep their place in the session.
                after = next(p for p in pieces if "ask 3" in _prompts([p]))
                self.assertEqual((_prompts([after])[0], after["record_index_base"]), ("ask 3", 3))

    def test_a_resume_point_that_no_longer_starts_a_line_sends_the_file_from_the_top(self):
        _write_transcript(self.path, [800] * 6)
        for up in UPLOADERS:
            with self.subTest(up.__name__):
                first, nxt = up._backfill_read_slice(self._head(), None, 3000)
                again, _ = up._backfill_read_slice(self._head(), dict(nxt, offset=nxt["offset"] + 5), 3000)
                self.assertEqual(again, first)
                beyond, _ = up._backfill_read_slice(self._head(), dict(nxt, offset=10 ** 9), 3000)
                self.assertEqual(beyond, first)

    def test_a_line_longer_than_a_slice_is_never_held_whole(self):
        self.path.parent.mkdir(parents=True)
        with open(self.path, "wb") as f:
            f.write(json.dumps({"type": "summary", "sessionId": SID}).encode() + b"\n")
            f.write(b'{"type": "assistant", "pad": "' + b"y" * (40 << 20) + b'"}\n')
            f.write(json.dumps({"type": "user", "sessionId": SID, "timestamp": _at(1),
                                "message": {"role": "user", "content": "after"}}).encode() + b"\n")
        for up in UPLOADERS:
            with self.subTest(up.__name__):
                tracemalloc.start()
                try:
                    head = up._backfill_read_session(self.path)
                    pieces = _streamed(up, head, 1 << 20)
                    peak = tracemalloc.get_traced_memory()[1]
                finally:
                    tracemalloc.stop()
                self.assertEqual(head["session_id"], SID)
                self.assertEqual(_prompts(pieces), ["after"])
                self.assertLess(peak, 8 << 20)

    def test_a_transcript_over_one_chunk_is_read_as_a_head_with_its_subagent_usage(self):
        _write_transcript(self.path, [2000] * 4)
        for up in UPLOADERS:
            with self.subTest(up.__name__), patch.object(up, "BACKFILL_CHUNK_BYTES", 1000), \
                    patch.object(up, "_backfill_subagent_usage", return_value=_subagents(1)) as usage:
                head = up._backfill_read_session(self.path)
                self.assertEqual(set(head), {"session_id", "transcript_path", "file_id", "subagents"})
                self.assertEqual(usage.call_count, 1)

    def test_lines_that_once_broke_the_reader_are_skipped_and_the_rest_still_goes(self):
        lines = _write_transcript(self.path, [500] * 4)
        with open(self.path, "a") as f:
            f.write(json.dumps({"type": "user", "sessionId": SID, "message": "not an object"}) + "\n")
            f.write("[" * 1500 + "]" * 1500 + "\n")  # parsed, and too deep to decode
            f.write(json.dumps({"type": "user", "sessionId": SID, "timestamp": _at(9),
                                "message": {"role": "user", "content": "ask last"}}) + "\n")
        for up in UPLOADERS:
            with self.subTest(up.__name__):
                self.assertEqual(_prompts(_streamed(up, self._head(), 20000))[-1], "ask last")
                whole = up._backfill_collect_session(self.path)
                self.assertEqual(len(whole["entries"]), len(lines) + 2)  # the deep line alone fails to parse
                self.assertTrue(list(up._backfill_slice_session(whole, 2500)))

    def test_an_offset_past_the_end_of_the_file_sends_it_from_the_top(self):
        _write_transcript(self.path, [800] * 6)
        for up in UPLOADERS:
            with self.subTest(up.__name__):
                first, _ = up._backfill_read_slice(self._head(), None, 3000)
                for offset in (10 ** 30, 10 ** 9):
                    again, _ = up._backfill_read_slice(self._head(), {"offset": offset, "base": 0, "latest": None}, 3000)
                    self.assertEqual(again, first)

    def test_a_too_big_exchange_after_a_full_slice_is_passed_over_not_read_again(self):
        _write_transcript(self.path, [500, 500, 50000, 500, 500])
        raw = self.path.read_bytes()
        ask3 = raw.index(b'"content": "ask 3"')
        ask3 = raw.rindex(b"\n", 0, ask3) + 1
        for up in UPLOADERS:
            with self.subTest(up.__name__):
                piece, nxt = up._backfill_read_slice(self._head(), None, 4000)
                self.assertEqual(_prompts([piece]), ["ask 0", "ask 1"])
                self.assertEqual((nxt["offset"], nxt["base"]), (ask3, 3))

    def test_a_file_swapped_under_the_walk_is_not_read(self):
        _write_transcript(self.path, [2000] * 4)
        for up in UPLOADERS:
            with self.subTest(up.__name__), patch.object(up, "BACKFILL_CHUNK_BYTES", 1000):
                head = up._backfill_read_session(self.path)
                other = self.path.with_name("other.jsonl")
                _write_transcript(other, [2000] * 4)
                other.replace(self.path)  # same name, another file
                self.assertIsNone(up._backfill_read_slice(head, None, 3000))


def _fake_http(sessions, clock=None, put_seconds=0.0):
    def http(url, method, headers, body=None, timeout=30):
        if url.endswith("/upload-url/"):
            return 200, json.dumps({"upload_url": "https://s3/put", "object_key": "k"}).encode()
        if method == "PUT":
            sessions.extend(json.loads(body.decode("utf-8"))["sessions"])
            if clock is not None:
                clock[0] += put_seconds
        return 200, b"{}"
    return http


class RunBackfillTestCase(unittest.TestCase):
    """The real run_backfill of each uploader, the network faked at the HTTP layer."""

    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.home = Path(tmp.name)
        self.big = self.home / ".claude" / "projects" / "p" / f"{SID}.jsonl"
        self.lines = _write_transcript(self.big, [3000] * 12)
        small = self.home / ".claude" / "projects" / "p" / "small.jsonl"
        small.write_text(json.dumps({"type": "user", "sessionId": "small", "message": {"role": "user",
                                                                                     "content": "hi"}}) + "\n")

    def _patches(self, up, sessions):
        return [patch.object(up, "_backfill_http_request", side_effect=_fake_http(sessions)),
                patch.object(up, "_backfill_force_config", return_value=(None, None)),
                patch.object(up, "_backfill_account_email", return_value=None),
                patch.object(up, "get_device_identifier", return_value="SERIAL"),
                patch.object(up, "BACKFILL_CHUNK_BYTES", 8000),
                redirect_stdout(io.StringIO())]

    def _sent_entries(self, sessions):
        return [json.dumps(e, sort_keys=True) for s in sessions if s["session_id"] == SID for e in s["entries"]]

    def _expected(self):
        return [json.dumps(e, sort_keys=True) for e in self.lines]

    def test_user_level_sends_every_line_of_a_big_transcript_once_at_low_priority(self):
        sessions = []
        with ExitStack() as stack:
            for ctx in self._patches(setup, sessions):
                stack.enter_context(ctx)
            stack.enter_context(patch.object(setup.Path, "home", return_value=self.home))
            nice = stack.enter_context(patch.object(setup.os, "nice"))
            usage = stack.enter_context(
                patch.object(setup, "_backfill_subagent_usage", wraps=setup._backfill_subagent_usage))
            setup.run_backfill("key", "https://backend", self.home / ".claude")
        nice.assert_called_once_with(19)
        self.assertEqual(self._sent_entries(sessions), self._expected())
        self.assertEqual({s["session_id"] for s in sessions}, {SID, "small"})
        self.assertTrue(all("transcript_path" not in s for s in sessions))
        self.assertTrue(all(s.get("device_serial") == "SERIAL" for s in sessions))
        self.assertEqual(usage.call_count, 2)  # once per transcript, not once per slice
        self.assertTrue((self.home / ".claude" / "hooks" / ".unbound_last_backfill").exists())

    def _mdm_run(self, sessions, slices_this_run):
        """One MDM run that has time for slices_this_run batches or slices, then reaches its soft stop."""
        budget = iter([True] * slices_this_run + [False] * 100)
        with ExitStack() as stack:
            for ctx in self._patches(mdm, sessions):
                stack.enter_context(ctx)
            stack.enter_context(patch.object(mdm, "_run_as_user", side_effect=lambda u, fn, *a, **k: fn(*a, **k)))
            stack.enter_context(patch.object(mdm._BackfillRun, "has_time_for_a_batch",
                                             side_effect=lambda: next(budget)))
            mdm.run_backfill("key", "https://backend", [("alice", self.home)])

    def _state(self):
        return json.loads((self.home / ".claude" / "hooks" / ".unbound_last_backfill").read_text())

    def _resume(self):
        return json.loads((self.home / ".claude" / "hooks" / ".unbound_backfill_resume").read_text())[str(self.big)]

    def _bases(self, sessions):
        return [s["record_index_base"] for s in sessions if s["session_id"] == SID]

    def _append(self, n):
        extra = [{"type": "user", "sessionId": SID, "timestamp": _at(50 + n), "message": {"role": "user",
                                                                                         "content": f"more {n}"}}]
        with open(self.big, "a") as f:
            f.write("".join(json.dumps(line) + "\n" for line in extra))
        self.lines += extra

    def test_mdm_resumes_inside_the_file_on_the_next_run_and_sends_each_line_once(self):
        sessions = []
        self._mdm_run(sessions, 3)
        self.assertGreater(self._resume()["offset"], 0)
        part = len(self._sent_entries(sessions))
        self.assertTrue(0 < part < len(self.lines))

        self._mdm_run(sessions, 100)
        self.assertEqual(self._sent_entries(sessions), self._expected())
        self.assertIsInstance(self._state(), float)
        self.assertTrue(all("transcript_path" not in s for s in sessions))
        self.assertEqual([s["session_id"] for s in sessions].count("small"), 1)

    def test_another_batch_saving_progress_keeps_the_resume_point(self):
        sessions = []
        self._mdm_run(sessions, 3)
        sent_bases = self._bases(sessions)
        # Another transcript changes first, so a batch of it lands, and saves progress, before this file resumes.
        later = self.home / ".claude" / "projects" / "p" / "later.jsonl"
        later.write_text(json.dumps({"type": "user", "sessionId": "later"}) + "\n")
        time.sleep(0.01)
        self._append(1)
        sessions.clear()
        self._mdm_run(sessions, 100)
        self.assertIn("later", [s["session_id"] for s in sessions])
        self.assertFalse(set(self._bases(sessions)) & set(sent_bases))

    def test_an_append_to_a_sent_file_sends_its_last_slice_onward_not_the_file(self):
        sessions = []
        self._mdm_run(sessions, 100)
        bases = self._bases(sessions)
        self._append(2)
        sessions.clear()
        self._mdm_run(sessions, 100)
        self.assertEqual(self._bases(sessions)[0], bases[-1])
        self.assertEqual(self._sent_entries(sessions)[-1], json.dumps(self.lines[-1], sort_keys=True))

    def test_a_forced_walk_sends_the_whole_file_whatever_an_earlier_walk_saved(self):
        sessions = []
        self._mdm_run(sessions, 100)
        sessions.clear()
        os.utime(self.big)
        with patch.object(mdm, "_backfill_force_config", return_value=(time.time(), None)):
            budget = iter([True] * 100)
            with ExitStack() as stack:
                for ctx in self._patches(mdm, sessions)[2:]:
                    stack.enter_context(ctx)
                stack.enter_context(patch.object(mdm, "_backfill_http_request", side_effect=_fake_http(sessions)))
                stack.enter_context(patch.object(mdm, "_run_as_user", side_effect=lambda u, fn, *a, **k: fn(*a, **k)))
                stack.enter_context(patch.object(mdm._BackfillRun, "has_time_for_a_batch",
                                                 side_effect=lambda: next(budget)))
                mdm.run_backfill("key", "https://backend", [("alice", self.home)])
        self.assertEqual(self._bases(sessions)[0], 0)
        self.assertEqual(self._sent_entries(sessions), self._expected())

    def test_mdm_starts_a_replaced_file_over(self):
        sessions = []
        self._mdm_run(sessions, 3)
        self.lines = _write_transcript(self.big, [2500] * 10)  # rewritten: the saved offset lands mid-line
        sessions.clear()
        self._mdm_run(sessions, 100)
        self.assertEqual(self._sent_entries(sessions), self._expected())

    def test_a_head_in_a_batch_is_streamed_never_sent_as_a_session(self):
        with patch.object(mdm, "BACKFILL_CHUNK_BYTES", 8000):
            head = mdm._backfill_read_session(self.big)
        uploaded = []
        with patch.object(mdm, "_run_as_user", side_effect=lambda u, fn, *a, **k: fn(*a, **k)), \
                patch.object(mdm, "_backfill_collect_sessions",
                             return_value=([{"session_id": "small", "entries": [{}]}, head], False, False)), \
                patch.object(mdm, "_backfill_send_sessions",
                             side_effect=lambda k, u, s, f=False: uploaded.extend(s) or (len(s), 1, 0)), \
                patch.object(mdm, "BACKFILL_CHUNK_BYTES", 8000), \
                patch.object(mdm._BackfillRun, "has_time_for_a_batch", return_value=True):
            run = mdm._BackfillRun("key", "https://backend", "SERIAL", (None, None), time.time())
            sent, _, status = mdm._backfill_drain_home(run, ("alice", self.home))
        self.assertEqual(status, "done")
        self.assertTrue(all("transcript_path" not in s for s in uploaded))
        self.assertEqual(self._sent_entries(uploaded), self._expected())


class PacingTestCase(unittest.TestCase):

    def test_each_upload_rests_as_long_as_its_put_took_and_at_most_30s(self):
        for up in UPLOADERS:
            for put_seconds, rest in ((7.0, 7.0), (100.0, 30)):
                with self.subTest(up.__name__, put_seconds=put_seconds):
                    clock, sessions = [1000.0], []
                    with patch.object(up, "_backfill_http_request",
                                      side_effect=_fake_http(sessions, clock, put_seconds)), \
                            patch.object(up.time, "time", side_effect=lambda: clock[0]), \
                            patch.object(up.time, "sleep") as sleep:
                        self.assertTrue(up._backfill_upload_chunk("key", "https://backend", [{"session_id": "s"}]))
                    sleep.assert_called_once_with(rest)


if __name__ == "__main__":
    unittest.main()
