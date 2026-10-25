"""The backfill uploads transcripts of any size up to 1 GiB, and reports the ones it cannot.

A transcript used to be read whole, so anything over 50 MB was skipped: on a heavy
user's laptop that left 88% of the tokens behind. A transcript bigger than one chunk is
now read line by line and sent a slice at a time, cut where a transcript read whole is
cut. The server keeps only the first 10,000 entries of an upload, so no slice carries
more. An MDM run that stops inside a transcript carries on there next run. Every upload
says how many transcripts the walk saw, and which it had to leave behind.
"""

import io
import json
import os
import random
import shutil
import tempfile
import time
import types
import unittest
import weakref
from contextlib import redirect_stdout
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch

from tests.conftest import tool_module

mdm = tool_module("claude-code/hooks/mdm", "setup")
setup = tool_module("claude-code/hooks", "setup")
uploaders = (mdm, setup)
CASES = Path(__file__).resolve().parents[2] / "fixtures" / "claude_code_usage" / "cases"
IDENTITY = {"device_serial": "SERIAL", "user_email": "alice@example.com"}


def _stamp(t):
    return t.strftime("%Y-%m-%dT%H:%M:%S.000Z")


def _write_transcript(path, seed, exchanges, pad=150, agents=True):
    """A transcript shaped like Claude Code's: leading lines with no session or time, then
    exchanges mixing replies, tool results, subagent prompts, progress, blank and broken
    lines. With agents, subagent usage under <session>/subagents/, some of it after every
    turn and some with no time at all."""
    rng = random.Random(seed)
    sid = "sess-%d" % seed
    t = datetime(2026, 9, 1, 10, 0, tzinfo=timezone.utc)
    first = t
    lines = [json.dumps({"type": "summary", "summary": "earlier"}), json.dumps({"type": "file-history-snapshot"})]

    def line(kind, content, role, **extra):
        nonlocal t
        t += timedelta(seconds=rng.randint(1, 20))
        lines.append(json.dumps(dict({"type": kind, "timestamp": _stamp(t), "sessionId": sid,
                                      "message": {"role": role, "content": content}}, **extra)))

    for i in range(exchanges):
        line("user", rng.choice(["prompt %d %s" % (i, "é" * rng.randint(0, 9)),
                                 [{"type": "text", "text": "prompt %d" % i}],
                                 [{"type": "image", "source": {}}]]), "user")
        for _ in range(rng.randint(0, 6)):
            roll = rng.random()
            if roll < 0.5:
                line("assistant", [{"type": "text", "text": "x" * rng.randint(0, pad)}], "assistant",
                     uuid="a%d" % rng.randint(0, 1 << 30))
            elif roll < 0.7:
                line("user", [{"type": "tool_result", "tool_use_id": "t", "content": "ok"}], "user")
            elif roll < 0.8:
                line("user", "subtask", "user", isSidechain=True)
            elif roll < 0.9:
                line("progress", "working", "assistant")
            else:
                lines.append(rng.choice(["", "{not json", "   "]))
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    if agents:
        subdir = path.with_suffix("") / "subagents"
        subdir.mkdir(parents=True)
        span = max(1, int((t - first).total_seconds()))
        replies = []
        for n in range(max(3, exchanges // 2)):
            at = first + timedelta(seconds=rng.randint(-60, span + 120))
            replies.append({"type": "assistant", "timestamp": _stamp(at), "isSidechain": True,
                            "message": {"id": "msg_%d_%d" % (seed, n), "usage": {"input_tokens": n, "output_tokens": 1}}})
        replies.append({"type": "assistant", "isSidechain": True,
                        "message": {"id": "msg_untimed_%d" % seed, "usage": {"input_tokens": 1}}})
        (subdir / "agent-a.jsonl").write_text("\n".join(json.dumps(r) for r in replies) + "\n")
    return sid


def _streamed(up, path, max_bytes, identity=None, resume=None):
    session = dict(identity or {}, session_id=up._backfill_first_session_id(path), transcript_path=path)
    return list(up._backfill_stream_session(session, max_bytes, resume))


def _read_whole(up, path, max_bytes, identity=None):
    session = up._backfill_collect_session(path)
    session.update(identity or {})
    return list(up._backfill_slice_session(session, max_bytes))


def _transcripts(root):
    """Generated transcripts of several shapes, plus every usage fixture."""
    paths = []
    for seed, exchanges, agents in ((1, 40, True), (2, 120, True), (3, 25, False), (4, 1, True), (5, 300, True)):
        path = root / ("gen-%d" % seed) / ("gen-%d.jsonl" % seed)
        path.parent.mkdir(parents=True)
        _write_transcript(path, seed, exchanges, agents=agents)
        paths.append(path)
    for case in sorted(CASES.iterdir()):
        shutil.copytree(case, root / case.name)
        paths.extend(sorted(p for p in (root / case.name).glob("*.jsonl")))
    return paths


class StreamingMatchesTheWholeFileSlicerTestCase(unittest.TestCase):
    """The oracle: for any transcript small enough to read whole, streaming it must give
    exactly the slices _backfill_slice_session cuts from it, whatever the caps."""

    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.paths = _transcripts(Path(tmp.name))

    def _limits(self, up, path, identity):
        whole = len(json.dumps(dict(up._backfill_collect_session(path), **(identity or {}))).encode("utf-8"))
        # Fits whole; just misses; a few slices; many slices; so small an exchange cannot fit.
        return sorted({whole + 50, whole, whole - 1, whole // 3, whole // 10, 1500})

    def test_streamed_slices_equal_the_slices_of_the_file_read_whole(self):
        for up in uploaders:
            for path in self.paths:
                for identity in (None, IDENTITY):
                    for cap in (up.BACKFILL_MAX_ENTRIES_PER_SLICE, 7):
                        for limit in self._limits(up, path, identity):
                            with self.subTest(up.__name__, file=path.name, identity=bool(identity), cap=cap,
                                              limit=limit), patch.object(up, "BACKFILL_MAX_ENTRIES_PER_SLICE", cap):
                                expected = _read_whole(up, path, limit, identity)
                                got = [piece for piece, _ in _streamed(up, path, limit, identity)]
                                self.assertEqual(got, expected)

    def test_the_oracle_is_not_vacuous(self):
        # The generated transcripts must actually be cut, carry subagent usage, and reach the
        # cases where a slice is too small for an exchange.
        up = mdm
        path = self.paths[1]
        slices = _read_whole(up, path, 4000, IDENTITY)
        self.assertGreater(len(slices), 5)
        self.assertTrue(any(s.get("subagents") for s in slices))
        self.assertGreater(slices[-1]["record_index_base"], 0)
        cut_short = _read_whole(up, path, 1500)
        self.assertLess(sum(len(s["entries"]) for s in cut_short), len(up._backfill_collect_session(path)["entries"]))

    def test_streaming_resumes_at_any_slice(self):
        """Started from the point any slice hands back, the stream gives exactly the slices
        that follow it, with the same record_index_base and subagent usage."""
        for up in uploaders:
            for path in self.paths:
                limit = max(1500, len(json.dumps(up._backfill_collect_session(path)).encode("utf-8")) // 8)
                with self.subTest(up.__name__, file=path.name):
                    full = _streamed(up, path, limit, IDENTITY)
                    for k, (_, nxt) in enumerate(full):
                        if nxt is None:
                            continue
                        rest = [piece for piece, _ in _streamed(up, path, limit, IDENTITY, resume=nxt)]
                        self.assertEqual(rest, [piece for piece, _ in full[k + 1:]])


class _Tracked(dict):
    """A transcript entry whose lifetime a test can watch."""
    __hash__ = object.__hash__


class StreamingMemoryTestCase(unittest.TestCase):

    def test_streaming_holds_about_one_slice_whatever_the_file_size(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        path = Path(tmp.name) / "big.jsonl"
        _write_transcript(path, 9, 4000, pad=600)
        self.assertGreater(path.stat().st_size, 3 * 1024 * 1024)
        for up in uploaders:
            with self.subTest(up.__name__):
                live, peak = weakref.WeakSet(), [0]

                def loads(text, **kwargs):
                    value = json.loads(text, **kwargs)
                    if isinstance(value, dict) and "sessionId" in value:
                        value = _Tracked(value)
                        live.add(value)
                        peak[0] = max(peak[0], len(live))
                    return value

                shim = types.SimpleNamespace(loads=loads, dumps=json.dumps, JSONDecodeError=json.JSONDecodeError)
                sizes, total = [], 0
                session = {"session_id": "sess-9", "transcript_path": path}
                with patch.object(up, "json", shim):
                    for piece, _ in up._backfill_stream_session(session, 32 * 1024):
                        sizes.append(len(piece["entries"]))
                        total += len(piece["entries"])
                        del piece
                # Thousands of entries went up; never more than one slice and the exchange after it at once.
                self.assertGreater(total, 40 * max(sizes))
                self.assertLessEqual(peak[0], max(sizes) + 20)


def _session_of(entries, sid="S"):
    return {"session_id": sid, "entries": entries}


def _prompt(i):
    return {"type": "user", "sessionId": "S", "message": {"role": "user", "content": "prompt %d" % i}}


def _reply(i):
    return {"type": "assistant", "sessionId": "S", "n": i}


class EntryCapTestCase(unittest.TestCase):
    """The server keeps only the first 10,000 entries of an upload; the rest of a bigger one
    vanished without a trace."""

    def _exchanges(self, lengths):
        entries = []
        for i, n in enumerate(lengths):
            entries.append(_prompt(i))
            entries.extend(_reply(j) for j in range(n - 1))
        return entries

    def test_a_small_session_over_the_entry_cap_is_cut_at_exchanges(self):
        entries = self._exchanges([3000] * 4 + [500])  # 12,500 tiny entries, well under one chunk
        for up in uploaders:
            with self.subTest(up.__name__):
                slices = list(up._backfill_slice_session(_session_of(entries), up.BACKFILL_CHUNK_BYTES))
                self.assertEqual([len(s["entries"]) for s in slices], [9000, 3500])
                self.assertEqual([s["record_index_base"] for s in slices], [0, 3])
                self.assertEqual([e for s in slices for e in s["entries"]], entries)

    def test_an_exchange_longer_than_the_cap_goes_alone_instead_of_ending_the_session(self):
        entries = self._exchanges([5, 10500, 5])
        for up in uploaders:
            with self.subTest(up.__name__):
                slices = list(up._backfill_slice_session(_session_of(entries), up.BACKFILL_CHUNK_BYTES))
                self.assertEqual([len(s["entries"]) for s in slices], [5, 10500, 5])
                self.assertEqual([s["record_index_base"] for s in slices], [0, 1, 2])

    def test_a_slice_cut_again_keeps_its_place_in_the_session(self):
        # The MDM send path runs every slice through _backfill_slice_session once more; one
        # that no longer fits (a lone exchange over the entry cap, or a tighter limit) is cut
        # again, and its pieces must keep counting from where the slice sat in the session.
        for up in uploaders:
            with self.subTest(up.__name__):
                piece = dict(_session_of(self._exchanges([10500, 3])), record_index_base=7)
                again = list(up._backfill_slice_session(piece, up.BACKFILL_CHUNK_BYTES))
                self.assertEqual([(s["record_index_base"], len(s["entries"])) for s in again], [(7, 10500), (8, 3)])
                small = dict(_session_of(self._exchanges([3, 3])), record_index_base=7)
                limit = len(json.dumps(small).encode("utf-8")) - 1
                self.assertEqual([s["record_index_base"] for s in up._backfill_slice_session(small, limit)], [7, 8])

    def test_a_session_under_the_cap_is_sent_as_before(self):
        entries = self._exchanges([4000, 6000])
        for up in uploaders:
            with self.subTest(up.__name__):
                session = _session_of(entries)
                self.assertEqual(list(up._backfill_slice_session(session, up.BACKFILL_CHUNK_BYTES)), [session])


def _fake_http(bodies):
    def http(url, method, headers, body=None, timeout=30):
        if url.endswith("/upload-url/"):
            return 200, json.dumps({"upload_url": "https://s3/put", "object_key": "k"}).encode()
        if method == "PUT":
            bodies.append(json.loads(body.decode("utf-8")))
        return 200, b"{}"
    return http


def _home(test):
    home = Path(tempfile.mkdtemp())
    test.addCleanup(shutil.rmtree, home)
    projects = home / ".claude" / "projects" / "p"
    projects.mkdir(parents=True)
    return home, projects


def _run(up, home, chunk_bytes=None, batch_bytes=None, max_file=None):
    """The real run_backfill of either uploader over one home, the network faked at the HTTP
    layer. Returns the JSON bodies uploaded."""
    bodies = []
    stack = [patch.object(up, "_backfill_http_request", side_effect=_fake_http(bodies)),
             patch.object(up, "_backfill_force_config", return_value=(None, None)),
             patch.object(up, "_backfill_account_email", return_value="alice@example.com"),
             patch.object(up, "get_device_identifier", return_value="SERIAL"),
             redirect_stdout(io.StringIO())]
    for name, value in (("BACKFILL_CHUNK_BYTES", chunk_bytes), ("BACKFILL_BATCH_BYTES", batch_bytes if up is mdm else None),
                        ("BACKFILL_MAX_FILE_BYTES", max_file)):
        if value is not None:
            stack.append(patch.object(up, name, value))
    if up is mdm:
        stack.append(patch.object(mdm, "_run_as_user", side_effect=lambda u, fn, *a, **k: fn(*a, **k)))
    else:
        stack.append(patch.object(setup.Path, "home", return_value=home))
    for ctx in stack:
        ctx.__enter__()
    try:
        if up is mdm:
            mdm.run_backfill("key", "https://backend", [("alice", home)])
        else:
            setup.run_backfill("key", "https://backend", home / ".claude")
    finally:
        for ctx in reversed(stack):
            ctx.__exit__(None, None, None)
    return bodies


def _sent(bodies):
    return [s for body in bodies for s in body["sessions"]]


class LargeTranscriptUploadTestCase(unittest.TestCase):

    def test_a_transcript_over_50_mb_is_uploaded_whole_in_slices(self):
        home, projects = _home(self)
        path = projects / "huge.jsonl"
        pad = "y" * (52 * 1024)
        with open(path, "w", encoding="utf-8") as f:
            for i in range(1040):
                kind = "user" if i % 10 == 0 else "assistant"
                f.write(json.dumps({"type": kind, "sessionId": "huge", "i": i, "pad": pad,
                                    "message": {"role": kind, "content": "go %d" % i}}) + "\n")
        self.assertGreater(path.stat().st_size, 50 * 1024 * 1024)
        for up in uploaders:
            with self.subTest(up.__name__):
                sent = _sent(_run(up, home, chunk_bytes=4 * 1024 * 1024, batch_bytes=12 * 1024 * 1024))
                self.assertEqual([e["i"] for s in sent for e in s["entries"]], list(range(1040)))
                self.assertEqual([s["record_index_base"] for s in sent], _bases(sent))
                self.assertTrue(all(s["device_serial"] == "SERIAL" and s["user_email"] == "alice@example.com"
                                    for s in sent))
                self.assertGreater(len(sent), 12)
                _reset_state(home)

    def test_a_streamed_transcript_matches_the_file_read_whole_end_to_end(self):
        home, projects = _home(self)
        path = projects / "big.jsonl"
        _write_transcript(path, 11, 400)
        chunk = path.stat().st_size // 6
        for up in uploaders:
            with self.subTest(up.__name__):
                expected = _read_whole(up, path, chunk, IDENTITY)
                self.assertGreater(len(expected), 3)
                self.assertEqual(_sent(_run(up, home, chunk_bytes=chunk, batch_bytes=10 ** 9)), expected)
                _reset_state(home)

    def test_normal_sessions_are_sent_exactly_as_before(self):
        home, projects = _home(self)
        for case in ("subagent_files", "multiline_replies"):
            shutil.copytree(CASES / case, projects / case)
        paths = sorted(projects.glob("*/*.jsonl"))
        for up in uploaders:
            with self.subTest(up.__name__):
                expected = sorted((dict(up._backfill_collect_session(p), **IDENTITY) for p in paths),
                                  key=lambda s: s["session_id"])
                sent = sorted(_sent(_run(up, home)), key=lambda s: s["session_id"])
                self.assertEqual(sent, expected)
                _reset_state(home)


def _bases(sent):
    bases, base = [], 0
    for s in sent:
        bases.append(base)
        base += sum(1 for e in s["entries"] if e["type"] == "user")
    return bases


def _reset_state(home):
    """Forget the last run, so the next uploader walks the same history."""
    state = home / ".claude" / "hooks" / mdm.BACKFILL_STATE_FILE
    if state.exists():
        state.unlink()


class MdmResumeInsideATranscriptTestCase(unittest.TestCase):
    """A run that stops part-way through a big transcript carries on at its next unsent
    slice next run, instead of skipping the rest or starting it over."""

    def setUp(self):
        self.home, projects = _home(self)
        self.path = projects / "big.jsonl"
        _write_transcript(self.path, 21, 500)
        self.chunk = self.path.stat().st_size // 12
        self.expected = _read_whole(mdm, self.path, self.chunk, IDENTITY)
        self.assertGreater(len(self.expected), 8)

    def _run(self, stop_after=None):
        """One MDM run, soft-stopping once stop_after batches have landed."""
        landed = {"n": 0}
        real_send = mdm._backfill_send_sessions

        def send(api_key, backend_url, sessions, forced=False):
            result = real_send(api_key, backend_url, sessions, forced)
            landed["n"] += 1
            if stop_after is not None and landed["n"] >= stop_after:
                mdm._SCRIPT_START -= mdm.BACKFILL_SOFT_STOP_SECONDS
            return result

        with patch.object(mdm, "_SCRIPT_START", time.time()), \
                patch.object(mdm, "_backfill_send_sessions", side_effect=send):
            return _sent(_run(mdm, self.home, chunk_bytes=self.chunk, batch_bytes=self.chunk * 3))

    def test_the_next_run_continues_at_the_next_slice(self):
        first = self._run(stop_after=1)
        self.assertTrue(0 < len(first) < len(self.expected))
        self.assertEqual(first, self.expected[:len(first)])
        state = mdm._backfill_read_state(self.home)
        self.assertEqual(state["cursor_resume"]["path"], str(self.path))
        self.assertEqual(state["cursor_resume"]["record_index_base"],
                         self.expected[len(first)]["record_index_base"])
        rest = self._run()
        self.assertEqual(first + rest, self.expected)
        self.assertIsNone(mdm._backfill_read_state(self.home)["cursor"])

    def test_a_replaced_transcript_starts_over(self):
        first = self._run(stop_after=1)
        copy = self.path.with_name("copy.tmp")
        shutil.copy2(self.path, copy)
        os.replace(copy, self.path)  # same content, new inode: not the file that was cut
        again = self._run()
        self.assertEqual(again, self.expected)
        self.assertEqual(again[0]["record_index_base"], 0)
        self.assertGreater(len(first), 0)

    def test_a_truncated_transcript_starts_over(self):
        self._run(stop_after=1)
        offset = mdm._backfill_read_state(self.home)["cursor_resume"]["offset"]
        with open(self.path, "r+b") as f:
            f.truncate(offset - 1)
        again = self._run()
        self.assertEqual(again[0]["record_index_base"], 0)

    def test_older_state_files_still_load(self):
        hooks = self.home / ".claude" / "hooks"
        hooks.mkdir(parents=True, exist_ok=True)
        state = hooks / mdm.BACKFILL_STATE_FILE
        old = time.time() - 3600
        for text in (str(old), json.dumps({"cursor": old, "cursor_path": "/x", "force_epoch": None,
                                            "completed_at": None}),
                     json.dumps({"cursor": old, "cursor_path": "/x", "cursor_resume": {"path": 3}})):
            with self.subTest(text=text[:40]):
                state.write_text(text)
                loaded = mdm._backfill_read_state(self.home)
                self.assertIsNone(loaded["cursor_resume"])
                position, _ = mdm._backfill_walk_start(loaded, None, None)
                self.assertEqual(len(position), 2)


class UploaderStatsTestCase(unittest.TestCase):
    """Every upload reports what the walk saw and what it had to leave behind."""

    def setUp(self):
        self.home, projects = _home(self)
        for name, size in (("a", 100), ("b", 200)):
            (projects / ("%s.jsonl" % name)).write_text(
                json.dumps({"type": "user", "sessionId": name, "pad": "x" * size}) + "\n")
        (projects / "big1.jsonl").write_text(json.dumps({"sessionId": "big1", "pad": "x" * 5000}) + "\n")
        (projects / "big2.jsonl").write_text(json.dumps({"sessionId": "big2", "pad": "x" * 9000}) + "\n")
        (projects / "nosession.jsonl").write_text(json.dumps({"type": "summary"}) + "\n")
        (projects / "garbage.jsonl").write_bytes(b"\xff\xfe\x00 not utf-8\n")
        # Not transcripts of their own: never counted.
        (projects / ".hidden.jsonl").write_text(json.dumps({"sessionId": "h"}) + "\n")
        (projects / "a" / "subagents").mkdir(parents=True)
        (projects / "a" / "subagents" / "agent-x.jsonl").write_text(json.dumps({"sessionId": "a"}) + "\n")
        self.big = sorted(len((projects / n).read_bytes()) for n in ("big1.jsonl", "big2.jsonl"))

    def test_every_upload_carries_the_run_stats_and_over_cap_files_are_not_sent(self):
        for up in uploaders:
            with self.subTest(up.__name__):
                # A tiny chunk puts each session in an upload of its own.
                bodies = _run(up, self.home, chunk_bytes=400, max_file=1000)
                _reset_state(self.home)
                self.assertEqual(sorted(s["session_id"] for s in _sent(bodies)), ["a", "b"])
                self.assertEqual(len(bodies), 2)
                expected = {"files_seen": 6,
                            "skipped_over_cap": {"count": 2, "largest_bytes": self.big[1],
                                                 "total_bytes": sum(self.big)},
                            "unreadable": 2}
                for body in bodies:
                    self.assertEqual(body["uploader_stats"], expected)
                    self.assertEqual(set(body), {"tool_type", "sessions", "uploader_stats"})

    def test_mdm_stats_cover_every_profile_of_the_run(self):
        other, projects = _home(self)
        (projects / "c.jsonl").write_text(json.dumps({"type": "user", "sessionId": "c"}) + "\n")
        bodies = []
        with patch.object(mdm, "_backfill_http_request", side_effect=_fake_http(bodies)), \
                patch.object(mdm, "_backfill_force_config", return_value=(None, None)), \
                patch.object(mdm, "_backfill_account_email", return_value=None), \
                patch.object(mdm, "get_device_identifier", return_value="SERIAL"), \
                patch.object(mdm, "BACKFILL_MAX_FILE_BYTES", 1000), \
                patch.object(mdm, "_run_as_user", side_effect=lambda u, fn, *a, **k: fn(*a, **k)), \
                redirect_stdout(io.StringIO()):
            mdm.run_backfill("key", "https://backend", [("alice", self.home), ("bob", other)])
        self.assertEqual({json.dumps(b["uploader_stats"], sort_keys=True) for b in bodies},
                         {json.dumps({"files_seen": 7, "unreadable": 2,
                                      "skipped_over_cap": {"count": 2, "largest_bytes": self.big[1],
                                                           "total_bytes": sum(self.big)}}, sort_keys=True)})
        self.assertEqual(sorted(s["session_id"] for s in _sent(bodies)), ["a", "b", "c"])


if __name__ == "__main__":
    unittest.main()
