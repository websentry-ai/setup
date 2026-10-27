"""The skip counts across many shapes of history: the readable-or-not peek against the collector over generated
transcripts, the walk counts over generated homes, how the counts ride each uploader's run, and that the
sessions uploaded are the ones the uploader sent before it counted anything."""

import importlib.util
import io
import json
import os
import random
import shutil
import subprocess
import sys
import tempfile
import time
import tracemalloc
import unittest
from contextlib import ExitStack, redirect_stdout
from pathlib import Path
from unittest import mock
from unittest.mock import patch

from tests.conftest import REPO, tool_module

mdm = tool_module("claude-code/hooks/mdm", "setup")
setup = tool_module("claude-code/hooks", "setup")
uploaders = (mdm, setup)
CAP_LINES, CAP_BYTES = 6, 400
# The uploader before it counted anything: #402 as it landed on staging.
BEFORE_STATS = "8f78e6071f8cedb32baa13bc5858e9fbcb3c68b3"
JUNCTION_TAG = 0xA0000003


def _line(entry) -> bytes:
    return (json.dumps(entry) + "\n").encode()


def _id_line(sid, rng) -> bytes:
    return _line({"type": "user", rng.choice(("sessionId", "session_id")): sid})


def _filler(rng, n) -> bytes:
    return b"".join(_line({"type": "summary", "n": rng.randint(0, 9)}) for _ in range(n))


# Each class: (bytes of a transcript, the session id it holds). The peek and the collector must agree on all but
# the last, which is the documented gap.
def _valid(rng, sid):
    return _filler(rng, rng.randint(0, CAP_LINES - 2)) + _id_line(sid, rng) + _filler(rng, rng.randint(0, 3))


def _blank_first(rng, sid):
    return b"".join(rng.choice((b"\n", b"   \n", b"\t\n")) for _ in range(rng.randint(1, CAP_LINES - 1))) \
        + _id_line(sid, rng)


def _bad_json_first(rng, sid):
    junk = (b"{not json\n", b"]]\n", b'{"a": \n', b"nul\n")
    return b"".join(rng.choice(junk) for _ in range(rng.randint(1, CAP_LINES - 1))) + _id_line(sid, rng)


def _array_first(rng, sid):
    return rng.choice((b"[1, 2]\n", b'"text"\n', b"5\n", b"null\n")) + _id_line(sid, rng)


def _id_after_cap(rng, sid):
    return _filler(rng, CAP_LINES + rng.randint(0, 2)) + _id_line(sid, rng)


def _no_id(rng, sid):
    return _filler(rng, rng.randint(0, CAP_LINES + 2)) + _line({"type": "user", "sessionId": ""})


def _utf8_before(rng, sid):
    return _filler(rng, rng.randint(0, 2)) + b"\xff\xfe broken\n" + _id_line(sid, rng)


def _utf8_just_after(rng, sid):
    # Inside the first block the reader decodes, so the peek meets it too.
    return _id_line(sid, rng) + b"\xc3\x28 broken\n"


def _utf8_far_after(rng, sid):
    # Past the first decoded block but inside the line cap: only the collector reads that far.
    return _id_line(sid, rng) + _line({"type": "summary", "pad": "x" * rng.randint(20_000, 60_000)}) \
        + b"\xff broken\n"


AGREEING = (_valid, _blank_first, _bad_json_first, _array_first, _id_after_cap, _no_id, _utf8_before,
            _utf8_just_after)
CLASSES = AGREEING + (_utf8_far_after,)


# The size bands as the spec states them, by upper bound, written out apart from the code under test.
BANDS = (("under_100mb", 100 << 20), ("under_250mb", 250 << 20), ("under_500mb", 500 << 20), ("under_1gb", 1 << 30),
         ("1gb_or_more", None))


def _by_size(sizes):
    bands = {name: {"count": 0, "total_bytes": 0} for name, _ in BANDS}
    for size in sizes:
        band = bands[next(name for name, upper in BANDS if upper is None or size < upper)]
        band["count"] += 1
        band["total_bytes"] += size
    return bands

class PeekMatchesCollectorTestCase(unittest.TestCase):
    """A4: over 150 seeded transcripts, the peek finds a session id exactly when the collector files one."""

    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        rng, folder = random.Random(4), Path(tmp.name)
        self.cases = []
        for n in range(150):
            # Every class at least once, then at random.
            kind = CLASSES[n] if n < len(CLASSES) else rng.choice(CLASSES)
            path = folder / f"t{n}.jsonl"
            path.write_bytes(kind(rng, f"s{n}"))
            self.cases.append((kind, path, f"s{n}"))

    def test_the_peek_agrees_with_the_collector(self):
        for up in uploaders:
            with patch.object(up, "BACKFILL_MAX_LINES_PER_FILE", CAP_LINES):
                for kind, path, sid in self.cases:
                    if kind is _utf8_far_after:
                        continue
                    with self.subTest(up.__name__, kind=kind.__name__, path=path.name):
                        session = up._backfill_collect_session(path)
                        peeked = up._backfill_first_session_id(path)
                        self.assertEqual(peeked, session and session["session_id"])
                        self.assertEqual(peeked is not None, kind in (_valid, _blank_first, _bad_json_first))

    def test_bad_utf8_past_the_peek_is_counted_readable_but_dropped(self):
        far = [(path, sid) for kind, path, sid in self.cases if kind is _utf8_far_after]
        self.assertGreater(len(far), 5)
        for up in uploaders:
            with patch.object(up, "BACKFILL_MAX_LINES_PER_FILE", CAP_LINES):
                for path, sid in far:
                    with self.subTest(up.__name__, path=path.name):
                        self.assertEqual(up._backfill_first_session_id(path), sid)
                        self.assertIsNone(up._backfill_collect_session(path))


class _Home:
    """A seeded home and the counts its walk must report, worked out from the spec."""

    def __init__(self, seed: int, base: Path, unreadable_files: bool):
        rng = random.Random(seed)
        self.home, self.n = base, 0
        self.projects = base / ".claude" / "projects"
        self.seen, self.unreadable, self.over = 0, 0, []
        for folder in range(rng.randint(1, 3)):
            self._fill(rng, self.projects / f"p{folder}", unreadable_files)

    def _write(self, path: Path, data: bytes, old: bool):
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
        if old:
            os.utime(path, (1, 1))  # the counts take every age

    def _fill(self, rng, folder: Path, unreadable_files: bool):
        for _ in range(rng.randint(0, 8)):
            self.n += 1
            kind = rng.choice(("ok", "ok", "big", "no_id", "hidden", "subagent", "locked", "other"))
            name = f"f{self.n}.jsonl"
            old = rng.random() < 0.3
            if kind == "ok":
                self._write(folder / name, _line({"sessionId": name}), old)
                self.seen += 1
            elif kind == "big":
                data = _line({"sessionId": name, "pad": "x" * rng.randint(CAP_BYTES, 3 * CAP_BYTES)})
                self._write(folder / name, data, old)
                self.seen += 1
                self.over.append(len(data))
            elif kind == "no_id":
                self._write(folder / name, _line({"type": "summary"}), old)
                self.seen, self.unreadable = self.seen + 1, self.unreadable + 1
            elif kind == "hidden":
                self._write(folder / f".{name}", _line({"sessionId": name}), old)
            elif kind == "subagent":
                self._write(folder / "s" / "subagents" / f"agent-{name}", b"\xff\n", old)
            elif kind == "locked" and unreadable_files:
                self._write(folder / name, _line({"sessionId": name}), old)
                (folder / name).chmod(0)
                self.seen, self.unreadable = self.seen + 1, self.unreadable + 1
            else:
                self._write(folder / f"f{self.n}.txt", b"\xff\n", old)

    def expected(self):
        return {"files_seen": self.seen, "unreadable": self.unreadable,
                "skipped_over_cap": {"count": len(self.over), "largest_bytes": max(self.over, default=0),
                                     "total_bytes": sum(self.over), "by_size": _by_size(self.over)}}


def _can_lock_files():
    return os.name == "posix" and os.geteuid() != 0


class WalkStatsTestCase(unittest.TestCase):
    """A5: over 50 seeded homes, the walk counts what the spec says it holds."""

    def test_generated_homes_are_counted_exactly(self):
        with tempfile.TemporaryDirectory() as tmp:
            homes = [_Home(seed, Path(tmp) / str(seed), _can_lock_files()) for seed in range(50)]
            try:
                self.assertTrue(any(h.over for h in homes) and any(h.unreadable for h in homes))
                for up in uploaders:
                    with patch.object(up, "BACKFILL_MAX_FILE_BYTES", CAP_BYTES):
                        for seed, home in enumerate(homes):
                            with self.subTest(up.__name__, seed=seed):
                                self.assertEqual(up._backfill_walk_stats(home.projects), home.expected())
            finally:
                for path in Path(tmp).rglob("*.jsonl"):
                    path.chmod(0o644)


def _stats(seen=0, unreadable=0, count=0, largest=0, total=0):
    # Every over-cap size these tests use is far under 100 MB, so it all lands in the first band.
    by_size = _by_size([])
    by_size["under_100mb"] = {"count": count, "total_bytes": total}
    return {"files_seen": seen, "unreadable": unreadable,
            "skipped_over_cap": {"count": count, "largest_bytes": largest, "total_bytes": total, "by_size": by_size}}


def _fake_http(bodies, raw=None):
    def http(url, method, headers, body=None, timeout=30):
        if url.endswith("/upload-url/"):
            return 200, json.dumps({"upload_url": "https://s3/put", "object_key": "k"}).encode()
        if method == "PUT":
            bodies.append(json.loads(body.decode("utf-8")))
            if raw is not None:
                raw.append(body)
        return 200, b"{}"
    return http


class StatsHelpersTestCase(unittest.TestCase):

    def test_adding_counts_sums_and_keeps_the_largest(self):
        # Only the MDM uploader sums profiles.
        for up in (mdm,):
            with self.subTest(up.__name__):
                total = _stats(3, 1, 1, 500, 500)
                up._backfill_add_stats(total, None)
                up._backfill_add_stats(total, {})
                self.assertEqual(total, _stats(3, 1, 1, 500, 500))
                up._backfill_add_stats(total, _stats(2, 4, 2, 300, 550))
                self.assertEqual(total, _stats(5, 5, 3, 500, 1050))
                up._backfill_add_stats(total, _stats(0, 0, 1, 900, 900))
                self.assertEqual(total, _stats(5, 5, 4, 900, 1950))

    def test_only_a_skip_counts_as_skipping(self):
        for up in uploaders:
            for over, unreadable in ((0, 0), (1, 0), (0, 1), (2, 3)):
                with self.subTest(up.__name__, over=over, unreadable=unreadable):
                    stats = _stats(seen=7, unreadable=unreadable, count=over)
                    self.assertIs(up._backfill_skipped_anything(stats), bool(over or unreadable))

    def _payload(self, up):
        bodies = []
        with patch.object(up, "_backfill_http_request", side_effect=_fake_http(bodies)):
            self.assertTrue(up._backfill_upload_chunk("key", "https://backend", [{"session_id": "a"}]))
        return bodies[0]

    def test_the_payload_carries_the_counts_only_when_there_are_some(self):
        for up in uploaders:
            with self.subTest(up.__name__):
                with patch.object(up, "_backfill_uploader_stats", None):
                    self.assertEqual(set(self._payload(up)), {"tool_type", "sessions"})
                with patch.object(up, "_backfill_uploader_stats", _stats(1, 1)):
                    self.assertEqual(self._payload(up)["uploader_stats"], _stats(1, 1))


def _run(up, homes, extra=()):
    """The real run_backfill, network faked at the HTTP layer; returns the uploaded bodies."""
    bodies = []
    with ExitStack() as stack:
        for ctx in (patch.object(up, "_backfill_http_request", side_effect=_fake_http(bodies)),
                    patch.object(up, "_backfill_force_config", return_value=(None, None)),
                    patch.object(up, "_backfill_account_email", return_value=None),
                    patch.object(up, "get_device_identifier", return_value="SERIAL"),
                    patch.object(up, "BACKFILL_MAX_FILE_BYTES", CAP_BYTES),
                    redirect_stdout(io.StringIO())) + tuple(extra):
            stack.enter_context(ctx)
        if hasattr(up, "_BackfillRun"):  # the MDM uploader, or its earlier copy
            stack.enter_context(patch.object(up, "_run_as_user", side_effect=lambda u, fn, *a, **k: fn(*a, **k)))
            up.run_backfill("key", "https://backend", [(f"user{i}", h) for i, h in enumerate(homes)])
        else:
            stack.enter_context(patch.object(up.Path, "home", return_value=homes[0]))
            up.run_backfill("key", "https://backend", homes[0] / ".claude")
    return bodies


class _HomesMixin:

    def _home(self, sessions=(), big=(), no_id=0):
        home = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, home)
        projects = home / ".claude" / "projects" / "p"
        projects.mkdir(parents=True)
        for sid in sessions:
            (projects / f"{sid}.jsonl").write_bytes(_line({"type": "user", "sessionId": sid}))
        sizes = []
        for n, pad in enumerate(big):
            data = _line({"sessionId": f"big{n}", "pad": "x" * pad})
            (projects / f"big{n}.jsonl").write_bytes(data)
            sizes.append(len(data))
        for n in range(no_id):
            (projects / f"none{n}.jsonl").write_bytes(_line({"type": "summary"}))
        expected = _stats(len(sessions) + len(big) + no_id, no_id, len(sizes), max(sizes, default=0), sum(sizes))
        return home, expected


class MdmRunTestCase(_HomesMixin, unittest.TestCase):
    """B1: the MDM uploader sends its sessions first, then the counts once, in a body of their own."""

    def test_uploads_then_one_counts_body(self):
        home, expected = self._home(("a", "b", "c"), big=(500, 900), no_id=1)
        bodies = _run(mdm, [home])
        counted = [b for b in bodies if "uploader_stats" in b]
        self.assertEqual(counted, [{"tool_type": "claude-code", "sessions": [], "uploader_stats": expected}])
        self.assertIs(bodies[-1], counted[0])
        self.assertEqual(sorted(s["session_id"] for b in bodies[:-1] for s in b["sessions"]), ["a", "b", "c"])

    def test_no_time_left_sends_no_counts(self):
        home, _ = self._home(("a",), big=(500,))
        bodies = _run(mdm, [home], [patch.object(mdm._BackfillRun, "has_time_for_a_batch",
                                                 side_effect=[True, False])])
        self.assertEqual([[s["session_id"] for s in b["sessions"]] for b in bodies], [["a"]])
        self.assertNotIn("uploader_stats", bodies[0])

    def test_nothing_skipped_sends_no_counts(self):
        home, _ = self._home(("a", "b"))
        bodies = _run(mdm, [home])
        self.assertTrue(bodies)
        self.assertFalse(any("uploader_stats" in b or not b["sessions"] for b in bodies))

    def test_every_profile_is_summed(self):
        alice, first = self._home(("a",), big=(500, 2000), no_id=2)
        bob, second = self._home(("b", "c"), big=(1200,), no_id=1)
        total = _stats()
        mdm._backfill_add_stats(total, first)
        mdm._backfill_add_stats(total, second)
        self.assertEqual(_run(mdm, [alice, bob])[-1]["uploader_stats"], total)

    def test_a_refused_profile_counts_nothing_and_keeps_no_state(self):
        alice, counted = self._home(("a",), big=(500,))
        bob, _ = self._home(("b",), big=(900, 900), no_id=3)
        hooks = bob / ".claude" / "hooks"
        hooks.mkdir()
        real_lstat = os.lstat

        def lstat(path, *args, **kwargs):
            result = real_lstat(path, *args, **kwargs)
            if os.fspath(path) == str(hooks):
                return mock.Mock(wraps=result, st_reparse_tag=JUNCTION_TAG, st_mode=result.st_mode)
            return result
        bodies = _run(mdm, [alice, bob], [patch("os.lstat", side_effect=lstat),
                                          patch.object(mdm.platform, "system", return_value="Windows")])
        self.assertEqual(bodies[-1]["uploader_stats"], counted)
        self.assertEqual(sorted(s["session_id"] for b in bodies for s in b["sessions"]), ["a"])
        self.assertEqual(list(hooks.iterdir()), [])
        self.assertTrue((alice / ".claude" / "hooks" / mdm.BACKFILL_STATE_FILE).exists())

    def test_the_counts_do_not_carry_into_the_next_run(self):
        skipping, _ = self._home(("a",), big=(500,))
        clean, _ = self._home(("b",))
        self.assertIn("uploader_stats", _run(mdm, [skipping])[-1])
        bodies = _run(mdm, [clean])
        self.assertEqual([[s["session_id"] for s in b["sessions"]] for b in bodies], [["b"]])
        self.assertNotIn("uploader_stats", bodies[0])
        self.assertIsNone(mdm._backfill_uploader_stats)

    def test_a_disabled_backfill_sends_nothing(self):
        home, _ = self._home(("a",), big=(500,))
        with patch.dict(os.environ, {"UNBOUND_BACKFILL_DISABLED": "1"}):
            self.assertEqual(_run(mdm, [home]), [])
        self.assertFalse((home / ".claude" / "hooks").exists())


class StandaloneRunTestCase(_HomesMixin, unittest.TestCase):
    """B2: the per-user uploader carries the same counts on every chunk."""

    def test_every_chunk_carries_the_same_counts(self):
        home, expected = self._home(("a", "b", "c", "d"), big=(700,), no_id=2)
        # Room for one session per chunk, so the four go up apart.
        bodies = _run(setup, [home], [patch.object(setup, "BACKFILL_CHUNK_BYTES", 150)])
        self.assertEqual(len(bodies), 4)
        self.assertEqual([b["uploader_stats"] for b in bodies], [expected] * 4)
        self.assertEqual(sorted(s["session_id"] for b in bodies for s in b["sessions"]), ["a", "b", "c", "d"])

    def test_a_run_that_only_skips_sends_the_counts_alone(self):
        home, expected = self._home(big=(500, 800), no_id=1)
        self.assertEqual(_run(setup, [home]),
                         [{"tool_type": "claude-code", "sessions": [], "uploader_stats": expected}])

    def test_an_empty_home_sends_nothing(self):
        home, _ = self._home()
        self.assertEqual(_run(setup, [home]), [])
        shutil.rmtree(home / ".claude" / "projects")
        self.assertEqual(_run(setup, [home]), [])

    def test_with_nothing_skipped_the_counts_still_ride_the_chunks(self):
        home, expected = self._home(("a", "b"))
        bodies = _run(setup, [home])
        self.assertTrue(bodies)
        self.assertEqual([b["uploader_stats"] for b in bodies], [expected] * len(bodies))
        self.assertEqual(expected, _stats(seen=2))


def _load_before(relpath: str):
    """relpath as it was before the counts, loaded from git into a temp module; None when the commit is absent."""
    try:
        source = subprocess.run(["git", "-C", str(REPO), "show", f"{BEFORE_STATS}:{relpath}"],
                                capture_output=True, check=True).stdout
    except (OSError, subprocess.CalledProcessError):
        return None
    tmp = tempfile.mkdtemp()
    path = Path(tmp) / "before.py"
    path.write_bytes(source)
    name = "before_stats_" + relpath.replace("/", "_").replace("-", "_")[:-3]
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    module.BACKFILL_ENABLED = True
    shutil.rmtree(tmp)
    return module


class SessionsUnchangedTestCase(unittest.TestCase):
    """C2: for one home, every uploaded body is byte for byte what the uploader sent before the counts, once the
    counts are taken out; MDM adds only its trailing counts body."""

    PATHS = {mdm: "claude-code/hooks/mdm/setup.py", setup: "claude-code/hooks/setup.py"}

    def _home(self):
        home = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, home)
        cases = Path(__file__).resolve().parents[2] / "fixtures" / "claude_code_usage" / "cases"
        projects = home / ".claude" / "projects"
        shutil.copytree(cases / "subagent_files", projects / "subagents-case")
        rng = random.Random(2)
        for n in range(12):
            entries = [{"type": "user", "sessionId": f"s{n}", "message": {"content": "hi" * rng.randint(1, 50)}}]
            entries += [{"type": "assistant", "message": {"id": f"m{n}-{k}", "usage": {"output_tokens": k}}}
                        for k in range(rng.randint(0, 5))]
            (projects / "p" / f"s{n}.jsonl").parent.mkdir(parents=True, exist_ok=True)
            (projects / "p" / f"s{n}.jsonl").write_text("".join(json.dumps(e) + "\n" for e in entries))
        (projects / "p" / "big.jsonl").write_text(json.dumps({"sessionId": "big", "pad": "x" * 5000}) + "\n")
        (projects / "p" / "none.jsonl").write_text(json.dumps({"type": "summary"}) + "\n")
        return home

    def _raw(self, up, home):
        raw = []
        # Room for every transcript but the big one, and chunks small enough that there are several.
        _run(up, [home], [patch.object(up, "_backfill_http_request", side_effect=_fake_http([], raw)),
                          patch.object(up, "BACKFILL_MAX_FILE_BYTES", 4000),
                          patch.object(up, "BACKFILL_CHUNK_BYTES", 2000)])
        return raw

    def test_the_sessions_sent_are_unchanged(self):
        for now in uploaders:
            before = _load_before(self.PATHS[now])
            if before is None:
                self.skipTest(f"{BEFORE_STATS[:8]} is not in this clone")
            with self.subTest(now.__name__):
                then = self._raw(before, self._home())
                current = [json.loads(b) for b in self._raw(now, self._home())]
                if now is mdm:
                    self.assertEqual(current[-1]["sessions"], [])
                    current = current[:-1]
                    self.assertFalse(any("uploader_stats" in b for b in current))
                else:
                    for body in current:
                        body.pop("uploader_stats")
                self.assertGreater(len(then), 1)
                # Each session byte for byte; upload order follows file times, which two fresh homes can tie on.
                def sessions(bodies):
                    return sorted(json.dumps(s, sort_keys=True) for b in bodies for s in b["sessions"])
                self.assertEqual(sessions(current), sessions(json.loads(b) for b in then))
                self.assertEqual([set(b) for b in current], [{"tool_type", "sessions"}] * len(current))


@unittest.skipUnless(os.environ.get("UNBOUND_SLOW_TESTS") == "1", "50,000 files; set UNBOUND_SLOW_TESTS=1")
class WalkStatsScaleTestCase(unittest.TestCase):
    """D2: counting a 50,000-transcript history, timed and with its peak memory."""

    def test_fifty_thousand_transcripts(self):
        with tempfile.TemporaryDirectory() as tmp:
            projects = Path(tmp) / "projects"
            for n in range(50_000):
                folder = projects / f"p{n % 200}"
                if n < 200:
                    folder.mkdir(parents=True)
                (folder / f"s{n}.jsonl").write_bytes(_line({"type": "user", "sessionId": f"s{n}"}) * 3)
            for up in uploaders:
                with self.subTest(up.__name__):
                    tracemalloc.start()
                    began = time.perf_counter()
                    stats = up._backfill_walk_stats(projects)
                    elapsed = time.perf_counter() - began
                    peak = tracemalloc.get_traced_memory()[1]
                    tracemalloc.stop()
                    print(f"\n{up.__name__}: {elapsed:.2f}s, peak {peak / 1024:.0f} KiB", file=sys.stderr)
                    self.assertEqual(stats, _stats(seen=50_000))


if __name__ == "__main__":
    unittest.main()
