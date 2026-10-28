"""The size bands of skipped transcripts across many generated histories: every file over the real 50 MiB cap lands
in exactly one band, sizes on and beside each band edge included, and the MDM uploader's per-profile sums equal one
walk over every profile's files."""

import io
import json
import random
import tempfile
import unittest
from contextlib import ExitStack, redirect_stdout
from pathlib import Path
from unittest.mock import patch

from tests.conftest import tool_module

mdm = tool_module("claude-code/hooks/mdm", "setup")
setup = tool_module("claude-code/hooks", "setup")
MiB, GiB = 1 << 20, 1 << 30
CAP = 50 * MiB
# Every size the bands must place exactly: the cap itself (not over it), the first byte over, and each band edge.
EDGES = (CAP, CAP + 1, 100 * MiB - 1, 100 * MiB, 250 * MiB - 1, 250 * MiB, 500 * MiB - 1, 500 * MiB, GiB - 1, GiB,
         8 * GiB)
BAND_NAMES = ("under_100mb", "under_250mb", "under_500mb", "under_1gb", "1gb_or_more")


def _band_of(size):
    # The spec, written out apart from the code under test: each band holds sizes below its upper bound.
    if size < 100 * MiB:
        return "under_100mb"
    if size < 250 * MiB:
        return "under_250mb"
    if size < 500 * MiB:
        return "under_500mb"
    if size < GiB:
        return "under_1gb"
    return "1gb_or_more"


def _spec_bands(sizes):
    bands = {name: {"count": 0, "total_bytes": 0} for name in BAND_NAMES}
    for size in sizes:
        if size > CAP:
            bands[_band_of(size)]["count"] += 1
            bands[_band_of(size)]["total_bytes"] += size
    return bands


def _size(rng):
    pick = rng.random()
    if pick < 0.45:
        return min(8 * GiB, rng.choice(EDGES) + rng.randint(-3, 3))
    if pick < 0.85:
        return rng.randint(CAP + 1, 8 * GiB)
    return rng.randint(0, 4096)


def _size_sets(n):
    """n seeded size lists: the first holds every edge, every tenth the cap itself, the rest drawn around them."""
    rng = random.Random("backfill-size-bands")
    sets = [list(EDGES)]
    for i in range(1, n):
        sizes = [_size(rng) for _ in range(rng.randint(1, 8))]
        sets.append(sizes + [CAP] if i % 10 == 0 else sizes)
    return sets


def _write_sparse(folder: Path, sizes, prefix="t"):
    # Sparse files report their full size without using the disk.
    folder.mkdir(parents=True, exist_ok=True)
    for i, size in enumerate(sizes):
        with open(folder / f"{prefix}{i}.jsonl", "wb") as f:
            f.truncate(size)


class SizeBandsTestCase(unittest.TestCase):
    """T1: over 200 seeded size sets at the real cap, every walk files each over-cap size in its spec band."""

    def test_every_over_cap_size_lands_in_its_band(self):
        sets = _size_sets(200)
        drawn = {s for sizes in sets for s in sizes}
        self.assertTrue(set(EDGES) <= drawn and max(drawn) == 8 * GiB and min(drawn) <= CAP)
        self.assertEqual((mdm.BACKFILL_MAX_FILE_BYTES, setup.BACKFILL_MAX_FILE_BYTES), (CAP, CAP))
        for case, sizes in enumerate(sets):
            with tempfile.TemporaryDirectory() as tmp:
                projects = Path(tmp) / ".claude" / "projects"
                _write_sparse(projects / "p", sizes)
                for up in (mdm, setup):
                    with self.subTest(up.__name__, case=case, sizes=sizes):
                        self._assert_banded(up._backfill_walk_stats(projects), sizes)

    def _assert_banded(self, stats, sizes):
        over = stats["skipped_over_cap"]
        over_sizes = [s for s in sizes if s > CAP]
        self.assertEqual(over["by_size"], _spec_bands(sizes))
        self.assertEqual(sum(b["count"] for b in over["by_size"].values()), over["count"])
        self.assertEqual(sum(b["total_bytes"] for b in over["by_size"].values()), over["total_bytes"])
        self.assertEqual((over["count"], over["total_bytes"]), (len(over_sizes), sum(over_sizes)))
        if over_sizes:
            highest = [name for name in BAND_NAMES if over["by_size"][name]["count"]][-1]
            self.assertEqual(_band_of(over["largest_bytes"]), highest)
        # Files at or under the cap are seen, belong to no band, and carry no session id.
        self.assertEqual((stats["files_seen"], stats["unreadable"]), (len(sizes), len(sizes) - len(over_sizes)))


def _sum_profiles(parts):
    total = mdm._backfill_empty_stats()
    for part in parts:
        mdm._backfill_add_stats(total, part)
    return total


def _fake_http(bodies):
    def http(url, method, headers, body=None, timeout=30):
        if url.endswith("/upload-url/"):
            return 200, json.dumps({"upload_url": "https://s3/put", "object_key": "k"}).encode()
        if method == "PUT":
            bodies.append(json.loads(body.decode("utf-8")))
        return 200, b"{}"
    return http


class MdmBandSumTestCase(unittest.TestCase):
    """T2: the MDM uploader's per-profile counts, summed, equal one walk over every profile's files."""

    def test_profile_sums_equal_one_walk_of_every_file(self):
        rng = random.Random("backfill-band-profiles")
        for case, sizes in enumerate(_size_sets(100)):
            profiles = [[] for _ in range(rng.randint(2, 5))]
            for size in sizes:
                rng.choice(profiles).append(size)
            with tempfile.TemporaryDirectory() as tmp, self.subTest(case=case, profiles=profiles):
                roots = [Path(tmp) / f"home{i}" / ".claude" / "projects" for i in range(len(profiles))]
                for root, part in zip(roots, profiles):
                    _write_sparse(root / "p", part)
                _write_sparse(Path(tmp) / "all" / "p", sizes)
                summed = _sum_profiles(mdm._backfill_walk_stats(root) for root in roots)
                self.assertEqual(summed, mdm._backfill_walk_stats(Path(tmp) / "all"))
                self.assertEqual(summed["skipped_over_cap"]["by_size"], _spec_bands(sizes))

    def test_a_real_run_over_three_profiles_sends_the_bands_of_all_of_them(self):
        rng = random.Random("backfill-band-run")
        sizes = [list(EDGES[1:5]), list(EDGES[5:8]) + [rng.randint(CAP + 1, 8 * GiB)], list(EDGES[8:]) + [CAP]]
        with tempfile.TemporaryDirectory() as tmp:
            homes = []
            for i, part in enumerate(sizes):
                home = Path(tmp) / f"home{i}"
                _write_sparse(home / ".claude" / "projects" / "p", part, prefix="big")
                session = home / ".claude" / "projects" / "p" / f"s{i}.jsonl"
                session.write_text(json.dumps({"type": "user", "sessionId": f"s{i}"}) + "\n")
                homes.append((f"user{i}", home))
            parts = [mdm._backfill_walk_stats(home / ".claude" / "projects") for _, home in homes]
            bodies = self._run(homes)
        *uploads, counts = bodies
        everything = [s for part in sizes for s in part]
        self.assertEqual(sorted(s["session_id"] for b in uploads for s in b["sessions"]), ["s0", "s1", "s2"])
        self.assertEqual(counts["sessions"], [])
        self.assertEqual(counts["uploader_stats"], _sum_profiles(parts))
        self.assertEqual(counts["uploader_stats"]["skipped_over_cap"]["by_size"], _spec_bands(everything))

    def _run(self, homes):
        """The real MDM run_backfill, network faked at the HTTP layer and each profile's walk run in process."""
        bodies = []
        with ExitStack() as stack:
            for ctx in (patch.object(mdm, "_backfill_http_request", side_effect=_fake_http(bodies)),
                        patch.object(mdm, "_backfill_force_config", return_value=(None, None)),
                        patch.object(mdm, "_backfill_account_email", return_value=None),
                        patch.object(mdm, "get_device_identifier", return_value="SERIAL"),
                        patch.object(mdm, "_run_as_user", side_effect=lambda u, fn, *a, **k: fn(*a, **k)),
                        redirect_stdout(io.StringIO())):
                stack.enter_context(ctx)
            mdm.run_backfill("key", "https://backend", homes)
        return bodies


if __name__ == "__main__":
    unittest.main()
