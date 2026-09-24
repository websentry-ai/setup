"""
Tests that the re-walk stops itself before onboard.py's 600s kill.

onboard.py runs each installer as a child it SIGKILLs at 600s and marks the whole tool
step failed on timeout. The hooks are already installed and reported by then, so a kill
only costs the walk and lies about the install. The walk therefore takes a deadline and
leaves untouched anything it did not reach, so the next run picks it up.
"""

import time
import unittest
from pathlib import Path
from unittest.mock import patch

from tests.conftest import tool_module

mdm = tool_module("copilot/hooks/mdm", "setup")

EXPIRED = time.monotonic() - 1


class TestTheWalkStopsAtItsDeadline(unittest.TestCase):
    def _run(self, deadline, homes):
        """Returns (usernames collected, usernames whose cutoff advanced)."""
        collected, advanced = [], []

        def _fake_run_as_user(username, fn, *args, **kwargs):
            if fn is mdm._backfill_collect_sessions:
                collected.append(username)
                return ([{"session_id": username.upper()}], False, False)
            if fn is mdm._backfill_write_cutoff:
                advanced.append(username)
            return None

        with patch.object(mdm, "_run_as_user", _fake_run_as_user), \
                patch.object(mdm, "_backfill_force_config", lambda *a: (None, None)), \
                patch.object(mdm, "_backfill_upload_chunk", lambda *a, **k: True):
            mdm.run_backfill("key", "https://backend", homes, deadline=deadline)
        return collected, advanced

    def test_an_expired_deadline_walks_nobody_and_advances_nobody(self):
        collected, advanced = self._run(
            EXPIRED, [("alice", Path("/home/alice")), ("bob", Path("/home/bob"))])
        self.assertEqual(collected, [])
        self.assertEqual(advanced, [], "a profile never walked must stay eligible")

    def test_no_deadline_walks_everyone(self):
        collected, advanced = self._run(
            None, [("alice", Path("/home/alice")), ("bob", Path("/home/bob"))])
        self.assertEqual(collected, ["alice", "bob"])
        self.assertEqual(advanced, ["alice", "bob"])


class TestTheUploadStopsAtItsDeadline(unittest.TestCase):
    def test_an_expired_deadline_books_the_remainder_as_unsent(self):
        # chunks_failed must be non-zero, or run_backfill advances cutoffs past sessions
        # that were never uploaded.
        with patch.object(mdm, "_backfill_upload_chunk", lambda *a, **k: True):
            sent, chunks_sent, chunks_failed = mdm._backfill_send_sessions(
                "key", "https://backend", [{"session_id": "S1", "entries": [{}]}],
                deadline=EXPIRED)
        self.assertEqual((sent, chunks_sent), (0, 0))
        self.assertEqual(chunks_failed, 1)

    def test_no_deadline_sends_everything(self):
        with patch.object(mdm, "_backfill_upload_chunk", lambda *a, **k: True):
            sent, chunks_sent, chunks_failed = mdm._backfill_send_sessions(
                "key", "https://backend", [{"session_id": "S1", "entries": [{}]}])
        self.assertEqual((sent, chunks_sent, chunks_failed), (1, 1, 0))


if __name__ == "__main__":
    unittest.main()


class ChunkStartedUnderTheDeadline(unittest.TestCase):
    """The per-session check lets a chunk begin under the budget and then spend three
    HTTP calls past it, which is what reaches onboard.py's kill. The clock here runs out
    after that check and before the upload, which the session check alone cannot see."""

    def _send(self, expiries):
        uploaded = []
        calls = iter(expiries)

        def clock(_deadline):
            return next(calls, True)

        with patch.object(mdm, "_backfill_upload_chunk",
                          lambda *a, **k: uploaded.append(a[2]) or True), \
                patch.object(mdm, "_backfill_out_of_time", clock):
            sent, chunks_sent, failed = mdm._backfill_send_sessions(
                "k", "https://b",
                [{"session_id": "S1", "entries": [
                    {"type": "user.message", "data": {"content": "x"}},
                    {"type": "assistant.message", "data": {"content": "y"}}]}],
                deadline=1.0)
        return uploaded, sent, failed

    def test_a_chunk_is_not_uploaded_when_the_budget_goes_mid_session(self):
        # False at the session check, True by the flush: the window this closes.
        uploaded, sent, failed = self._send([False, True])
        self.assertEqual(uploaded, [])
        self.assertEqual(sent, 0)
        self.assertGreater(failed, 0, "the remainder must hold the cutoff")

    def test_a_chunk_still_uploads_inside_the_budget(self):
        uploaded, sent, failed = self._send([False, False])
        self.assertEqual(len(uploaded), 1)
        self.assertEqual((sent, failed), (1, 0))


class WorkAlreadyWalkedIsNotDiscarded(unittest.TestCase):
    """The collect loop checks the budget before each profile, so a profile whose walk
    alone outlasts it leaves the deadline expired with sessions in hand. Sharing that
    deadline with the upload threw them away and held the cutoff, so the next run walked
    and discarded the same work again."""

    def _run(self, walk_seconds, deadline):
        clock = {"t": 0.0}
        uploaded, cutoffs = [], []

        def _fake_run_as_user(username, fn, *args, **kwargs):
            if fn is mdm._backfill_collect_sessions:
                clock["t"] += walk_seconds
                return ([{"session_id": username, "entries": [
                    {"type": "user.message", "data": {"content": "p"}},
                    {"type": "assistant.message", "data": {"content": "a"}}]}], False, False)
            if fn is mdm._backfill_write_cutoff:
                cutoffs.append(username)
            return None

        with patch.object(mdm, "_run_as_user", _fake_run_as_user), \
                patch.object(mdm, "_backfill_force_config", lambda *a: (None, None)), \
                patch.object(mdm, "_backfill_upload_chunk",
                             lambda *a, **k: uploaded.append(a[2]) or True), \
                patch.object(mdm.time, "monotonic", lambda: clock["t"]):
            mdm.run_backfill("k", "https://b",
                             [("alice", Path("/h/alice")), ("bob", Path("/h/bob"))],
                             deadline=deadline)
        return uploaded, cutoffs

    def test_a_walk_that_overruns_still_uploads_what_it_collected(self):
        uploaded, cutoffs = self._run(walk_seconds=430.0, deadline=420.0)
        self.assertEqual(len(uploaded), 1, "the walked profile's sessions must be sent")
        self.assertEqual(cutoffs, ["alice"], "and its cutoff must advance, or it repeats")

    def test_the_grace_window_is_not_unbounded(self):
        # 541s is one second past the shipped 420 + 120, written out rather than derived
        # from the constant so that widening the grace has to fail here first.
        uploaded, cutoffs = self._run(walk_seconds=541.0, deadline=420.0)
        self.assertEqual(uploaded, [])
        self.assertEqual(cutoffs, [])

    def test_the_grace_leaves_margin_before_onboard_kills_the_installer(self):
        self.assertLess(mdm.BACKFILL_TIME_BUDGET_SECONDS
                        + mdm.BACKFILL_UPLOAD_GRACE_SECONDS, 600)


class EachRequestFitsWhatIsLeft(unittest.TestCase):
    """A chunk makes three HTTP calls and each spends timeout * 4 + 20 before giving up,
    so a guard before the chunk overshoots by all three. 420s of overshoot on a 420s
    budget is what reaches onboard.py's 600s kill."""

    def test_a_full_budget_keeps_the_normal_timeout(self):
        self.assertEqual(mdm._backfill_request_timeout(None), 30)
        with patch.object(mdm.time, "monotonic", lambda: 0.0):
            self.assertEqual(mdm._backfill_request_timeout(1000.0), 30)

    def test_a_thin_budget_shortens_the_request_instead_of_overshooting(self):
        with patch.object(mdm.time, "monotonic", lambda: 0.0):
            timeout = mdm._backfill_request_timeout(100.0)
        self.assertEqual(timeout, 20)
        self.assertLessEqual(timeout * 4 + 20, 100, "the request must fit the budget")

    def test_no_budget_left_declines_the_request(self):
        with patch.object(mdm.time, "monotonic", lambda: 0.0):
            self.assertIsNone(mdm._backfill_request_timeout(30.0))

    def test_a_chunk_out_of_time_sends_nothing(self):
        requests = []
        with patch.object(mdm, "_backfill_http_request",
                          lambda *a, **k: requests.append(k) or (200, b"{}")), \
                patch.object(mdm.time, "monotonic", lambda: 0.0):
            self.assertFalse(mdm._backfill_upload_chunk(
                "k", "https://b", [{"session_id": "S1"}], deadline=30.0))
        self.assertEqual(requests, [], "not one of the three calls may start")

    def test_the_shortened_timeout_reaches_the_request(self):
        seen = []

        def _fake_request(url, method, headers, body=None, timeout=30):
            seen.append(timeout)
            return 200, b'{"upload_url": "https://s3", "object_key": "k"}'

        with patch.object(mdm, "_backfill_http_request", _fake_request), \
                patch.object(mdm.time, "monotonic", lambda: 0.0):
            mdm._backfill_upload_chunk("k", "https://b", [{"session_id": "S1"}],
                                       deadline=100.0)
        self.assertEqual(seen, [20, 20, 20], "a flat 30 would outlast the budget")

    def test_the_sender_hands_its_deadline_to_the_chunk(self):
        # Without this the per-request budget never engages on the path that ships.
        seen = []
        with patch.object(mdm, "_backfill_upload_chunk",
                          lambda *a, **k: seen.append(a[5] if len(a) > 5
                                                      else k.get("deadline")) or True):
            mdm._backfill_send_sessions("k", "https://b", [{"session_id": "S1", "entries": [
                {"type": "user.message", "data": {"content": "x"}},
                {"type": "assistant.message", "data": {"content": "y"}}]}],
                deadline=10 ** 9)
        self.assertEqual(seen, [10 ** 9])
