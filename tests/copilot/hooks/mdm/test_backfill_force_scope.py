"""
Tests that an org force request stays scoped to the profiles actually behind it.

One MDM run walks several user homes and uploads under a single device key. Profiles
backfill at different times, so a request can cover some and not others. Sessions from
a profile that is not behind must never ride an upload asserting force, or that
profile's settled sessions get reopened.
"""

import time
import unittest
from pathlib import Path
from unittest.mock import patch

from tests.conftest import tool_module

mdm = tool_module("copilot/hooks/mdm", "setup")


class TestForceStaysScopedToTheProfilesBehind(unittest.TestCase):
    def _run(self, homes, collect):
        """Run the driver with collection stubbed per home. Returns the (sessions, forced)
        pairs handed to the uploader, in call order."""
        uploads = []

        def _fake_run_as_user(username, fn, *args, **kwargs):
            return collect[username]

        def _fake_send(api_key, backend_url, sessions, forced=False):
            uploads.append((sorted(s["session_id"] for s in sessions), forced))
            return len(sessions), 1, 0

        with patch.object(mdm, "_run_as_user", _fake_run_as_user), \
                patch.object(mdm, "_backfill_force_config", lambda *a: (1000.0, None)), \
                patch.object(mdm, "_backfill_send_sessions", _fake_send):
            mdm.run_backfill("key", "https://backend", homes)
        return uploads

    def test_a_forced_and_an_unforced_profile_upload_separately(self):
        homes = [("alice", Path("/home/alice")), ("bob", Path("/home/bob"))]
        uploads = self._run(homes, {
            # (sessions, capped, forced)
            "alice": ([{"session_id": "A1"}], False, True),
            "bob": ([{"session_id": "B1"}], False, False),
        })

        self.assertEqual(len(uploads), 2)
        self.assertIn((["A1"], True), uploads)
        self.assertIn((["B1"], False), uploads)

    def test_one_profile_behind_does_not_force_the_others_sessions(self):
        homes = [("alice", Path("/home/alice")), ("bob", Path("/home/bob"))]
        uploads = self._run(homes, {
            "alice": ([{"session_id": "A1"}], False, True),
            "bob": ([{"session_id": "B1"}, {"session_id": "B2"}], False, False),
        })

        forced = [ids for ids, is_forced in uploads if is_forced]
        self.assertEqual(forced, [["A1"]], "only the profile behind may be forced")

    def test_all_profiles_behind_send_one_forced_upload(self):
        homes = [("alice", Path("/home/alice")), ("bob", Path("/home/bob"))]
        uploads = self._run(homes, {
            "alice": ([{"session_id": "A1"}], False, True),
            "bob": ([{"session_id": "B1"}], False, True),
        })

        self.assertEqual(uploads, [(["A1", "B1"], True)])

    def test_no_profile_behind_sends_nothing_forced(self):
        homes = [("alice", Path("/home/alice")), ("bob", Path("/home/bob"))]
        uploads = self._run(homes, {
            "alice": ([{"session_id": "A1"}], False, False),
            "bob": ([{"session_id": "B1"}], False, False),
        })

        self.assertEqual(uploads, [(["A1", "B1"], False)])

    def test_an_unreadable_home_is_skipped_without_forcing(self):
        homes = [("alice", Path("/home/alice")), ("bob", Path("/home/bob"))]
        uploads = self._run(homes, {
            "alice": None,
            "bob": ([{"session_id": "B1"}], False, False),
        })

        self.assertEqual(uploads, [(["B1"], False)])


if __name__ == "__main__":
    unittest.main()


class TestForceWindow(unittest.TestCase):
    """How far back a forced re-walk reaches. Without the org's window the walk cannot
    pass 30 days, so history an earlier backfill had already reached is never revisited."""

    def _forced_cutoff(self, force_days, persisted=None):
        """The mtime floor a forced collection actually walks from."""
        # A device that backfilled yesterday, which is what the window widens.
        persisted = time.time() - 86400 if persisted is None else persisted
        seen = {}

        def _capture(home_dir, cutoff_mtime):
            seen['cutoff'] = cutoff_mtime
            return iter(())

        with patch.object(mdm, "_backfill_read_cutoff", lambda home: persisted), \
                patch.object(mdm, "_backfill_iter_transcripts", _capture):
            mdm._backfill_collect_sessions(Path("/home/alice"), 1e12, force_days)
        return seen['cutoff']

    def test_the_window_widens_the_walk(self):
        reach = time.time() - self._forced_cutoff(45)
        self.assertAlmostEqual(reach / 86400, 45, delta=1)

    def test_no_window_keeps_the_installer_default(self):
        reach = time.time() - self._forced_cutoff(None)
        self.assertAlmostEqual(reach / 86400, mdm.BACKFILL_MAX_AGE_DAYS, delta=1)

    def test_the_window_reaches_the_profile_collector(self):
        # It travels through _run_as_user positionally, so a dropped argument is silent.
        seen = {}

        def _fake_run_as_user(username, fn, *args, **kwargs):
            # run_backfill also drops privileges to write each profile's cutoff, so the
            # collector's call is the one to look at, not the last one.
            if fn is mdm._backfill_collect_sessions:
                seen['args'] = args
            return ([], False, False)

        with patch.object(mdm, "_run_as_user", _fake_run_as_user), \
                patch.object(mdm, "_backfill_force_config", lambda *a: (1000.0, 45)), \
                patch.object(mdm, "_backfill_send_sessions", lambda *a, **k: (0, 0, 0)):
            mdm.run_backfill("key", "https://backend", [("alice", Path("/home/alice"))])
        self.assertEqual(seen['args'][-1], 45, "the window must reach the collector")


    def test_a_narrow_window_never_gives_up_ground_already_reached(self):
        # The run advances the cutoff on success, so anything a narrow window skips is
        # never visited again. Force may widen the walk; it may not shrink it.
        sixty_days_ago = time.time() - 60 * 86400
        cutoff = self._forced_cutoff(10, persisted=sixty_days_ago)
        self.assertAlmostEqual(cutoff, sixty_days_ago, delta=2)
