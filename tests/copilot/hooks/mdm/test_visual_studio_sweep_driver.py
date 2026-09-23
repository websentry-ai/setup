"""
Tests the driver that uploads each profile's Visual Studio conversations.

Visual Studio fires no hooks, so an ordinary sweep is the only delivery those turns ever
get and must declare itself not-backfilled, or the rows are skipped by the consumers that
ignore replayed traffic. Anything not delivered -- a failed upload, or a session the slicer
declined -- must leave the cutoff where it is, or that conversation is never re-read.
"""

import unittest
from pathlib import Path
from unittest.mock import patch

from tests.conftest import tool_module

mdm = tool_module("copilot/hooks/mdm", "setup")

HOMES = [("alice", Path("/home/alice"))]


def _session(sid="S1"):
    return {"session_id": sid, "entries": [{"type": "user.message", "data": {"content": "x"}}]}


class TestVisualStudioSweepDriver(unittest.TestCase):
    def _run(self, collected, failed_chunks=0, sent_override=None, env=None, **kwargs):
        uploads, advanced = [], []

        def _fake_run_as_user(username, fn, *args, **kw):
            if fn is mdm._vs_collect_for_user:
                return collected
            advanced.append(args)
            return None

        def _fake_send(api_key, backend_url, sessions, forced=False, backfilled=True):
            uploads.append({"sessions": sessions, "backfilled": backfilled})
            sent = len(sessions) if sent_override is None else sent_override
            return sent, 1, failed_chunks

        patches = [
            patch.object(mdm.platform, "system", return_value="Windows"),
            patch.object(mdm, "_run_as_user", _fake_run_as_user),
            patch.object(mdm, "_backfill_send_sessions", _fake_send),
            patch.dict(mdm.os.environ, env or {}, clear=False),
        ]
        for p in patches:
            p.start()
        try:
            mdm.run_visual_studio_sweep("key", "https://backend", HOMES, **kwargs)
        finally:
            for p in reversed(patches):
                p.stop()
        return uploads, advanced

    def test_an_ordinary_sweep_declares_itself_not_backfilled(self):
        uploads, _ = self._run({"sessions": [_session()], "first_run": False, "truncated": False})
        self.assertEqual(len(uploads), 1)
        self.assertIs(uploads[0]["backfilled"], False)

    def test_the_opt_in_seed_is_marked_historical(self):
        # A month of past turns must not raise a month of live alerts at once.
        uploads, _ = self._run({"sessions": [_session()], "first_run": True, "truncated": False},
                               seed_history=True)
        self.assertIs(uploads[0]["backfilled"], True)

    def test_a_first_run_without_the_flag_is_still_live(self):
        uploads, _ = self._run({"sessions": [_session()], "first_run": True, "truncated": False})
        self.assertIs(uploads[0]["backfilled"], False)

    def test_the_device_serial_rides_along_so_rows_map_to_a_device(self):
        uploads, _ = self._run({"sessions": [_session()], "first_run": False, "truncated": False},
                               device_serial="SERIAL-1")
        self.assertEqual(uploads[0]["sessions"][0]["device_serial"], "SERIAL-1")

    def test_a_delivered_upload_advances_the_cutoff(self):
        _, advanced = self._run({"sessions": [_session()], "first_run": False, "truncated": False})
        self.assertEqual(len(advanced), 1)
        self.assertEqual(advanced[0][2], mdm.VS_STATE_FILE)

    def test_a_failed_chunk_holds_the_cutoff_so_the_turns_retry(self):
        _, advanced = self._run({"sessions": [_session()], "first_run": False, "truncated": False},
                                failed_chunks=1)
        self.assertEqual(advanced, [])

    def test_a_session_the_slicer_declined_also_holds_the_cutoff(self):
        # Dropped-before-send counts no failed chunk, so the delivered count is the guard.
        _, advanced = self._run(
            {"sessions": [_session("S1"), _session("S2")], "first_run": False, "truncated": False},
            failed_chunks=0, sent_override=1)
        self.assertEqual(advanced, [])

    def test_a_capped_walk_resumes_where_it_stopped(self):
        # Advancing to now would skip the files it never reached; holding the cutoff
        # outright would re-read the same ones every run and never reach them either.
        _, advanced = self._run({"sessions": [_session()], "first_run": False,
                                 "truncated": True, "resume_at": 1789900100})
        self.assertEqual(len(advanced), 1)
        self.assertEqual(advanced[0][1], 1789900100)

    def test_a_capped_walk_with_nothing_finished_holds_the_cutoff(self):
        _, advanced = self._run({"sessions": [_session()], "first_run": False,
                                 "truncated": True, "resume_at": None})
        self.assertEqual(advanced, [])

    def test_nothing_collected_uploads_nothing(self):
        uploads, advanced = self._run({"sessions": [], "first_run": True, "truncated": False})
        self.assertEqual(uploads, [])
        self.assertEqual(advanced, [])

    def test_the_env_kill_switch_stops_the_sweep(self):
        uploads, _ = self._run({"sessions": [_session()], "first_run": False, "truncated": False},
                               env={"UNBOUND_VS_SWEEP_DISABLED": "1"})
        self.assertEqual(uploads, [])

    def test_nothing_runs_off_windows(self):
        uploads = []
        with patch.object(mdm.platform, "system", return_value="Darwin"), \
                patch.object(mdm, "_backfill_send_sessions",
                             lambda *a, **k: uploads.append(a) or (0, 0, 0)):
            mdm.run_visual_studio_sweep("key", "https://backend", HOMES)
        self.assertEqual(uploads, [])


if __name__ == "__main__":
    unittest.main()
