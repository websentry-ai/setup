"""WEB-6392: every backfill run ends with one upload saying how it ended (outcome, failed uploads), and a run
that could not send that leaves it on disk for the next run to send as previous_outcome. Both uploaders: the
MDM one (all profiles, run clock) and the per-user one. The network is faked at the HTTP layer only."""

import io
import json
import shutil
import tempfile
import time
import unittest
from contextlib import ExitStack, redirect_stdout
from pathlib import Path
from unittest.mock import patch

from tests.conftest import tool_module

mdm = tool_module("claude-code/hooks/mdm", "setup")
setup = tool_module("claude-code/hooks", "setup")


class _Backend:
    """Records each uploaded body. fail_puts: the PUTs (by index) S3 refuses; down: every request fails."""

    def __init__(self, fail_puts=(), down=False):
        self.bodies, self.fail_puts, self.down, self.puts = [], set(fail_puts), down, 0

    def __call__(self, url, method, headers, body=None, timeout=30):
        if self.down:
            return -7, b""  # curl: could not connect
        if url.endswith("/upload-url/"):
            return 200, json.dumps({"upload_url": "https://s3/put", "object_key": "k"}).encode()
        if method == "PUT":
            self.puts += 1
            if self.puts - 1 in self.fail_puts:
                return 403, b"denied"
            self.bodies.append(json.loads(body.decode("utf-8")))
        return 200, b"{}"

    def stats(self):
        return [b["uploader_stats"] for b in self.bodies if "outcome" in b.get("uploader_stats", {})]


def _run(up, home, backend, more=()):
    with ExitStack() as stack:
        for ctx in (patch.object(up, "_backfill_http_request", side_effect=backend),
                    patch.object(up, "_backfill_force_config", return_value=(None, None)),
                    patch.object(up, "_backfill_account_email", return_value=None),
                    patch.object(up, "get_device_identifier", return_value="SERIAL"),
                    patch.object(up.time, "sleep", lambda s: None),
                    redirect_stdout(io.StringIO()), *more):
            stack.enter_context(ctx)
        if up is mdm:
            stack.enter_context(patch.object(mdm, "_run_as_user", side_effect=lambda u, fn, *a, **k: fn(*a, **k)))
            mdm.run_backfill("key", "https://backend", [("alice", home)])
        else:
            stack.enter_context(patch.object(setup.Path, "home", return_value=home))
            setup.run_backfill("key", "https://backend", home / ".claude")
    return backend


class _Homes(unittest.TestCase):

    def _home(self, sessions=("a",)):
        home = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, home)
        projects = home / ".claude" / "projects" / "p"
        projects.mkdir(parents=True)
        for sid in sessions:
            (projects / f"{sid}.jsonl").write_text(json.dumps({"type": "user", "sessionId": sid}) + "\n")
        return home


class EveryRunReportsHowItEndedTestCase(_Homes):

    def test_a_clean_run_ends_with_completed(self):
        for up in (mdm, setup):
            with self.subTest(up.__name__):
                backend = _run(up, self._home(("a", "b")), _Backend())
                [stats] = backend.stats()
                self.assertEqual((stats["outcome"], stats["uploads_failed"]), ("completed", 0))
                self.assertNotIn("previous_outcome", stats)
                self.assertIs(backend.bodies[-1]["uploader_stats"], stats)
                self.assertEqual(backend.bodies[-1]["sessions"], [])
                # The walk's counts ride along, as before.
                self.assertEqual(stats["files_seen"], 2)

    def test_a_run_with_nothing_to_send_still_reports(self):
        for up in (mdm, setup):
            with self.subTest(up.__name__):
                backend = _run(up, self._home(()), _Backend())
                self.assertEqual([s["outcome"] for s in backend.stats()], ["completed"])

    def test_a_failed_upload_ends_with_failed_and_counts_it(self):
        for up in (mdm, setup):
            with self.subTest(up.__name__):
                backend = _run(up, self._home(("a",)), _Backend(fail_puts={0}))
                [stats] = backend.stats()
                self.assertEqual((stats["outcome"], stats["uploads_failed"]), ("failed", 1))

    def test_an_mdm_run_out_of_time_ends_with_stopped_by_time_limit(self):
        backend = _run(mdm, self._home(("a",)), _Backend(),
                       [patch.object(mdm._BackfillRun, "has_time_for_a_batch", return_value=False)])
        self.assertEqual([b["sessions"] for b in backend.bodies], [[]])
        [stats] = backend.stats()
        self.assertEqual(stats["outcome"], "stopped_by_time_limit")
        # No time to walk every transcript either: the outcome goes up without the counts.
        self.assertNotIn("files_seen", stats)

    def test_the_mdm_run_keeps_time_back_for_its_closing_report(self):
        # 100s before the soft stop: an old run started one more batch here; now that time is the report's.
        start = time.time() - (mdm.BACKFILL_SOFT_STOP_SECONDS - 100)
        backend = _run(mdm, self._home(("a",)), _Backend(), [patch.object(mdm, "_SCRIPT_START", start)])
        self.assertEqual([b["sessions"] for b in backend.bodies], [[]])
        self.assertEqual([s["outcome"] for s in backend.stats()], ["stopped_by_time_limit"])

    def test_data_uploads_carry_no_outcome(self):
        for up in (mdm, setup):
            with self.subTest(up.__name__):
                backend = _run(up, self._home(("a", "b")), _Backend())
                self.assertTrue(all("outcome" not in b.get("uploader_stats", {}) for b in backend.bodies[:-1]))


class AnUnsentOutcomeGoesUpNextRunTestCase(_Homes):

    def test_an_outcome_that_could_not_be_sent_is_sent_once_by_the_next_run(self):
        for up in (mdm, setup):
            with self.subTest(up.__name__):
                home = self._home(("a",))
                self.assertEqual(_run(up, home, _Backend(down=True)).bodies, [])
                [second] = _run(up, home, _Backend()).stats()
                self.assertEqual((second["outcome"], second["previous_outcome"]), ("completed", "failed"))
                [third] = _run(up, home, _Backend()).stats()
                self.assertNotIn("previous_outcome", third)

    def test_an_mdm_run_killed_before_it_reported_reads_as_stopped_by_time_limit(self):
        home = self._home(("a",))

        class Killed(BaseException):
            """The hard deadline's SIGKILL: nothing after it runs."""

        with self.assertRaises(Killed):
            _run(mdm, home, _Backend(), [patch.object(mdm, "_backfill_drain_home", side_effect=Killed)])
        [stats] = _run(mdm, home, _Backend()).stats()
        self.assertEqual(stats["previous_outcome"], "stopped_by_time_limit")

    def test_a_garbled_saved_outcome_is_not_sent(self):
        for up in (mdm, setup):
            with self.subTest(up.__name__):
                home = self._home(("a",))
                hooks = home / ".claude" / "hooks"
                hooks.mkdir(parents=True, exist_ok=True)
                (hooks / up.BACKFILL_OUTCOME_FILE).write_text("exploded\n")
                [stats] = _run(up, home, _Backend()).stats()
                self.assertNotIn("previous_outcome", stats)


if __name__ == "__main__":
    unittest.main()
