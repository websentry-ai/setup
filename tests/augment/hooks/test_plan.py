"""The Augment plan comes from `auggie account status`, the only place Auggie
reports it. The call takes seconds, so SessionStart makes it and turns read a
day-long cache keyed to the account."""

import json
import unittest
from unittest.mock import Mock, patch

from tests.conftest import tool_module

unbound = tool_module("augment/hooks")
# Taken before conftest stubs it for each test.
REAL_FETCH = unbound._fetch_augment_plan


class TestAugmentPlan(unittest.TestCase):
    def _plan(self, fetched, email="dev@acme.com", probe=True):
        with patch.object(unbound, "_fetch_augment_plan", return_value=fetched) as fetch:
            return unbound._augment_plan(email, probe), fetch

    def test_reads_the_plan(self):
        self.assertEqual(self._plan("Business Plan")[0], "Business Plan")

    def test_a_turn_never_runs_the_cli(self):
        plan, fetch = self._plan("Business Plan", probe=False)
        self.assertIsNone(plan)
        fetch.assert_not_called()

    def test_a_turn_reads_what_session_start_cached(self):
        self._plan("Business Plan")
        plan, fetch = self._plan(None, probe=False)
        self.assertEqual(plan, "Business Plan")
        fetch.assert_not_called()

    def test_another_accounts_plan_is_not_served(self):
        self._plan("Business Plan", email="dev@acme.com")
        self.assertIsNone(self._plan(None, email="other@acme.com", probe=False)[0])

    def test_a_miss_is_cached_so_the_cli_is_not_rerun(self):
        self._plan(None)
        plan, fetch = self._plan("Business Plan")
        self.assertIsNone(plan)
        fetch.assert_not_called()

    def test_a_failed_cli_reports_nothing(self):
        with patch.object(unbound, "_fetch_augment_plan", side_effect=OSError("boom")):
            self.assertIsNone(unbound._augment_plan("dev@acme.com", True))

    def test_the_cli_output_is_parsed(self):
        out = json.dumps({"planName": " Business Plan ", "amountRemaining": "1"}).encode()
        done = Mock(returncode=0, stdout=out)
        with patch.object(unbound.shutil, "which", return_value="/usr/bin/auggie"), \
                patch.object(unbound.subprocess, "run", return_value=done) as run:
            self.assertEqual(REAL_FETCH(), "Business Plan")
        self.assertEqual(run.call_args[0][0][1:], ["account", "status", "--json"])

    def test_no_cli_means_no_plan(self):
        with patch.object(unbound.shutil, "which", return_value=None):
            self.assertIsNone(REAL_FETCH())

    def test_the_identity_carries_the_cached_plan(self):
        self._plan("Business Plan", email="dev@acme.com")
        with patch.object(unbound, "read_account_identity",
                          return_value={"user_email": "dev@acme.com"}), \
                patch.object(unbound, "_device_serial", return_value=None):
            self.assertEqual(unbound.build_account_identity(probe=True)["plan"], "Business Plan")


if __name__ == "__main__":
    unittest.main()
