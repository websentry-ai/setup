"""The backfill uploads a session's subagent usage with the session, as the live hook bills it.

Claude Code writes a subagent's replies under <session>/subagents/, never in the main
transcript. Sent as files of their own they reached the server without the turn that ran
them, so it dropped them; bundled with the session, the server bills each to its turn.
"""

import json
import shutil
import tempfile
import unittest
from pathlib import Path

from tests.conftest import tool_module

uploaders = (tool_module("claude-code/hooks/mdm", "setup"), tool_module("claude-code/hooks", "setup"))
CASES = Path(__file__).resolve().parents[2] / "fixtures" / "claude_code_usage" / "cases"


class BackfillSubagentsTestCase(unittest.TestCase):

    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name) / "projects"
        for case in ("subagent_files", "multiline_replies"):
            shutil.copytree(CASES / case, self.root / case)
        self.with_agents = self.root / "subagent_files" / "subagent-files.jsonl"
        self.without = self.root / "multiline_replies" / "multiline-replies.jsonl"

    def test_the_walk_leaves_subagent_files_to_their_session(self):
        for up in uploaders:
            with self.subTest(up.__name__):
                walked = sorted(p.name for p in up._backfill_iter_transcripts(self.root, 0))
                self.assertEqual(walked, ["multiline-replies.jsonl", "subagent-files.jsonl"])

    def test_a_session_carries_its_subagent_usage_and_no_content(self):
        for up in uploaders:
            with self.subTest(up.__name__):
                session = up._backfill_collect_session(self.with_agents)
                records = session["subagents"]
                self.assertEqual([r["message"]["id"] for r in records], ["msg_s1", "msg_s2", "msg_s3"])
                # The reply's first line's time, and nothing a person wrote or read.
                self.assertEqual(records[0]["timestamp"], "2026-09-01T10:10:05.000Z")
                self.assertEqual({k for r in records for k in r}, {"type", "timestamp", "isSidechain", "message"})
                self.assertEqual({k for r in records for k in r["message"]}, {"id", "usage"})

    def test_a_session_without_subagents_is_sent_as_before(self):
        for up in uploaders:
            with self.subTest(up.__name__):
                self.assertNotIn("subagents", up._backfill_collect_session(self.without))

    def test_a_sliced_session_sends_each_reply_once_with_the_turn_that_ran_it(self):
        for up in uploaders:
            with self.subTest(up.__name__):
                session = up._backfill_collect_session(self.with_agents)
                whole = len(json.dumps(session).encode("utf-8"))
                slices = list(up._backfill_slice_session(session, whole - 1))
                self.assertEqual(len(slices), 2)
                self.assertTrue(all(len(json.dumps(s).encode("utf-8")) <= whole - 1 for s in slices))
                # The research agent ran inside the first turn; the background reply first appeared after it ended.
                self.assertEqual([[r["message"]["id"] for r in s.get("subagents", [])] for s in slices],
                                 [["msg_s1", "msg_s2"], ["msg_s3"]])

    def test_a_reply_after_every_turn_rides_with_the_last_slice(self):
        for up in uploaders:
            with self.subTest(up.__name__):
                session = up._backfill_collect_session(self.with_agents)
                late = dict(session["subagents"][-1], timestamp="2026-09-01T11:00:00.000Z")
                late["message"] = dict(late["message"], id="msg_late")
                session["subagents"].append(late)
                slices = list(up._backfill_slice_session(session, len(json.dumps(session).encode("utf-8")) - 1))
                self.assertEqual(slices[-1]["subagents"][-1]["message"]["id"], "msg_late")


if __name__ == "__main__":
    unittest.main()
