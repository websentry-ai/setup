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

    # ------------------------------------------------------------------ hostile and unusual subagent files

    def _agent_file(self, lines, name="agent-extra.jsonl"):
        subdir = self.with_agents.with_suffix("") / "subagents"
        subdir.mkdir(parents=True, exist_ok=True)
        (subdir / name).write_text("".join(json.dumps(line) + "\n" for line in lines))

    @staticmethod
    def _reply(reply_id, ts, output, advisors=()):
        usage = {"input_tokens": 1, "output_tokens": output}
        if advisors:
            usage["iterations"] = [{"type": "advisor_message", "model": "claude-opus-4-1", "output_tokens": n}
                                   for n in advisors]
        line = {"type": "assistant", "isSidechain": True, "message": {"id": reply_id, "usage": usage}}
        if ts is not None:
            line["timestamp"] = ts
        return line

    def test_mixed_timestamp_shapes_never_cost_the_session(self):
        self._agent_file([self._reply("msg_naive", "2026-09-01T10:20:00.000", 3),
                          self._reply("msg_naive", "2026-09-01T10:19:00.000Z", 4),
                          self._reply("msg_epoch", 1788257000000, 5),
                          self._reply("msg_untimed", None, 6)])
        for up in uploaders:
            with self.subTest(up.__name__):
                session = up._backfill_collect_session(self.with_agents)
                by_id = {r["message"]["id"]: r for r in session["subagents"]}
                self.assertEqual(by_id["msg_naive"]["timestamp"], "2026-09-01T10:19:00.000Z")
                # Epoch milliseconds, which the live hook accepts, reach the server as a time it can read.
                self.assertEqual(by_id["msg_epoch"]["timestamp"], "2026-09-01T10:03:20Z")
                self.assertEqual(session["subagents"][-1]["message"]["id"], "msg_untimed")
                list(up._backfill_slice_session(session, len(json.dumps(session).encode("utf-8")) // 2))

    def test_an_unreadable_subagent_dir_still_uploads_the_session(self):
        for up in uploaders:
            with self.subTest(up.__name__):
                original = up._backfill_subagent_usage
                up._backfill_subagent_usage = lambda path: 1 / 0
                try:
                    session = up._backfill_collect_session(self.with_agents)
                finally:
                    up._backfill_subagent_usage = original
                self.assertTrue(session["entries"])
                self.assertNotIn("subagents", session)

    def test_a_later_copy_that_adds_advisor_usage_keeps_it(self):
        # Same top-level usage on both copies; only the later one carries the advisor turn.
        self._agent_file([self._reply("msg_adv", "2026-09-01T10:21:00.000Z", 7),
                          self._reply("msg_adv", "2026-09-01T10:21:01.000Z", 7, advisors=(40,))])
        for up in uploaders:
            with self.subTest(up.__name__):
                [record] = [r for r in up._backfill_collect_session(self.with_agents)["subagents"]
                            if r["message"]["id"] == "msg_adv"]
                self.assertEqual([it["output_tokens"] for it in record["message"]["usage"]["iterations"]], [40])

    def test_the_reply_cap_holds_while_reading(self):
        self._agent_file([self._reply(f"msg_cap{i}", "2026-09-01T10:30:00.000Z", 1) for i in range(5)])
        for up in uploaders:
            with self.subTest(up.__name__):
                cap = up.BACKFILL_MAX_SUBAGENT_REPLIES
                up.BACKFILL_MAX_SUBAGENT_REPLIES = 4
                try:
                    records = up._backfill_collect_session(self.with_agents)["subagents"]
                finally:
                    up.BACKFILL_MAX_SUBAGENT_REPLIES = cap
                self.assertEqual(len(records), 4)

    def test_subagent_usage_counts_toward_the_mdm_batch_budget(self):
        mdm = uploaders[0]
        self._agent_file([self._reply(f"msg_heavy{i}", "2026-09-01T10:30:00.000Z", 1) for i in range(200)])
        stamped = [(1.0, 10, self.with_agents), (2.0, 10, self.without)]
        budget = mdm.BACKFILL_BATCH_BYTES
        mdm.BACKFILL_BATCH_BYTES = 1000
        try:
            sessions, capped = mdm._backfill_read_batch(stamped)
        finally:
            mdm.BACKFILL_BATCH_BYTES = budget
        self.assertEqual(len(sessions), 1)
        self.assertEqual(capped, (1.0, str(self.with_agents)))


if __name__ == "__main__":
    unittest.main()
