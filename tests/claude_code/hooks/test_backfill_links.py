"""The backfill never follows a link out of a home's history: a symlink anywhere, or a Windows junction.

Junctions can't be created off Windows, so they are simulated by reporting a junction's reparse tag from
os.lstat for chosen paths, which is what the uploader reads on Python 3.11.
"""

import json
import os
import shutil
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from tests.conftest import tool_module

uploaders = (tool_module("claude-code/hooks/mdm", "setup"), tool_module("claude-code/hooks", "setup"))
CASES = Path(__file__).resolve().parents[2] / "fixtures" / "claude_code_usage" / "cases"
JUNCTION_TAG = 0xA0000003


class BackfillLinksTestCase(unittest.TestCase):

    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name) / "projects"
        shutil.copytree(CASES / "subagent_files", self.root / "proj")
        self.session = self.root / "proj" / "subagent-files.jsonl"
        self.subagents = self.session.with_suffix("") / "subagents"
        # A folder outside the session that a junction would point into.
        self.outside = self.root / "proj" / "elsewhere"
        self.outside.mkdir()
        (self.outside / "agent-outside.jsonl").write_text(json.dumps({
            "type": "assistant", "timestamp": "2026-09-01T10:10:06.000Z", "isSidechain": True,
            "message": {"id": "msg_OUTSIDE", "usage": {"input_tokens": 1, "output_tokens": 999}}}) + "\n")

    def _as_junction(self, *junctions, tag=JUNCTION_TAG):
        """os.lstat reports a reparse tag for these paths, as Windows does."""
        real_lstat, marked = os.lstat, {str(p) for p in junctions}

        def lstat(path, *args, **kwargs):
            result = real_lstat(path, *args, **kwargs)
            if str(path) in marked:
                return mock.Mock(wraps=result, st_reparse_tag=tag, st_mode=result.st_mode)
            return result
        return mock.patch("os.lstat", side_effect=lstat)

    def test_a_junction_reads_as_a_link(self):
        for up in uploaders:
            with self.subTest(up.__name__), self._as_junction(self.outside):
                self.assertTrue(up._is_reparse_point(self.outside))
                self.assertFalse(up._is_reparse_point(self.subagents))

    def test_a_junction_inside_subagents_is_not_followed(self):
        # The junction sits under subagents/ and leads to the outside folder's files.
        shutil.copytree(self.outside, self.subagents / "linked")
        for up in uploaders:
            with self.subTest(up.__name__), self._as_junction(self.subagents / "linked"):
                ids = [r["message"]["id"] for r in up._backfill_collect_session(self.session)["subagents"]]
                self.assertNotIn("msg_OUTSIDE", ids)
                self.assertEqual(ids, ["msg_s1", "msg_s2", "msg_s3"])

    def test_a_junctioned_subagents_dir_is_not_followed(self):
        for up in uploaders:
            with self.subTest(up.__name__), self._as_junction(self.subagents):
                self.assertNotIn("subagents", up._backfill_collect_session(self.session))

    def test_the_transcript_walk_does_not_enter_a_junction(self):
        for up in uploaders:
            with self.subTest(up.__name__), self._as_junction(self.outside):
                walked = sorted(p.name for p in up._backfill_iter_transcripts(self.root, 0))
                self.assertEqual(walked, ["subagent-files.jsonl"])

    def test_without_links_everything_is_still_walked(self):
        for up in uploaders:
            with self.subTest(up.__name__):
                walked = sorted(p.name for p in up._backfill_iter_transcripts(self.root, 0))
                self.assertEqual(walked, ["agent-outside.jsonl", "subagent-files.jsonl"])

    def test_a_missing_path_is_not_a_link(self):
        # A fresh install checks settings files that don't exist yet.
        for up in uploaders:
            with self.subTest(up.__name__):
                self.assertFalse(up._is_reparse_point(self.root / "not-there.json"))

    def test_every_redirecting_reparse_tag_is_a_link_and_a_placeholder_is_not(self):
        for up in uploaders:
            for tag, linked in ((0xA000001D, True), (0xA000000C, True), (0x9000701A, False)):
                with self.subTest(up.__name__, tag=hex(tag)), self._as_junction(self.outside, tag=tag):
                    self.assertIs(up._is_reparse_point(self.outside), linked)

    def test_a_linked_session_folder_is_not_read_for_subagents(self):
        for up in uploaders:
            with self.subTest(up.__name__), self._as_junction(self.session.with_suffix("")):
                self.assertNotIn("subagents", up._backfill_collect_session(self.session))

    def test_a_linked_claude_folder_is_not_walked_by_the_mdm_uploader_on_windows(self):
        # Only the MDM uploader reads as SYSTEM; the per-user one reads as its own user, so a moved .claude still works.
        home = Path(self.root).parent / "home"
        shutil.copytree(self.root, home / ".claude" / "projects")
        mdm = uploaders[0]
        for system, sessions in (("Windows", 0), ("Darwin", 1)):
            with self.subTest(system), self._as_junction(home / ".claude"), \
                    mock.patch.object(mdm.platform, "system", return_value=system):
                found, _, _ = mdm._backfill_collect_sessions(home)
                self.assertEqual(len(found), sessions)
        with self._as_junction(home / ".claude" / "projects"), \
                mock.patch.object(mdm.platform, "system", return_value="Windows"):
            self.assertEqual(mdm._backfill_collect_sessions(home)[0], [])


if __name__ == "__main__":
    unittest.main()
