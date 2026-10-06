"""Cowork skill runs resolve to the SKILL.md the discovery scanner reports.

Cowork keeps skills under Claude Desktop's local-agent-mode-sessions tree, not in
any Claude Code skills dir. Without these paths every Cowork run reported no path
and no hash, so the backend could never tie it to a discovered body.
"""

import hashlib
import os
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch

from tests.conftest import tool_module

unbound = tool_module("claude-code/hooks")


def _write(path, text, age=0):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text)
    stamp = time.time() - age
    os.utime(path, (stamp, stamp))
    return path


class _CoworkTree(unittest.TestCase):

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.support = Path(self._tmp.name).resolve() / "Claude"
        self.root = self.support / "local-agent-mode-sessions"
        self.org = self.root / "acct-1" / "org-1"
        self.cwd = self.org / "local_abc" / "outputs"
        self.cwd.mkdir(parents=True)
        patcher = patch.object(unbound, "_claude_desktop_support_dirs", return_value=[self.support])
        patcher.start()
        self.addCleanup(patcher.stop)
        self.addCleanup(self._tmp.cleanup)

    def bundle(self, bundle, name, text="# bundled", age=0):
        return _write(self.root / "skills-plugin" / bundle / "v" / "skills" / name / "SKILL.md", text, age)

    def plugin(self, name, text="# plugin", org=None, age=0):
        base = org or self.org
        return _write(base / "rpm" / "plugin_01" / "skills" / name / "SKILL.md", text, age)

    def resolve(self, skill, cwd=None):
        return unbound._resolve_skill_path(skill, str(cwd or self.cwd))


class TestCoworkSkillResolution(_CoworkTree):

    def test_anthropic_skill_resolves_to_the_newest_bundle_copy(self):
        self.bundle("b-old", "xlsx", "# old", age=3600)
        newest = self.bundle("b-new", "xlsx", "# new")
        self.assertEqual(self.resolve("anthropic-skills:xlsx"), str(newest))

    def test_bare_name_resolves_too(self):
        skill = self.bundle("b1", "docx")
        self.assertEqual(self.resolve("docx"), str(skill))

    def test_org_plugin_skill_resolves_under_the_session_org(self):
        skill = self.plugin("cs-comms-coach")
        self.assertEqual(self.resolve("gtm-skills:cs-comms-coach"), str(skill))

    def test_another_orgs_plugin_is_not_used(self):
        self.plugin("cs-comms-coach", org=self.root / "acct-1" / "org-2")
        self.assertIsNone(self.resolve("gtm-skills:cs-comms-coach"))

    def test_a_run_outside_cowork_never_picks_a_cowork_copy(self):
        cowork_copy = self.bundle("b1", "xlsx")
        elsewhere = Path(self._tmp.name) / "repo"
        elsewhere.mkdir()
        self.assertNotEqual(self.resolve("anthropic-skills:xlsx", cwd=elsewhere), str(cowork_copy))

    def test_a_claude_code_copy_is_never_used_for_a_cowork_run(self):
        cc_skills = Path(self._tmp.name) / "cc" / "skills"
        _write(cc_skills / "xlsx" / "SKILL.md", "# claude code copy")
        with patch.object(unbound, "CLAUDE_SKILLS_ROOT", cc_skills):
            self.assertIsNone(self.resolve("xlsx"))
            cowork_copy = self.bundle("b1", "xlsx")
            self.assertEqual(self.resolve("xlsx"), str(cowork_copy))


class TestCoworkSkillRunCarriesPathAndHash(_CoworkTree):
    """End to end through the hook's turn builder: the Skill call it sends upstream."""

    def test_skill_call_carries_the_resolved_path_and_the_scanner_hash(self):
        content = "---\nname: xlsx\n---\nMake spreadsheets.\n"
        skill = self.bundle("b1", "xlsx", content)
        event = {
            "hook_event_name": "PostToolUse", "session_id": "s1", "cwd": str(self.cwd),
            "tool_name": "Skill", "tool_input": {"skill": "anthropic-skills:xlsx"},
            "tool_response": {},
        }
        prompt = {"hook_event_name": "UserPromptSubmit", "session_id": "s1",
                  "cwd": str(self.cwd), "prompt": "make the sheet"}
        exchange = unbound.build_llm_exchange(
            [{"timestamp": "2026-10-06T10:00:00Z", "session_id": "s1", "event": prompt},
             {"timestamp": "2026-10-06T10:00:05Z", "session_id": "s1", "event": event}],
            stop_assistant_message="done", cwd=str(self.cwd))

        tool_uses = [t for m in exchange["messages"] for t in m.get("tool_use", [])]
        entry = next(t for t in tool_uses if t["tool_name"] == "Skill")
        self.assertEqual(entry["skill_path"], str(skill))
        # The discovery scanner's recipe for the same file: sha256("SKILL.md:" + content).
        expected = hashlib.sha256(("SKILL.md:" + content).encode("utf-8")).hexdigest()
        self.assertEqual(entry["content_hash"], expected)


if __name__ == "__main__":
    unittest.main()
