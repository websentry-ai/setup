"""Cowork skill runs resolve to the SKILL.md the discovery scanner reports.

Cowork keeps skills under Claude Desktop's local-agent-mode-sessions tree, not in
any Claude Code skills dir. Without these paths every Cowork run reported no path
and no hash, so the backend could never tie it to a discovered body.
"""

import hashlib
import os
import re
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

    def plugin(self, name, text="# plugin", org=None, age=0, plugin="plugin_01", declares="gtm-skills"):
        root = (org or self.org) / "rpm" / plugin
        _write(root / ".claude-plugin" / "plugin.json", '{"name": "%s"}' % declares)
        return _write(root / "skills" / name / "SKILL.md", text, age)

    def resolve(self, skill, cwd=None, transcript_path=None):
        return unbound._resolve_skill_path(skill, str(cwd or self.cwd), transcript_path)


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


class TestCoworkSkillIdentity(_CoworkTree):
    """The prefix names the skill's source; a run is never tied to a different skill
    that merely shares its name."""

    def test_bundled_prefix_ignores_a_newer_org_plugin_of_the_same_name(self):
        bundled = self.bundle("b1", "xlsx", age=3600)
        self.plugin("xlsx")
        self.assertEqual(self.resolve("anthropic-skills:xlsx"), str(bundled))

    def test_plugin_prefix_ignores_the_bundle(self):
        self.bundle("b1", "review")
        plugin = self.plugin("review", age=3600)
        self.assertEqual(self.resolve("gtm-skills:review"), str(plugin))

    def test_prefix_resolves_only_the_plugin_that_declares_it(self):
        self.plugin("review", plugin="plugin_01", declares="other-skills")
        mine = self.plugin("review", plugin="plugin_02", age=3600)
        self.assertEqual(self.resolve("gtm-skills:review"), str(mine))

    def test_prefix_no_plugin_declares_resolves_nothing(self):
        self.plugin("review", declares="other-skills")
        self.assertIsNone(self.resolve("gtm-skills:review"))

    def test_two_org_plugins_sharing_a_name_resolve_nothing(self):
        self.plugin("review", plugin="plugin_01")
        self.plugin("review", plugin="plugin_02")
        self.assertIsNone(self.resolve("gtm-skills:review"))

    def test_bare_name_in_bundle_and_plugin_resolves_nothing(self):
        self.bundle("b1", "review")
        self.plugin("review")
        self.assertIsNone(self.resolve("review"))

    def test_the_sessions_own_copy_wins_for_a_bare_name(self):
        self.bundle("b1", "xlsx")
        own = _write(self.cwd.parent / ".claude" / "skills" / "xlsx" / "SKILL.md", "# mine", age=3600)
        self.assertEqual(self.resolve("xlsx"), str(own))

    def test_a_prefixed_call_never_takes_the_sessions_own_copy(self):
        bundled = self.bundle("b1", "xlsx", age=3600)
        _write(self.cwd.parent / ".claude" / "skills" / "xlsx" / "SKILL.md", "# mine")
        self.assertEqual(self.resolve("anthropic-skills:xlsx"), str(bundled))

    def test_session_found_from_the_transcript_when_cwd_is_elsewhere(self):
        skill = self.bundle("b1", "xlsx")
        elsewhere = Path(self._tmp.name) / "picked-folder"
        elsewhere.mkdir()
        transcript = self.cwd.parent / ".claude" / "projects" / "p" / "s1.jsonl"
        _write(transcript, "{}")
        self.assertEqual(
            self.resolve("anthropic-skills:xlsx", cwd=elsewhere, transcript_path=str(transcript)),
            str(skill))


class TestCoworkRunInAPickedFolder(_CoworkTree):
    """A run working in a folder the user picked: cwd is outside the sandbox and the
    transcript sits in a temp dir, named by a slug of the session's outputs path."""

    def transcript(self):
        slug = re.sub(r"[^A-Za-z0-9]", "-", str(self.cwd))
        return str(Path(self._tmp.name) / "claude-hostloop-plugins" / "h" / "projects" / slug / "s.jsonl")

    def test_session_recovered_from_the_temp_transcript_slug(self):
        skill = self.bundle("b1", "xlsx")
        picked = Path(self._tmp.name) / "picked"
        picked.mkdir()
        self.assertEqual(
            self.resolve("anthropic-skills:xlsx", cwd=picked, transcript_path=self.transcript()),
            str(skill))

    def test_a_longer_session_id_never_matches_a_shorter_one(self):
        skill = self.bundle("b1", "xlsx")
        longer = self.org / "local_abc_extra" / "outputs"
        longer.mkdir(parents=True)
        picked = Path(self._tmp.name) / "picked"
        picked.mkdir()
        transcript = str(Path(self._tmp.name) / "projects" / re.sub(r"[^A-Za-z0-9]", "-", str(longer)) / "s.jsonl")
        self.assertEqual(self.resolve("anthropic-skills:xlsx", cwd=picked, transcript_path=transcript), str(skill))
        # Only the shorter session left: the longer one's transcript names no session.
        longer.rmdir()
        longer.parent.rmdir()
        self.assertIsNone(self.resolve("anthropic-skills:xlsx", cwd=picked, transcript_path=transcript))

    def test_a_slug_naming_no_real_session_resolves_nothing(self):
        self.bundle("b1", "xlsx")
        fake = str(Path(self._tmp.name) / "projects" / "-x-local-agent-mode-sessions-a-b-local-zz-outputs" / "s.jsonl")
        picked = Path(self._tmp.name) / "picked"
        picked.mkdir()
        self.assertIsNone(self.resolve("xlsx", cwd=picked, transcript_path=fake))

    def test_an_undefined_transcript_never_shadows_the_real_one(self):
        skill = self.bundle("b1", "xlsx")
        picked = Path(self._tmp.name) / "picked"
        picked.mkdir()
        base = {"session_id": "s1", "cwd": str(picked)}
        events = [
            dict(base, hook_event_name="UserPromptSubmit", prompt="sheet", transcript_path="undefined"),
            dict(base, hook_event_name="PostToolUse", tool_name="Skill", transcript_path=self.transcript(),
                 tool_input={"skill": "anthropic-skills:xlsx"}, tool_response={}),
        ]
        exchange = unbound.build_llm_exchange(
            [{"timestamp": "2026-10-06T10:00:0%dZ" % i, "session_id": "s1", "event": e} for i, e in enumerate(events)],
            stop_assistant_message="done", cwd=str(picked))
        tool_uses = [t for m in exchange["messages"] for t in m.get("tool_use", [])]
        entry = next(t for t in tool_uses if t["tool_name"] == "Skill")
        self.assertEqual(entry["skill_path"], str(skill))

    def test_typed_skill_uses_the_session_transcript(self):
        content = "---\nname: xlsx\n---\nMake spreadsheets.\n"
        skill = self.bundle("b1", "xlsx", content)
        picked = Path(self._tmp.name) / "picked"
        picked.mkdir()
        prompt = {"hook_event_name": "UserPromptSubmit", "session_id": "s1", "cwd": str(picked),
                  "transcript_path": self.transcript(), "prompt": "/xlsx build it"}
        exchange = unbound.build_llm_exchange(
            [{"timestamp": "2026-10-06T10:00:00Z", "session_id": "s1", "event": prompt}],
            stop_assistant_message="done", cwd=str(picked))
        tool_uses = [t for m in exchange["messages"] for t in m.get("tool_use", [])]
        entry = next(t for t in tool_uses if t["tool_name"] == "Skill")
        self.assertEqual(entry["skill_path"], str(skill))


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
