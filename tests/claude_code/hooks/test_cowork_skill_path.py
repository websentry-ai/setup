"""Cowork skill runs resolve to the SKILL.md the discovery scanner reports.

Cowork keeps skills under Claude Desktop's local-agent-mode-sessions tree, not in
any Claude Code skills dir. Without these paths every Cowork run reported no path
and no hash, so the backend could never tie it to a discovered body.
"""

import hashlib
import json
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

    def bundle(self, name, text="# bundled", age=0, org="org-1", account="acct-1"):
        """The account's bundled skill, at skills-plugin/<org>/<account> as Cowork keeps it."""
        return _write(self.root / "skills-plugin" / org / account / "skills" / name / "SKILL.md", text, age)

    def plugin(self, name, text="# plugin", org=None, age=0, plugin="plugin_01", declares="gtm-skills"):
        root = (org or self.org) / "rpm" / plugin
        _write(root / ".claude-plugin" / "plugin.json", '{"name": "%s"}' % declares)
        return _write(root / "skills" / name / "SKILL.md", text, age)

    def resolve(self, skill, cwd=None, transcript_path=None):
        return unbound._resolve_skill_path(skill, str(cwd or self.cwd), transcript_path)


class TestCoworkSkillResolution(_CoworkTree):

    def test_anthropic_skill_resolves_to_the_accounts_bundle(self):
        skill = self.bundle("xlsx")
        self.assertEqual(self.resolve("anthropic-skills:xlsx"), str(skill))

    def test_bare_name_resolves_too(self):
        skill = self.bundle("docx")
        self.assertEqual(self.resolve("docx"), str(skill))

    def test_org_plugin_skill_resolves_under_the_session_org(self):
        skill = self.plugin("cs-comms-coach")
        self.assertEqual(self.resolve("gtm-skills:cs-comms-coach"), str(skill))

    def test_another_orgs_plugin_is_not_used(self):
        self.plugin("cs-comms-coach", org=self.root / "acct-1" / "org-2")
        self.assertIsNone(self.resolve("gtm-skills:cs-comms-coach"))

    def test_a_run_outside_cowork_never_picks_a_cowork_copy(self):
        cowork_copy = self.bundle("xlsx")
        elsewhere = Path(self._tmp.name) / "repo"
        elsewhere.mkdir()
        self.assertNotEqual(self.resolve("anthropic-skills:xlsx", cwd=elsewhere), str(cowork_copy))

    def test_a_claude_code_copy_is_never_used_for_a_cowork_run(self):
        cc_skills = Path(self._tmp.name) / "cc" / "skills"
        _write(cc_skills / "xlsx" / "SKILL.md", "# claude code copy")
        with patch.object(unbound, "CLAUDE_SKILLS_ROOT", cc_skills):
            self.assertIsNone(self.resolve("xlsx"))
            cowork_copy = self.bundle("xlsx")
            self.assertEqual(self.resolve("xlsx"), str(cowork_copy))


class TestCoworkSkillIdentity(_CoworkTree):
    """The prefix names the skill's source; a run is never tied to a different skill
    that merely shares its name."""

    def test_bundled_prefix_ignores_a_newer_org_plugin_of_the_same_name(self):
        bundled = self.bundle("xlsx", age=3600)
        self.plugin("xlsx")
        self.assertEqual(self.resolve("anthropic-skills:xlsx"), str(bundled))

    def test_plugin_prefix_ignores_the_bundle(self):
        self.bundle("review")
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

    def test_bare_name_in_bundle_and_plugin_is_the_bundles(self):
        bundled = self.bundle("review", age=3600)
        self.plugin("review")
        self.assertEqual(self.resolve("review"), str(bundled))

    def test_bare_name_in_two_plugins_only_resolves_nothing(self):
        self.plugin("review", plugin="plugin_01")
        self.plugin("review", plugin="plugin_02")
        self.assertIsNone(self.resolve("review"))

    def test_the_sessions_own_copy_wins_for_a_bare_name(self):
        self.bundle("xlsx")
        own = _write(self.cwd.parent / ".claude" / "skills" / "xlsx" / "SKILL.md", "# mine", age=3600)
        self.assertEqual(self.resolve("xlsx"), str(own))

    def test_a_prefixed_call_never_takes_the_sessions_own_copy(self):
        bundled = self.bundle("xlsx", age=3600)
        _write(self.cwd.parent / ".claude" / "skills" / "xlsx" / "SKILL.md", "# mine")
        self.assertEqual(self.resolve("anthropic-skills:xlsx"), str(bundled))

    def test_session_found_from_the_transcript_when_cwd_is_elsewhere(self):
        skill = self.bundle("xlsx")
        elsewhere = Path(self._tmp.name) / "picked-folder"
        elsewhere.mkdir()
        transcript = self.cwd.parent / ".claude" / "projects" / "p" / "s1.jsonl"
        _write(transcript, "{}")
        self.assertEqual(
            self.resolve("anthropic-skills:xlsx", cwd=elsewhere, transcript_path=str(transcript)),
            str(skill))


class TestCoworkGuardIsStructural(_CoworkTree):
    """Only Claude Desktop's real sessions tree marks a run as Cowork, never a folder name."""

    def test_claude_code_in_a_folder_merely_named_like_cowork_keeps_its_skills(self):
        cc_skills = Path(self._tmp.name) / "cc" / "skills"
        _write(cc_skills / "review" / "SKILL.md", "# review")
        repo = Path(self._tmp.name) / "work" / "local-agent-mode-sessions-tools"
        repo.mkdir(parents=True)
        with patch.object(unbound, "CLAUDE_SKILLS_ROOT", cc_skills):
            self.assertEqual(unbound._resolve_skill_path("review", str(repo)),
                             str(cc_skills / "review" / "SKILL.md"))


class TestCoworkBundleScope(_CoworkTree):
    """Several people can share one Mac, each with their own bundle under the org."""

    def test_a_colleagues_bundle_under_the_same_org_is_never_used(self):
        mine = self.bundle("xlsx", "# mine", age=3600)
        self.bundle("xlsx", "# theirs", account="acct-2")
        self.assertEqual(self.resolve("anthropic-skills:xlsx"), str(mine))

    def test_without_an_own_bundle_nothing_resolves(self):
        self.bundle("xlsx", "# theirs", account="acct-2")
        self.bundle("xlsx", "# other org", org="org-9", account="acct-1")
        self.assertIsNone(self.resolve("anthropic-skills:xlsx"))

    def test_a_bundle_in_session_order_is_not_the_accounts(self):
        _write(self.root / "skills-plugin" / "acct-1" / "org-1" / "skills" / "xlsx" / "SKILL.md", "# wrong order")
        self.assertIsNone(self.resolve("anthropic-skills:xlsx"))


class TestCoworkInstalledPlugins(_CoworkTree):
    """Plugins a user installs or uploads, laid out as Cowork keeps them, and recorded in
    installed_plugins.json the way Cowork records them (from inside its VM)."""

    def setUp(self):
        super().setUp()
        self.plugins_root = self.org / "cowork_plugins"
        self.registry = {}

    def _record(self, key, rel_dir):
        self.registry.setdefault(key, []).append(
            {"scope": "user", "installPath": "/sessions/vm/mnt/.claude/cowork_plugins/" + rel_dir})
        _write(self.plugins_root / "installed_plugins.json", json.dumps({"version": 2, "plugins": self.registry}))

    def _plugin(self, rel_dir, declares, rel_skill, text="# skill", age=0):
        root = self.plugins_root / rel_dir
        _write(root / ".claude-plugin" / "plugin.json", '{"name": "%s"}' % declares)
        return _write(root / rel_skill / "SKILL.md", text, age)

    def installed(self, rel_dir, declares, rel_skill, **kw):
        skill = self._plugin(rel_dir, declares, rel_skill, **kw)
        self._record("%s@mkt" % declares, rel_dir)
        return skill

    def test_installed_marketplace_plugin_resolves(self):
        skill = self.installed("cache/claude-plugins-official/plugin-dev/2cd88e7947b7", "plugin-dev",
                               "skills/skill-development")
        self.assertEqual(self.resolve("plugin-dev:skill-development"), str(skill))

    def test_a_skill_grouped_under_skills_resolves(self):
        skill = self.installed("cache/claude-plugins-official/Notion/0.1.0", "Notion", "skills/notion/knowledge-capture")
        self.assertEqual(self.resolve("Notion:knowledge-capture"), str(skill))

    def test_the_recorded_version_wins_over_a_newer_stale_one(self):
        recorded = self.installed("cache/mkt/plugin-dev/aaa111", "plugin-dev", "skills/agent-development",
                                  text="# recorded", age=3600)
        self._plugin("cache/mkt/plugin-dev/bbb222", "plugin-dev", "skills/agent-development", text="# stale")
        self.assertEqual(self.resolve("plugin-dev:agent-development"), str(recorded))

    def test_only_the_first_recorded_install_of_a_plugin_counts(self):
        first = self.installed("cache/mkt/plugin-dev/aaa111", "plugin-dev", "skills/agent-development", age=3600)
        self._plugin("cache/mkt/plugin-dev/bbb222", "plugin-dev", "skills/agent-development")
        self._record("plugin-dev@mkt", "cache/mkt/plugin-dev/bbb222")
        self.assertEqual(self.resolve("plugin-dev:agent-development"), str(first))

    def test_the_first_record_inside_cowork_plugins_counts(self):
        self.registry["plugin-dev@mkt"] = [{"scope": "project", "installPath": "/elsewhere/plugin-dev"}]
        skill = self.installed("cache/mkt/plugin-dev/live", "plugin-dev", "skills/agent-development")
        self.assertEqual(self.resolve("plugin-dev:agent-development"), str(skill))

    def test_a_recorded_install_that_is_gone_falls_through_to_the_next(self):
        self.registry["plugin-dev@mkt"] = [{"scope": "user", "installPath": "/vm/cowork_plugins/cache/mkt/plugin-dev/deleted"}]
        skill = self.installed("cache/mkt/plugin-dev/live", "plugin-dev", "skills/agent-development")
        self.assertEqual(self.resolve("plugin-dev:agent-development"), str(skill))

    def test_a_drive_letter_segment_never_leaves_cowork_plugins(self):
        self.assertIsNone(unbound._cowork_install_dir(self.plugins_root, "/vm/cowork_plugins/D:/other/plugin"))

    def test_a_plugin_without_plugin_json_is_named_by_its_registry_key(self):
        root = self.plugins_root / "cache" / "mkt" / "lean-kit" / "1.0"
        skill = _write(root / "skills" / "brief" / "SKILL.md", "# brief")
        self._record("lean-kit@mkt", "cache/mkt/lean-kit/1.0")
        self.assertEqual(self.resolve("lean-kit:brief"), str(skill))

    def test_a_direct_skill_wins_over_a_grouped_one_of_the_same_name(self):
        direct = self.installed("cache/mkt/plugin-dev/aaa", "plugin-dev", "skills/agent-development", age=3600)
        _write(direct.parents[2] / "skills" / "extra" / "agent-development" / "SKILL.md", "# grouped")
        self.assertEqual(self.resolve("plugin-dev:agent-development"), str(direct))

    def test_a_recorded_path_with_a_trailing_slash_still_resolves(self):
        skill = self._plugin("cache/mkt/kit/1.0", "kit", "skills/brief")
        self.registry["kit@mkt"] = [{"scope": "user", "installPath": "/sessions/vm/mnt/.claude/cowork_plugins/cache/mkt/kit/1.0/"}]
        _write(self.plugins_root / "installed_plugins.json", json.dumps({"version": 2, "plugins": self.registry}))
        self.assertEqual(self.resolve("kit:brief"), str(skill))

    def test_an_uploaded_plugin_resolves(self):
        skill = self.installed("marketplaces/local-desktop-app-uploads/my-kit", "my-kit", "skills/deck-review")
        self.assertEqual(self.resolve("my-kit:deck-review"), str(skill))

    def test_a_plugin_installed_in_its_marketplace_clone_resolves(self):
        skill = self.installed("marketplaces/team-plugins/release-kit", "release-kit", "skills/cut-release")
        self.assertEqual(self.resolve("release-kit:cut-release"), str(skill))

    def test_the_marketplace_catalog_is_not_installed(self):
        self._plugin("marketplaces/knowledge-work-plugins/sales", "sales", "skills/call-prep")
        self.assertIsNone(self.resolve("sales:call-prep"))

    def test_a_skill_md_shipped_inside_another_skill_is_not_a_skill(self):
        skill = self.installed("cache/mkt/plugin-dev/aaa111", "plugin-dev", "skills/skill-development", age=3600)
        _write(skill.parent / "templates" / "skill-development" / "SKILL.md", "# template")
        self.assertEqual(self.resolve("plugin-dev:skill-development"), str(skill))

    def test_a_bare_name_stays_with_the_bundle_when_it_has_it(self):
        bundled = self.bundle("docx", age=3600)
        self.installed("cache/mkt/document-skills/1.0", "document-skills", "skills/docx")
        self.assertEqual(self.resolve("docx"), str(bundled))

    def test_the_prefix_picks_between_an_org_plugin_and_an_installed_one(self):
        self.plugin("review")
        mine = self.installed("cache/mkt/code-review/1.0", "code-review", "skills/review")
        self.assertEqual(self.resolve("code-review:review"), str(mine))


class TestCoworkRunInAPickedFolder(_CoworkTree):
    """A run working in a folder the user picked: cwd is outside the sandbox and the
    transcript sits in a temp dir, named by a slug of the session's outputs path."""

    def transcript(self):
        slug = re.sub(r"[^A-Za-z0-9]", "-", str(self.cwd))
        return str(Path(self._tmp.name) / "claude-hostloop-plugins" / "h" / "projects" / slug / "s.jsonl")

    def test_session_recovered_from_the_temp_transcript_slug(self):
        skill = self.bundle("xlsx")
        picked = Path(self._tmp.name) / "picked"
        picked.mkdir()
        self.assertEqual(
            self.resolve("anthropic-skills:xlsx", cwd=picked, transcript_path=self.transcript()),
            str(skill))

    def test_a_longer_session_id_never_matches_a_shorter_one(self):
        skill = self.bundle("xlsx")
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
        self.bundle("xlsx")
        slug = re.sub(r"[^A-Za-z0-9]", "-", str(self.root / "a" / "b" / "local_zz" / "outputs"))
        fake = str(Path(self._tmp.name) / "projects" / slug / "s.jsonl")
        picked = Path(self._tmp.name) / "picked"
        picked.mkdir()
        self.assertIsNone(self.resolve("xlsx", cwd=picked, transcript_path=fake))

    def test_an_undefined_transcript_never_shadows_the_real_one(self):
        skill = self.bundle("xlsx")
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
        skill = self.bundle("xlsx", content)
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
        skill = self.bundle("xlsx", content)
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
