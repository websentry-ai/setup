"""Skill-injection policy on the tools that are not Claude Code.

Copilot, Cursor and Codex share the install/prune/reconcile half verbatim, so that
half is parametrized over all three. Each tool then gets its own class for the one
part that cannot be shared: how it reports a skill was actually loaded, which is a
different file in a different format for every one of them.
"""

import hashlib
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from tests.conftest import tool_module

TOOLS = {
    "copilot": "copilot/hooks",
    "cursor": "cursor",
    "codex": "codex/hooks",
}

MODULES = {name: tool_module(path) for name, path in TOOLS.items()}


def skills_root(module):
    for attr in ("COPILOT_SKILLS_ROOT", "CURSOR_SKILLS_ROOT", "CODEX_SKILLS_ROOT"):
        root = getattr(module, attr, None)
        if root is not None:
            return root
    raise AssertionError("tool module exposes no skills root")


def body(text="# skill\n"):
    return {"slug": "secure-sql", "content": text,
            "sha256": hashlib.sha256(text.encode()).hexdigest()}


class SkillsRootCase(unittest.TestCase):
    """Points a tool's skills root at a scratch directory for the duration."""

    tool = None

    def setUp(self):
        self.module = MODULES[self.tool]
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name) / "skills"
        self.root.mkdir(parents=True)
        self._attr = next(a for a in ("COPILOT_SKILLS_ROOT", "CURSOR_SKILLS_ROOT", "CODEX_SKILLS_ROOT")
                          if getattr(self.module, a, None) is not None)
        self._saved = getattr(self.module, self._attr)
        setattr(self.module, self._attr, self.root)
        self._lock = Path(self._tmp.name) / "sync.lock"
        self._saved_lock = self.module.SKILLS_SYNC_LOCK_PATH
        self.module.SKILLS_SYNC_LOCK_PATH = self._lock
        self._guard = Path(self._tmp.name) / "turn-guard"
        self._saved_guard = self.module.INJECTION_TURN_GUARD_DIR
        self.module.INJECTION_TURN_GUARD_DIR = self._guard

    def tearDown(self):
        setattr(self.module, self._attr, self._saved)
        self.module.SKILLS_SYNC_LOCK_PATH = self._saved_lock
        self.module.INJECTION_TURN_GUARD_DIR = self._saved_guard
        self._tmp.cleanup()

    def installed(self, slug):
        return self.root / (self.module.UNBOUND_SKILL_PREFIX + slug)


class InstallTests(SkillsRootCase):
    def test_installs_body_marker_and_reports_it(self):
        self.module.install_injected_skills([body()])
        directory = self.installed("secure-sql")
        self.assertEqual((directory / "SKILL.md").read_text(), "# skill\n")
        self.assertTrue((directory / self.module.UNBOUND_SKILL_MARKER).exists())
        self.assertEqual(self.module.installed_skill_report(),
                         [{"slug": "secure-sql", "sha256": body()["sha256"]}])

    def test_leaves_no_partial_file_behind(self):
        self.module.install_injected_skills([body()])
        names = sorted(p.name for p in self.installed("secure-sql").iterdir())
        self.assertEqual(names, [self.module.UNBOUND_SKILL_MARKER, "SKILL.md"])

    def test_rewrites_a_stale_body(self):
        self.module.install_injected_skills([body("old\n")])
        self.module.install_injected_skills([body("new\n")])
        self.assertEqual((self.installed("secure-sql") / "SKILL.md").read_text(), "new\n")

    def test_never_overwrites_a_dir_we_do_not_own(self):
        directory = self.installed("secure-sql")
        directory.mkdir(parents=True)
        (directory / "SKILL.md").write_text("mine\n")
        self.module.install_injected_skills([body()])
        self.assertEqual((directory / "SKILL.md").read_text(), "mine\n")

    def test_rejects_a_traversing_slug(self):
        entry = dict(body(), slug="../escape")
        self.module.install_injected_skills([entry])
        self.assertEqual(list(self.root.iterdir()), [])

    def test_rejects_an_empty_body(self):
        self.module.install_injected_skills([dict(body(), content="")])
        self.assertEqual(list(self.root.iterdir()), [])

    def test_installs_the_bytes_in_hand_over_a_wrong_wire_hash(self):
        self.module.install_injected_skills([dict(body("real\n"), sha256="0" * 64)])
        directory = self.installed("secure-sql")
        self.assertEqual((directory / "SKILL.md").read_text(), "real\n")
        self.assertEqual(self.module.installed_skill_report()[0]["sha256"],
                         hashlib.sha256(b"real\n").hexdigest())


class PruneTests(SkillsRootCase):
    def test_removes_only_what_we_marked(self):
        self.module.install_injected_skills([body()])
        self.module.prune_injected_skills(["secure-sql"])
        self.assertFalse(self.installed("secure-sql").exists())

    def test_keeps_an_unmarked_dir_of_the_same_name(self):
        directory = self.installed("secure-sql")
        directory.mkdir(parents=True)
        (directory / "SKILL.md").write_text("mine\n")
        self.module.prune_injected_skills(["secure-sql"])
        self.assertTrue(directory.exists())

    def test_rejects_a_traversing_slug(self):
        victim = self.root.parent / "victim"
        victim.mkdir()
        self.module.prune_injected_skills(["../victim"])
        self.assertTrue(victim.exists())


class ReportTests(SkillsRootCase):
    def test_ignores_a_dir_without_our_marker(self):
        (self.root / "unbound-handwritten").mkdir()
        (self.root / "unbound-handwritten" / "SKILL.md").write_text("x\n")
        self.assertEqual(self.module.installed_skill_report(), [])

    def test_empty_when_the_root_does_not_exist(self):
        setattr(self.module, self._attr, self.root / "missing")
        self.assertEqual(self.module.installed_skill_report(), [])


class SyncTests(SkillsRootCase):
    def _plan(self, plan):
        class Result:
            returncode = 0
            stdout = json.dumps(plan).encode()
        return Result()

    def test_applies_the_plan(self):
        with patch.object(self.module.subprocess, "run", return_value=self._plan(
                {"install": [body()], "remove": []})):
            self.module._sync_skills_once("key")
        self.assertTrue((self.installed("secure-sql") / "SKILL.md").exists())

    def test_prunes_before_it_installs(self):
        self.module.install_injected_skills([body()])
        with patch.object(self.module.subprocess, "run", return_value=self._plan(
                {"install": [], "remove": ["secure-sql"]})):
            self.module._sync_skills_once("key")
        self.assertFalse(self.installed("secure-sql").exists())

    def test_a_held_lock_stops_a_second_reconcile(self):
        self._lock.parent.mkdir(parents=True, exist_ok=True)
        self._lock.write_text("")
        with patch.object(self.module.subprocess, "run") as run:
            self.module._sync_skills_once("key")
        run.assert_not_called()

    def test_releases_the_lock_when_the_call_fails(self):
        with patch.object(self.module.subprocess, "run", side_effect=OSError("boom")):
            self.module._sync_skills_once("key")
        self.assertFalse(self._lock.exists())

    def test_a_non_dict_plan_changes_nothing(self):
        class Result:
            returncode = 0
            stdout = b'["not-a-plan"]'
        with patch.object(self.module.subprocess, "run", return_value=Result()):
            self.module._sync_skills_once("key")
        self.assertEqual(list(self.root.iterdir()), [])

    def test_dispatch_is_a_no_op_without_a_key(self):
        with patch.object(self.module.subprocess, "Popen") as popen:
            self.module._dispatch_skills_sync("")
        popen.assert_not_called()

    def test_dispatch_passes_the_key_by_env_only(self):
        with patch.object(self.module.subprocess, "Popen") as popen:
            self.module._dispatch_skills_sync("secret")
        cmd, kwargs = popen.call_args[0][0], popen.call_args[1]
        self.assertIn("--sync-skills", cmd)
        self.assertNotIn("secret", " ".join(cmd))
        self.assertIn("secret", kwargs["env"].values())


class TurnGuardTests(SkillsRootCase):
    def test_round_trips_per_session(self):
        self.module._turn_guard_write("session-a", "turn-1")
        self.module._turn_guard_write("session-b", "turn-9")
        self.assertEqual(self.module._turn_guard_read("session-a"), "turn-1")
        self.assertEqual(self.module._turn_guard_read("session-b"), "turn-9")

    def test_unknown_session_reads_empty(self):
        self.assertEqual(self.module._turn_guard_read("nobody"), "")


def _tool_case(base, tool):
    return type(f"{base.__name__}_{tool}", (base,), {"tool": tool})


for _base in (InstallTests, PruneTests, ReportTests, SyncTests, TurnGuardTests):
    for _tool in TOOLS:
        globals()[f"{_base.__name__}_{_tool}"] = _tool_case(_base, _tool)
    del globals()[_base.__name__]
# The loop names would otherwise be collected as a bare, tool-less test class.
del _base, _tool


class LoadedSkillsCase(unittest.TestCase):
    """The per-tool half: what each tool writes down when a skill is loaded.

    Every fixture below is the shape a real session produced, not an invented one."""

    tool = None

    def setUp(self):
        self.module = MODULES[self.tool]
        self._tmp = tempfile.TemporaryDirectory()
        self.transcript = Path(self._tmp.name) / "transcript.jsonl"

    def tearDown(self):
        self._tmp.cleanup()

    def write(self, entries):
        """entries are oldest-first, as every one of these tools appends them."""
        self.transcript.write_text(
            "\n".join(json.dumps(e) for e in entries) + "\n", encoding="utf-8")

    def facts(self, **event):
        event.setdefault("transcript_path", str(self.transcript))
        return self.module.read_skill_facts(event)

    def loaded(self, **event):
        return sorted(self.facts(**event)["loaded"])


class CopilotLoadedTests(LoadedSkillsCase):
    tool = "copilot"

    TURN = {"type": "assistant.turn_start", "data": {}}

    def invoked(self, name):
        return {"type": "skill.invoked", "data": {"name": name}}

    def prompt(self, text):
        return {"type": "user.message", "data": {"content": text}}

    def test_reads_a_skill_invoked_event(self):
        self.write([self.invoked("unbound-secure-sql"), self.TURN])
        self.assertEqual(self.loaded(), ["secure-sql"])

    def test_probes_the_undocumented_name_field(self):
        self.write([{"type": "skill.invoked", "data": {"skillName": "unbound-secure-sql"}}])
        self.assertEqual(self.loaded(), ["secure-sql"])

    def test_ignores_a_skill_we_do_not_manage(self):
        self.write([self.invoked("someone-elses-skill")])
        self.assertEqual(self.loaded(), [])

    def test_a_slash_token_in_the_users_prompt_counts(self):
        self.write([self.prompt("please run /unbound-secure-sql now")])
        self.assertEqual(self.loaded(), ["secure-sql"])

    def test_drops_out_of_the_window(self):
        self.write([self.invoked("unbound-secure-sql")] + [self.TURN] * 11)
        self.assertEqual(self.loaded(), [])
        self.assertEqual(self.facts()["session_count"], 1)

    def test_session_count_ignores_the_window(self):
        self.write([self.invoked("unbound-a"), self.invoked("unbound-b")] + [self.TURN] * 20)
        self.assertEqual(self.facts()["session_count"], 2)

    def test_derives_the_transcript_from_the_session_id(self):
        home = Path(self._tmp.name) / "copilot-home"
        state = home / "session-state" / "sess-1"
        state.mkdir(parents=True)
        (state / "events.jsonl").write_text(json.dumps(self.invoked("unbound-secure-sql")) + "\n")
        with patch.object(self.module, "_copilot_home", return_value=home), \
             patch.object(self.module, "_transcript_path_for_session", return_value=None):
            facts = self.module.read_skill_facts({"session_id": "sess-1"})
        self.assertEqual(sorted(facts["loaded"]), ["secure-sql"])


class CursorLoadedTests(LoadedSkillsCase):
    tool = "cursor"

    def setUp(self):
        super().setUp()
        self.root = Path(self._tmp.name) / "cursor-skills"
        self._saved = self.module.CURSOR_SKILLS_ROOT
        self.module.CURSOR_SKILLS_ROOT = self.root

    def tearDown(self):
        self.module.CURSOR_SKILLS_ROOT = self._saved
        super().tearDown()

    def user(self, text):
        return {"role": "user", "message": {"content": [{"type": "text", "text": text}]}}

    def read(self, path):
        return {"role": "assistant", "message": {"content": [
            {"type": "tool_use", "name": "Read", "input": {"path": str(path)}}]}}

    def attached(self, name):
        return self.user(
            "<manually_attached_skills>\n"
            "The user has manually attached the following skills to their message.\n\n"
            f"Skill Name: {name}\nPath: {self.root}/{name}/SKILL.md\n"
            "SKILL.md content:\n# body\n")

    def test_an_attached_skill_counts_with_no_file_read(self):
        self.write([self.attached("unbound-secure-sql")])
        self.assertEqual(self.loaded(), ["secure-sql"])

    def test_an_attached_skill_we_do_not_manage_is_ignored(self):
        self.write([self.attached("poteto-mode")])
        self.assertEqual(self.loaded(), [])

    def test_a_read_of_our_skill_counts(self):
        self.write([self.read(self.root / "unbound-secure-sql" / "SKILL.md")])
        self.assertEqual(self.loaded(), ["secure-sql"])

    def test_a_read_outside_our_root_does_not_count(self):
        other = Path(self._tmp.name) / "elsewhere" / "unbound-secure-sql" / "SKILL.md"
        self.write([self.read(other)])
        self.assertEqual(self.loaded(), [])

    def test_a_read_of_a_skill_we_did_not_install_does_not_count(self):
        self.write([self.read(self.root / "poteto-mode" / "SKILL.md")])
        self.assertEqual(self.loaded(), [])

    def test_drops_out_of_the_window(self):
        self.write([self.read(self.root / "unbound-secure-sql" / "SKILL.md")]
                   + [self.user("next")] * 11)
        self.assertEqual(self.loaded(), [])
        self.assertEqual(self.facts()["session_count"], 1)

    def test_no_transcript_path_is_no_facts(self):
        self.assertEqual(self.module.read_skill_facts({}), {"loaded": set(), "session_count": 0})


class CodexLoadedTests(LoadedSkillsCase):
    tool = "codex"

    def setUp(self):
        super().setUp()
        self.root = Path(self._tmp.name) / "codex-skills"
        self._saved = self.module.CODEX_SKILLS_ROOT
        self.module.CODEX_SKILLS_ROOT = self.root
        # The read matcher is compiled against the root, so it moves with it.
        self._saved_re = self.module.SKILL_READ_PATH_RE
        import os as _os
        import re as _re
        self.module.SKILL_READ_PATH_RE = _re.compile(
            _re.escape(str(self.root)) + _re.escape(_os.sep)
            + _re.escape(self.module.UNBOUND_SKILL_PREFIX) + r'([A-Za-z0-9-]+)'
            + _re.escape(_os.sep) + r'SKILL\.md')

    def tearDown(self):
        self.module.CODEX_SKILLS_ROOT = self._saved
        self.module.SKILL_READ_PATH_RE = self._saved_re
        super().tearDown()

    TURN = {"type": "event_msg", "payload": {"type": "task_started", "turn_id": "t"}}
    COMPACTED = {"type": "compacted", "payload": {"message": ""}}

    def selected(self, name):
        return {"type": "response_item", "payload": {
            "type": "message", "role": "user",
            "content": [{"type": "input_text",
                         "text": f"<skill>\n<name>{name}</name>\n<path>{self.root}/{name}/SKILL.md</path>\n---\n"}],
            "internal_chat_message_metadata_passthrough": {
                "turn_id": "t", "content_item_kinds": ["skills.selected_skill_instructions"]}}}

    def exec_read(self, path, status="completed"):
        return {"type": "response_item", "payload": {
            "type": "custom_tool_call", "status": status, "name": "exec",
            "input": "const r = await tools.exec_command({cmd:\"sed -n '1,240p' %s\"});" % path}}

    def test_a_dollar_sigil_injection_counts(self):
        self.write([self.selected("unbound-secure-sql")])
        self.assertEqual(self.loaded(), ["secure-sql"])

    def test_an_injection_of_a_skill_we_do_not_manage_is_ignored(self):
        self.write([self.selected("zz-probe-skill")])
        self.assertEqual(self.loaded(), [])

    def test_a_model_initiated_read_counts(self):
        self.write([self.exec_read(self.root / "unbound-secure-sql" / "SKILL.md")])
        self.assertEqual(self.loaded(), ["secure-sql"])

    def test_an_unfinished_read_does_not_count(self):
        self.write([self.exec_read(self.root / "unbound-secure-sql" / "SKILL.md",
                                   status="in_progress")])
        self.assertEqual(self.loaded(), [])

    def test_a_read_outside_our_root_does_not_count(self):
        other = Path(self._tmp.name) / "elsewhere" / "unbound-secure-sql" / "SKILL.md"
        self.write([self.exec_read(other)])
        self.assertEqual(self.loaded(), [])

    def test_the_installed_catalog_alone_is_not_a_load(self):
        # Codex lists every installed skill in world_state on every session.
        self.write([{"type": "world_state", "payload": {"state": {"host_skills": {
            "body": "unbound-secure-sql: does things"}}}}])
        self.assertEqual(self.loaded(), [])

    def test_drops_out_of_the_window(self):
        self.write([self.selected("unbound-secure-sql")] + [self.TURN] * 11)
        self.assertEqual(self.loaded(), [])
        self.assertEqual(self.facts()["session_count"], 1)

    def test_a_compaction_ends_the_search(self):
        self.write([self.selected("unbound-secure-sql"), self.TURN, self.COMPACTED, self.TURN])
        self.assertEqual(self.loaded(), [])
        self.assertEqual(self.facts()["session_count"], 1)

    def test_undefined_transcript_path_is_no_facts(self):
        self.assertEqual(self.module.read_skill_facts({"transcript_path": "undefined"}),
                         {"loaded": set(), "session_count": 0})


del LoadedSkillsCase
