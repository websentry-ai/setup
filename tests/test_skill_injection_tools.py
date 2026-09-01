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

import pytest

from tests.conftest import tool_module

TOOLS = {
    "copilot": ("copilot/hooks", "COPILOT_SKILLS_ROOT"),
    "cursor": ("cursor", "CURSOR_SKILLS_ROOT"),
    "codex": ("codex/hooks", "CODEX_SKILLS_ROOT"),
}

MODULES = {name: tool_module(path) for name, (path, _) in TOOLS.items()}
ROOT_ATTR = {name: attr for name, (_, attr) in TOOLS.items()}


def body(text="# skill\n"):
    return {"slug": "secure-sql", "content": text,
            "sha256": hashlib.sha256(text.encode()).hexdigest()}


class Sandbox:
    """A tool's skills root, sync lock and turn guard, all pointed at scratch."""

    def __init__(self, module, attr, base):
        self.module = module
        self.attr = attr
        self.root = base / "skills"
        self.root.mkdir(parents=True)
        self.lock = base / "sync.lock"
        self.guard = base / "turn-guard"

    def installed(self, slug):
        return self.root / (self.module.UNBOUND_SKILL_PREFIX + slug)


@pytest.fixture(params=sorted(TOOLS), ids=sorted(TOOLS))
def sandbox(request, tmp_path, monkeypatch):
    module = MODULES[request.param]
    box = Sandbox(module, ROOT_ATTR[request.param], tmp_path)
    monkeypatch.setattr(module, box.attr, box.root)
    monkeypatch.setattr(module, "SKILLS_SYNC_LOCK_PATH", box.lock)
    monkeypatch.setattr(module, "INJECTION_TURN_GUARD_DIR", box.guard)
    return box


def _plan(plan):
    class Result:
        returncode = 0
        stdout = json.dumps(plan).encode()
    return Result()


def test_installs_body_marker_and_reports_it(sandbox):
    sandbox.module.install_injected_skills([body()])
    directory = sandbox.installed("secure-sql")
    assert (directory / "SKILL.md").read_text() == "# skill\n"
    assert (directory / sandbox.module.UNBOUND_SKILL_MARKER).exists()
    assert sandbox.module.installed_skill_report() == [
        {"slug": "secure-sql", "sha256": body()["sha256"]}]


def test_leaves_no_partial_file_behind(sandbox):
    sandbox.module.install_injected_skills([body()])
    names = sorted(f.name for f in sandbox.installed("secure-sql").iterdir())
    assert names == [sandbox.module.UNBOUND_SKILL_MARKER, "SKILL.md"]


def test_rewrites_a_stale_body(sandbox):
    sandbox.module.install_injected_skills([body("old\n")])
    sandbox.module.install_injected_skills([body("new\n")])
    assert (sandbox.installed("secure-sql") / "SKILL.md").read_text() == "new\n"


def test_never_overwrites_a_dir_we_do_not_own(sandbox):
    directory = sandbox.installed("secure-sql")
    directory.mkdir(parents=True)
    (directory / "SKILL.md").write_text("mine\n")
    sandbox.module.install_injected_skills([body()])
    assert (directory / "SKILL.md").read_text() == "mine\n"


def test_install_rejects_a_traversing_slug(sandbox):
    sandbox.module.install_injected_skills([dict(body(), slug="../escape")])
    assert list(sandbox.root.iterdir()) == []


def test_install_rejects_an_empty_body(sandbox):
    sandbox.module.install_injected_skills([dict(body(), content="")])
    assert list(sandbox.root.iterdir()) == []


def test_installs_the_bytes_in_hand_over_a_wrong_wire_hash(sandbox):
    sandbox.module.install_injected_skills([dict(body("real\n"), sha256="0" * 64)])
    assert (sandbox.installed("secure-sql") / "SKILL.md").read_text() == "real\n"
    assert (sandbox.module.installed_skill_report()[0]["sha256"]
            == hashlib.sha256(b"real\n").hexdigest())


def test_prune_removes_only_what_we_marked(sandbox):
    sandbox.module.install_injected_skills([body()])
    sandbox.module.prune_injected_skills(["secure-sql"])
    assert not sandbox.installed("secure-sql").exists()


def test_prune_keeps_an_unmarked_dir_of_the_same_name(sandbox):
    directory = sandbox.installed("secure-sql")
    directory.mkdir(parents=True)
    (directory / "SKILL.md").write_text("mine\n")
    sandbox.module.prune_injected_skills(["secure-sql"])
    assert directory.exists()


def test_prune_rejects_a_traversing_slug(sandbox):
    victim = sandbox.root.parent / "victim"
    victim.mkdir()
    sandbox.module.prune_injected_skills(["../victim"])
    assert victim.exists()


def test_report_ignores_a_dir_without_our_marker(sandbox):
    (sandbox.root / "unbound-handwritten").mkdir()
    (sandbox.root / "unbound-handwritten" / "SKILL.md").write_text("x\n")
    assert sandbox.module.installed_skill_report() == []


def test_report_is_empty_when_the_root_does_not_exist(sandbox, monkeypatch):
    monkeypatch.setattr(sandbox.module, sandbox.attr, sandbox.root / "missing")
    assert sandbox.module.installed_skill_report() == []


def test_sync_applies_the_plan(sandbox):
    with patch.object(sandbox.module.subprocess, "run",
                      return_value=_plan({"install": [body()], "remove": []})):
        sandbox.module._sync_skills_once("key")
    assert (sandbox.installed("secure-sql") / "SKILL.md").exists()


def test_sync_prunes_before_it_installs(sandbox):
    sandbox.module.install_injected_skills([body()])
    with patch.object(sandbox.module.subprocess, "run",
                      return_value=_plan({"install": [], "remove": ["secure-sql"]})):
        sandbox.module._sync_skills_once("key")
    assert not sandbox.installed("secure-sql").exists()


def test_a_held_lock_stops_a_second_reconcile(sandbox):
    sandbox.lock.parent.mkdir(parents=True, exist_ok=True)
    sandbox.lock.write_text("")
    with patch.object(sandbox.module.subprocess, "run") as run:
        sandbox.module._sync_skills_once("key")
    run.assert_not_called()


def test_sync_releases_the_lock_when_the_call_fails(sandbox):
    with patch.object(sandbox.module.subprocess, "run", side_effect=OSError("boom")):
        sandbox.module._sync_skills_once("key")
    assert not sandbox.lock.exists()


def test_a_non_dict_plan_changes_nothing(sandbox):
    class Result:
        returncode = 0
        stdout = b'["not-a-plan"]'
    with patch.object(sandbox.module.subprocess, "run", return_value=Result()):
        sandbox.module._sync_skills_once("key")
    assert list(sandbox.root.iterdir()) == []


def test_dispatch_is_a_no_op_without_a_key(sandbox):
    with patch.object(sandbox.module.subprocess, "Popen") as popen:
        sandbox.module._dispatch_skills_sync("")
    popen.assert_not_called()


def test_dispatch_passes_the_key_by_env_only(sandbox):
    with patch.object(sandbox.module.subprocess, "Popen") as popen:
        sandbox.module._dispatch_skills_sync("secret")
    cmd, kwargs = popen.call_args[0][0], popen.call_args[1]
    assert "--sync-skills" in cmd
    assert "secret" not in " ".join(cmd)
    assert "secret" in kwargs["env"].values()


def test_turn_guard_round_trips_per_session(sandbox):
    sandbox.module._turn_guard_write("session-a", "turn-1")
    sandbox.module._turn_guard_write("session-b", "turn-9")
    assert sandbox.module._turn_guard_read("session-a") == "turn-1"
    assert sandbox.module._turn_guard_read("session-b") == "turn-9"


def test_turn_guard_unknown_session_reads_empty(sandbox):
    assert sandbox.module._turn_guard_read("nobody") == ""


class LoadedSkillsCase:
    """Every fixture below is the shape a real session produced, not an invented one."""

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


class CopilotLoadedTests(LoadedSkillsCase, unittest.TestCase):
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

    def test_a_string_data_field_does_not_lose_the_other_facts(self):
        self.write([{"type": "skill.invoked", "data": "oops"},
                    {"type": "user.message", "data": "oops"},
                    self.invoked("unbound-secure-sql")])
        self.assertEqual(self.loaded(), ["secure-sql"])

    def test_derives_the_transcript_from_the_session_id(self):
        home = Path(self._tmp.name) / "copilot-home"
        state = home / "session-state" / "sess-1"
        state.mkdir(parents=True)
        (state / "events.jsonl").write_text(json.dumps(self.invoked("unbound-secure-sql")) + "\n")
        with patch.object(self.module, "_copilot_home", return_value=home), \
             patch.object(self.module, "_transcript_path_for_session", return_value=None):
            facts = self.module.read_skill_facts({"session_id": "sess-1"})
        self.assertEqual(sorted(facts["loaded"]), ["secure-sql"])


class CursorLoadedTests(LoadedSkillsCase, unittest.TestCase):
    tool = "cursor"

    CONVERSATION = "conv-1"

    def setUp(self):
        super().setUp()
        self.root = Path(self._tmp.name) / "cursor-skills"
        self.audit = Path(self._tmp.name) / "agent-audit.log"
        self._saved = self.module.CURSOR_SKILLS_ROOT
        self._saved_audit = self.module.AUDIT_LOG
        self.module.CURSOR_SKILLS_ROOT = self.root
        self.module.AUDIT_LOG = self.audit

    def tearDown(self):
        self.module.CURSOR_SKILLS_ROOT = self._saved
        self.module.AUDIT_LOG = self._saved_audit
        super().tearDown()

    def facts(self, **event):
        event.setdefault("conversation_id", self.CONVERSATION)
        return super().facts(**event)

    def audit_rows(self, events):
        self.audit.write_text(
            "\n".join(json.dumps({"timestamp": "t", "event": e}) for e in events) + "\n",
            encoding="utf-8")

    def read_row(self, path, conversation_id=None):
        return {"hook_event_name": "beforeReadFile", "file_path": str(path),
                "conversation_id": conversation_id or self.CONVERSATION}

    def prompt_row(self):
        return {"hook_event_name": "beforeSubmitPrompt", "prompt": "next",
                "conversation_id": self.CONVERSATION}

    def user(self, text):
        return {"role": "user", "message": {"content": [{"type": "text", "text": text}]}}

    def read(self, path):
        return {"role": "assistant", "message": {"content": [
            {"type": "tool_use", "name": "Read", "input": {"path": str(path)}}]}}

    def attached(self, name, path=None):
        return self.user(
            "<manually_attached_skills>\n"
            "The user has manually attached the following skills to their message.\n\n"
            f"Skill Name: {name}\nPath: {path or self.root / name / 'SKILL.md'}\n"
            "SKILL.md content:\n# body\n")

    def test_an_attached_skill_counts_with_no_file_read(self):
        self.write([self.attached("unbound-secure-sql")])
        self.assertEqual(self.loaded(), ["secure-sql"])

    def test_an_attached_skill_we_do_not_manage_is_ignored(self):
        self.write([self.attached("poteto-mode")])
        self.assertEqual(self.loaded(), [])

    def test_an_attached_block_whose_path_is_outside_our_root_is_ignored(self):
        elsewhere = Path(self._tmp.name) / "elsewhere" / "unbound-secure-sql" / "SKILL.md"
        self.write([self.attached("unbound-secure-sql", path=elsewhere)])
        self.assertEqual(self.loaded(), [])

    def test_an_attached_block_with_no_path_line_is_ignored(self):
        self.write([self.user(
            "<manually_attached_skills>\nSkill Name: unbound-secure-sql\n"
            "SKILL.md content:\n# body\n")])
        self.assertEqual(self.loaded(), [])

    def test_an_attached_name_that_disagrees_with_its_path_is_ignored(self):
        self.write([self.attached(
            "unbound-secure-sql", path=self.root / "unbound-other" / "SKILL.md")])
        self.assertEqual(self.loaded(), [])

    def test_a_harness_read_of_our_skill_counts(self):
        self.audit_rows([self.read_row(self.root / "unbound-secure-sql" / "SKILL.md")])
        self.assertEqual(self.loaded(), ["secure-sql"])

    def test_a_harness_read_outside_our_root_does_not_count(self):
        other = Path(self._tmp.name) / "elsewhere" / "unbound-secure-sql" / "SKILL.md"
        self.audit_rows([self.read_row(other)])
        self.assertEqual(self.loaded(), [])

    def test_a_harness_read_of_a_skill_we_did_not_install_does_not_count(self):
        self.audit_rows([self.read_row(self.root / "poteto-mode" / "SKILL.md")])
        self.assertEqual(self.loaded(), [])

    def test_a_harness_read_in_another_conversation_does_not_count(self):
        self.audit_rows([self.read_row(self.root / "unbound-secure-sql" / "SKILL.md",
                                       conversation_id="conv-other")])
        self.assertEqual(self.loaded(), [])

    def test_a_model_requested_read_alone_does_not_count(self):
        # The transcript records the model asking to Read, never a result, so the
        # request is not evidence the body reached the context.
        self.write([self.read(self.root / "unbound-secure-sql" / "SKILL.md")])
        self.assertEqual(self.loaded(), [])
        self.assertEqual(self.facts()["session_count"], 0)

    def test_drops_out_of_the_window(self):
        self.audit_rows([self.read_row(self.root / "unbound-secure-sql" / "SKILL.md")]
                        + [self.prompt_row()] * 11)
        self.assertEqual(self.loaded(), [])
        self.assertEqual(self.facts()["session_count"], 1)

    def test_stays_in_the_window_at_its_edge(self):
        self.audit_rows([self.read_row(self.root / "unbound-secure-sql" / "SKILL.md")]
                        + [self.prompt_row()] * 10)
        self.assertEqual(self.loaded(), ["secure-sql"])

    def test_a_string_message_does_not_lose_the_other_facts(self):
        self.write([{"role": "user", "message": "oops"},
                    self.attached("unbound-secure-sql")])
        self.assertEqual(self.loaded(), ["secure-sql"])

    def test_a_string_tool_input_does_not_lose_the_other_facts(self):
        self.write([{"role": "assistant", "message": {"content": [
                        {"type": "tool_use", "name": "Read", "input": "oops"}]}},
                    self.attached("unbound-secure-sql")])
        self.assertEqual(self.loaded(), ["secure-sql"])

    def test_no_transcript_path_is_no_facts(self):
        self.assertEqual(self.module.read_skill_facts({}), {"loaded": set(), "session_count": 0})


class CodexLoadedTests(LoadedSkillsCase, unittest.TestCase):
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

    def exec_read(self, path, status="completed", call_id="call-1"):
        return {"type": "response_item", "payload": {
            "type": "custom_tool_call", "status": status, "name": "exec",
            "call_id": call_id,
            "input": "const r = await tools.exec_command({cmd:\"sed -n '1,240p' %s\"});" % path}}

    def exec_output(self, name="unbound-secure-sql", call_id="call-1", parts=None):
        if parts is None:
            parts = [{"type": "input_text", "text": "Script completed\nWall time 0.1 seconds\nOutput:\n"},
                     {"type": "input_text",
                      "text": f"---\nname: {name}\ndescription: does things\n---\n\n# body\n"}]
        return {"type": "response_item", "payload": {
            "type": "custom_tool_call_output", "call_id": call_id, "output": parts}}

    def test_a_dollar_sigil_injection_counts(self):
        self.write([self.selected("unbound-secure-sql")])
        self.assertEqual(self.loaded(), ["secure-sql"])

    def test_an_injection_of_a_skill_we_do_not_manage_is_ignored(self):
        self.write([self.selected("zz-probe-skill")])
        self.assertEqual(self.loaded(), [])

    def test_a_model_initiated_read_counts(self):
        self.write([self.exec_read(self.root / "unbound-secure-sql" / "SKILL.md"),
                    self.exec_output()])
        self.assertEqual(self.loaded(), ["secure-sql"])

    def test_a_read_with_no_output_does_not_count(self):
        # The command text is model-chosen, so a no-op exec naming the path is not
        # evidence the body entered the context.
        self.write([self.exec_read(self.root / "unbound-secure-sql" / "SKILL.md")])
        self.assertEqual(self.loaded(), [])
        self.assertEqual(self.facts()["session_count"], 0)

    def test_an_output_for_another_call_does_not_count(self):
        self.write([self.exec_read(self.root / "unbound-secure-sql" / "SKILL.md"),
                    self.exec_output(call_id="call-9")])
        self.assertEqual(self.loaded(), [])

    def test_an_output_without_the_body_does_not_count(self):
        self.write([self.exec_read(self.root / "unbound-secure-sql" / "SKILL.md"),
                    self.exec_output(parts=[{"type": "input_text",
                                             "text": "Script completed\nOutput:\n"}])])
        self.assertEqual(self.loaded(), [])

    def test_an_output_naming_a_different_skill_does_not_count(self):
        self.write([self.exec_read(self.root / "unbound-secure-sql" / "SKILL.md"),
                    self.exec_output(name="unbound-other")])
        self.assertEqual(self.loaded(), [])

    def test_a_non_dict_output_part_does_not_raise(self):
        self.write([self.exec_read(self.root / "unbound-secure-sql" / "SKILL.md"),
                    self.exec_output(parts=["oops", {"type": "input_text",
                                                     "text": "name: unbound-secure-sql\n"}])])
        self.assertEqual(self.loaded(), ["secure-sql"])

    def test_an_unfinished_read_does_not_count(self):
        self.write([self.exec_read(self.root / "unbound-secure-sql" / "SKILL.md",
                                   status="in_progress"),
                    self.exec_output()])
        self.assertEqual(self.loaded(), [])

    def test_a_read_outside_our_root_does_not_count(self):
        other = Path(self._tmp.name) / "elsewhere" / "unbound-secure-sql" / "SKILL.md"
        self.write([self.exec_read(other), self.exec_output()])
        self.assertEqual(self.loaded(), [])

    def test_a_string_input_does_not_lose_the_other_facts(self):
        broken = {"type": "response_item", "payload": {
            "type": "custom_tool_call", "status": "completed", "input": {"cmd": "oops"}}}
        self.write([broken, self.selected("unbound-secure-sql")])
        self.assertEqual(self.loaded(), ["secure-sql"])

    def test_a_string_message_content_does_not_lose_the_other_facts(self):
        broken = {"type": "response_item", "payload": {
            "type": "message", "role": "user", "content": "oops",
            "internal_chat_message_metadata_passthrough": {
                "content_item_kinds": ["skills.selected_skill_instructions"]}}}
        self.write([broken, self.selected("unbound-secure-sql")])
        self.assertEqual(self.loaded(), ["secure-sql"])

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
