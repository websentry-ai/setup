import hashlib
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

import unbound


def unbound_skill_loaded(transcript_path, invoked_name):
    slug = invoked_name[len(unbound.UNBOUND_SKILL_PREFIX):]
    return slug in unbound.read_skill_facts(transcript_path)['loaded']


def unbound_loaded_slugs(transcript_path):
    return sorted(unbound.read_skill_facts(transcript_path)['loaded'])


ASSISTANT = {"type": "assistant", "message": {"role": "assistant", "content": []}}
COMPACT = {"type": "system", "subtype": "compact_boundary"}


def _streamed(mid, rid="req"):
    """One line of a streamed assistant message. Several share the same pair of ids."""
    return {"type": "assistant", "requestId": rid, "message": {"role": "assistant", "id": mid, "content": []}}


def _invocation(name, success=True):
    return {"type": "user", "toolUseResult": {"success": success, "commandName": name}}


def _write_transcript(path, entries):
    """entries are oldest-first, as Claude Code appends them."""
    lines = [e if isinstance(e, str) else json.dumps(e) for e in entries]
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


class TestSkillLoaded(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.transcript = Path(self._tmp.name) / "session.jsonl"

    def tearDown(self):
        self._tmp.cleanup()

    def test_hit_inside_window(self):
        _write_transcript(self.transcript, [_invocation("unbound-secure-sql")] + [ASSISTANT] * 3)
        self.assertTrue(unbound_skill_loaded(str(self.transcript), "unbound-secure-sql"))

    def test_hit_outside_window(self):
        _write_transcript(self.transcript, [_invocation("unbound-secure-sql")] + [ASSISTANT] * 11)
        self.assertFalse(unbound_skill_loaded(str(self.transcript), "unbound-secure-sql"))

    def test_compact_boundary_ends_the_search(self):
        _write_transcript(self.transcript, [
            _invocation("unbound-secure-sql"), ASSISTANT, COMPACT, ASSISTANT,
        ])
        self.assertFalse(unbound_skill_loaded(str(self.transcript), "unbound-secure-sql"))

    def test_invocation_after_the_boundary_survives_it(self):
        # Compaction only drops what precedes it, so a skill invoked after the boundary
        # is still in context.
        _write_transcript(self.transcript, [
            ASSISTANT, COMPACT, _invocation("unbound-secure-sql"), ASSISTANT,
        ])
        self.assertTrue(unbound_skill_loaded(str(self.transcript), "unbound-secure-sql"))

    def test_boundary_hides_only_the_older_skill(self):
        _write_transcript(self.transcript, [
            _invocation("unbound-pii"), COMPACT, _invocation("unbound-secure-sql"), ASSISTANT,
        ])
        self.assertTrue(unbound_skill_loaded(str(self.transcript), "unbound-secure-sql"))
        self.assertFalse(unbound_skill_loaded(str(self.transcript), "unbound-pii"))

    def test_bare_string_tool_use_result(self):
        # The hook-denial shape: toolUseResult is a bare string, not an object.
        _write_transcript(self.transcript, [
            _invocation("unbound-secure-sql"),
            {"type": "user", "toolUseResult": "blocked by policy"},
            ASSISTANT,
        ])
        self.assertTrue(unbound_skill_loaded(str(self.transcript), "unbound-secure-sql"))
        self.assertFalse(unbound_skill_loaded(str(self.transcript), "blocked by policy"))

        _write_transcript(self.transcript, [{"type": "user", "toolUseResult": "blocked by policy"}])
        self.assertFalse(unbound_skill_loaded(str(self.transcript), "unbound-secure-sql"))

    def test_missing_transcript(self):
        missing = str(Path(self._tmp.name) / "nope.jsonl")
        self.assertFalse(unbound_skill_loaded(missing, "unbound-secure-sql"))

    def test_window_counts_assistant_turns_not_lines(self):
        entries = [_invocation("unbound-secure-sql")]
        for i in range(3):
            entries.extend([{"type": "attachment", "n": j} for j in range(60)])
            entries.append({"type": "user", "message": {"role": "user", "content": "go on"}})
            entries.append({"type": "system", "subtype": "info"})
            entries.append(ASSISTANT)
        _write_transcript(self.transcript, entries)
        self.assertGreater(len(entries), 180)
        self.assertTrue(unbound_skill_loaded(str(self.transcript), "unbound-secure-sql"))

    def test_streamed_lines_of_one_message_are_one_turn(self):
        entries = [_invocation("unbound-secure-sql")]
        for turn in range(unbound.SKILL_LOADED_WINDOW - 1):
            entries.extend(_streamed(f"msg_{turn}", f"req_{turn}") for _ in range(3))
        _write_transcript(self.transcript, entries)

        self.assertGreater(len(entries), unbound.SKILL_LOADED_WINDOW * 2)
        self.assertTrue(unbound_skill_loaded(str(self.transcript), "unbound-secure-sql"))

    def test_distinct_messages_still_close_the_window(self):
        entries = [_invocation("unbound-secure-sql")]
        entries.extend(_streamed(f"msg_{t}", f"req_{t}") for t in range(unbound.SKILL_LOADED_WINDOW + 1))
        _write_transcript(self.transcript, entries)

        self.assertFalse(unbound_skill_loaded(str(self.transcript), "unbound-secure-sql"))

    def test_unsuccessful_invocation_does_not_match(self):
        _write_transcript(self.transcript, [_invocation("unbound-secure-sql", success=False), ASSISTANT])
        self.assertFalse(unbound_skill_loaded(str(self.transcript), "unbound-secure-sql"))

    def test_non_boolean_success_does_not_match(self):
        _write_transcript(self.transcript, [
            {"type": "user", "toolUseResult": {"success": "true", "commandName": "unbound-secure-sql"}},
        ])
        self.assertFalse(unbound_skill_loaded(str(self.transcript), "unbound-secure-sql"))

    def test_different_command_name_does_not_match(self):
        _write_transcript(self.transcript, [_invocation("unbound-other"), ASSISTANT])
        self.assertFalse(unbound_skill_loaded(str(self.transcript), "unbound-secure-sql"))

    def test_malformed_lines_are_skipped(self):
        _write_transcript(self.transcript, [
            _invocation("unbound-secure-sql"), "{not json", "", "   ", "[1,2,3]", ASSISTANT,
        ])
        self.assertTrue(unbound_skill_loaded(str(self.transcript), "unbound-secure-sql"))

    def test_empty_transcript(self):
        self.transcript.write_text("", encoding="utf-8")
        self.assertFalse(unbound_skill_loaded(str(self.transcript), "unbound-secure-sql"))
        self.transcript.write_text("   \n\n  \n", encoding="utf-8")
        self.assertFalse(unbound_skill_loaded(str(self.transcript), "unbound-secure-sql"))

    def test_sidechain_entries_are_skipped(self):
        _write_transcript(self.transcript, [
            dict(_invocation("unbound-secure-sql"), isSidechain=True), ASSISTANT,
        ])
        self.assertFalse(unbound_skill_loaded(str(self.transcript), "unbound-secure-sql"))

    def test_guard_clauses(self):
        _write_transcript(self.transcript, [_invocation("unbound-secure-sql")])
        self.assertFalse(unbound_skill_loaded("", "unbound-secure-sql"))
        self.assertFalse(unbound_skill_loaded(str(self.transcript), ""))

    def test_the_whole_transcript_is_read_not_just_a_tail(self):
        filler = json.dumps({"type": "attachment", "pad": "x" * 4096})
        entries = [_invocation("unbound-secure-sql")]
        entries += [filler] * 300
        _write_transcript(self.transcript, entries)

        self.assertGreater(self.transcript.stat().st_size, 1_000_000)
        self.assertEqual(unbound.read_skill_facts(str(self.transcript))["session_count"], 1)


class TestLoadedSkillSlugs(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name) / "skills"
        self.root.mkdir(parents=True)
        self.transcript = Path(self._tmp.name) / "session.jsonl"
        self._patch = patch.object(unbound, "CLAUDE_SKILLS_ROOT", self.root)
        self._patch.start()

    def tearDown(self):
        self._patch.stop()
        self._tmp.cleanup()

    def _install(self, name):
        (self.root / name).mkdir(parents=True, exist_ok=True)

    def test_reports_slugs_not_invoked_names(self):
        self._install("unbound-secure-sql")
        self._install("unbound-pii")
        _write_transcript(self.transcript, [_invocation("unbound-secure-sql"), ASSISTANT])
        self.assertEqual(unbound_loaded_slugs(str(self.transcript)), ["secure-sql"])

    def test_non_unbound_and_bad_slug_dirs_ignored(self):
        self._install("some-other-skill")
        self._install("unbound-Bad_Slug")
        (self.root / "unbound-not-a-dir").write_text("", encoding="utf-8")
        self.assertEqual([e['slug'] for e in unbound.installed_skill_report()], [])

    def test_nothing_installed_skips_the_transcript(self):
        reader = MagicMock(return_value={"loaded": set(), "session_count": 0})
        with patch.object(unbound, "read_skill_facts", reader):
            self.assertEqual(unbound_loaded_slugs(str(self.transcript)), [])
        reader.assert_called_once()

    def test_installed_but_not_invoked(self):
        self._install("unbound-secure-sql")
        _write_transcript(self.transcript, [ASSISTANT])
        self.assertEqual(unbound_loaded_slugs(str(self.transcript)), [])

    def test_missing_transcript_path(self):
        self._install("unbound-secure-sql")
        self.assertEqual(unbound_loaded_slugs(None), [])


class TestInstallInjectedSkills(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name) / "skills"
        self.log = MagicMock()
        self._patchers = [
            patch.object(unbound, "CLAUDE_SKILLS_ROOT", self.root),
            patch.object(unbound, "log_error", self.log),
        ]
        for p in self._patchers:
            p.start()

    def tearDown(self):
        for p in self._patchers:
            p.stop()
        self._tmp.cleanup()

    def _entry(self, slug="secure-sql", content="---\nname: unbound-secure-sql\n---\n\nbody\n"):
        return {"slug": slug, "content": content,
                "sha256": hashlib.sha256(content.encode("utf-8")).hexdigest()}

    def test_fresh_write(self):
        entry = self._entry()
        unbound.install_injected_skills([entry])
        directory = self.root / "unbound-secure-sql"
        self.assertEqual((directory / "SKILL.md").read_text(encoding="utf-8"), entry["content"])
        self.assertTrue((directory / unbound.UNBOUND_SKILL_MARKER).exists())
        self.assertEqual(sorted(p.name for p in directory.iterdir()),
                         [unbound.UNBOUND_SKILL_MARKER, "SKILL.md"])

    def test_unchanged_content_is_not_rewritten(self):
        entry = self._entry()
        unbound.install_injected_skills([entry])
        calls = []
        with patch.object(unbound.tempfile, "mkstemp", lambda *a, **k: calls.append(k)):
            unbound.install_injected_skills([entry])
        self.assertEqual(calls, [])
        self.assertEqual((self.root / "unbound-secure-sql" / "SKILL.md").read_text(encoding="utf-8"),
                         entry["content"])

    def test_changed_content_is_rewritten(self):
        unbound.install_injected_skills([self._entry()])
        updated = self._entry(content="---\nname: unbound-secure-sql\n---\n\nnew body\n")
        unbound.install_injected_skills([updated])
        self.assertEqual((self.root / "unbound-secure-sql" / "SKILL.md").read_text(encoding="utf-8"),
                         updated["content"])

    def test_unmarked_directory_is_left_untouched(self):
        directory = self.root / "unbound-secure-sql"
        directory.mkdir(parents=True)
        theirs = "# a developer's own skill\n"
        (directory / "SKILL.md").write_text(theirs, encoding="utf-8")
        unbound.install_injected_skills([self._entry()])
        self.assertEqual((directory / "SKILL.md").read_bytes(), theirs.encode("utf-8"))
        self.assertFalse((directory / unbound.UNBOUND_SKILL_MARKER).exists())
        self.assertEqual([p.name for p in directory.iterdir()], ["SKILL.md"])
        self.assertTrue(any("not unbound-managed" in c.args[0] for c in self.log.call_args_list))

    def test_malformed_entries_write_nothing(self):
        unbound.install_injected_skills([
            {"slug": "../evil", "content": "x"},
            {"slug": "Bad_Slug", "content": "x"},
            {"slug": "", "content": "x"},
            {"slug": None, "content": "x"},
            {"slug": "ok-slug", "content": ""},
            {"slug": "ok-slug", "content": None},
            "not-a-dict",
        ])
        self.assertFalse(self.root.exists())
        self.assertEqual(sorted(p.name for p in Path(self._tmp.name).iterdir()), [])

    def test_one_bad_entry_does_not_stop_the_rest(self):
        unbound.install_injected_skills([{"slug": "../evil", "content": "x"}, self._entry()])
        self.assertTrue((self.root / "unbound-secure-sql" / "SKILL.md").exists())

    def test_wire_hash_disagreement_writes_the_content(self):
        entry = self._entry()
        entry["sha256"] = "0" * 64
        unbound.install_injected_skills([entry])
        self.assertEqual((self.root / "unbound-secure-sql" / "SKILL.md").read_text(encoding="utf-8"),
                         entry["content"])
        self.assertTrue(any("hash mismatch" in c.args[0] for c in self.log.call_args_list))

    def test_marker_without_body_is_repaired(self):
        directory = self.root / "unbound-secure-sql"
        directory.mkdir(parents=True)
        (directory / unbound.UNBOUND_SKILL_MARKER).write_text("", encoding="utf-8")
        entry = self._entry()
        unbound.install_injected_skills([entry])
        self.assertEqual((directory / "SKILL.md").read_text(encoding="utf-8"), entry["content"])

    def test_a_failed_marker_write_leaves_nothing_to_skip_next_run(self):
        real_write = unbound.Path.write_text

        def fail_on_marker(self_path, *args, **kwargs):
            if self_path.name == unbound.UNBOUND_SKILL_MARKER:
                raise OSError("read-only")
            return real_write(self_path, *args, **kwargs)

        with patch.object(unbound.Path, "write_text", fail_on_marker):
            unbound.install_injected_skills([self._entry()])
        self.assertFalse((self.root / "unbound-secure-sql").exists())

        unbound.install_injected_skills([self._entry()])
        self.assertTrue((self.root / "unbound-secure-sql" / "SKILL.md").exists())

    def test_write_failure_is_non_fatal(self):
        with patch.object(unbound.tempfile, "mkstemp", side_effect=OSError("no space")):
            unbound.install_injected_skills([self._entry()])
        self.assertFalse((self.root / "unbound-secure-sql" / "SKILL.md").exists())
        self.assertTrue(any("skill injection failed" in c.args[0] for c in self.log.call_args_list))


class ProcessPreToolUseSkillBase(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.tmp = Path(self._tmp.name)
        self.skills_root = self.tmp / "skills"
        self.skills_root.mkdir(parents=True)
        self.transcript = self.tmp / "session.jsonl"
        _write_transcript(self.transcript, [ASSISTANT])
        self.log = MagicMock()
        self._patchers = [
            patch.object(unbound, "CLAUDE_SKILLS_ROOT", self.skills_root),
            patch.object(unbound, "log_error", self.log),
            patch.object(unbound, "load_policy_cache", lambda: {"tools_to_check": [], "ts": 0}),
            patch.object(unbound, "is_cache_stale", lambda c: False),
            patch.object(unbound, "get_recent_user_prompts_for_session", lambda *a, **k: []),
            patch.object(unbound, "_get_session_model", lambda *a, **k: "auto"),
            patch.object(unbound, "_is_approval_retry", lambda *a, **k: False),
            patch.object(unbound, "build_account_identity", lambda *a, **k: {}),
            patch.object(unbound, "report_error_to_gateway", lambda *a, **k: None),
        ]
        for p in self._patchers:
            p.start()

    def tearDown(self):
        for p in self._patchers:
            p.stop()
        self._tmp.cleanup()

    def _event(self, **extra):
        event = {
            "hook_event_name": "PreToolUse",
            "tool_name": "Bash",
            "tool_input": {"command": "psql -c 'select 1'"},
            "cwd": str(self.tmp),
            "session_id": "sess",
            "transcript_path": str(self.transcript),
        }
        event.update(extra)
        return event

    def _run(self, api_response, **extra):
        captured = {}

        def capturing_gw(request_body, api_key):
            captured["md"] = request_body["pre_tool_use_data"]["metadata"]
            return api_response

        with patch.object(unbound, "send_to_hook_api", capturing_gw):
            result = unbound.process_pre_tool_use(self._event(**extra), "API_KEY")
        return captured.get("md", {}), result


class TestPreToolUseSkillReporting(ProcessPreToolUseSkillBase):
    def _managed(self, slug):
        directory = self.skills_root / ("unbound-" + slug)
        directory.mkdir(parents=True, exist_ok=True)
        (directory / unbound.UNBOUND_SKILL_MARKER).write_text("", encoding="utf-8")
        (directory / "SKILL.md").write_text("body\n", encoding="utf-8")
        return directory

    def test_loaded_skills_carries_slugs(self):
        self._managed("secure-sql")
        _write_transcript(self.transcript, [_invocation("unbound-secure-sql"), ASSISTANT])
        metadata, _ = self._run({"decision": "allow"})
        self.assertEqual(metadata.get("loaded_skills"), ["secure-sql"])

    def test_an_unmanaged_dir_reports_nothing(self):
        """The gateway only injects for a slug we manage, so a developer's own
        unbound-<slug> can no longer cause a re-injection loop and needs no special case."""
        (self.skills_root / "unbound-hand-rolled").mkdir()
        _write_transcript(self.transcript, [_invocation("unbound-hand-rolled"), ASSISTANT])
        metadata, _ = self._run({"decision": "allow"})
        self.assertNotIn("loaded_skills", metadata)
        self.assertNotIn("installed_skills", metadata)

    def test_loaded_skills_absent_when_nothing_loaded(self):
        self._managed("secure-sql")
        metadata, _ = self._run({"decision": "allow"})
        self.assertNotIn("loaded_skills", metadata)

    def test_prompt_id_forwarded(self):
        metadata, _ = self._run({"decision": "allow"}, prompt_id="prompt-abc")
        self.assertEqual(metadata.get("prompt_id"), "prompt-abc")

    def test_prompt_id_absent_when_event_lacks_it(self):
        metadata, _ = self._run({"decision": "allow"})
        self.assertNotIn("prompt_id", metadata)


class TestPreToolUseSkillInstall(ProcessPreToolUseSkillBase):
    def _deny_response(self):
        content = "---\nname: unbound-secure-sql\n---\n\nuse parameterised queries\n"
        return {
            "decision": "deny",
            "reason": "Invoke unbound-secure-sql, then retry the identical command.",
            "additionalContext": "An organization policy requires the unbound-secure-sql skill.",
            "inject_skills": [{
                "slug": "secure-sql",
                "sha256": hashlib.sha256(content.encode("utf-8")).hexdigest(),
            }],
        }

    def test_deny_writes_nothing_because_the_device_already_had_it(self):
        """The gateway only denies for a slug this device reported current, so the deny
        carries no body and the hook has nothing to write."""
        response = self._deny_response()
        _, result = self._run(response)
        self.assertFalse((self.skills_root / "unbound-secure-sql").exists())
        self.assertEqual(result["hookSpecificOutput"]["permissionDecision"], "deny")

    def test_deny_records_the_turn_so_the_retry_is_not_blocked_again(self):
        guard_dir = self.tmp / "injection-turn"
        with patch.object(unbound, "INJECTION_TURN_GUARD_DIR", guard_dir):
            metadata, _ = self._run({"decision": "allow"}, prompt_id="turn-1")
            self.assertNotIn("already_injected_this_turn", metadata)

            self._run(self._deny_response(), prompt_id="turn-1")
            self.assertEqual(
                unbound._turn_guard_path("sess").read_text(encoding="utf-8"), "turn-1"
            )

            metadata, _ = self._run({"decision": "allow"}, prompt_id="turn-1")
            self.assertTrue(metadata["already_injected_this_turn"])

            metadata, _ = self._run({"decision": "allow"}, prompt_id="turn-2")
            self.assertNotIn("already_injected_this_turn", metadata)

    def test_the_turn_guard_is_scoped_per_session(self):
        guard_dir = self.tmp / "injection-turn"
        with patch.object(unbound, "INJECTION_TURN_GUARD_DIR", guard_dir):
            unbound._turn_guard_write("session-a", "turn-1")
            unbound._turn_guard_write("session-b", "turn-9")

            self.assertEqual(unbound._turn_guard_read("session-a"), "turn-1")
            self.assertEqual(unbound._turn_guard_read("session-b"), "turn-9")
            self.assertEqual(unbound._turn_guard_read("session-c"), "")

    def test_a_path_hostile_session_id_cannot_escape_the_guard_dir(self):
        guard_dir = self.tmp / "injection-turn"
        with patch.object(unbound, "INJECTION_TURN_GUARD_DIR", guard_dir):
            target = unbound._turn_guard_path("../../etc/passwd")

        self.assertEqual(target.parent, guard_dir)

    def test_allow_never_installs(self):
        response = dict(self._deny_response(), decision="allow")
        self._run(response)
        self.assertFalse((self.skills_root / "unbound-secure-sql").exists())


class TestPreToolUseSkillPrune(ProcessPreToolUseSkillBase):
    def _managed(self, slug):
        directory = self.skills_root / ("unbound-" + slug)
        directory.mkdir(parents=True)
        (directory / unbound.UNBOUND_SKILL_MARKER).write_text("", encoding="utf-8")
        (directory / "SKILL.md").write_text("body\n", encoding="utf-8")
        return directory

    def test_installed_skills_reports_managed_dirs_with_their_hashes(self):
        directory = self._managed("secure-sql")
        (self.skills_root / "unbound-hand-rolled").mkdir()
        metadata, _ = self._run({"decision": "allow"})
        expected = hashlib.sha256((directory / "SKILL.md").read_bytes()).hexdigest()
        self.assertEqual(metadata.get("installed_skills"),
                         [{"slug": "secure-sql", "sha256": expected}])

    def test_installed_skills_absent_when_nothing_managed(self):
        metadata, _ = self._run({"decision": "allow"})
        self.assertNotIn("installed_skills", metadata)

    def test_remove_skills_deletes_the_managed_dir(self):
        directory = self._managed("secure-sql")
        self._run({"decision": "allow", "remove_skills": ["secure-sql"]})
        self.assertFalse(directory.exists())

    def test_remove_skills_leaves_an_unmanaged_dir_alone(self):
        directory = self.skills_root / "unbound-hand-rolled"
        directory.mkdir()
        (directory / "SKILL.md").write_text("mine\n", encoding="utf-8")
        self._run({"decision": "allow", "remove_skills": ["hand-rolled"]})
        self.assertTrue((directory / "SKILL.md").exists())
        self.assertTrue(any("not unbound-managed" in c.args[0] for c in self.log.call_args_list))

    def test_remove_skills_rejects_a_traversing_slug(self):
        victim = self.skills_root / "unbound-secure-sql"
        victim.mkdir()
        self._run({"decision": "allow", "remove_skills": ["../unbound-secure-sql"]})
        self.assertTrue(victim.exists())
        self.assertTrue(any("prune rejected slug" in c.args[0] for c in self.log.call_args_list))

    def test_remove_skills_prunes_on_a_deny_too(self):
        directory = self._managed("stale")
        response = {"decision": "deny", "reason": "blocked", "remove_skills": ["stale"]}
        _, result = self._run(response)
        self.assertFalse(directory.exists())
        self.assertEqual(result["hookSpecificOutput"]["permissionDecision"], "deny")

    def test_one_bad_slug_does_not_stop_the_rest(self):
        good = self._managed("good")
        self._run({"decision": "allow", "remove_skills": ["Bad Slug", "good"]})
        self.assertFalse(good.exists())


class TestSkillsSync(ProcessPreToolUseSkillBase):
    def _managed(self, slug, body="old body\n"):
        directory = self.skills_root / ("unbound-" + slug)
        directory.mkdir(parents=True)
        (directory / unbound.UNBOUND_SKILL_MARKER).write_text("", encoding="utf-8")
        (directory / "SKILL.md").write_text(body, encoding="utf-8")
        return directory

    def _sync(self, plan, returncode=0):
        completed = MagicMock(returncode=returncode, stdout=json.dumps(plan).encode())
        with patch.object(unbound, "SKILLS_SYNC_LOCK_PATH", self.tmp / "sync.lock"), \
             patch.object(unbound.subprocess, "run", return_value=completed) as run:
            unbound._sync_skills_once("test-key")
        return run

    def test_installs_a_skill_it_did_not_have(self):
        body = "---\nname: unbound-secure-sql\n---\n\nuse parameters\n"
        self._sync({"install": [{
            "slug": "secure-sql",
            "content": body,
            "sha256": hashlib.sha256(body.encode()).hexdigest(),
        }], "remove": []})

        written = (self.skills_root / "unbound-secure-sql" / "SKILL.md").read_text(encoding="utf-8")
        self.assertEqual(written, body)

    def test_overwrites_a_stale_body(self):
        directory = self._managed("secure-sql", body="stale\n")
        fresh = "fresh\n"
        self._sync({"install": [{
            "slug": "secure-sql",
            "content": fresh,
            "sha256": hashlib.sha256(fresh.encode()).hexdigest(),
        }], "remove": []})

        self.assertEqual((directory / "SKILL.md").read_text(encoding="utf-8"), fresh)

    def test_deletes_what_the_plan_removes(self):
        directory = self._managed("gone")
        self._sync({"install": [], "remove": ["gone"]})

        self.assertFalse(directory.exists())

    def test_reports_what_is_on_disk_with_hashes(self):
        directory = self._managed("secure-sql")
        run = self._sync({"install": [], "remove": []})

        sent = json.loads(run.call_args.kwargs["input"].decode())
        expected = hashlib.sha256((directory / "SKILL.md").read_bytes()).hexdigest()
        self.assertEqual(sent["installed"], [{"slug": "secure-sql", "sha256": expected}])

    def test_a_failed_request_changes_nothing(self):
        directory = self._managed("keep-me")
        self._sync({"install": [], "remove": ["keep-me"]}, returncode=22)

        self.assertTrue(directory.exists())

    def test_a_held_lock_makes_it_a_no_op(self):
        directory = self._managed("gone")
        lock = self.tmp / "sync.lock"
        lock.write_text("", encoding="utf-8")
        completed = MagicMock(returncode=0, stdout=json.dumps({"install": [], "remove": ["gone"]}).encode())
        with patch.object(unbound, "SKILLS_SYNC_LOCK_PATH", lock), \
             patch.object(unbound.subprocess, "run", return_value=completed) as run:
            unbound._sync_skills_once("test-key")

        run.assert_not_called()
        self.assertTrue(directory.exists())

    def test_the_lock_is_released_for_the_next_run(self):
        lock = self.tmp / "sync.lock"
        self._sync({"install": [], "remove": []})
        self.assertFalse(lock.exists())

    def test_a_stale_lock_does_not_wedge_it_forever(self):
        directory = self._managed("gone")
        lock = self.tmp / "sync.lock"
        lock.write_text("", encoding="utf-8")
        os.utime(lock, (0, 0))
        completed = MagicMock(returncode=0, stdout=json.dumps({"install": [], "remove": ["gone"]}).encode())
        with patch.object(unbound, "SKILLS_SYNC_LOCK_PATH", lock), \
             patch.object(unbound.subprocess, "run", return_value=completed):
            unbound._sync_skills_once("test-key")

        self.assertFalse(directory.exists())

    def test_a_sync_flag_on_the_response_dispatches_a_reconcile(self):
        with patch.object(unbound, "_dispatch_skills_sync") as dispatch:
            self._run({"decision": "allow", "sync_skills": True})
        dispatch.assert_called_once()

    def test_no_sync_flag_dispatches_nothing(self):
        with patch.object(unbound, "_dispatch_skills_sync") as dispatch:
            self._run({"decision": "allow"})
        dispatch.assert_not_called()


class TestSkillsSyncDispatchTarget(unittest.TestCase):
    def test_re_execs_the_running_file_not_the_user_level_install_path(self):
        with patch.object(unbound.subprocess, "Popen") as popen:
            unbound._dispatch_skills_sync("test-key")

        argv = popen.call_args[0][0]
        self.assertEqual(argv[1], os.path.abspath(unbound.__file__))
        self.assertEqual(argv[2], "--sync-skills")
        self.assertNotEqual(argv[1], str(unbound.SELF_SCRIPT_PATH))

    def test_spawns_nothing_when_the_running_file_is_gone(self):
        with patch.object(unbound.os.path, "isfile", return_value=False), \
             patch.object(unbound.subprocess, "Popen") as popen, \
             patch.object(unbound, "log_error") as log_error:
            unbound._dispatch_skills_sync("test-key")

        popen.assert_not_called()
        log_error.assert_called_once()

    def test_a_frozen_build_re_execs_the_binary_subcommand(self):
        with patch.dict(os.environ, {"UNBOUND_HOOK_TOOL": "claude-code"}), \
             patch.object(unbound, "RUNNING_FROZEN", True), \
             patch.object(unbound.subprocess, "Popen") as popen:
            unbound._dispatch_skills_sync("test-key")

        argv = popen.call_args[0][0]
        self.assertEqual(argv, [unbound.sys.executable, "sync-skills", "claude-code"])

    def test_the_key_travels_by_env_never_argv(self):
        with patch.object(unbound.subprocess, "Popen") as popen:
            unbound._dispatch_skills_sync("test-key")

        argv, kwargs = popen.call_args[0][0], popen.call_args[1]
        self.assertNotIn("test-key", argv)
        self.assertEqual(kwargs["env"]["UNBOUND_CLAUDE_API_KEY"], "test-key")

    def test_the_child_is_detached_on_this_platform(self):
        with patch.object(unbound.subprocess, "Popen") as popen:
            unbound._dispatch_skills_sync("test-key")

        kwargs = popen.call_args[1]
        self.assertTrue(kwargs["close_fds"])
        if os.name == "nt":
            self.assertIn("creationflags", kwargs)
            self.assertNotIn("start_new_session", kwargs)
        else:
            self.assertTrue(kwargs["start_new_session"])
            self.assertNotIn("creationflags", kwargs)

    def test_spawns_nothing_without_an_api_key(self):
        with patch.object(unbound.subprocess, "Popen") as popen:
            unbound._dispatch_skills_sync("")

        popen.assert_not_called()


class TestSessionLoadCount(ProcessPreToolUseSkillBase):
    def _managed(self, slug):
        directory = self.skills_root / ("unbound-" + slug)
        directory.mkdir(parents=True)
        (directory / unbound.UNBOUND_SKILL_MARKER).write_text("", encoding="utf-8")
        (directory / "SKILL.md").write_text("body\n", encoding="utf-8")
        return directory

    def test_counts_distinct_skills_loaded_this_session(self):
        self._managed("secure-sql")
        _write_transcript(self.transcript, [
            _invocation("unbound-secure-sql"), ASSISTANT,
            _invocation("unbound-shell-safety"), ASSISTANT,
            _invocation("unbound-secure-sql"), ASSISTANT,
        ])
        metadata, _ = self._run({"decision": "allow"})
        self.assertEqual(metadata["skills_loaded_this_session"], 2)

    def test_counts_across_a_compaction_unlike_the_reinjection_window(self):
        """The append-only JSONL keeps the record, so bloat spent earlier still counts."""
        self._managed("secure-sql")
        _write_transcript(self.transcript, [
            _invocation("unbound-old-one"), ASSISTANT,
            {"type": "system", "subtype": "compact_boundary"},
            _invocation("unbound-secure-sql"), ASSISTANT,
        ])
        metadata, _ = self._run({"decision": "allow"})
        self.assertEqual(metadata["skills_loaded_this_session"], 2)
        self.assertEqual(metadata.get("loaded_skills"), ["secure-sql"])

    def test_ignores_a_non_unbound_skill(self):
        self._managed("secure-sql")
        _write_transcript(self.transcript, [_invocation("some-other-skill"), ASSISTANT])
        metadata, _ = self._run({"decision": "allow"})
        self.assertEqual(metadata["skills_loaded_this_session"], 0)


if __name__ == '__main__':
    unittest.main()
