import hashlib
import io
import json
import shutil
import tempfile
import unittest
from contextlib import ExitStack
from pathlib import Path
from unittest.mock import patch

from tests.conftest import tool_module


CLIENTS = {
    "copilot": tool_module("copilot/hooks"),
    "cursor": tool_module("cursor"),
    "codex": tool_module("codex/hooks"),
}


def _entry(slug="secure-sql", body="Reject N+1 queries."):
    content = f"---\nname: unbound-{slug}\n---\n\n{body}\n"
    return {
        "slug": slug,
        "content": content,
        "sha256": hashlib.sha256(content.encode()).hexdigest(),
    }


class CrossClientSkillLifecycleTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name) / "skills"

    def tearDown(self):
        self.tmp.cleanup()

    def _reset_root(self):
        shutil.rmtree(self.root, ignore_errors=True)

    def test_install_report_update_and_prune_are_identical(self):
        for name, module in CLIENTS.items():
            with self.subTest(client=name), patch.object(module, "MANAGED_SKILLS_ROOT", self.root):
                first = _entry()
                module.install_injected_skills([first])
                directory = self.root / "unbound-secure-sql"
                self.assertEqual((directory / "SKILL.md").read_text(), first["content"])
                self.assertTrue((directory / module.UNBOUND_SKILL_MARKER).exists())
                self.assertEqual(
                    module.installed_skill_report(),
                    [{"slug": "secure-sql", "sha256": first["sha256"]}],
                )

                updated = _entry(body="Reject N+1 queries and require bounded reads.")
                module.install_injected_skills([updated])
                self.assertEqual((directory / "SKILL.md").read_text(), updated["content"])

                module.prune_injected_skills(["secure-sql"])
                self.assertFalse(directory.exists())
            self._reset_root()

    def test_inventory_ignores_marked_directories_outside_managed_namespace(self):
        for name, module in CLIENTS.items():
            with self.subTest(client=name), patch.object(module, "MANAGED_SKILLS_ROOT", self.root):
                directory = self.root / "not-unbound-prefixed"
                directory.mkdir(parents=True)
                (directory / module.UNBOUND_SKILL_MARKER).touch()
                (directory / "SKILL.md").write_text("developer-owned\n")

                self.assertEqual(module.installed_skill_report(), [])
            self._reset_root()

    def test_never_overwrites_or_prunes_an_unmanaged_skill(self):
        for name, module in CLIENTS.items():
            with self.subTest(client=name), patch.object(module, "MANAGED_SKILLS_ROOT", self.root):
                directory = self.root / "unbound-secure-sql"
                directory.mkdir(parents=True)
                original = "developer-owned\n"
                (directory / "SKILL.md").write_text(original)

                module.install_injected_skills([_entry()])
                module.prune_injected_skills(["secure-sql"])

                self.assertEqual((directory / "SKILL.md").read_text(), original)
                self.assertFalse((directory / module.UNBOUND_SKILL_MARKER).exists())
            self._reset_root()

    def test_never_trusts_a_symlinked_managed_marker(self):
        for name, module in CLIENTS.items():
            with self.subTest(client=name), patch.object(module, "MANAGED_SKILLS_ROOT", self.root):
                directory = self.root / "unbound-secure-sql"
                directory.mkdir(parents=True)
                original = "developer-owned\n"
                (directory / "SKILL.md").write_text(original)
                target = self.root / "marker-target"
                target.write_text("keep me\n")
                (directory / module.UNBOUND_SKILL_MARKER).symlink_to(target)

                self.assertFalse(module.install_injected_skills([_entry()]))
                module.prune_injected_skills(["secure-sql"])

                self.assertEqual(target.read_text(), "keep me\n")
                self.assertEqual((directory / "SKILL.md").read_text(), original)
            self._reset_root()

    def test_never_reads_or_overwrites_a_symlinked_skill_body(self):
        for name, module in CLIENTS.items():
            with self.subTest(client=name), patch.object(module, "MANAGED_SKILLS_ROOT", self.root):
                directory = self.root / "unbound-secure-sql"
                directory.mkdir(parents=True)
                (directory / module.UNBOUND_SKILL_MARKER).touch()
                target = self.root / "body-target"
                target.write_text("keep me\n")
                (directory / "SKILL.md").symlink_to(target)

                self.assertEqual(module.installed_skill_report(), [])
                self.assertFalse(module.install_injected_skills([_entry()]))
                module.prune_injected_skills(["secure-sql"])

                self.assertEqual(target.read_text(), "keep me\n")
                self.assertFalse(directory.exists())
            self._reset_root()

    def test_sync_sends_hash_inventory_then_applies_plan(self):
        for name, module in CLIENTS.items():
            with self.subTest(client=name), \
                    patch.object(module, "MANAGED_SKILLS_ROOT", self.root), \
                    patch.object(module, "SKILLS_SYNC_LOCK_PATH", self.root.parent / f"{name}.lock"):
                module.install_injected_skills([_entry("old")])
                incoming = _entry("secure-sql")
                plan = {"install": [incoming], "remove": ["old"]}
                with patch.object(module, "_request_skill_sync", return_value=plan) as request:
                    module._sync_skills_once("secret")

                api_key, payload = request.call_args.args
                self.assertEqual(api_key, "secret")
                self.assertEqual(payload["installed"][0]["slug"], "old")
                self.assertTrue((self.root / "unbound-secure-sql" / "SKILL.md").exists())
                self.assertFalse((self.root / "unbound-old").exists())
            self._reset_root()

    def test_sync_rejects_entire_plan_before_mutating_skills(self):
        for name, module in CLIENTS.items():
            with self.subTest(client=name), \
                    patch.object(module, "MANAGED_SKILLS_ROOT", self.root), \
                    patch.object(module, "SKILLS_SYNC_LOCK_PATH", self.root.parent / f"{name}.lock"):
                old = _entry("old")
                module.install_injected_skills([old])
                incoming = _entry("secure-sql")
                incoming["sha256"] = "0" * 64
                plan = {"install": [incoming], "remove": ["old"]}
                with patch.object(module, "_request_skill_sync", return_value=plan):
                    module._sync_skills_once("secret")

                self.assertEqual(
                    (self.root / "unbound-old" / "SKILL.md").read_text(),
                    old["content"],
                )
                self.assertFalse((self.root / "unbound-secure-sql").exists())
            self._reset_root()

    def test_sync_failure_logs_never_include_the_api_key(self):
        for name, module in CLIENTS.items():
            with self.subTest(client=name), \
                    patch.object(module, "SKILLS_SYNC_LOCK_PATH", self.root.parent / f"{name}.lock"), \
                    patch.object(
                        module,
                        "_request_skill_sync",
                        side_effect=TimeoutError("Authorization: Bearer secret"),
                    ), \
                    patch.object(module, "log_error") as log_error:
                module._sync_skills_once("secret")

                logged = " ".join(str(part) for call in log_error.call_args_list for part in call.args)
                self.assertNotIn("secret", logged)

    def test_install_rejects_hash_mismatch_without_writing(self):
        for name, module in CLIENTS.items():
            with self.subTest(client=name), patch.object(module, "MANAGED_SKILLS_ROOT", self.root):
                incoming = _entry()
                incoming["sha256"] = "0" * 64
                self.assertFalse(module.install_injected_skills([incoming]))
                self.assertFalse((self.root / "unbound-secure-sql").exists())
            self._reset_root()

    def test_turn_claim_is_written_for_each_provider(self):
        event = {"session_id": "s1", "turn_id": "t1"}
        for name, module in CLIENTS.items():
            with self.subTest(client=name), tempfile.TemporaryDirectory() as tmp:
                client_event = dict(event)
                if name == "cursor":
                    client_event = {"conversation_id": "s1", "generation_id": "t1"}
                if name == "copilot":
                    with patch.object(module, "get_turn_start_timestamp_for_session", return_value="t1"):
                        with patch.object(module, "SKILL_POLICY_STATE_ROOT", Path(tmp)):
                            self.assertFalse(module._skill_turn_claim_path("s1:t1").exists())
                            module._claim_skill_injection_turn(client_event)
                            self.assertTrue(module._skill_turn_claim_path("s1:t1").exists())
                    continue
                with patch.object(module, "SKILL_POLICY_STATE_ROOT", Path(tmp)):
                    self.assertFalse(module._skill_turn_claim_path("s1:t1").exists())
                    module._claim_skill_injection_turn(client_event)
                    self.assertTrue(module._skill_turn_claim_path("s1:t1").exists())


class CrossClientInjectionContextTests(unittest.TestCase):
    def test_codex_prompt_forwards_gateway_context_unchanged(self):
        context = "Invoke the skill unbound-secure-sql before answering."
        response = CLIENTS["codex"].transform_response_for_codex_prompt({
            "decision": "allow",
            "additionalContext": context,
            "inject_skills": [_entry()],
        })
        self.assertEqual(response["hookSpecificOutput"]["additionalContext"], context)

    def test_copilot_prompt_forwards_gateway_context_unchanged(self):
        context = "Invoke the skill unbound-secure-sql before answering."
        response = CLIENTS["copilot"].transform_response_for_copilot_prompt({
            "decision": "allow",
            "additionalContext": context,
            "inject_skills": [_entry()],
        })
        self.assertEqual(response["additionalContext"], context)

    def test_copilot_prompt_preserves_gateway_blocks(self):
        for decision in ("deny", "block"):
            with self.subTest(decision=decision):
                response = CLIENTS["copilot"].transform_response_for_copilot_prompt(
                    {"decision": decision, "reason": "Blocked by policy."},
                )
                self.assertEqual(
                    response,
                    {"decision": "block", "reason": "Blocked by policy."},
                )

    def test_tool_injection_forwards_gateway_context_unchanged(self):
        plan = {
            "decision": "deny",
            "reason": "Load the required skill.",
            "additionalContext": "Invoke the skill unbound-secure-sql, then retry.",
            "inject_skills": [_entry()],
        }
        copilot = CLIENTS["copilot"].transform_response_for_copilot(plan)
        codex = CLIENTS["codex"].transform_response_for_codex(plan)
        cursor = CLIENTS["cursor"].format_hook_response(plan)

        context = plan["additionalContext"]
        self.assertEqual(copilot["hookSpecificOutput"]["additionalContext"], context)
        self.assertEqual(codex["hookSpecificOutput"]["additionalContext"], context)
        self.assertEqual(cursor["agent_message"], context)

    def test_transcript_tail_is_bounded_and_drops_a_partial_first_record(self):
        for name in ("copilot", "codex"):
            client = CLIENTS[name]
            with self.subTest(client=name), tempfile.TemporaryDirectory() as tmp:
                transcript = Path(tmp) / "events.jsonl"
                transcript.write_bytes(
                    b'{"discarded":"' + b'x' * 128 + b'"}\n'
                    b'{"kept":true}\n'
                )
                with patch.object(client, "SKILL_TRANSCRIPT_TAIL_BYTES", 32):
                    lines = client._skill_policy_transcript_tail(str(transcript))

                self.assertEqual(lines, [b'{"kept":true}'])

    def test_session_count_reads_beyond_the_active_tail(self):
        copilot_row = {"type": "skill.invoked", "data": {"name": "unbound-secure-sql"}}
        codex_row = {
            "type": "response_item",
            "payload": {
                "type": "message",
                "role": "user",
                "content": [{"type": "input_text", "text": "<skill><name>unbound-secure-sql</name></skill>"}],
                "internal_chat_message_metadata_passthrough": {
                    "content_item_kinds": ["skills.selected_skill_instructions"],
                },
            },
        }
        cursor_row = {
            "role": "assistant",
            "message": {"content": [{
                "type": "tool_use",
                "name": "Read",
                "input": {"path": "/skills/unbound-secure-sql/SKILL.md"},
            }]},
        }
        for name, row in (("copilot", copilot_row), ("codex", codex_row), ("cursor", cursor_row)):
            client = CLIENTS[name]
            with self.subTest(client=name), tempfile.TemporaryDirectory() as tmp:
                transcript = Path(tmp) / "transcript.jsonl"
                transcript.write_text(json.dumps(row) + "\n" + json.dumps({"padding": "x" * 256}) + "\n")
                event = {"session_id": "s1", "transcript_path": str(transcript)}
                with ExitStack() as stack:
                    stack.enter_context(patch.object(client, "SKILL_TRANSCRIPT_TAIL_BYTES", 32))
                    if name == "cursor":
                        stack.enter_context(patch.object(
                            client, "_skill_name_from_path", return_value="unbound-secure-sql"
                        ))
                    facts = client._skill_policy_loaded_facts(event)

                self.assertEqual(facts["loaded"], set())
                self.assertEqual(facts["session_count"], 1)

    def test_copilot_loaded_skill_expires_after_ten_assistant_turns(self):
        copilot = CLIENTS["copilot"]
        invoked = {"type": "skill.invoked", "data": {"name": "unbound-secure-sql"}}
        turn = {"type": "assistant.turn_start", "data": {}}
        with tempfile.TemporaryDirectory() as tmp:
            transcript = Path(tmp) / "events.jsonl"
            event = {"session_id": "s1", "transcript_path": str(transcript)}
            with patch.object(copilot, "SKILL_POLICY_STATE_ROOT", Path(tmp) / "state"):
                transcript.write_text("\n".join(json.dumps(row) for row in [invoked] + [turn] * 10) + "\n")
                edge = copilot._skill_policy_loaded_facts(event)
                transcript.write_text("\n".join(json.dumps(row) for row in [invoked] + [turn] * 11) + "\n")
                expired = copilot._skill_policy_loaded_facts(event)

        self.assertEqual(edge, {"loaded": {"secure-sql"}, "session_count": 1})
        self.assertEqual(expired, {"loaded": set(), "session_count": 1})

    def test_copilot_finds_the_normal_cli_transcript_without_an_event_path(self):
        copilot = CLIENTS["copilot"]
        event = {"session_id": "s1"}
        with tempfile.TemporaryDirectory() as tmp:
            home = Path(tmp) / ".copilot"
            transcript = home / "session-state" / "s1" / "events.jsonl"
            transcript.parent.mkdir(parents=True)
            transcript.write_text(json.dumps({
                "type": "skill.invoked",
                "data": {"name": "unbound-secure-sql"},
            }) + "\n")
            with patch.object(copilot, "_copilot_home", return_value=home), \
                    patch.object(copilot, "SKILL_POLICY_STATE_ROOT", Path(tmp) / "state"):
                facts = copilot._skill_policy_loaded_facts(event)

        self.assertEqual(facts["loaded"], {"secure-sql"})

    def test_copilot_ignores_malformed_skill_invocation_events(self):
        copilot = CLIENTS["copilot"]
        with tempfile.TemporaryDirectory() as tmp:
            transcript = Path(tmp) / "events.jsonl"
            transcript.write_text("\n".join(json.dumps(entry) for entry in (
                {"type": "skill.invoked", "data": "unbound-secure-sql"},
                {"type": "skill.invoked", "data": {"name": "unbound-invalid/slug"}},
            )) + "\n")
            event = {"session_id": "s1", "transcript_path": str(transcript)}
            with patch.object(copilot, "SKILL_POLICY_STATE_ROOT", Path(tmp) / "state"):
                facts = copilot._skill_policy_loaded_facts(event)

        self.assertEqual(facts["loaded"], set())
        self.assertEqual(facts["session_count"], 0)

    def test_cursor_reads_loaded_state_from_transcript(self):
        cursor = CLIENTS["cursor"]
        row = {
            "role": "assistant",
            "message": {"content": [{
                "type": "tool_use",
                "name": "Read",
                "input": {"path": "/skills/unbound-secure-sql/SKILL.md"},
            }]},
        }
        with tempfile.TemporaryDirectory() as tmp:
            transcript = Path(tmp) / "transcript.jsonl"
            transcript.write_text(json.dumps(row) + "\n")
            event = {"conversation_id": "c1", "transcript_path": str(transcript)}
            with patch.object(cursor, "_skill_name_from_path", return_value="unbound-secure-sql"):
                facts = cursor._skill_policy_loaded_facts(event)

        self.assertEqual(facts, {"loaded": {"secure-sql"}, "session_count": 1})

    def test_cursor_loaded_skill_expires_after_ten_user_prompts(self):
        cursor = CLIENTS["cursor"]
        skill_read = {
            "role": "assistant",
            "message": {"content": [{
                "type": "tool_use",
                "name": "Read",
                "input": {"path": "/skills/unbound-secure-sql/SKILL.md"},
            }]},
        }
        user = {"role": "user", "message": {"content": []}}
        with tempfile.TemporaryDirectory() as tmp:
            transcript = Path(tmp) / "transcript.jsonl"
            event = {"conversation_id": "c1", "transcript_path": str(transcript)}
            with patch.object(cursor, "_skill_name_from_path", return_value="unbound-secure-sql"):
                transcript.write_text("\n".join(json.dumps(row) for row in [skill_read] + [user] * 10) + "\n")
                edge = cursor._skill_policy_loaded_facts(event)
                transcript.write_text("\n".join(json.dumps(row) for row in [skill_read] + [user] * 11) + "\n")
                expired = cursor._skill_policy_loaded_facts(event)

        self.assertEqual(edge, {"loaded": {"secure-sql"}, "session_count": 1})
        self.assertEqual(expired, {"loaded": set(), "session_count": 1})

    def test_cursor_tracks_two_skill_reads_in_one_generation(self):
        cursor = CLIENTS["cursor"]
        row = {
            "role": "assistant",
            "message": {"content": [
                {"type": "tool_use", "name": "Read", "input": {"path": "/skills/unbound-first-rule/SKILL.md"}},
                {"type": "tool_use", "name": "Read", "input": {"path": "/skills/unbound-second-rule/SKILL.md"}},
            ]},
        }

        def skill_name(path, _roots):
            return Path(path).parent.name

        with tempfile.TemporaryDirectory() as tmp:
            transcript = Path(tmp) / "transcript.jsonl"
            transcript.write_text(json.dumps(row) + "\n")
            with patch.object(cursor, "_skill_name_from_path", side_effect=skill_name):
                facts = cursor._skill_policy_loaded_facts({
                    "conversation_id": "c1",
                    "transcript_path": str(transcript),
                })

        self.assertEqual(facts, {
            "loaded": {"first-rule", "second-rule"},
            "session_count": 2,
        })

    def test_cursor_defers_prompt_injection_to_next_tool_context(self):
        cursor = CLIENTS["cursor"]
        event = {"conversation_id": "c1", "generation_id": "g1"}
        with tempfile.TemporaryDirectory() as tmp:
            with patch.object(cursor, "SKILL_POLICY_STATE_ROOT", Path(tmp)):
                cursor._defer_prompt_skill_context(
                    event, "Invoke /unbound-secure-sql before continuing."
                )
                response = cursor._with_deferred_skill_context(event, {})
                self.assertEqual(response["permission"], "deny")
                self.assertIn("/unbound-secure-sql", response["agent_message"])
                self.assertEqual(cursor._consume_deferred_skill_context(event), ("", ""))

    def test_codex_shows_the_admin_notice_not_the_model_instruction(self):
        instruction = "ORGANIZATION POLICY: you MUST invoke unbound-secure-sql first."
        notice = "Policy PROMPT-C requires unbound-secure-sql before this request."
        response = CLIENTS["codex"].transform_response_for_codex_prompt({
            "decision": "allow",
            "additionalContext": instruction,
            "user_notice": notice,
            "inject_skills": [_entry()],
        })
        self.assertEqual(response["hookSpecificOutput"]["additionalContext"], instruction)
        self.assertEqual(response["systemMessage"], notice)

    def test_codex_falls_back_to_context_when_no_notice(self):
        instruction = "You've used $80 of your $100 limit."
        response = CLIENTS["codex"].transform_response_for_codex_prompt({
            "decision": "allow",
            "additionalContext": instruction,
        })
        self.assertEqual(response["systemMessage"], instruction)

    def test_cursor_shows_the_admin_notice_to_the_user(self):
        cursor = CLIENTS["cursor"]
        event = {"conversation_id": "c1", "generation_id": "g1"}
        notice = "Policy PROMPT-C requires unbound-secure-sql before this request."
        with tempfile.TemporaryDirectory() as tmp, \
                patch.object(cursor, "SKILL_POLICY_STATE_ROOT", Path(tmp)):
            cursor._defer_prompt_skill_context(
                event, "Invoke /unbound-secure-sql before continuing.", notice
            )
            response = cursor._with_deferred_skill_context(event, {})
        self.assertEqual(response["user_message"], notice)

    def test_cursor_falls_back_when_the_gateway_sends_no_notice(self):
        cursor = CLIENTS["cursor"]
        event = {"conversation_id": "c1", "generation_id": "g1"}
        with tempfile.TemporaryDirectory() as tmp, \
                patch.object(cursor, "SKILL_POLICY_STATE_ROOT", Path(tmp)):
            cursor._defer_prompt_skill_context(
                event, "Invoke /unbound-secure-sql before continuing."
            )
            response = cursor._with_deferred_skill_context(event, {})
        self.assertIn("organization policy", response["user_message"])

    def test_cursor_preserves_existing_tool_context_when_delivering_prompt_skill(self):
        cursor = CLIENTS["cursor"]
        event = {"conversation_id": "c1", "generation_id": "g1"}
        with tempfile.TemporaryDirectory() as tmp, \
                patch.object(cursor, "SKILL_POLICY_STATE_ROOT", Path(tmp)):
            cursor._defer_prompt_skill_context(
                event, "Invoke /unbound-secure-sql before continuing."
            )
            response = cursor._with_deferred_skill_context(
                event, {"agent_message": "Existing policy advisory."}
            )

        self.assertIn("Existing policy advisory.", response["agent_message"])
        self.assertIn("/unbound-secure-sql", response["agent_message"])

    def test_cursor_keeps_deferred_context_when_another_policy_denies_the_tool(self):
        cursor = CLIENTS["cursor"]
        event = {"conversation_id": "c1", "generation_id": "g1"}
        denied = {"permission": "deny", "user_message": "Blocked by another policy."}
        with tempfile.TemporaryDirectory() as tmp, \
                patch.object(cursor, "SKILL_POLICY_STATE_ROOT", Path(tmp)):
            cursor._defer_prompt_skill_context(
                event, "Invoke /unbound-secure-sql before continuing."
            )

            response = cursor._with_deferred_skill_context(event, denied)

            self.assertEqual(response, denied)
            self.assertFalse(cursor._skill_turn_claim_path("c1:g1").exists())
            delivered = cursor._with_deferred_skill_context(event, {})
            self.assertIn("/unbound-secure-sql", delivered["agent_message"])
            cursor._claim_skill_injection_turn(event)
            self.assertTrue(cursor._skill_turn_claim_path("c1:g1").exists())

    def test_codex_does_not_conflate_skill_delivery_with_confirmed_load(self):
        codex = CLIENTS["codex"]
        with tempfile.TemporaryDirectory() as tmp:
            transcript = Path(tmp) / "rollout.jsonl"
            transcript.write_text(json.dumps({
                "type": "response_item",
                "payload": {
                    "type": "message",
                    "role": "developer",
                    "content": [{"type": "input_text", "text": "$unbound-secure-sql do it"}],
                },
            }) + "\n")
            metadata = {}
            with patch.object(codex, "MANAGED_SKILLS_ROOT", Path(tmp) / "skills"):
                codex._attach_installed_skill_facts(
                    metadata, {"transcript_path": str(transcript)}
                )
        self.assertNotIn("loaded_skills", metadata)
        self.assertNotIn("skills_loaded_this_session", metadata)

    def test_codex_reports_a_host_selected_managed_skill_as_loaded(self):
        codex = CLIENTS["codex"]
        with tempfile.TemporaryDirectory() as tmp:
            transcript = Path(tmp) / "rollout.jsonl"
            transcript.write_text(json.dumps({
                "type": "response_item",
                "payload": {
                    "type": "message",
                    "role": "user",
                    "content": [{
                        "type": "input_text",
                        "text": (
                            "<skill>\n<name>unbound-secure-sql</name>\n"
                            "<path>/tmp/unbound-secure-sql/SKILL.md</path>\n"
                        ),
                    }],
                    "internal_chat_message_metadata_passthrough": {
                        "content_item_kinds": ["skills.selected_skill_instructions"],
                    },
                },
            }) + "\n")
            event = {"session_id": "s1", "transcript_path": str(transcript)}
            with patch.object(codex, "SKILL_POLICY_STATE_ROOT", Path(tmp) / "state"):
                facts = codex._skill_policy_loaded_facts(event)

        self.assertEqual(facts["loaded"], {"secure-sql"})
        self.assertEqual(facts["session_count"], 1)

    def test_codex_does_not_trust_a_model_tool_call_as_load_evidence(self):
        codex = CLIENTS["codex"]
        with tempfile.TemporaryDirectory() as tmp:
            transcript = Path(tmp) / "rollout.jsonl"
            transcript.write_text(json.dumps({
                "type": "response_item",
                "payload": {
                    "type": "custom_tool_call",
                    "status": "completed",
                    "name": "exec",
                    "input": "echo /tmp/unbound-secure-sql/SKILL.md",
                },
            }) + "\n")
            event = {"session_id": "s1", "transcript_path": str(transcript)}
            with patch.object(codex, "SKILL_POLICY_STATE_ROOT", Path(tmp) / "state"):
                facts = codex._skill_policy_loaded_facts(event)

        self.assertEqual(facts["loaded"], set())
        self.assertEqual(facts["session_count"], 0)

    def test_codex_ignores_post_tool_events_without_transcript_evidence(self):
        codex = CLIENTS["codex"]
        body = "---\nname: unbound-secure-sql\n---\n\nCheck every query.\n"
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "skills"
            skill = root / "unbound-secure-sql"
            skill.mkdir(parents=True)
            (skill / ".unbound-managed").touch()
            (skill / "SKILL.md").write_text(body)
            event = {
                "hook_event_name": "PostToolUse",
                "session_id": "s1",
                "tool_name": "Bash",
                "tool_input": {"command": f"cat {skill / 'SKILL.md'}"},
                "tool_response": body,
            }
            with patch.object(codex, "MANAGED_SKILLS_ROOT", root), \
                    patch.object(codex, "SKILL_POLICY_STATE_ROOT", Path(tmp) / "state"):
                facts = codex._skill_policy_loaded_facts(event)

        self.assertEqual(facts, {"loaded": set(), "session_count": 0})

    def test_codex_reads_function_call_skill_evidence_from_transcript(self):
        codex = CLIENTS["codex"]
        body = "---\nname: unbound-secure-sql\n---\n\nCheck every query.\n"
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "skills"
            skill = root / "unbound-secure-sql"
            skill.mkdir(parents=True)
            (skill / ".unbound-managed").touch()
            (skill / "SKILL.md").write_text(body)
            rows = [
                {
                    "type": "response_item",
                    "payload": {
                        "type": "function_call",
                        "name": "Bash",
                        "arguments": json.dumps({"command": f"cat {skill / 'SKILL.md'}"}),
                        "call_id": "call-1",
                    },
                },
                {
                    "type": "response_item",
                    "payload": {
                        "type": "function_call_output",
                        "call_id": "call-1",
                        "output": body,
                    },
                },
            ]
            transcript = Path(tmp) / "rollout.jsonl"
            transcript.write_text("\n".join(json.dumps(row) for row in rows) + "\n")
            with patch.object(codex, "MANAGED_SKILLS_ROOT", root):
                facts = codex._skill_policy_loaded_facts({"transcript_path": str(transcript)})

        self.assertEqual(facts, {"loaded": {"secure-sql"}, "session_count": 1})

    def test_codex_reads_completed_command_skill_evidence_from_transcript(self):
        codex = CLIENTS["codex"]
        body = "---\nname: unbound-secure-sql\n---\n\nCheck every query.\n"
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "skills"
            skill = root / "unbound-secure-sql"
            skill.mkdir(parents=True)
            (skill / ".unbound-managed").touch()
            (skill / "SKILL.md").write_text(body)
            row = {
                "type": "event_msg",
                "payload": {
                    "type": "item_completed",
                    "item": {
                        "type": "CommandExecution",
                        "command": ["/bin/zsh", "-lc", f"sed -n '1,240p' {skill / 'SKILL.md'}"],
                        "stdout": body,
                        "aggregated_output": body,
                    },
                },
            }
            transcript = Path(tmp) / "rollout.jsonl"
            transcript.write_text(json.dumps(row) + "\n")
            with patch.object(codex, "MANAGED_SKILLS_ROOT", root):
                facts = codex._skill_policy_loaded_facts({"transcript_path": str(transcript)})

        self.assertEqual(facts, {"loaded": {"secure-sql"}, "session_count": 1})

    def test_codex_does_not_read_symlinked_skill_body_as_load_evidence(self):
        codex = CLIENTS["codex"]
        body = "---\nname: unbound-secure-sql\n---\n\nCheck every query.\n"
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "skills"
            skill = root / "unbound-secure-sql"
            skill.mkdir(parents=True)
            (skill / ".unbound-managed").touch()
            target = Path(tmp) / "target.md"
            target.write_text(body)
            (skill / "SKILL.md").symlink_to(target)
            with patch.object(codex, "MANAGED_SKILLS_ROOT", root):
                found = codex._codex_skill_slugs_from_output(
                    f"cat {skill / 'SKILL.md'}", body
                )

        self.assertEqual(found, set())

    def test_codex_does_not_read_skill_facts_from_the_audit_log(self):
        codex = CLIENTS["codex"]
        body = "---\nname: unbound-secure-sql\n---\n\nCheck every query.\n"
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "skills"
            skill = root / "unbound-secure-sql"
            skill.mkdir(parents=True)
            (skill / ".unbound-managed").touch()
            (skill / "SKILL.md").write_text(body)
            with patch.object(codex, "MANAGED_SKILLS_ROOT", root), \
                    patch.object(codex, "load_existing_logs") as load_logs:
                facts = codex._skill_policy_loaded_facts({
                    "session_id": "s1",
                    "turn_id": "t1",
                })

        self.assertEqual(facts, {"loaded": set(), "session_count": 0})
        load_logs.assert_not_called()

    def test_codex_loaded_skill_expires_after_ten_tasks_and_at_compaction(self):
        codex = CLIENTS["codex"]
        selected = {
            "type": "response_item",
            "payload": {
                "type": "message",
                "role": "user",
                "content": [{"type": "input_text", "text": "<skill><name>unbound-secure-sql</name></skill>"}],
                "internal_chat_message_metadata_passthrough": {
                    "content_item_kinds": ["skills.selected_skill_instructions"],
                },
            },
        }
        task = {"type": "event_msg", "payload": {"type": "task_started"}}
        compacted = {"type": "event_msg", "payload": {"type": "context_compacted"}}
        with tempfile.TemporaryDirectory() as tmp:
            transcript = Path(tmp) / "rollout.jsonl"
            event = {"session_id": "s1", "transcript_path": str(transcript)}
            with patch.object(codex, "SKILL_POLICY_STATE_ROOT", Path(tmp) / "state"):
                transcript.write_text("\n".join(json.dumps(row) for row in [selected] + [task] * 10) + "\n")
                edge = codex._skill_policy_loaded_facts(event)
                transcript.write_text("\n".join(json.dumps(row) for row in [selected] + [task] * 11) + "\n")
                expired = codex._skill_policy_loaded_facts(event)
                transcript.write_text("\n".join(json.dumps(row) for row in [selected, task, compacted, task]) + "\n")
                after_compaction = codex._skill_policy_loaded_facts(event)

        self.assertEqual(edge, {"loaded": {"secure-sql"}, "session_count": 1})
        self.assertEqual(expired, {"loaded": set(), "session_count": 1})
        self.assertEqual(after_compaction, {"loaded": set(), "session_count": 1})

    def test_codex_compaction_keeps_only_post_compaction_skill_active(self):
        codex = CLIENTS["codex"]

        def selected(slug):
            return {
                "type": "response_item",
                "payload": {
                    "type": "message",
                    "role": "user",
                    "content": [{"type": "input_text", "text": f"<skill><name>unbound-{slug}</name></skill>"}],
                    "internal_chat_message_metadata_passthrough": {
                        "content_item_kinds": ["skills.selected_skill_instructions"],
                    },
                },
            }

        rows = [
            selected("old-rule"),
            {"type": "event_msg", "payload": {"type": "task_started"}},
            {"type": "compacted"},
            selected("new-rule"),
            {"type": "event_msg", "payload": {"type": "task_started"}},
        ]
        with tempfile.TemporaryDirectory() as tmp:
            transcript = Path(tmp) / "rollout.jsonl"
            transcript.write_text("\n".join(json.dumps(row) for row in rows) + "\n")
            with patch.object(codex, "SKILL_POLICY_STATE_ROOT", Path(tmp) / "state"):
                facts = codex._skill_policy_loaded_facts({
                    "session_id": "s1",
                    "transcript_path": str(transcript),
                })

        self.assertEqual(facts, {"loaded": {"new-rule"}, "session_count": 2})

    def test_codex_requires_most_of_a_long_skill_body(self):
        codex = CLIENTS["codex"]
        body = "---\nname: unbound-secure-sql\n---\n\n" + "important rule\n" * 400
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "skills"
            skill = root / "unbound-secure-sql"
            skill.mkdir(parents=True)
            (skill / ".unbound-managed").touch()
            (skill / "SKILL.md").write_text(body)
            command = f"sed -n '1,240p' {skill / 'SKILL.md'}"
            with patch.object(codex, "MANAGED_SKILLS_ROOT", root):
                short_prefix = codex._codex_skill_slugs_from_output(command, body[:2048])
                long_prefix = codex._codex_skill_slugs_from_output(command, body[:int(len(body) * 0.95)])
                frontmatter = codex._codex_skill_slugs_from_output(
                    command, "---\nname: unbound-secure-sql\n---\n"
                )

        self.assertEqual(short_prefix, set())
        self.assertEqual(long_prefix, {"secure-sql"})
        self.assertEqual(frontmatter, set())

    def test_codex_does_not_trust_skill_path_without_body_in_tool_response(self):
        codex = CLIENTS["codex"]
        body = "---\nname: unbound-secure-sql\n---\n\nCheck every query.\n"
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "skills"
            skill = root / "unbound-secure-sql"
            skill.mkdir(parents=True)
            (skill / ".unbound-managed").touch()
            (skill / "SKILL.md").write_text(body)
            command = f"echo {skill / 'SKILL.md'}"
            with patch.object(codex, "MANAGED_SKILLS_ROOT", root):
                facts = codex._codex_skill_slugs_from_output(command, str(skill / "SKILL.md"))

        self.assertEqual(facts, set())

    def test_user_prompt_skill_facts_include_the_project_directory(self):
        cases = (
            (
                "copilot",
                CLIENTS["copilot"]._evaluate_user_prompt_policy,
                {"session_id": "s1", "prompt": "query", "cwd": "/work/copilot"},
                "/work/copilot",
            ),
            (
                "cursor",
                CLIENTS["cursor"].process_user_prompt_submit,
                {
                    "conversation_id": "s1",
                    "generation_id": "g1",
                    "prompt": "query",
                    "workspace_roots": ["/work/cursor"],
                },
                "/work/cursor",
            ),
            (
                "codex",
                CLIENTS["codex"].process_user_prompt_submit,
                {"session_id": "s1", "prompt": "query", "cwd": "/work/codex"},
                "/work/codex",
            ),
        )
        for name, processor, event, expected in cases:
            module = CLIENTS[name]
            with self.subTest(client=name), \
                    patch.object(module, "load_policy_cache", return_value={}), \
                    patch.object(module, "is_cache_stale", return_value=False), \
                    patch.object(module, "installed_skill_report", return_value=[]), \
                    patch.object(module, "send_to_hook_api", return_value={"decision": "allow"}) as send:
                processor(event, "key")

            request = send.call_args.args[0]
            metadata = request["pre_tool_use_data"]["metadata"]
            self.assertEqual(metadata["cwd"], expected)


class CopilotVisibleInventoryTests(unittest.TestCase):
    """Copilot discovers skills once per session, so a skill installed mid-session
    must not be advertised as installed until the next one."""

    def _snapshot(self, tmp, report):
        copilot = CLIENTS["copilot"]
        event = {"session_id": "s1"}
        with patch.object(copilot, "SKILL_POLICY_STATE_ROOT", Path(tmp)), \
                patch.object(copilot, "installed_skill_report", return_value=report):
            copilot._snapshot_copilot_skill_inventory(event)
        return event

    def test_skill_present_at_session_start_is_visible(self):
        copilot = CLIENTS["copilot"]
        physical = [{"slug": "secure-sql", "sha256": "a" * 64}]
        with tempfile.TemporaryDirectory() as tmp:
            event = self._snapshot(tmp, physical)
            with patch.object(copilot, "SKILL_POLICY_STATE_ROOT", Path(tmp)):
                self.assertEqual(
                    copilot._skill_policy_visible_inventory(event, physical), physical
                )

    def test_skill_installed_after_session_start_is_hidden(self):
        copilot = CLIENTS["copilot"]
        late = {"slug": "late-arrival", "sha256": "b" * 64}
        with tempfile.TemporaryDirectory() as tmp:
            event = self._snapshot(tmp, [])
            with patch.object(copilot, "SKILL_POLICY_STATE_ROOT", Path(tmp)):
                self.assertEqual(
                    copilot._skill_policy_visible_inventory(event, [late]), []
                )

    def test_skill_edited_after_session_start_is_hidden(self):
        copilot = CLIENTS["copilot"]
        old = {"slug": "secure-sql", "sha256": "a" * 64}
        edited = {"slug": "secure-sql", "sha256": "c" * 64}
        with tempfile.TemporaryDirectory() as tmp:
            event = self._snapshot(tmp, [old])
            with patch.object(copilot, "SKILL_POLICY_STATE_ROOT", Path(tmp)):
                self.assertEqual(
                    copilot._skill_policy_visible_inventory(event, [edited]), []
                )

    def test_skill_removed_from_disk_is_not_reported(self):
        copilot = CLIENTS["copilot"]
        gone = {"slug": "secure-sql", "sha256": "a" * 64}
        with tempfile.TemporaryDirectory() as tmp:
            event = self._snapshot(tmp, [gone])
            with patch.object(copilot, "SKILL_POLICY_STATE_ROOT", Path(tmp)):
                self.assertEqual(copilot._skill_policy_visible_inventory(event, []), [])

    def test_missing_snapshot_falls_back_to_physical(self):
        copilot = CLIENTS["copilot"]
        physical = [{"slug": "secure-sql", "sha256": "a" * 64}]
        with tempfile.TemporaryDirectory() as tmp:
            with patch.object(copilot, "SKILL_POLICY_STATE_ROOT", Path(tmp)):
                self.assertEqual(
                    copilot._skill_policy_visible_inventory({"session_id": "s9"}, physical),
                    physical,
                )


class CopilotRegistrationTests(unittest.TestCase):
    def test_prompt_context_rides_user_prompt_submit_alone(self):
        installers = (
            tool_module("copilot/hooks", "setup"),
            tool_module("copilot/hooks/mdm", "setup"),
        )
        for installer in installers:
            with self.subTest(installer=installer.__name__):
                hooks = installer._copilot_hooks_config(Path("/tmp/unbound.py"))["hooks"]
                self.assertIn("UserPromptSubmit", hooks)
                self.assertNotIn("userPromptTransformed", hooks)


if __name__ == "__main__":
    unittest.main()
