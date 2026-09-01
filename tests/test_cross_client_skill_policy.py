import hashlib
import io
import json
import shutil
import tempfile
import unittest
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

    def test_turn_claim_is_written_only_after_output_ack(self):
        event = {"session_id": "s1", "turn_id": "t1"}
        delivered_outputs = {
            "copilot": {
                "permissionDecision": "deny",
                "permissionDecisionReason": "Invoke /unbound-secure-sql before continuing.",
            },
            "cursor": {
                "permission": "deny",
                "agent_message": "Invoke /unbound-secure-sql before continuing.",
            },
            "codex": {
                "hookSpecificOutput": {
                    "additionalContext": "Invoke $unbound-secure-sql before continuing.",
                },
            },
        }
        for name, module in CLIENTS.items():
            with self.subTest(client=name), tempfile.TemporaryDirectory() as tmp:
                client_event = dict(event)
                if name == "cursor":
                    client_event = {"conversation_id": "s1", "generation_id": "t1"}
                if name == "copilot":
                    with patch.object(module, "get_turn_start_timestamp_for_session", return_value="t1"):
                        with patch.object(module, "SKILL_POLICY_STATE_ROOT", Path(tmp)):
                            module._apply_skill_lifecycle_actions({"inject_skills": [_entry()]}, "key", client_event)
                            self.assertFalse(module._skill_turn_claim_path("s1:t1").exists())
                            module._ack_skill_injection_delivery(client_event, {})
                            self.assertFalse(module._skill_turn_claim_path("s1:t1").exists())
                            module._ack_skill_injection_delivery(client_event, delivered_outputs[name])
                            self.assertTrue(module._skill_turn_claim_path("s1:t1").exists())
                    continue
                with patch.object(module, "SKILL_POLICY_STATE_ROOT", Path(tmp)):
                    module._apply_skill_lifecycle_actions({"inject_skills": [_entry()]}, "key", client_event)
                    self.assertFalse(module._skill_turn_claim_path("s1:t1").exists())
                    module._ack_skill_injection_delivery(client_event, {})
                    self.assertFalse(module._skill_turn_claim_path("s1:t1").exists())
                    module._ack_skill_injection_delivery(client_event, delivered_outputs[name])
                    self.assertTrue(module._skill_turn_claim_path("s1:t1").exists())


class CrossClientNativeInjectionTests(unittest.TestCase):
    def test_codex_prompt_injection_uses_additional_context(self):
        response = CLIENTS["codex"].transform_response_for_codex_prompt({
            "decision": "allow",
            "additionalContext": "Invoke the skill unbound-secure-sql before answering.",
            "inject_skills": [_entry()],
        })
        self.assertIn("$unbound-secure-sql", response["hookSpecificOutput"]["additionalContext"])

    def test_copilot_transformed_prompt_can_inject_slash_skill(self):
        response = CLIENTS["copilot"].transform_response_for_copilot_transformed_prompt(
            {"transformedPrompt": "Write the query."},
            {
                "decision": "allow",
                "additionalContext": "Invoke the skill unbound-secure-sql before answering.",
                "inject_skills": [_entry()],
            },
        )
        self.assertIn("/unbound-secure-sql", response["modifiedTransformedPrompt"])
        self.assertIn("Write the query.", response["modifiedTransformedPrompt"])

    def test_copilot_transformed_prompt_preserves_blocking_decisions(self):
        for decision in ("deny", "block"):
            with self.subTest(decision=decision):
                response = CLIENTS["copilot"].transform_response_for_copilot_transformed_prompt(
                    {"transformedPrompt": "Drop the table."},
                    {"decision": decision, "reason": "Blocked by policy."},
                )
                self.assertEqual(response, {"decision": "block", "reason": "Blocked by policy."})

    def test_tool_injection_uses_each_clients_native_syntax(self):
        plan = {
            "decision": "deny",
            "reason": "Load the required skill.",
            "additionalContext": "Invoke the skill unbound-secure-sql, then retry.",
            "inject_skills": [_entry()],
        }
        copilot = CLIENTS["copilot"].transform_response_for_copilot(plan)
        codex = CLIENTS["codex"].transform_response_for_codex(plan)
        cursor = CLIENTS["cursor"].format_hook_response(plan)

        self.assertIn("/unbound-secure-sql", copilot["hookSpecificOutput"]["additionalContext"])
        self.assertIn("/unbound-secure-sql", copilot["permissionDecisionReason"])
        self.assertIn(
            "/unbound-secure-sql",
            copilot["hookSpecificOutput"]["permissionDecisionReason"],
        )
        self.assertIn("$unbound-secure-sql", codex["hookSpecificOutput"]["additionalContext"])
        self.assertIn("/unbound-secure-sql", cursor["agent_message"])

    def test_copilot_loaded_state_survives_transcript_tail_eviction(self):
        copilot = CLIENTS["copilot"]
        event = {"session_id": "s1"}
        with tempfile.TemporaryDirectory() as tmp:
            transcript = Path(tmp) / "events.jsonl"
            transcript.write_text(json.dumps({
                "type": "skill.invoked",
                "data": {"name": "unbound-secure-sql"},
            }) + "\n")
            event["transcript_path"] = str(transcript)
            with patch.object(copilot, "SKILL_POLICY_STATE_ROOT", Path(tmp) / "state"):
                first = copilot._skill_policy_loaded_facts(event)
                transcript.write_text("{}\n")
                after_eviction = copilot._skill_policy_loaded_facts(event)

        self.assertEqual(first["loaded"], {"secure-sql"})
        self.assertEqual(after_eviction, first)

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

    def test_cursor_loaded_state_survives_audit_log_eviction(self):
        cursor = CLIENTS["cursor"]
        event = {"conversation_id": "c1"}
        row = {"event": {
            "hook_event_name": "beforeReadFile",
            "conversation_id": "c1",
            "file_path": "/skills/unbound-secure-sql/SKILL.md",
        }}
        with tempfile.TemporaryDirectory() as tmp, \
                patch.object(cursor, "SKILL_POLICY_STATE_ROOT", Path(tmp) / "state"), \
                patch.object(cursor, "load_existing_logs", side_effect=[[row], []]), \
                patch.object(cursor, "_skill_name_from_path", return_value="unbound-secure-sql"):
            first = cursor._skill_policy_loaded_facts(event)
            after_eviction = cursor._skill_policy_loaded_facts(event)

        self.assertEqual(first["loaded"], {"secure-sql"})
        self.assertEqual(after_eviction, first)

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
                self.assertEqual(cursor._consume_deferred_skill_context(event), "")

    def test_cursor_keeps_deferred_context_when_another_policy_denies_the_tool(self):
        cursor = CLIENTS["cursor"]
        event = {"conversation_id": "c1", "generation_id": "g1"}
        denied = {"permission": "deny", "user_message": "Blocked by another policy."}
        with tempfile.TemporaryDirectory() as tmp, \
                patch.object(cursor, "SKILL_POLICY_STATE_ROOT", Path(tmp)):
            cursor._PENDING_SKILL_DELIVERY_KEYS.clear()
            cursor._defer_prompt_skill_context(
                event, "Invoke /unbound-secure-sql before continuing."
            )
            cursor._apply_skill_lifecycle_actions(
                {"inject_skills": [_entry("another-skill")]}, "key", event
            )

            response = cursor._with_deferred_skill_context(event, denied)
            cursor._ack_skill_injection_delivery(event, response)

            self.assertEqual(response, denied)
            self.assertFalse(cursor._skill_turn_claim_path("c1:g1").exists())
            delivered = cursor._with_deferred_skill_context(event, {})
            self.assertIn("/unbound-secure-sql", delivered["agent_message"])
            cursor._ack_skill_injection_delivery(event, delivered)
            self.assertTrue(cursor._skill_turn_claim_path("c1:g1").exists())
            cursor._PENDING_SKILL_DELIVERY_KEYS.clear()

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
        self.assertEqual(metadata["skills_loaded_this_session"], 0)

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

    def test_codex_reports_a_completed_managed_skill_read_as_loaded(self):
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
                remembered = codex._skill_policy_loaded_facts({"session_id": "s1"})

        self.assertEqual(facts["loaded"], {"secure-sql"})
        self.assertEqual(remembered, facts)

    def test_codex_does_not_trust_skill_path_without_body_in_tool_response(self):
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
                "tool_input": {"command": f"echo {skill / 'SKILL.md'}"},
                "tool_response": str(skill / "SKILL.md"),
            }
            with patch.object(codex, "MANAGED_SKILLS_ROOT", root), \
                    patch.object(codex, "SKILL_POLICY_STATE_ROOT", Path(tmp) / "state"):
                facts = codex._skill_policy_loaded_facts(event)

        self.assertEqual(facts["loaded"], set())
        self.assertEqual(facts["session_count"], 0)

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

    def test_copilot_keeps_plan_for_the_matching_batched_message(self):
        copilot = CLIENTS["copilot"]
        submitted = {"session_id": "s1", "prompt": "current message"}
        preceding = {"sessionId": "s1", "prompt": "preceding message"}
        current = {"sessionId": "s1", "prompt": "current message"}
        with tempfile.TemporaryDirectory() as tmp:
            with patch.object(copilot, "SKILL_POLICY_STATE_ROOT", Path(tmp)):
                copilot._store_copilot_prompt_plan(submitted, {"inject_skills": [_entry()]})
                found, plan = copilot._take_copilot_prompt_plan(preceding)
                self.assertTrue(found)
                self.assertEqual(plan, {})
                found, plan = copilot._take_copilot_prompt_plan(current)
        self.assertTrue(found)
        self.assertEqual(plan["inject_skills"][0]["slug"], "secure-sql")

    def test_copilot_transformed_prompt_blocks_stored_and_fallback_denies(self):
        copilot = CLIENTS["copilot"]
        event = {
            "hook_event_name": "userPromptTransformed",
            "sessionId": "s1",
            "prompt": "Drop the table.",
            "transformedPrompt": "Drop the table.",
        }
        deny = {"decision": "deny", "reason": "Blocked by policy."}
        for source in ("stored", "fallback"):
            with self.subTest(source=source), tempfile.TemporaryDirectory() as tmp, \
                    patch.object(copilot, "SKILL_POLICY_STATE_ROOT", Path(tmp)), \
                    patch.object(copilot, "get_api_key", return_value="key"), \
                    patch.object(copilot, "_stage_skill_injection_delivery"), \
                    patch.object(copilot, "_ack_skill_injection_delivery"), \
                    patch.object(copilot, "_evaluate_user_prompt_policy", return_value=deny) as evaluate, \
                    patch.object(copilot.sys, "stdin", io.StringIO(json.dumps(event))), \
                    patch.object(copilot.sys, "stdout", io.StringIO()) as stdout:
                if source == "stored":
                    copilot._store_copilot_prompt_plan(event, deny)
                copilot.main()
                output = json.loads(stdout.getvalue())

            self.assertEqual(output, {"decision": "block", "reason": "Blocked by policy."})
            self.assertEqual(evaluate.call_count, 0 if source == "stored" else 1)


class GeneratedCoreTests(unittest.TestCase):
    def test_embedded_core_is_current_in_all_clients(self):
        from skill_policy.generate import check

        self.assertEqual(check(), [])


class CopilotRegistrationTests(unittest.TestCase):
    def test_transformed_prompt_is_registered_by_every_installer(self):
        installers = (
            tool_module("copilot/hooks", "setup"),
            tool_module("copilot/hooks/mdm", "setup"),
        )
        for installer in installers:
            with self.subTest(installer=installer.__name__):
                hooks = installer._copilot_hooks_config(Path("/tmp/unbound.py"))["hooks"]
                self.assertIn("UserPromptSubmit", hooks)
                self.assertIn("userPromptTransformed", hooks)


if __name__ == "__main__":
    unittest.main()
