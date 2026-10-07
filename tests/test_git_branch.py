"""Every hook reports the checked-out branch beside the project it resolved (WEB-6034).

The branch is read at the same repo root the project came from: the nearest
`.git` above a tool call's file path or shell directory, so a linked worktree
reports its own branch and a detached HEAD reports none.
"""

import json
import subprocess
from unittest.mock import patch

import pytest

from tests.conftest import tool_module

HOOKS = {
    "claude-code": "claude-code/hooks",
    "cursor": "cursor",
    "copilot": "copilot/hooks",
    "codex": "codex/hooks",
    "augment": "augment/hooks",
}
# Per-call resolvers: file-path candidates (codex, copilot, cursor) vs a tool call (claude-code, augment).
PATH_HOOKS = ["codex", "copilot", "cursor"]
TOOL_HOOKS = ["claude-code", "augment"]

BRANCH = "feat/checkout-v2"
WORKTREE_BRANCH = "fix/other"


def _git(repo, *args):
    subprocess.run(["git", "-C", str(repo), *args], check=True, capture_output=True)


@pytest.fixture
def repo(tmp_path):
    """A clone of acme/web checked out on a feature branch, with a src/ subdir."""
    r = tmp_path / "web"
    r.mkdir()
    _git(r, "init", "-q", "-b", "main")
    _git(r, "remote", "add", "origin", "https://github.com/acme/web.git")
    _git(r, "-c", "user.email=t@t", "-c", "user.name=t", "commit", "-q", "--allow-empty", "-m", "init")
    _git(r, "switch", "-q", "-c", BRANCH)
    (r / "src").mkdir()
    return r


def _resolve(tool, module, path, cache):
    """(project, branch) a hook resolves for a write at `path`."""
    if tool in TOOL_HOOKS:
        return module._repo_for_tool_use("Write", {"file_path": path}, None, cache)[:2]
    return module._repo_for_paths([str(path).rsplit("/", 1)[0]], cache)


@pytest.mark.parametrize("tool", sorted(HOOKS))
class TestBranchHelper:
    def test_reads_the_branch_from_any_directory_in_the_checkout(self, tool, repo):
        m = tool_module(HOOKS[tool])
        assert m._git_branch(str(repo / "src")) == BRANCH

    def test_detached_head_has_no_branch(self, tool, repo):
        _git(repo, "checkout", "-q", "--detach")
        m = tool_module(HOOKS[tool])
        assert m._git_branch(str(repo)) is None

    def test_outside_a_repo_and_no_root_are_none(self, tool, tmp_path):
        m = tool_module(HOOKS[tool])
        assert m._git_branch(str(tmp_path)) is None
        assert m._git_branch(None) is None

    def test_git_failure_fails_open(self, tool, repo):
        m = tool_module(HOOKS[tool])
        with patch.object(m.subprocess, "run", side_effect=OSError("no git")):
            assert m._git_branch(str(repo)) is None


@pytest.mark.parametrize("tool", sorted(HOOKS))
class TestPerCallResolution:
    def test_a_file_deep_in_the_repo_resolves_project_and_branch(self, tool, repo):
        m = tool_module(HOOKS[tool])
        assert _resolve(tool, m, str(repo / "src" / "a.py"), {}) == ("acme/web", BRANCH)

    def test_a_linked_worktree_reports_its_own_branch(self, tool, repo, tmp_path):
        wt = tmp_path / "web-wt"
        _git(repo, "worktree", "add", "-q", str(wt), "-b", WORKTREE_BRANCH)
        m = tool_module(HOOKS[tool])
        cache = {}
        assert _resolve(tool, m, str(repo / "src" / "a.py"), cache) == ("acme/web", BRANCH)
        assert _resolve(tool, m, str(wt / "b.py"), cache) == ("acme/web", WORKTREE_BRANCH)

    def test_outside_a_repo_resolves_nothing(self, tool, tmp_path):
        m = tool_module(HOOKS[tool])
        assert _resolve(tool, m, str(tmp_path / "x.py"), {}) == (None, None)

    def test_a_repo_without_origin_skips_the_branch_lookup(self, tool, tmp_path):
        r = tmp_path / "local-only"
        r.mkdir()
        _git(r, "init", "-q", "-b", "main")
        m = tool_module(HOOKS[tool])
        with patch.object(m, "_git_branch", side_effect=AssertionError("looked up a branch with no project")):
            assert _resolve(tool, m, str(r / "a.py"), {}) == (None, None)

    def test_the_branch_is_read_once_per_repo_root(self, tool, repo):
        m = tool_module(HOOKS[tool])
        cache = {}
        with patch.object(m, "_git_branch", wraps=m._git_branch) as spy:
            _resolve(tool, m, str(repo / "src" / "a.py"), cache)
            _resolve(tool, m, str(repo / "b.py"), cache)
        assert spy.call_count == 1


def _tool_uses(exchange):
    return [tu for msg in exchange["messages"] for tu in (msg.get("tool_use") or [])]


class TestClaudeCodePayload:
    def test_tool_call_and_turn_carry_the_branch(self, repo):
        unbound = tool_module("claude-code/hooks")
        events = [
            {"event": {"hook_event_name": "UserPromptSubmit", "session_id": "s", "prompt": "edit a.py"}},
            {"event": {"hook_event_name": "PostToolUse", "session_id": "s", "tool_name": "Write",
                       "tool_input": {"file_path": str(repo / "src" / "a.py"), "content": "x"},
                       "tool_response": {}}},
        ]
        exchange = unbound.build_llm_exchange(events, stop_assistant_message="done", cwd=str(repo))
        [tu] = _tool_uses(exchange)
        assert (tu["project"], tu["git_branch"]) == ("acme/web", BRANCH)
        assert (exchange["project"], exchange["git_branch"]) == ("acme/web", BRANCH)

    def test_a_call_outside_any_repo_carries_none(self, repo, tmp_path):
        unbound = tool_module("claude-code/hooks")
        events = [
            {"event": {"hook_event_name": "UserPromptSubmit", "session_id": "s", "prompt": "edit"}},
            {"event": {"hook_event_name": "PostToolUse", "session_id": "s", "tool_name": "Write",
                       "tool_input": {"file_path": str(tmp_path / "notes.txt"), "content": "x"},
                       "tool_response": {}}},
        ]
        exchange = unbound.build_llm_exchange(events, stop_assistant_message="done", cwd=str(repo))
        [tu] = _tool_uses(exchange)
        assert (tu["project"], tu["git_branch"]) == (None, None)
        assert exchange["git_branch"] == BRANCH


class TestCursorPayload:
    def test_file_edit_and_turn_carry_the_branch(self, repo):
        unbound = tool_module("cursor")
        base = {"conversation_id": "c", "generation_id": "g", "model": "auto",
                "workspace_roots": [str(repo)]}
        events = [
            {"timestamp": "2026-08-20T10:00:00Z", "event": dict(base, hook_event_name="beforeSubmitPrompt", prompt="edit")},
            {"timestamp": "2026-08-20T10:00:05Z", "event": dict(base, hook_event_name="afterFileEdit",
                                                                 file_path=str(repo / "src" / "a.py"), edits=[])},
            {"timestamp": "2026-08-20T10:00:08Z", "event": dict(base, hook_event_name="afterAgentResponse", text="done")},
            {"timestamp": "2026-08-20T10:00:10Z", "event": dict(base, hook_event_name="stop")},
        ]
        exchange = unbound.build_llm_exchange(events)
        [tu] = _tool_uses(exchange)
        assert (tu["project"], tu["git_branch"]) == ("acme/web", BRANCH)
        assert (exchange["project"], exchange["git_branch"]) == ("acme/web", BRANCH)


class TestCopilotPayload:
    def test_mapped_write_carries_the_branch(self, repo):
        unbound = tool_module("copilot/hooks")
        mapped = unbound.map_copilot_tool("write", {"filePath": str(repo / "src" / "a.py"), "content": "x"},
                                          "ok", shell_state={"dir": str(repo)}, root_projects={})
        assert (mapped["project"], mapped["git_branch"]) == ("acme/web", BRANCH)

    def test_unresolved_write_has_no_branch_key(self, tmp_path):
        unbound = tool_module("copilot/hooks")
        mapped = unbound.map_copilot_tool("write", {"filePath": str(tmp_path / "x.py"), "content": "x"},
                                          "ok", shell_state={"dir": str(tmp_path)}, root_projects={})
        assert "project" not in mapped and "git_branch" not in mapped


class TestCodexPayload:
    def test_shell_call_carries_the_branch(self, repo, tmp_path):
        unbound = tool_module("codex/hooks")
        transcript = tmp_path / "rollout.jsonl"
        transcript.write_text("\n".join(json.dumps(line) for line in [
            {"type": "response_item", "timestamp": "2026-08-20T10:00:05Z",
             "payload": {"type": "function_call", "call_id": "c1", "name": "exec_command",
                         "arguments": json.dumps({"cmd": "ls " + str(repo / "src")})}},
            {"type": "response_item", "timestamp": "2026-08-20T10:00:06Z",
             "payload": {"type": "function_call_output", "call_id": "c1", "output": "a.py"}},
        ]) + "\n")
        [tu] = unbound.parse_codex_transcript_for_tools(str(transcript), session_cwd=str(repo))
        assert (tu["project"], tu["git_branch"]) == ("acme/web", BRANCH)


class TestAugmentPayload:
    def test_tool_call_and_turn_carry_the_branch(self, repo):
        unbound = tool_module("augment/hooks")
        stop = {"session_id": "s", "hook_event_name": "Stop", "cwd": str(repo),
                "conversation": {"userPrompt": "edit a.py", "agentTextResponse": "done"}}
        post = [{"event": {"hook_event_name": "PostToolUse", "tool_name": "Write",
                           "tool_input": {"file_path": "src/a.py", "content": "x"}, "tool_use_id": "tu-1"}}]
        exchange = unbound.build_llm_exchange(stop, post)
        [tu] = _tool_uses(exchange)
        assert (tu["project"], tu["git_branch"]) == ("acme/web", BRANCH)
        assert (exchange["project"], exchange["git_branch"]) == ("acme/web", BRANCH)
