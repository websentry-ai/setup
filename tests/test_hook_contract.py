"""The contract every tool's hook must honour, for every tool that ships one.

A hook sits between the developer and their editor, so the bar is the same
everywhere: answer a basic event, never block on anything unexpected, and never
exit non-zero. These run the real `unbound.py` as a subprocess, the way the
editor invokes it, against a gateway address nothing is listening on.
"""

import json
import subprocess
import sys

import pytest

from tests.conftest import REPO

# Every tool that ships a hook, and the event names it is invoked with.
HOOKS = {
    "claude-code": REPO / "claude-code" / "hooks" / "unbound.py",
    "cursor": REPO / "cursor" / "unbound.py",
    "copilot": REPO / "copilot" / "hooks" / "unbound.py",
    "codex": REPO / "codex" / "hooks" / "unbound.py",
    "augment": REPO / "augment" / "hooks" / "unbound.py",
}

# A port nothing listens on: a hook that reaches the network must still fail open.
DEAD_GATEWAY = "http://127.0.0.1:9"


def run_hook(tool, payload, home, extra_env=None):
    env = {
        "HOME": str(home),
        "PATH": "/usr/bin:/bin:/usr/sbin:/sbin",
        "UNBOUND_GATEWAY_URL": DEAD_GATEWAY,
    }
    if extra_env:
        env.update(extra_env)
    return subprocess.run(
        [sys.executable, str(HOOKS[tool])],
        input=payload if isinstance(payload, str) else json.dumps(payload),
        capture_output=True, text=True, timeout=60, env=env,
    )


@pytest.fixture
def home(tmp_path):
    h = tmp_path / "home"
    h.mkdir()
    return h


@pytest.mark.parametrize("tool", sorted(HOOKS))
class TestEveryHookFailsOpen:
    """Whatever arrives, the editor keeps working."""

    def test_a_basic_prompt_is_answered_without_blocking(self, tool, home):
        r = run_hook(tool, {"hook_event_name": "UserPromptSubmit",
                            "session_id": "S1",
                            "prompt": "list the files in this repo",
                            "cwd": str(home)}, home)
        assert r.returncode == 0, r.stderr[-400:]
        if r.stdout.strip():
            body = json.loads(r.stdout)
            assert body.get("decision") != "block"

    def test_a_basic_tool_call_is_answered_without_blocking(self, tool, home):
        r = run_hook(tool, {"hook_event_name": "PreToolUse",
                            "session_id": "S1",
                            "tool_name": "Bash",
                            "tool_input": {"command": "ls -la"},
                            "cwd": str(home)}, home)
        assert r.returncode == 0, r.stderr[-400:]
        if r.stdout.strip():
            body = json.loads(r.stdout)
            assert body.get("decision") != "block"
            assert (body.get("hookSpecificOutput", {})
                        .get("permissionDecision") != "deny")

    def test_stdout_is_json_or_empty(self, tool, home):
        """The editor parses stdout; a stray print would break it."""
        r = run_hook(tool, {"hook_event_name": "PreToolUse", "session_id": "S1",
                            "tool_name": "Bash", "tool_input": {"command": "ls"},
                            "cwd": str(home)}, home)
        if r.stdout.strip():
            json.loads(r.stdout)

    @pytest.mark.parametrize("payload", [
        "", "   ", "not json at all", "[]", "null", "123", '{"unclosed":',
        json.dumps({}), json.dumps({"hook_event_name": "Nonexistent"}),
        json.dumps({"hook_event_name": None}),
        json.dumps({"hook_event_name": "PreToolUse", "tool_input": "not-a-dict"}),
        json.dumps({"hook_event_name": "PreToolUse", "tool_name": None,
                    "tool_input": {"command": None}}),
    ])
    def test_malformed_input_never_blocks_the_editor(self, tool, home, payload):
        r = run_hook(tool, payload, home)
        assert r.returncode == 0, "%s: exit %d on %r" % (tool, r.returncode, payload[:40])
        if r.stdout.strip():
            body = json.loads(r.stdout)
            assert body.get("decision") != "block"

    def test_an_unreachable_gateway_never_blocks(self, tool, home):
        """Fail-open is the rule: a gateway that is down must not stop the user."""
        r = run_hook(tool, {"hook_event_name": "PreToolUse", "session_id": "S1",
                            "tool_name": "Bash",
                            "tool_input": {"command": "git status"},
                            "cwd": str(home)},
                     home, {"UNBOUND_GATEWAY_URL": DEAD_GATEWAY})
        assert r.returncode == 0, r.stderr[-400:]
        if r.stdout.strip():
            assert json.loads(r.stdout).get("decision") != "block"

    def test_a_closed_stdin_is_survivable(self, tool, home):
        env = {"HOME": str(home), "PATH": "/usr/bin:/bin",
               "UNBOUND_GATEWAY_URL": DEAD_GATEWAY}
        r = subprocess.run([sys.executable, str(HOOKS[tool])],
                           stdin=subprocess.DEVNULL, capture_output=True,
                           text=True, timeout=60, env=env)
        assert r.returncode == 0, r.stderr[-400:]
