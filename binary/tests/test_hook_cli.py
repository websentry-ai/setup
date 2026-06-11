"""CLI-boundary tests for `unbound-hook hook <tool> <event>` (WEB-4786).

The contract under test: for every tool and event, piping the event JSON to
the CLI produces EXACTLY what piping it to `python3 <tool>/unbound.py`
produces — stdout and exit code. Plus the frozen-mode network gates and the
dispatcher's fail-open behavior.
"""

import json

import pytest

from conftest import run_binary, run_cli_dev, run_python_path

S = {"session_id": "test-session", "transcript_path": "/nonexistent/transcript.jsonl"}

EVENT_PAYLOADS = {
    "claude-code": {
        "PreToolUse": {**S, "hook_event_name": "PreToolUse", "tool_name": "Bash",
                       "tool_input": {"command": "git status"}, "cwd": "/tmp"},
        "PostToolUse": {**S, "hook_event_name": "PostToolUse", "tool_name": "Bash",
                        "tool_input": {"command": "git status"},
                        "tool_response": {"output": "clean"}},
        "UserPromptSubmit": {**S, "hook_event_name": "UserPromptSubmit", "prompt": "hello"},
        "Stop": {**S, "hook_event_name": "Stop", "last_assistant_message": "done"},
        "SessionStart": {**S, "hook_event_name": "SessionStart", "model": "claude-opus-4-8"},
        "SessionEnd": {**S, "hook_event_name": "SessionEnd"},
    },
    "copilot": {
        "PreToolUse": {**S, "hook_event_name": "PreToolUse", "tool_name": "bash",
                       "tool_input": {"command": "git status"}},
        "PostToolUse": {**S, "hook_event_name": "PostToolUse", "tool_name": "bash",
                        "tool_input": {"command": "git status"},
                        "tool_response": {"output": "clean"}},
        "UserPromptSubmit": {**S, "hook_event_name": "UserPromptSubmit", "prompt": "hello"},
        "Stop": {**S, "hook_event_name": "Stop"},
        "SessionStart": {**S, "hook_event_name": "SessionStart"},
        "SessionEnd": {**S, "hook_event_name": "SessionEnd"},
    },
    "codex": {
        "PreToolUse": {**S, "hook_event_name": "PreToolUse", "tool_name": "Bash",
                       "tool_input": {"command": "git status"}},
        "PostToolUse": {**S, "hook_event_name": "PostToolUse", "tool_name": "Bash",
                        "tool_input": {"command": "git status"},
                        "tool_response": {"output": "clean"}},
        "UserPromptSubmit": {**S, "hook_event_name": "UserPromptSubmit", "prompt": "hello"},
        "Stop": {**S, "hook_event_name": "Stop"},
        "SessionStart": {**S, "hook_event_name": "SessionStart"},
        "SessionEnd": {**S, "hook_event_name": "SessionEnd"},
    },
    "cursor": {
        "preToolUse": {**S, "hook_event_name": "preToolUse", "tool_name": "Read",
                       "tool_input": {"file_path": "/tmp/x"}},
        "beforeShellExecution": {**S, "hook_event_name": "beforeShellExecution",
                                 "command": "git status"},
        "beforeMCPExecution": {**S, "hook_event_name": "beforeMCPExecution",
                               "tool_name": "linear_search", "tool_input": {}},
        "beforeSubmitPrompt": {**S, "hook_event_name": "beforeSubmitPrompt",
                               "prompt": "hello"},
        "stop": {**S, "hook_event_name": "stop"},
        "sessionStart": {**S, "hook_event_name": "sessionStart"},
    },
}

CASES = [(tool, event) for tool, events in EVENT_PAYLOADS.items() for event in events]


@pytest.mark.parametrize("tool,event", CASES)
def test_cli_dev_matches_python_path(tool, event, sandbox_home):
    payload = json.dumps(EVENT_PAYLOADS[tool][event])
    ref = run_python_path(tool, payload, sandbox_home)
    got = run_cli_dev(["hook", tool, event], payload, sandbox_home)
    assert got.stdout == ref.stdout
    assert got.returncode == ref.returncode


@pytest.mark.parametrize("tool,event", CASES)
def test_frozen_binary_matches_python_path(tool, event, sandbox_home):
    payload = json.dumps(EVENT_PAYLOADS[tool][event])
    ref = run_python_path(tool, payload, sandbox_home)
    got = run_binary(["hook", tool, event], payload, sandbox_home)
    assert got.stdout == ref.stdout
    assert got.returncode == ref.returncode


@pytest.mark.parametrize("tool", list(EVENT_PAYLOADS))
@pytest.mark.parametrize("junk", ["", "not json at all"])
def test_malformed_stdin_parity(tool, junk, sandbox_home):
    ref = run_python_path(tool, junk, sandbox_home)
    got = run_cli_dev(["hook", tool], junk, sandbox_home)
    assert got.stdout == ref.stdout
    assert got.returncode == ref.returncode


def test_unknown_tool_fails_open(sandbox_home):
    got = run_cli_dev(["hook", "not-a-tool", "PreToolUse"], "{}", sandbox_home)
    assert got.returncode == 0
    assert json.loads(got.stdout) == {}


def test_missing_tool_fails_open(sandbox_home):
    got = run_cli_dev(["hook"], "{}", sandbox_home)
    assert got.returncode == 0
    assert json.loads(got.stdout) == {}


def test_version_does_not_read_stdin(sandbox_home):
    # pkg postinstall pre-warms with --version; it must not block on stdin.
    got = run_cli_dev(["--version"], None, sandbox_home, stdin_close=True)
    assert got.returncode == 0
    assert got.stdout.startswith("unbound-hook ")


@pytest.mark.parametrize("tool,event", [
    ("claude-code", "SessionStart"), ("cursor", "sessionStart"),
    ("copilot", "SessionStart"), ("codex", "SessionStart"),
])
def test_frozen_session_start_makes_no_downloads(tool, event, discovery_enabled_home):
    """SessionStart is the event that triggers self-update + discovery. In
    frozen mode, with discovery enabled for the org, the hook must neither
    download install.sh nor write self-update state — it logs the missing
    local discovery binary and moves on."""
    home = discovery_enabled_home
    payload = json.dumps({**EVENT_PAYLOADS[tool][event]})
    got = run_cli_dev(["hook", tool, event], payload, home,
                      extra_env={"UNBOUND_HOOK_FROZEN": "1"})
    assert got.returncode == 0
    install_sh = home / ".local" / "share" / "unbound" / "install.sh"
    assert not install_sh.exists(), "frozen hook downloaded install.sh"
    for state in home.rglob(".self_update_check"):
        pytest.fail(f"frozen hook wrote self-update state: {state}")
    err_logs = list(home.rglob("error.log"))
    assert err_logs, "expected the missing-discovery-binary skip to be logged"
    combined = "".join(p.read_text() for p in err_logs)
    assert "discovery binary missing" in combined


def test_frozen_binary_session_start_makes_no_downloads(discovery_enabled_home):
    home = discovery_enabled_home
    payload = json.dumps(EVENT_PAYLOADS["claude-code"]["SessionStart"])
    got = run_binary(["hook", "claude-code", "SessionStart"], payload, home)
    assert got.returncode == 0
    assert not (home / ".local" / "share" / "unbound" / "install.sh").exists()
    assert not (home / ".claude" / "hooks" / ".self_update_check").exists()
