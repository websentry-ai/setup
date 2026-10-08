"""Setup reports whether each tool is on the machine, beside its install state.

Setup hooks every tool on every profile, so without this a machine that never had
codex still reports codex installed or tampered. The check leans to "present" (a
wrong "absent" would hide a real tamper), only stats paths, and never counts what
setup itself writes."""

import json
import os

import pytest

from unbound_hook import tool_presence
from unbound_hook._loader import load_mdm_setup_module

TOOLS = ("claude-code", "codex", "cursor", "copilot", "augment")


@pytest.fixture(autouse=True)
def no_machine_installs(tmp_path, monkeypatch):
    """This machine's own /opt/homebrew/bin and /Applications stay out of it."""
    machine = tmp_path / "machine"
    (machine / "bin").mkdir(parents=True)
    (machine / "Applications").mkdir()
    monkeypatch.setattr(tool_presence, "_MACHINE_BIN_DIRS", (str(machine / "bin"),))
    monkeypatch.setattr(tool_presence, "_APP_DIRS", (str(machine / "Applications"),))
    return machine


def _home(tmp_path, name="u"):
    home = tmp_path / name
    home.mkdir()
    return home


def _touch(path, executable=False):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("x")
    if executable:
        path.chmod(0o755)
    return path


@pytest.mark.parametrize("tool", TOOLS)
def test_an_empty_machine_has_no_tool(tmp_path, tool):
    assert tool_presence.tool_present(tool, [("u", _home(tmp_path))]) is False


@pytest.mark.parametrize("tool, rel", [
    ("claude-code", ".local/bin/claude"),
    ("claude-code", ".local/share/claude/versions/2.1.278"),
    ("claude-code", ".claude/local/claude"),
    ("claude-code", ".vscode/extensions/anthropic.claude-code-2.0.5-darwin-arm64/package.json"),
    ("claude-code", ".claude/projects/-Users-u-repo/0a1b.jsonl"),
    ("codex", ".nvm/versions/node/v22.11.0/bin/codex"),
    ("codex", ".cargo/bin/codex"),
    ("codex", ".codex/sessions/2026/10/08/rollout.jsonl"),
    ("codex", ".codex/history.jsonl"),
    ("codex", ".cursor/extensions/openai.chatgpt-0.4.1/package.json"),
    ("cursor", ".local/bin/cursor-agent"),
    ("cursor", "Applications/Cursor.app/Contents/Info.plist"),
    ("copilot", ".bun/bin/copilot"),
    ("copilot", ".copilot/session-state/abc/events.jsonl"),
    ("copilot", ".vscode/extensions/github.copilot-chat-0.30.0/package.json"),
    ("augment", ".local/bin/auggie"),
    ("augment", ".vscode/extensions/augment.vscode-augment-0.500.0/package.json"),
    ("augment", "Library/Application Support/JetBrains/IntelliJIdea2025.2/plugins/augment-intellij"),
])
def test_each_kind_of_sign_counts(tmp_path, tool, rel):
    home = _home(tmp_path)
    _touch(home / rel, executable=True)
    assert tool_presence.tool_present(tool, [("u", home)]) is True
    others = [t for t in TOOLS if t != tool]
    assert not any(tool_presence.tool_present(t, [("u", home)]) for t in others), rel


@pytest.mark.parametrize("tool, app_or_bin", [
    ("claude-code", "bin/claude"), ("codex", "bin/codex"), ("cursor", "Applications/Cursor.app"),
    ("codex", "Applications/Codex.app"), ("copilot", "bin/copilot"), ("augment", "bin/auggie"),
])
def test_a_machine_wide_install_counts_for_the_device(tmp_path, no_machine_installs, tool, app_or_bin):
    _touch(no_machine_installs / app_or_bin)
    assert tool_presence.tool_present(tool, [("u", _home(tmp_path))]) is True


def test_any_profile_counts_for_the_device(tmp_path):
    """The report is per device: Bob's codex makes it present even if Alice has none."""
    alice, bob = _home(tmp_path, "alice"), _home(tmp_path, "bob")
    _touch(bob / ".local/bin/codex", executable=True)
    assert tool_presence.tool_present("codex", [("alice", alice), ("bob", bob)]) is True


def test_what_setup_writes_never_counts(tmp_path):
    home = _home(tmp_path)
    for rel in (".unbound/config.json", ".codex/hooks.json", ".codex/hooks/unbound.py",
                ".codex/config.toml", ".copilot/hooks/unbound.json"):
        _touch(home / rel)
    assert {t: tool_presence.tool_present(t, [("u", home)]) for t in TOOLS} == dict.fromkeys(TOOLS, False)


@pytest.mark.skipif(os.geteuid() == 0, reason="root reads every folder")
def test_a_home_that_cannot_be_read_is_unknown_not_absent(tmp_path):
    locked, other = _home(tmp_path, "locked"), _home(tmp_path, "other")
    (locked / ".local").mkdir()
    (locked / ".local").chmod(0)
    try:
        assert tool_presence.tool_present("codex", [("l", locked), ("o", other)]) is None
        _touch(other / ".local/bin/codex", executable=True)
        assert tool_presence.tool_present("codex", [("l", locked), ("o", other)]) is True
    finally:
        (locked / ".local").chmod(0o755)


def test_a_huge_session_folder_is_bounded(tmp_path, monkeypatch):
    home = _home(tmp_path)
    folder = home / ".claude/projects/p"
    folder.mkdir(parents=True)
    calls = []
    real = tool_presence.itertools.islice
    monkeypatch.setattr(tool_presence.itertools, "islice", lambda it, n: (calls.append(n), real(it, n))[1])
    tool_presence.tool_present("claude-code", [("u", home)])
    assert calls and set(calls) == {tool_presence._MAX_MATCHES}


def test_an_unknown_tool_or_a_broken_check_is_unknown(tmp_path, monkeypatch):
    assert tool_presence.tool_present("gemini-cli", [("u", _home(tmp_path))]) is None
    monkeypatch.setattr(tool_presence, "_home_patterns", lambda signs: 1 / 0)
    assert tool_presence.tool_present("codex", [("u", tmp_path)]) is None


# --- the report body ------------------------------------------------------------


@pytest.mark.parametrize("tool", TOOLS)
@pytest.mark.parametrize("present", [True, False, None])
def test_the_report_carries_tool_present_only_when_known(monkeypatch, tool, present):
    m = load_mdm_setup_module(tool)
    sent = []
    monkeypatch.setattr(m.subprocess, "run", lambda *a, **k: sent.append(json.loads(k["input"])))
    m.notify_setup_complete("key", tool, install_state="fresh", serial_number="S", tool_present=present)
    body = sent[0]
    assert body["install_state"] == "fresh"
    if present is None:
        assert "tool_present" not in body  # an older report shape, which the backend already accepts
    else:
        assert body["tool_present"] is present


@pytest.mark.parametrize("tool", TOOLS)
def test_an_old_caller_without_tool_present_still_works(monkeypatch, tool):
    m = load_mdm_setup_module(tool)
    sent = []
    monkeypatch.setattr(m.subprocess, "run", lambda *a, **k: sent.append(json.loads(k["input"])))
    m.notify_setup_complete("key", tool, install_state="persisted", serial_number="S")
    assert "tool_present" not in sent[0]
