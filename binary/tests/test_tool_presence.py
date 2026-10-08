"""Setup reports whether each tool is on the machine, beside its install state.

Setup hooks every tool on every profile, so without this a machine that never had
codex still reports codex installed or tampered. The check leans to "present" (a
wrong "absent" would hide a real tamper), only stats paths, and never counts what
setup itself writes."""

import json
import os
import time

import pytest

from pathlib import Path

from unbound_hook import tool_presence

_REAL_ACCOUNT_HOMES = tool_presence._account_homes
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
    monkeypatch.setattr(tool_presence, "_account_homes", lambda: [])  # this machine's real users
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
    ("claude-code", "Library/Application Support/Claude/claude-code-sessions/3f2a/session.json"),
    ("claude-code", "Library/Application Support/Claude/local-agent-mode-sessions/3f2a/session.json"),
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
    ("copilot", "Library/Application Support/Code/User/globalStorage/github.copilot-chat/x"),
    ("copilot", "Library/Application Support/Code/User/workspaceStorage/ab12/GitHub.copilot-chat/x"),
    ("copilot", ".config/Code - Insiders/User/workspaceStorage/ab12/GitHub.copilot-chat/x"),
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
    ("copilot", "bin/copilot"), ("augment", "bin/auggie"),
])
def test_a_machine_wide_install_counts_for_the_device(tmp_path, no_machine_installs, tool, app_or_bin):
    _touch(no_machine_installs / app_or_bin)
    assert tool_presence.tool_present(tool, [("u", _home(tmp_path))]) is True


def test_any_profile_counts_for_the_device(tmp_path):
    """The report is per device: Bob's codex makes it present even if Alice has none."""
    alice, bob = _home(tmp_path, "alice"), _home(tmp_path, "bob")
    _touch(bob / ".local/bin/codex", executable=True)
    assert tool_presence.tool_present("codex", [("alice", alice), ("bob", bob)]) is True


def test_an_account_setup_did_not_list_is_still_checked(tmp_path, monkeypatch):
    """Setup lists only readable homes under /Users; a home elsewhere still counts."""
    listed, elsewhere = _home(tmp_path, "listed"), _home(tmp_path, "Volumes-Data-alice")
    _touch(elsewhere / ".local/bin/codex", executable=True)
    monkeypatch.setattr(tool_presence, "_account_homes", lambda: [listed, elsewhere])
    assert tool_presence.tool_present("codex", [("listed", listed)]) is True
    assert tool_presence.tool_present("codex", []) is True  # setup's list came back empty


@pytest.mark.parametrize("rel", [".local/share/claude/versions/.DS_Store", ".claude/projects/.DS_Store/x.jsonl"])
def test_finder_residue_alone_is_not_a_sign(tmp_path, rel):
    home = _home(tmp_path)
    _touch(home / rel)
    assert tool_presence.tool_present("claude-code", [("u", home)]) is False


@pytest.mark.skipif(os.geteuid() == 0, reason="root reads every folder")
def test_an_account_home_that_cannot_be_reached_is_unknown(tmp_path, monkeypatch):
    """A readable account with nothing doesn't make the device absent while another
    account's home couldn't be looked at."""
    readable, fenced = _home(tmp_path, "readable"), tmp_path / "fence"
    _touch(fenced / "home/.local/bin/codex", executable=True)
    fenced.chmod(0)
    monkeypatch.setattr(tool_presence, "_account_homes", lambda: [readable, fenced / "home"])
    try:
        assert tool_presence.tool_present("codex", [("r", readable)]) is None
    finally:
        fenced.chmod(0o755)


@pytest.mark.skipif(os.name == "nt", reason="POSIX accounts")
def test_the_account_list_keeps_homes_it_cannot_reach(tmp_path, monkeypatch):
    """Only the checks decide what an unreachable home means (unknown); the listing
    must not drop it on the way."""
    import pwd
    from types import SimpleNamespace
    fenced = tmp_path / "fence"
    (fenced / "home").mkdir(parents=True)
    fenced.chmod(0)
    accounts = [SimpleNamespace(pw_uid=1001, pw_dir=str(fenced / "home")),
                SimpleNamespace(pw_uid=0, pw_dir="/var/root"),
                SimpleNamespace(pw_uid=1002, pw_dir="")]
    monkeypatch.setattr(pwd, "getpwall", lambda: accounts)
    try:
        assert _REAL_ACCOUNT_HOMES() == [fenced / "home"]
    finally:
        fenced.chmod(0o755)


def test_an_account_without_a_home_folder_is_skipped(tmp_path, monkeypatch):
    readable = _home(tmp_path, "readable")
    monkeypatch.setattr(tool_presence, "_account_homes", lambda: [readable, tmp_path / "gone"])
    assert tool_presence.tool_present("codex", []) is False


def test_no_account_to_look_in_is_unknown(monkeypatch):
    assert tool_presence.tool_present("codex", []) is None


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


@pytest.mark.skipif(os.geteuid() == 0, reason="root reads every folder")
def test_a_wildcard_folder_that_cannot_be_listed_is_unknown(tmp_path):
    """pathlib's glob would skip it silently and answer absent."""
    home = _home(tmp_path)
    _touch(home / ".nvm/versions/node/v22.11.0/bin/codex", executable=True)
    (home / ".nvm/versions/node").chmod(0)
    try:
        assert tool_presence.tool_present("codex", [("u", home)]) is None
    finally:
        (home / ".nvm/versions/node").chmod(0o755)


def test_a_folder_too_big_to_list_is_unknown(tmp_path, monkeypatch):
    home = _home(tmp_path)
    for i in range(5):
        (home / ".claude/projects" / f"p{i}").mkdir(parents=True)
    monkeypatch.setattr(tool_presence, "_MAX_ENTRIES", 3)
    assert tool_presence.tool_present("claude-code", [("u", home)]) is None


def test_running_out_of_time_is_unknown(tmp_path, monkeypatch):
    monkeypatch.setattr(tool_presence, "_BUDGET_SECONDS", -1)
    assert tool_presence.tool_present("codex", [("u", _home(tmp_path))]) is None


def test_a_check_stuck_on_a_dead_mount_does_not_hold_setup(tmp_path, monkeypatch):
    import threading
    release = threading.Event()
    monkeypatch.setattr(tool_presence, "_BUDGET_SECONDS", 0.2)
    monkeypatch.setattr(tool_presence, "_find", lambda *a: release.wait(30))
    started = time.monotonic()
    try:
        assert tool_presence.tool_present("codex", [("u", _home(tmp_path))]) is None
        assert time.monotonic() - started < 5
    finally:
        release.set()


def test_a_match_beside_an_unreadable_folder_still_counts(tmp_path):
    home = _home(tmp_path)
    _touch(home / ".local/bin/codex", executable=True)
    (home / ".nvm/versions/node").mkdir(parents=True)
    (home / ".nvm/versions/node").chmod(0)
    try:
        assert tool_presence.tool_present("codex", [("u", home)]) is True
    finally:
        (home / ".nvm/versions/node").chmod(0o755)


@pytest.mark.parametrize("tool, app", [("claude-code", "Claude.app"), ("codex", "Codex.app")])
def test_a_desktop_app_alone_is_not_the_cli(tmp_path, no_machine_installs, tool, app):
    """Claude Desktop and the Codex app are other products; when they run the agent
    they write the same session files, which do count."""
    _touch(no_machine_installs / "Applications" / app / "Contents/Info.plist")
    home = _home(tmp_path)
    _touch(home / "Applications" / app / "Contents/Info.plist")
    assert tool_presence.tool_present(tool, [("u", home)]) is False


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


@pytest.mark.skipif(os.name == "nt" or os.geteuid() == 0, reason="a POSIX login account, not root")
def test_the_account_list_includes_this_users_home():
    assert any(home.resolve() == Path.home().resolve() for home in _REAL_ACCOUNT_HOMES())
