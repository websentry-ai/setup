"""The binary's codex install-state detector, judged per profile on the pair setup
installs: the wrapper script and our entry in that user's ~/.codex/hooks.json.
Runs the real detector against sandboxed homes; only the privilege drop is
stubbed (it needs root), except where a test exercises its failure."""

import getpass
import json
import os
import signal
from pathlib import Path

import pytest

from unbound_hook import setup_cmd
from unbound_hook._loader import load_mdm_setup_module
from unbound_hook._resources import HOOK_BINARY

ME = getpass.getuser()
EVENTS = ("PreToolUse", "PostToolUse", "UserPromptSubmit", "Stop", "SessionStart")


@pytest.fixture
def m(monkeypatch):
    mod = load_mdm_setup_module("codex")
    monkeypatch.setattr(mod, "_run_as_user", lambda u, fn, *a, **k: fn(*a, **k))
    return mod


def _wrapper(home: Path) -> Path:
    return home / ".codex" / "hooks" / "unbound.py"


def _registration(command) -> dict:
    return {"hooks": {e: [{"hooks": [{"type": "command", "command": command}]}] for e in EVENTS}}


def _profile(tmp_path, name="u", *, script=False, config=None, raw=None) -> Path:
    home = tmp_path / name
    (home / ".codex" / "hooks").mkdir(parents=True)
    if script:
        _wrapper(home).write_text("#!/usr/bin/env python3\n")
    hooks_json = home / ".codex" / "hooks.json"
    if raw is not None:
        hooks_json.write_text(raw)
    elif config is not None:
        hooks_json.write_text(json.dumps(config))
    return home


def _state(m, *homes):
    return setup_cmd._codex_detect_state(m, [(ME, h) for h in homes])


def _ours(home):
    return _registration(str(_wrapper(home)))


# --- one profile: the pair ---------------------------------------------------

def test_no_codex_footprint_is_fresh(m, tmp_path):
    home = tmp_path / "u"
    home.mkdir()
    assert _state(m, home) == "fresh"


def test_script_and_registration_is_persisted(m, tmp_path):
    home = _profile(tmp_path, script=True)
    (home / ".codex" / "hooks.json").write_text(json.dumps(_ours(home)))
    assert _state(m, home) == "persisted"


def test_registration_without_the_script_is_tampered(m, tmp_path):
    home = _profile(tmp_path)
    (home / ".codex" / "hooks.json").write_text(json.dumps(_ours(home)))
    assert _state(m, home) == "tampered"


@pytest.mark.parametrize("config", [None, _registration("/usr/local/bin/other-hook")])
def test_script_without_registration_is_tampered(m, tmp_path, config):
    assert _state(m, _profile(tmp_path, script=True, config=config)) == "tampered"


def test_foreign_hooks_only_is_not_an_install(m, tmp_path):
    assert _state(m, _profile(tmp_path, config=_registration("/usr/local/bin/other-hook"))) == "fresh"


def test_a_symlinked_wrapper_is_not_our_script(m, tmp_path):
    home = _profile(tmp_path)
    target = tmp_path / "elsewhere.py"
    target.write_text("#!/usr/bin/env python3\n")
    _wrapper(home).symlink_to(target)
    (home / ".codex" / "hooks.json").write_text(json.dumps(_ours(home)))
    assert _state(m, home) == "tampered"


# --- what counts as our registration -----------------------------------------

@pytest.mark.parametrize("shape", ["{w}", '"{w}"', "'{w}'"])
def test_every_shape_our_installers_wrote_is_ours(m, tmp_path, shape):
    home = _profile(tmp_path, script=True)
    cfg = _registration(shape.format(w=_wrapper(home)))
    (home / ".codex" / "hooks.json").write_text(json.dumps(cfg))
    assert _state(m, home) == "persisted"


@pytest.mark.parametrize("decoy", [
    f"true {HOOK_BINARY}",
    "echo {w}",
    "/opt/other/unbound.py",
    "/usr/local/bin/unbound.py-wrapper",
    'python3 -c "{w}"',
    '"{w}/"',
    '"{w}/."',
    "{w}//",
    'python3 "{w}"',
    '/tmp/bin/python3 "{w}"',
    'python3 -u "{w}"',
    'bash "{w}"',
    'python3 -m "{w}"',
    '"{w}" > /dev/null',
    '"{w}"; true',
    '"{w}" || true',
    "{w} &",
    '"{w}',
])
def test_a_command_that_only_mentions_our_paths_is_not_ours(m, tmp_path, decoy):
    home = _profile(tmp_path, script=True)
    cfg = _registration(decoy.format(w=_wrapper(home)))
    (home / ".codex" / "hooks.json").write_text(json.dumps(cfg))
    assert _state(m, home) == "tampered"


def test_another_users_wrapper_path_is_not_ours(m, tmp_path):
    other = tmp_path / "someone-else"
    home = _profile(tmp_path, script=True, config=_ours(other))
    assert _state(m, home) == "tampered"


@pytest.mark.parametrize("quoted, expected", [(True, "persisted"), (False, "tampered")])
def test_a_home_path_with_a_space_is_judged_as_the_shell_runs_it(m, tmp_path, quoted, expected):
    """Codex runs the command through `$SHELL -lc`, so an unquoted path with a
    space never reaches our wrapper."""
    home = _profile(tmp_path, "Jane Doe", script=True)
    w = str(_wrapper(home))
    cfg = _registration(f'"{w}"' if quoted else w)
    (home / ".codex" / "hooks.json").write_text(json.dumps(cfg))
    assert _state(m, home) == expected


@pytest.mark.parametrize("dropped", EVENTS)
def test_every_installed_event_must_be_registered(m, tmp_path, dropped):
    home = _profile(tmp_path, script=True)
    cfg = _ours(home)
    del cfg["hooks"][dropped]
    (home / ".codex" / "hooks.json").write_text(json.dumps(cfg))
    assert _state(m, home) == "tampered"


@pytest.mark.parametrize("matcher, expected", [
    ("*", "persisted"), ("", "persisted"), ("^$", "tampered"), ("Bash", "tampered"),
])
def test_a_narrowed_matcher_is_not_our_registration(m, tmp_path, matcher, expected):
    """Codex treats a missing, empty or "*" matcher as every tool."""
    home = _profile(tmp_path, script=True)
    cfg = _ours(home)
    cfg["hooks"]["PreToolUse"][0]["matcher"] = matcher
    (home / ".codex" / "hooks.json").write_text(json.dumps(cfg))
    assert _state(m, home) == expected


def test_a_non_command_entry_is_not_our_registration(m, tmp_path):
    home = _profile(tmp_path, script=True)
    cfg = _ours(home)
    cfg["hooks"]["PreToolUse"][0]["hooks"][0]["type"] = "mcp_tool"
    (home / ".codex" / "hooks.json").write_text(json.dumps(cfg))
    assert _state(m, home) == "tampered"


# --- malformed content reads as "codex couldn't load it" ---------------------

@pytest.mark.parametrize("raw", [
    "{not json",
    "\xff\xfe",
    "[]",
    '{"hooks": []}',
    '{"hooks": {"PreToolUse": 1}}',
    '{"hooks": {"PreToolUse": [1, "x", {"hooks": 1}]}}',
    '{"hooks": {"PreToolUse": [{"hooks": [{"command": 1}, {"command": null}, "x"]}]}}',
    "[" * 100000,
])
def test_malformed_content_with_the_script_is_tampered_not_a_crash(m, tmp_path, raw):
    assert _state(m, _profile(tmp_path, script=True, raw=raw)) == "tampered"


def test_an_oversized_file_is_not_read(m, tmp_path, monkeypatch):
    home = _profile(tmp_path, script=True)
    (home / ".codex" / "hooks.json").write_text(json.dumps(_ours(home)))
    monkeypatch.setattr(setup_cmd, "_USER_FILE_MAX_BYTES", 10)
    assert _state(m, home) == "tampered"


@pytest.mark.skipif(os.geteuid() == 0, reason="root reads a 0o000 file")
def test_a_file_the_user_cannot_read_is_not_registered(m, tmp_path):
    home = _profile(tmp_path, script=True)
    hooks_json = home / ".codex" / "hooks.json"
    hooks_json.write_text(json.dumps(_ours(home)))
    hooks_json.chmod(0)
    try:
        assert _state(m, home) == "tampered"
    finally:
        hooks_json.chmod(0o644)


# --- read the way codex does: a symlink is followed, a FIFO never blocks ------

@pytest.mark.parametrize("ours", [True, False])
def test_a_symlinked_hooks_json_is_judged_by_its_content(m, tmp_path, ours):
    home = _profile(tmp_path, script=True)
    dotfile = tmp_path / "dotfiles" / "hooks.json"
    dotfile.parent.mkdir()
    dotfile.write_text(json.dumps(_ours(home) if ours else _registration("/usr/bin/other")))
    (home / ".codex" / "hooks.json").symlink_to(dotfile)
    assert _state(m, home) == ("persisted" if ours else "tampered")


def test_a_dangling_symlink_is_not_registered(m, tmp_path):
    home = _profile(tmp_path, script=True)
    (home / ".codex" / "hooks.json").symlink_to(tmp_path / "gone.json")
    assert _state(m, home) == "tampered"


def test_a_fifo_does_not_hang_setup(m, tmp_path):
    home = _profile(tmp_path, script=True)
    os.mkfifo(home / ".codex" / "hooks.json")

    def _hung(*_):
        raise TimeoutError("detector blocked on a FIFO")

    old = signal.signal(signal.SIGALRM, _hung)
    signal.alarm(5)
    try:
        assert _state(m, home) == "tampered"
    finally:
        signal.alarm(0)
        signal.signal(signal.SIGALRM, old)


# --- several profiles ---------------------------------------------------------

def test_one_healthy_profile_does_not_hide_a_half_installed_one(m, tmp_path):
    a = _profile(tmp_path, "a", script=True)
    (a / ".codex" / "hooks.json").write_text(json.dumps(_ours(a)))
    b = _profile(tmp_path, "b", script=True, config=_registration("/usr/bin/other"))
    assert _state(m, a, b) == "tampered"
    assert _state(m, b, a) == "tampered"


def test_profiles_without_codex_do_not_count(m, tmp_path):
    a = _profile(tmp_path, "a", script=True)
    (a / ".codex" / "hooks.json").write_text(json.dumps(_ours(a)))
    b = tmp_path / "b"
    b.mkdir()
    c = _profile(tmp_path, "c", config=_registration("/usr/bin/other"))
    assert _state(m, a, b, c) == "persisted"


def test_a_failed_privilege_drop_leaves_the_state_unknown(m, tmp_path, monkeypatch):
    home = _profile(tmp_path, script=True)
    (home / ".codex" / "hooks.json").write_text(json.dumps(_ours(home)))
    monkeypatch.setattr(m, "_run_as_user", lambda *a, **k: None)
    assert _state(m, home) is None


def test_tampered_wins_over_an_unknown_profile(m, tmp_path, monkeypatch):
    a = _profile(tmp_path, "a", script=True, config={"hooks": {}})
    b = _profile(tmp_path, "b", script=True, config={"hooks": {}})
    real = m._run_as_user
    monkeypatch.setattr(m, "_run_as_user",
                        lambda u, fn, path, w: None if path.parent.parent == b else real(u, fn, path, w))
    assert _state(m, a, b) == "tampered"


def test_the_file_is_read_as_the_profiles_user(m, tmp_path, monkeypatch):
    home = _profile(tmp_path, script=True)
    (home / ".codex" / "hooks.json").write_text(json.dumps(_ours(home)))
    seen = []
    real = m._run_as_user
    monkeypatch.setattr(m, "_run_as_user", lambda u, fn, *a: (seen.append(u), real(u, fn, *a))[1])
    setup_cmd._codex_detect_state(m, [("alice", home)])
    assert seen == ["alice"]


def test_no_privilege_drop_when_the_profile_has_no_hooks_json(m, tmp_path, monkeypatch):
    home = _profile(tmp_path, script=True)
    monkeypatch.setattr(m, "_run_as_user", lambda *a, **k: pytest.fail("forked for nothing"))
    assert _state(m, home) == "tampered"
