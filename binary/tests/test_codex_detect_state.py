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
        _wrapper(home).write_text(setup_cmd._codex_wrapper_source())
        _wrapper(home).chmod(0o755)  # every installer sets it
    hooks_json = home / ".codex" / "hooks.json"
    if raw is not None:
        hooks_json.write_text(raw)
    elif config is not None:
        hooks_json.write_text(json.dumps(config))
    return home


def _state(m, *homes, **kwargs):
    return setup_cmd._codex_detect_state(m, [(ME, h) for h in homes], **kwargs)


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


def _old_era(home):
    """What the python installers wrote before async was removed: a 10s
    PreToolUse timeout and async PostToolUse / SessionStart."""
    cfg = _ours(home)
    w = str(_wrapper(home))
    timeouts = {"PreToolUse": 10}
    for event in EVENTS:
        hook = {"type": "command", "command": w, "timeout": timeouts.get(event, 60)}
        if event in ("PostToolUse", "SessionStart"):
            hook["async"] = True
        cfg["hooks"][event] = [{"matcher": "*", "hooks": [hook]}]
    return cfg


def test_an_old_era_install_is_still_ours(m, tmp_path):
    home = _profile(tmp_path, script=True)
    (home / ".codex" / "hooks.json").write_text(json.dumps(_old_era(home)))
    assert _state(m, home) == "persisted"


@pytest.mark.parametrize("event", ["PreToolUse", "UserPromptSubmit", "Stop"])
def test_an_async_hook_where_it_must_block_is_not_ours(m, tmp_path, event):
    home = _profile(tmp_path, script=True)
    cfg = _ours(home)
    cfg["hooks"][event][0]["hooks"][0]["async"] = True
    (home / ".codex" / "hooks.json").write_text(json.dumps(cfg))
    assert _state(m, home) == "tampered"


@pytest.mark.parametrize("timeout, expected", [(1, "tampered"), (9, "tampered"), ("15000", "tampered"),
                                               (True, "tampered"), (10, "persisted"), (15000, "persisted")])
def test_a_pretooluse_timeout_shorter_than_any_we_wrote_is_not_ours(m, tmp_path, timeout, expected):
    home = _profile(tmp_path, script=True)
    cfg = _ours(home)
    cfg["hooks"]["PreToolUse"][0]["hooks"][0]["timeout"] = timeout
    (home / ".codex" / "hooks.json").write_text(json.dumps(cfg))
    assert _state(m, home) == expected


@pytest.mark.parametrize("shape, expected", [
    ("{w}", "tampered"), ('"{w}"', "tampered"), ("'{w}'", "persisted"),
])
def test_a_home_path_the_shell_would_expand(m, tmp_path, shape, expected):
    """`$Doe` in `/Users/Jane$Doe` is expanded bare or double-quoted, so only the
    single-quoted form runs the wrapper."""
    home = _profile(tmp_path, "Jane$Doe", script=True)
    cfg = _registration(shape.format(w=_wrapper(home)))
    (home / ".codex" / "hooks.json").write_text(json.dumps(cfg))
    assert _state(m, home) == expected


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
    # Big enough for the wrapper, too small for hooks.json.
    monkeypatch.setattr(setup_cmd, "_USER_FILE_MAX_BYTES", len(setup_cmd._codex_wrapper_source()) + 1)
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


@pytest.mark.parametrize("spoil", [
    lambda raw: "\ufeff" + raw,                                   # byte-order mark
    lambda raw: raw[:-1] + ', "x": NaN}',                          # NaN
    lambda raw: raw[:-1] + ', "x": Infinity}',                     # Infinity
    lambda raw: raw[:-1] + ', "x": "\\ud800"}',                  # lone surrogate
])
def test_a_file_codex_would_refuse_to_parse_is_not_registered(m, tmp_path, spoil):
    """Python's json accepts these; codex's serde_json does not, so no hook runs."""
    home = _profile(tmp_path, script=True)
    raw = json.dumps(_ours(home))
    (home / ".codex" / "hooks.json").write_text(spoil(raw), encoding="utf-8")
    assert _state(m, home) == "tampered"


@pytest.mark.parametrize("last_is_ours", [True, False])
def test_a_duplicate_known_field_makes_codex_refuse_the_file(m, tmp_path, last_is_ours):
    """serde's derived structs reject a repeated field, so neither copy counts."""
    home = _profile(tmp_path, script=True)
    ours, empty = json.dumps(_ours(home)["hooks"]), "{}"
    first, last = (empty, ours) if last_is_ours else (ours, empty)
    (home / ".codex" / "hooks.json").write_text(f'{{"hooks": {first}, "hooks": {last}}}')
    assert _state(m, home) == "tampered"


def test_a_duplicate_key_inside_free_form_mcp_input_is_fine(m, tmp_path):
    """mcp_tool `input` is a map, not a struct, so a repeat just keeps the last value."""
    home = _profile(tmp_path, script=True)
    cfg = _ours(home)
    raw = json.dumps(cfg)[:-2] + ', "Interrupt": [{"hooks": [{"type": "mcp_tool", "server": "s", "tool": "t", "input": {"a": 1, "a": 2}}]}]}}'
    (home / ".codex" / "hooks.json").write_text(raw)
    assert json.loads(raw)  # still valid JSON
    assert _state(m, home) == "persisted"


@pytest.mark.parametrize("timeout", [10.0, 15000.0])
def test_a_float_timeout_is_not_registered(m, tmp_path, timeout):
    """Codex reads timeout as a u64, so a float makes it reject the whole file."""
    home = _profile(tmp_path, script=True)
    cfg = _ours(home)
    cfg["hooks"]["PreToolUse"][0]["hooks"][0]["timeout"] = timeout
    (home / ".codex" / "hooks.json").write_text(json.dumps(cfg))
    assert _state(m, home) == "tampered"


def _spoiled(home, mutate):
    cfg = _ours(home)
    mutate(cfg)
    (home / ".codex" / "hooks.json").write_text(json.dumps(cfg))


def _add_sibling(cfg, handler):
    cfg["hooks"]["PreToolUse"][0]["hooks"].append(handler)


@pytest.mark.parametrize("mutate", [
    lambda c: c.update(x=1),                                                     # unknown top-level key
    lambda c: c.update(description=5),
    lambda c: _add_sibling(c, {"type": "command", "command": "/x", "timeout": 1.5}),
    lambda c: _add_sibling(c, {"type": "command", "command": "/x", "timeout": 2 ** 64}),
    lambda c: _add_sibling(c, {"type": "command", "command": "/x", "timeout": -1}),
    lambda c: _add_sibling(c, {"type": "command", "command": "/x", "async": None}),
    lambda c: _add_sibling(c, {"type": "command", "command": "/x", "async": 0}),
    lambda c: _add_sibling(c, {"type": "command", "command": "/x", "additionalContextLimit": 1.0}),
    lambda c: _add_sibling(c, {"type": "command", "command": "/x", "statusMessage": 3}),
    lambda c: _add_sibling(c, {"type": "command", "command": "/x", "commandWindows": "a", "command_windows": "b"}),
    lambda c: _add_sibling(c, {"type": "command"}),                              # no command
    lambda c: _add_sibling(c, {"type": "shell", "command": "/x"}),               # unknown handler type
    lambda c: _add_sibling(c, {"command": "/x"}),                                # no type tag
    lambda c: _add_sibling(c, {"type": [], "command": "/x"}),                    # unhashable type tag
    lambda c: _add_sibling(c, {"type": {}, "command": "/x"}),
    lambda c: _add_sibling(c, {"type": "mcp_tool", "server": "s", "tool": "t", "input": {"a": None}}),
    lambda c: _add_sibling(c, {"type": "mcp_tool", "server": "s", "tool": "t", "input": {"a": 2 ** 63}}),
    lambda c: c["hooks"].update(SessionEnd=None),                                # a known event not a list
    lambda c: c["hooks"]["PreToolUse"].append({"matcher": 3, "hooks": []}),
    lambda c: c["hooks"]["PreToolUse"].append({"hooks": None}),
])
def test_a_file_codex_would_not_deserialize_is_not_registered(m, tmp_path, mutate):
    """Codex rejects the whole hooks.json when any part fails its schema, so none
    of our five entries run either."""
    home = _profile(tmp_path, script=True)
    _spoiled(home, mutate)
    assert _state(m, home) == "tampered"


@pytest.mark.parametrize("mutate", [
    lambda c: c.update(description="team hooks"),
    lambda c: c["hooks"].update(SomeFutureEvent=[{"x": 1}]),                     # unknown events are ignored
    lambda c: c["hooks"]["PreToolUse"][0].update(note="kept"),                   # unknown group keys are ignored
    lambda c: c["hooks"]["PreToolUse"][0]["hooks"][0].update(statusMessage="checking", extra=1),
    lambda c: _add_sibling(c, {"type": "mcp_tool", "server": "s", "tool": "t", "input": {"a": [1, "b"]}}),
    lambda c: _add_sibling(c, {"type": "prompt", "anything": 1}),
    lambda c: c["hooks"]["Stop"][0].update(matcher="ignored-on-stop"),           # codex ignores it here
])
def test_content_codex_loads_still_counts(m, tmp_path, mutate):
    home = _profile(tmp_path, script=True)
    _spoiled(home, mutate)
    assert _state(m, home) == "persisted"


def test_a_wrapper_without_its_execute_bit_is_tampered(m, tmp_path):
    """Codex runs the path through the shell, which can't execute it."""
    home = _profile(tmp_path, script=True)
    _wrapper(home).chmod(0o644)
    (home / ".codex" / "hooks.json").write_text(json.dumps(_ours(home)))
    assert _state(m, home) == "tampered"


@pytest.mark.parametrize("squat", ["fifo", "dir"])
def test_something_else_at_the_script_path_is_tampered(m, tmp_path, squat):
    home = tmp_path / "u"
    (home / ".codex" / "hooks").mkdir(parents=True)
    if squat == "fifo":
        os.mkfifo(_wrapper(home))
    else:
        _wrapper(home).mkdir()
    assert _state(m, home) == "tampered"


def test_many_duplicate_keys_parse_in_linear_time(m, tmp_path):
    """A user-controlled file full of repeated keys must not stall setup."""
    import time
    home = _profile(tmp_path, script=True)
    body = ", ".join('"a": 0' for _ in range(300_000))
    (home / ".codex" / "hooks.json").write_text("{" + body + "}")
    started = time.monotonic()
    assert _state(m, home) == "tampered"
    assert time.monotonic() - started < 5


@pytest.mark.parametrize("depth, expected", [(127, "persisted"), (128, "tampered"), (150, "tampered")])
def test_nesting_at_serde_json_s_limit_is_not_registered(m, tmp_path, depth, expected):
    """serde_json fails on the 128th nested [ or {, so codex can't load such a file."""
    home = _profile(tmp_path, script=True)
    cfg = _ours(home)
    # The file, hooks, PreToolUse, group, hooks, handler and input objects are 7 levels.
    nested = 1
    for _ in range(depth - 7):
        nested = [nested]
    _add_sibling(cfg, {"type": "mcp_tool", "server": "s", "tool": "t", "input": {"a": nested}})
    assert setup_cmd._json_depth(cfg) == depth
    (home / ".codex" / "hooks.json").write_text(json.dumps(cfg))
    assert _state(m, home) == expected


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
                        lambda u, fn, *a: None if fn is setup_cmd._codex_hook_registered
                        and a[0].parent.parent == b else real(u, fn, *a))
    assert _state(m, b, a) == "tampered"


def test_the_file_is_read_as_the_profiles_user(m, tmp_path, monkeypatch):
    home = _profile(tmp_path, script=True)
    (home / ".codex" / "hooks.json").write_text(json.dumps(_ours(home)))
    seen = []
    real = m._run_as_user
    monkeypatch.setattr(m, "_run_as_user", lambda u, fn, *a: (seen.append(u), real(u, fn, *a))[1])
    setup_cmd._codex_detect_state(m, [("alice", home)])
    assert seen and set(seen) == {"alice"}  # the wrapper and hooks.json are both read as alice


def test_no_privilege_drop_for_a_profile_without_codex(m, tmp_path, monkeypatch):
    home = tmp_path / "u"
    home.mkdir()
    monkeypatch.setattr(m, "_run_as_user", lambda *a, **k: pytest.fail("forked for nothing"))
    assert _state(m, home) == "fresh"


@pytest.mark.parametrize("content", [
    "#!/bin/sh\nexit 0\n",
    "#!/usr/bin/env python3\n",
    "#!/usr/bin/env python3\n# def main hook_event_name api.getunbound.ai\n",
    # A forged "python-era" hook: the markers and the size, but a no-op.
    "#!/usr/bin/env python3\n# def main\n# hook_event_name\n# api.getunbound.ai\n" + "# pad\n" * 5000,
])
def test_a_runnable_script_that_is_not_ours_is_tampered(m, tmp_path, content):
    """A no-op kept at our path with the right mode enforces nothing."""
    home = _profile(tmp_path, script=True)
    _wrapper(home).write_text(content)
    (home / ".codex" / "hooks.json").write_text(json.dumps(_ours(home)))
    assert _state(m, home) == "tampered"


@pytest.mark.parametrize("gateway", [None, "https://gateway.acme.example"])
def test_a_python_era_hook_script_is_ours(m, tmp_path, gateway):
    """The python installers patch the tenant gateway into the hook they download."""
    home = _profile(tmp_path, script=True)
    real_hook = (Path(setup_cmd.__file__).resolve().parents[3] / "codex" / "hooks" / "unbound.py").read_text()
    if gateway:
        real_hook = real_hook.replace('"https://api.getunbound.ai"', f'"{gateway}"')
    _wrapper(home).write_text(real_hook)
    (home / ".codex" / "hooks.json").write_text(json.dumps(_ours(home)))
    assert _state(m, home, gateway=gateway or "https://api.getunbound.ai") == "persisted"


@pytest.mark.parametrize("gateway", [
    "https://api.getunbound.ai",  # the public default, where a tenant's checks fail open
    "https://allow-everything.example",  # a server that answers allow
    "https://gateway.acme.example/\\xZZ",  # a SyntaxError: the hook never runs
])
def test_a_python_era_hook_pointing_elsewhere_is_not_ours(m, tmp_path, gateway):
    """Only the default or this device's configured gateway was ever written there."""
    home = _profile(tmp_path, script=True)
    real_hook = (Path(setup_cmd.__file__).resolve().parents[3] / "codex" / "hooks" / "unbound.py").read_text()
    _wrapper(home).write_text(real_hook.replace('"https://api.getunbound.ai"', f'"{gateway}"'))
    (home / ".codex" / "hooks.json").write_text(json.dumps(_ours(home)))
    assert _state(m, home, gateway="https://gateway.acme.example") == "tampered"


def test_an_edited_python_era_hook_is_not_ours(m, tmp_path):
    home = _profile(tmp_path, script=True)
    real_hook = (Path(setup_cmd.__file__).resolve().parents[3] / "codex" / "hooks" / "unbound.py").read_text()
    _wrapper(home).write_text(real_hook.replace("def main(", "def _unused(", 1) + "\nraise SystemExit(0)\n")
    (home / ".codex" / "hooks.json").write_text(json.dumps(_ours(home)))
    assert _state(m, home) == "tampered"


def test_the_shipped_hash_list_matches_the_canonical_form():
    """Every shipped hash is a canonical (default-gateway) script, and the bundled
    hook canonicalises to itself."""
    bundled = (Path(setup_cmd.__file__).resolve().parents[3] / "codex" / "hooks" / "unbound.py").read_text()
    patched = bundled.replace('"https://api.getunbound.ai"', '"https://tenant.example"')
    assert (setup_cmd._python_era_hook_sha256(patched, "https://tenant.example")
            == setup_cmd._python_era_hook_sha256(bundled))
    assert setup_cmd._python_era_hook_sha256(patched) is None
    assert all(len(h) == 64 for h in setup_cmd.CODEX_PYTHON_ERA_HOOK_SHA256)


@pytest.mark.skipif(setup_cmd.tomllib is None, reason="tomllib is python 3.11+; the binary bundles it")
@pytest.mark.parametrize("toml, expected", [
    ("[features]\nhooks = false\n", "tampered"),
    ("[features]\ncodex_hooks = false\n", "tampered"),
    ("features = { hooks = false }\n", "tampered"),
    ("[features]\nhooks = true\n", "persisted"),
    ("model = \"o3\"\n", "persisted"),  # on by default
    ("[other]\nhooks = false\n", "persisted"),  # another table's key
    ("not toml [", "persisted"),
])
def test_hooks_turned_off_in_config_toml_are_not_registered(m, tmp_path, toml, expected):
    home = _profile(tmp_path, script=True)
    (home / ".codex" / "hooks.json").write_text(json.dumps(_ours(home)))
    (home / ".codex" / "config.toml").write_text(toml)
    assert _state(m, home) == expected


def test_a_wrapper_the_profiles_user_cannot_run_is_tampered(m, tmp_path, monkeypatch):
    """Another account's file with our content and owner bits set still can't run here."""
    home = _profile(tmp_path, script=True)
    (home / ".codex" / "hooks.json").write_text(json.dumps(_ours(home)))
    real = os.access
    monkeypatch.setattr(setup_cmd.os, "access",
                        lambda p, mode, **k: False if Path(p) == _wrapper(home) and mode & os.X_OK else real(p, mode, **k))
    assert _state(m, home) == "tampered"


@pytest.mark.parametrize("mode, expected", [(0o500, "persisted"), (0o100, "tampered"), (0o111, "tampered")])
def test_the_owner_must_be_able_to_read_and_execute_the_wrapper(m, tmp_path, mode, expected):
    home = _profile(tmp_path, script=True)
    (home / ".codex" / "hooks.json").write_text(json.dumps(_ours(home)))
    _wrapper(home).chmod(mode)
    try:
        assert _state(m, home) == expected
    finally:
        _wrapper(home).chmod(0o755)
