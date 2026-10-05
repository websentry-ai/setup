"""Codex install-state detection, for the binary install path.

The state this reports is what the backend stores and what the dashboard shows
as Tampered. Guessing it wrong is not cosmetic: a wrong 'tampered' makes setup
reassert the hook on every run, and each rewrite touches ~/.codex, which moves
the config-dir age we use to tell an inert installer footprint from a tool in
real use.

The case that matters most here is a hooks.json we cannot read. Our hook may
well be registered in it, so the only honest answer is "no evidence" — None,
which omits install_state from the report and leaves the stored state alone.
"""

from __future__ import annotations

import json
import os
import stat

import pytest

from unbound_hook import setup_cmd
from unbound_hook._resources import HOOK_BINARY


def _profile(root, username="u"):
    home = root / username
    (home / ".codex" / "hooks").mkdir(parents=True)
    return home


def _install(home, command=None):
    """Write what a healthy install leaves: the wrapper plus a hooks.json
    registering it."""
    wrapper = home / ".codex" / "hooks" / "unbound.py"
    wrapper.write_text(setup_cmd._codex_wrapper_source())
    command = command if command is not None else str(wrapper)
    (home / ".codex" / "hooks.json").write_text(
        json.dumps({"hooks": setup_cmd._codex_hooks_config(command)})
    )
    return wrapper


def test_healthy_install_is_persisted(tmp_path):
    home = _profile(tmp_path)
    _install(home)
    assert setup_cmd._codex_detect_state([("u", home)]) == "persisted"


def test_no_hooks_json_anywhere_is_fresh(tmp_path):
    home = _profile(tmp_path)
    assert setup_cmd._codex_detect_state([("u", home)]) == "fresh"


def test_only_a_foreign_hook_is_tampered(tmp_path):
    home = _profile(tmp_path)
    (home / ".codex" / "hooks.json").write_text(json.dumps({
        "hooks": {"PreToolUse": [
            {"matcher": "*", "hooks": [
                {"type": "command", "command": "/usr/local/bin/someone-else"}]}]}
    }))
    assert setup_cmd._codex_detect_state([("u", home)]) == "tampered"


@pytest.mark.skipif(os.geteuid() == 0, reason="root can read a 0o000 file")
def test_unreadable_hooks_json_is_undetermined_not_tampered(tmp_path):
    """The regression: our hook IS registered, we just cannot read the file.

    Reporting 'tampered' here told the backend a healthy install was
    compromised on every run, and setup then rewrote the hook each time.
    """
    home = _profile(tmp_path)
    hooks_path = home / ".codex" / "hooks.json"
    _install(home)
    os.chmod(hooks_path, 0o000)
    try:
        assert setup_cmd._codex_detect_state([("u", home)]) is None
    finally:
        os.chmod(hooks_path, stat.S_IRUSR | stat.S_IWUSR)


def test_emptied_or_truncated_hooks_json_is_tampered(tmp_path):
    """Emptying the file is a way to switch the hook off, so it must not read as
    undetermined. We read it, codex gets no hooks from it, so the hook is not
    active for this user — that is tampered, not unknown."""
    home = _profile(tmp_path)
    hooks_path = home / ".codex" / "hooks.json"

    hooks_path.write_text("")
    assert setup_cmd._codex_detect_state([("u", home)]) == "tampered"

    hooks_path.write_text('{"hooks": {"PreToolUse": [')
    assert setup_cmd._codex_detect_state([("u", home)]) == "tampered"

    hooks_path.write_bytes(b"\x00\x81\xfe")  # not even decodable
    assert setup_cmd._codex_detect_state([("u", home)]) == "tampered"


def test_a_readable_profile_decides_even_when_another_is_refused(tmp_path):
    """A negative rests on a file we read. One refused sibling must not turn a
    real negative into unknown, or corrupting one profile would mask the rest."""
    seen = _profile(tmp_path, "seen")
    (seen / ".codex" / "hooks.json").write_text("")
    refused = _profile(tmp_path, "refused")
    refused_path = refused / ".codex" / "hooks.json"
    _install(refused)
    os.chmod(refused_path, 0o000)
    try:
        expected = "tampered" if os.geteuid() != 0 else "persisted"
        assert setup_cmd._codex_detect_state(
            [("seen", seen), ("refused", refused)]) == expected
    finally:
        os.chmod(refused_path, stat.S_IRUSR | stat.S_IWUSR)


def test_hook_registered_against_the_binary_still_counts(tmp_path):
    """Machines set up before the wrapper existed registered HOOK_BINARY
    directly. They are installed, and must not read as tampered."""
    home = _profile(tmp_path)
    _install(home, command=str(HOOK_BINARY))
    assert setup_cmd._codex_detect_state([("u", home)]) == "persisted"


def test_one_installed_profile_outweighs_an_unreadable_sibling(tmp_path):
    """Positive evidence wins: a profile that registers our hook means the
    install is in place, whatever another profile's file looked like."""
    good = _profile(tmp_path, "good")
    _install(good)
    other = _profile(tmp_path, "other")
    (other / ".codex" / "hooks.json").write_text("")
    assert setup_cmd._codex_detect_state(
        [("good", good), ("other", other)]) == "persisted"


def test_detection_uses_the_same_ownership_rule_as_the_merge(tmp_path):
    """Registration, removal and detection must agree on what is ours, so a
    command the merge treats as ours is never read as someone else's."""
    home = _profile(tmp_path)
    wrapper = home / ".codex" / "hooks" / "unbound.py"
    for command in (str(wrapper), f'"{wrapper}"', f'python3 "{wrapper}"'):
        _install(home, command=command)
        assert setup_cmd._command_targets_hook(command, wrapper), command
        assert setup_cmd._codex_detect_state([("u", home)]) == "persisted", command
