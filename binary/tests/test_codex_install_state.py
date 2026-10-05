"""One malformed hook entry must not blank install state for a whole device.

`detect_install_state` reports what the backend stores and the dashboard shows
as Tampered. Its per-profile loop catches everything and answers None for the
entire device, so an exception raised while inspecting one profile throws away
what every other profile said — including a confirmed tamper on another user,
and including the healthy answer that would have cleared a stale stored state.

Two shapes in hooks.json raised instead of being rejected. Both come from a
file users and other tools can write, so neither is hypothetical.
"""

from __future__ import annotations

import json

import pytest

from unbound_hook import setup_cmd


@pytest.fixture
def codex_module():
    return setup_cmd._module("codex")


@pytest.fixture
def detect(codex_module, monkeypatch):
    """Run the real detector over exactly the profiles a test builds."""
    def _detect(homes):
        monkeypatch.setattr(codex_module, "get_all_user_homes", lambda: homes)
        return codex_module.detect_install_state()
    return _detect


def _profile(root, name="u"):
    home = root / name
    (home / ".codex" / "hooks").mkdir(parents=True)
    return home


def _script(home):
    path = home / ".codex" / "hooks" / "unbound.py"
    path.write_text("# hook\n")
    return path


def _register(home, command):
    (home / ".codex" / "hooks.json").write_text(
        json.dumps({"hooks": {"PreToolUse": [
            {"matcher": "*", "hooks": [{"type": "command", "command": command}]}]}}))


def test_a_healthy_install_is_persisted(tmp_path, detect):
    home = _profile(tmp_path)
    _register(home, str(_script(home)))
    assert detect([("u", home)]) == "persisted"


@pytest.mark.parametrize("command", [1, True, 3.5, {}, ["/x"]])
def test_a_non_string_command_does_not_blank_the_device(tmp_path, detect, command):
    """An int or a bool raises in the ownership matcher's membership test, and
    the detector turns that into no answer for every profile."""
    home = _profile(tmp_path)
    _script(home)
    _register(home, command)
    assert detect([("u", home)]) == "tampered"


def test_a_scalar_where_the_hooks_list_belongs_does_not_blank_the_device(tmp_path, detect):
    """`item.get('hooks') or []` keeps a truthy scalar, and iterating an int
    raises TypeError."""
    home = _profile(tmp_path)
    _script(home)
    (home / ".codex" / "hooks.json").write_text(
        '{"hooks": {"PreToolUse": [{"hooks": 1}]}}')
    assert detect([("u", home)]) == "tampered"


def test_a_garbage_entry_does_not_discard_a_healthy_profiles_answer(tmp_path, detect):
    """The case the guards exist for.

    A garbage `hooks.json` with no script beside a healthy profile used to
    raise, and the device answered None — throwing away the healthy answer that
    should have cleared a stale stored `tampered`. The malformed profile is
    itself no evidence (neither artifact is ours), so the healthy one decides.
    """
    good = _profile(tmp_path, "good")
    _register(good, str(_script(good)))
    junk = _profile(tmp_path, "junk")  # deliberately no script
    _register(junk, 1)
    assert detect([("junk", junk), ("good", good)]) == "persisted"
    assert detect([("good", good), ("junk", junk)]) == "persisted"


def test_a_garbage_entry_alone_is_fresh(tmp_path, detect):
    """With no script and nothing of ours registered, the profile carries no
    evidence either way — so a device with only that reads fresh, not a
    device-wide None."""
    junk = _profile(tmp_path, "junk")
    _register(junk, 1)
    assert detect([("junk", junk)]) == "fresh"


def test_a_malformed_profile_does_not_hide_a_confirmed_tamper(tmp_path, detect):
    """And in the other direction: a profile with the script but no hook of
    ours is a real miss, and must still win over a healthy sibling."""
    good = _profile(tmp_path, "good")
    _register(good, str(_script(good)))
    missed = _profile(tmp_path, "missed")
    _script(missed)
    _register(missed, 1)
    assert detect([("missed", missed), ("good", good)]) == "tampered"
    assert detect([("good", good), ("missed", missed)]) == "tampered"


def test_a_foreign_command_is_still_not_ours(tmp_path, detect):
    """The guards reject shapes. They must not widen what counts as our hook."""
    home = _profile(tmp_path)
    _script(home)
    _register(home, "/usr/local/bin/someone-else")
    assert detect([("u", home)]) == "tampered"
