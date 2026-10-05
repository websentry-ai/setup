"""Codex install state as the binary setup reports it.

The state here is what the backend stores and the dashboard shows as Tampered,
so a wrong answer is not cosmetic: 719 of 720 Salesloft users sat at `tampered`
with a lifetime count of 41,846 because a detector guessed.

The binary delegates to the vendored MDM module rather than carrying its own
copy. These tests pin the behaviour through the binary's own module handle, so
a future second implementation has to pass them before it can ship.

Two cases carry the weight. A hooks.json we were refused is evidence of
nothing, and reporting it as tampered made a healthy install look compromised
on every run. A hooks.json we read that codex cannot load hooks from means the
hook is not active, so it stays tampered — emptying the file is otherwise a
silent way to switch the hook off.
"""

from __future__ import annotations

import json
import os

import pytest

from unbound_hook import setup_cmd


@pytest.fixture
def codex_module():
    return setup_cmd._module("codex")


@pytest.fixture
def detect(codex_module, monkeypatch):
    """Run the shipped detector over exactly the profiles a test builds."""
    def _detect(homes):
        monkeypatch.setattr(codex_module, "get_all_user_homes", lambda: homes)
        return codex_module.detect_install_state()
    return _detect


def _profile(root, name="u"):
    home = root / name
    (home / ".codex" / "hooks").mkdir(parents=True)
    return home


def _wrapper(home):
    path = home / ".codex" / "hooks" / "unbound.py"
    path.write_text(setup_cmd._codex_wrapper_source())
    return path


def _register(home, command):
    (home / ".codex" / "hooks.json").write_text(
        json.dumps({"hooks": setup_cmd._codex_hooks_config(command)}))


def test_healthy_install_is_persisted(tmp_path, detect):
    home = _profile(tmp_path)
    _register(home, str(_wrapper(home)))
    assert detect([("u", home)]) == "persisted"


def test_a_home_with_a_space_is_still_persisted(tmp_path, detect):
    """/Users/Jane Doe is a real fleet shape. The registered command is the bare
    wrapper path, so a check that tokenises it splits at the space and calls an
    installer-written registration tampered on every run."""
    home = _profile(tmp_path, "Jane Doe")
    _register(home, str(_wrapper(home)))
    assert detect([("Jane Doe", home)]) == "persisted"


def test_a_malformed_nested_shape_does_not_blank_the_device(tmp_path, detect):
    """{"hooks": 1} where a list belongs must come back tampered, not abort
    detection for every profile on the device."""
    home = _profile(tmp_path)
    _wrapper(home)
    (home / ".codex" / "hooks.json").write_text('{"hooks": {"PreToolUse": [{"hooks": 1}]}}')
    assert detect([("u", home)]) == "tampered"


def test_nothing_installed_is_fresh(tmp_path, detect):
    assert detect([("u", _profile(tmp_path))]) == "fresh"


def test_each_half_without_the_other_is_tampered(tmp_path, detect):
    """Either artifact alone leaves codex unenforced for that user."""
    only_script = _profile(tmp_path, "only_script")
    _wrapper(only_script)
    assert detect([("only_script", only_script)]) == "tampered"

    only_entry = _profile(tmp_path, "only_entry")
    _register(only_entry, str(only_entry / ".codex" / "hooks" / "unbound.py"))
    assert detect([("only_entry", only_entry)]) == "tampered"


def test_emptied_hooks_json_stays_tampered(tmp_path, detect):
    """The bypass guard: emptying the file must not read as undetermined.

    We can read it, and codex gets no hooks from it, so the hook is not active.
    """
    home = _profile(tmp_path)
    _wrapper(home)
    for content in ("", '{"hooks": {"PreToolUse": ['):
        (home / ".codex" / "hooks.json").write_text(content)
        assert detect([("u", home)]) == "tampered", content


def test_a_non_string_command_does_not_blank_the_device(tmp_path, detect):
    """A list where a command string belongs must not crash the detector into
    reporting nothing for the whole device."""
    home = _profile(tmp_path)
    _wrapper(home)
    (home / ".codex" / "hooks.json").write_text(json.dumps({"hooks": {"PreToolUse": [
        {"matcher": "*", "hooks": [{"type": "command", "command": ["/x"]}]}]}}))
    assert detect([("u", home)]) == "tampered"

    # An int or bool is the shape that actually raises in the matcher; a list
    # happens to survive membership, so it does not cover this.
    for bad in (1, True, 3.5, {}):
        (home / ".codex" / "hooks.json").write_text(json.dumps({"hooks": {"PreToolUse": [
            {"matcher": "*", "hooks": [{"type": "command", "command": bad}]}]}}))
        assert detect([("u", home)]) == "tampered", bad


def test_a_symlinked_hooks_json_is_tampered(tmp_path, detect):
    """A symlink there is interference, not absent evidence.

    Setup only ever writes a regular file and the merge will not write through
    a link, so a link left in place means nothing we control is enforcing.
    Calling it undetermined would omit install_state and leave a device sitting
    on a stale `persisted` while the hook was switched off.
    """
    home = _profile(tmp_path)
    _wrapper(home)
    real = home / ".codex" / "elsewhere.json"
    real.write_text(json.dumps({"hooks": {}}))
    (home / ".codex" / "hooks.json").symlink_to(real)
    assert detect([("u", home)]) == "tampered"


def test_a_genuinely_refused_file_is_undetermined(codex_module, detect, tmp_path,
                                                  monkeypatch):
    """A real permission failure says nothing either way, so install_state is
    omitted and the stored value is left alone.

    Forced rather than chmod 000: MDM setup runs as root, and root reads a
    0o000 file, so a mode-based test would skip itself exactly where the
    behaviour matters.
    """
    home = _profile(tmp_path)
    _register(home, str(_wrapper(home)))
    real_open = os.open

    def refuse(path, *a, **kw):
        if str(path).endswith("hooks.json"):
            raise PermissionError(13, "refused")
        return real_open(path, *a, **kw)

    monkeypatch.setattr(codex_module.os, "open", refuse)
    assert detect([("u", home)]) is None


def test_a_pre_wrapper_binary_registration_is_persisted(tmp_path, detect):
    """Machines set up before the wrapper existed register the hook binary
    directly. There is no per-user script to pair with and the hook still runs,
    so requiring one would report them tampered forever."""
    home = _profile(tmp_path)
    from unbound_hook._resources import HOOK_BINARY
    _register(home, f'"{HOOK_BINARY}" hook codex PreToolUse')
    assert not (home / ".codex" / "hooks" / "unbound.py").exists()
    assert detect([("u", home)]) == "persisted"


def test_one_unenforced_profile_is_not_hidden_by_a_healthy_one(tmp_path, detect):
    """A device where one user is unenforced is tampered, however healthy
    another user looks — otherwise the dashboard calls it clean."""
    good = _profile(tmp_path, "good")
    _register(good, str(_wrapper(good)))
    bad = _profile(tmp_path, "bad")
    _wrapper(bad)  # script, never registered
    assert detect([("good", good), ("bad", bad)]) == "tampered"


def test_the_binary_does_not_carry_its_own_detector(tmp_path):
    """The drift this suite exists to prevent: two implementations of the same
    question, disagreeing on unreadable files, non-string commands and whether
    the script has to be there at all."""
    source = (setup_cmd.__file__ or "")
    assert source, "setup_cmd has no file to inspect"
    text = open(source, encoding="utf-8").read()
    assert "def _codex_detect_state" not in text
    assert "def _codex_hook_registered" not in text
