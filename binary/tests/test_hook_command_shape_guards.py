"""A malformed hook entry must not raise inside the matchers.

`hooks.json` and the managed settings are files users and other tools write, so
a command that is not a string, or a `hooks` value that is not a list, is
reachable input rather than a hypothetical. Every matcher below did membership
or `shlex.split` on that value and raised, and each caller turns a raise into
something worse than a rejection:

  - detection answers None for the WHOLE device, discarding every other
    profile's verdict and leaving a stale stored state in place;
  - the uninstall strip aborts, leaving our hook registered on a machine we
    were asked to clean.

The same matcher is implemented four times across the tools, so the guard is
tested four times. Three of the four raised until this change.
"""

from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path

import pytest

from unbound_hook import setup_cmd

REPO = Path(__file__).resolve().parents[2]

# Values a hooks file can legally hold as JSON, and that every matcher used to
# choke on. `{}` and `""` are falsy, so the pre-existing emptiness check
# already rejected them — they are here to pin that they stay rejected.
NON_STRING_COMMANDS = [1, True, 3.5, ["/x"], {"a": 1}, None, {}, ""]


def _load(name: str, rel: str):
    """Load a tool's MDM module from its real path in the repo — the same file
    the MDM path runs and the frozen binary bundles."""
    path = REPO / rel
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


@pytest.fixture(scope="module")
def codex_mdm():
    return _load("t_codex_mdm", "codex/hooks/mdm/setup.py")


@pytest.fixture(scope="module")
def claude_mdm():
    return _load("t_claude_mdm", "claude-code/hooks/mdm/setup.py")


# --- the four implementations of the same matcher ---------------------------

@pytest.mark.parametrize("command", NON_STRING_COMMANDS)
def test_codex_mdm_matcher_rejects_a_non_string(codex_mdm, command):
    assert codex_mdm._is_unbound_hook_command(command, Path("/tmp/unbound.py")) is False


@pytest.mark.parametrize("command", NON_STRING_COMMANDS)
def test_claude_mdm_matcher_rejects_a_non_string(claude_mdm, command):
    assert claude_mdm._command_targets_hook(command, Path("/tmp/unbound.py")) is False


@pytest.mark.parametrize("command", NON_STRING_COMMANDS)
def test_binary_matcher_rejects_a_non_string(command):
    """The binary's own copy, used by the codex merge to dedupe entries."""
    assert setup_cmd._command_targets_hook(command, Path("/tmp/unbound.py")) is False


def test_the_matchers_still_recognise_our_hook(codex_mdm, claude_mdm):
    """The guards reject shapes. They must not narrow what counts as ours."""
    script = Path("/Users/jane doe/.codex/hooks/unbound.py")
    assert codex_mdm._is_unbound_hook_command(str(script), script)
    assert claude_mdm._command_targets_hook(f'"{script}"', script)
    assert setup_cmd._command_targets_hook(f'"{script}"', script)


def test_the_matchers_still_reject_a_foreign_hook(codex_mdm, claude_mdm):
    script = Path("/tmp/unbound.py")
    assert not codex_mdm._is_unbound_hook_command("/usr/local/bin/other", script)
    assert not claude_mdm._command_targets_hook("/usr/local/bin/other", script)
    assert not setup_cmd._command_targets_hook("/usr/local/bin/other", script)


# --- the uninstall strip: the second caller, and its behaviour changed ------

def test_codex_uninstall_strips_ours_and_keeps_a_foreign_entry(codex_mdm, tmp_path,
                                                               monkeypatch):
    """Backward-compat for the strip path.

    A managed config carrying a non-string command beside our hook used to
    raise here, so the strip aborted and our hook stayed registered on a
    machine we were told to clean. It must now strip ours, keep the foreign
    entry, and report cleared.
    """
    managed = tmp_path / "managed"
    hooks_dir = managed / "hooks"
    hooks_dir.mkdir(parents=True)
    script = hooks_dir / "unbound.py"
    script.write_text("# hook\n")
    settings = managed / "hooks.json"
    settings.write_text(json.dumps({"hooks": {"PreToolUse": [
        {"matcher": "*", "hooks": [
            {"type": "command", "command": 1},                 # the shape that raised
            {"type": "command", "command": str(script)},        # ours
            {"type": "command", "command": "/usr/local/bin/keep-me"},
        ]},
    ]}}))

    monkeypatch.setattr(codex_mdm, "get_managed_settings_dir", lambda: managed)
    status = codex_mdm.clear_managed_hooks()

    remaining = [
        h.get("command")
        for group in json.loads(settings.read_text()).get("hooks", {}).get("PreToolUse", [])
        for h in group.get("hooks", [])
    ]
    assert status == "cleared", status
    assert str(script) not in remaining, "our hook survived the strip"
    assert "/usr/local/bin/keep-me" in remaining, "a foreign hook was dropped"


def test_codex_uninstall_on_an_absent_config_reports_rather_than_raises(codex_mdm,
                                                                       tmp_path,
                                                                       monkeypatch):
    monkeypatch.setattr(codex_mdm, "get_managed_settings_dir", lambda: tmp_path / "nope")
    assert codex_mdm.clear_managed_hooks() == "not_found"


# --- detection, through the module the MDM path actually runs --------------

def test_detection_survives_mixed_junk_beside_a_real_entry(codex_mdm, tmp_path,
                                                           monkeypatch):
    """Stress: several malformed shapes in one file, plus our hook.

    The verdict must come from the entry that is actually ours, not be lost to
    the first value that would have raised.
    """
    home = tmp_path / "u"
    (home / ".codex" / "hooks").mkdir(parents=True)
    script = home / ".codex" / "hooks" / "unbound.py"
    script.write_text("# hook\n")
    (home / ".codex" / "hooks.json").write_text(json.dumps({"hooks": {
        "PreToolUse": [
            {"hooks": 1},                                       # scalar where a list belongs
            {"hooks": [{"type": "command", "command": True}]},  # non-string command
            {"hooks": [{"type": "command", "command": str(script)}]},  # ours
        ],
        "Stop": [{"hooks": [{"command": ["nested", "list"]}]}],
    }}))
    monkeypatch.setattr(codex_mdm, "get_all_user_homes",
                        lambda: [("u", home)])
    assert codex_mdm.detect_install_state() == "persisted"
