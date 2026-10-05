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
def codex_user():
    return _load("t_codex_user", "codex/hooks/setup.py")


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


# --- the merge and the gateway strip: callers that raised before the matcher --

def test_the_codex_merge_survives_a_scalar_hooks_value(tmp_path):
    """`.get("hooks", [])` only defaults a *missing* key, so a scalar was
    returned and iterated — the merge aborted before the command check ran, and
    our hook never got registered for that user."""
    hooks_path = tmp_path / "hooks.json"
    wrapper = tmp_path / ".codex" / "hooks" / "unbound.py"
    hooks_path.write_text(json.dumps({"hooks": {
        "PreToolUse": [
            {"matcher": "foreign", "hooks": 1},          # the shape that raised
            {"matcher": "other", "hooks": ["not-a-dict"]},
        ],
    }}))

    setup_cmd._merge_codex_hooks_json(hooks_path, str(wrapper))

    config = json.loads(hooks_path.read_text())
    commands = [
        h.get("command")
        for item in config["hooks"]["PreToolUse"]
        if isinstance(item, dict) and isinstance(item.get("hooks"), list)
        for h in item["hooks"] if isinstance(h, dict)
    ]
    assert str(wrapper) in commands, "our hook was never registered"
    # The foreign entries are still there, untouched.
    assert {"matcher": "foreign", "hooks": 1} in config["hooks"]["PreToolUse"]


def test_the_gateway_strip_preserves_a_non_dict_element(tmp_path, monkeypatch):
    """A non-dict element had `.get` called on it and raised AttributeError.
    The surrounding handler swallowed that, the file was left alone, and our
    hook stayed registered on a machine we were cleaning."""
    gateway = _load("t_codex_gateway_mdm", "codex/gateway/mdm/setup.py")
    managed = tmp_path / "managed"
    (managed / "hooks").mkdir(parents=True)
    script = managed / "hooks" / "unbound.py"
    script.write_text("# hook\n")
    settings = managed / "hooks.json"
    settings.write_text(json.dumps({"hooks": {"Stop": [
        {"matcher": "*", "hooks": [
            "a-bare-string",                      # the element that raised
            {"type": "command", "command": str(script)},
            {"type": "command", "command": "/usr/local/bin/keep-me"},
        ]},
    ]}}))

    monkeypatch.setattr(gateway, "get_managed_settings_dir", lambda: managed)
    gateway.clear_managed_hooks()

    after = json.loads(settings.read_text())
    remaining = after.get("hooks", {}).get("Stop", [{}])[0].get("hooks", [])
    assert str(script) not in [h.get("command") for h in remaining if isinstance(h, dict)], \
        "our hook survived the strip"
    assert "a-bare-string" in remaining, "a foreign element was dropped"
    assert "/usr/local/bin/keep-me" in [
        h.get("command") for h in remaining if isinstance(h, dict)]


@pytest.mark.parametrize("hooks_value", [
    [1, "x"],                          # junk items in the event list
    [{"hooks": 1}],                    # a scalar `hooks` inside an item
    [{"hooks": ["bare"]}],             # a non-dict hook
    [{"hooks": [{"command": 1}]}],     # a non-string command
])
def test_the_python_mdm_codex_merge_survives_bad_shapes(codex_mdm, tmp_path,
                                                        monkeypatch, hooks_value):
    """Malformed entries inside an event's list no longer abort the python MDM
    install merge, so our hook still gets registered for that user.

    A non-list event value is deliberately not covered: it keeps main's
    behaviour, because both ways of handling it are worse (see WEB-6057)."""
    home = tmp_path / "u"
    (home / ".codex" / "hooks").mkdir(parents=True)
    hooks_path = home / ".codex" / "hooks.json"
    hooks_path.write_text(json.dumps({"hooks": {"PreToolUse": hooks_value}}))

    # The install privilege-drops; run the inner work as the current user.
    monkeypatch.setattr(codex_mdm, "_run_as_user", lambda username, fn, *a: fn())
    monkeypatch.setattr(codex_mdm, "download_file", lambda url, path: True)
    monkeypatch.setattr(codex_mdm, "rewrite_gateway_url_in_file",
                        lambda *a, **k: None)
    (home / ".codex" / "hooks" / "unbound.py").write_text("# hook\n")

    assert codex_mdm.configure_codex_hooks_for_user("u", home) is True

    config = json.loads(hooks_path.read_text())
    event = config["hooks"]["PreToolUse"]
    expected = str(home / ".codex" / "hooks" / "unbound.py")
    registered = [
        h.get("command")
        for item in event if isinstance(item, dict)
        for h in (item.get("hooks") if isinstance(item.get("hooks"), list) else [])
        if isinstance(h, dict)
    ]
    assert expected in registered, f"our hook missing for {hooks_value!r}"


# --- the remaining callers review found, each in its own module -------------

@pytest.fixture(scope="module")
def augment_user():
    return _load("t_augment_user", "augment/hooks/setup.py")


@pytest.mark.parametrize("command", NON_STRING_COMMANDS)
def test_augment_matcher_rejects_a_non_string(augment_user, command):
    """The one matcher without the guard. Its Windows branch does a membership
    test, so a truthy non-string raised there and aborted the whole install."""
    for is_windows in (False, True):
        assert augment_user._hook_command_matches(
            command, "cmd", Path("/tmp/unbound.py"), is_windows) is False


def test_the_codex_user_level_strip_survives_bad_shapes(codex_user, tmp_path,
                                                        monkeypatch):
    """The user-level uninstall strip iterated the event value and called .get
    on every element, so a malformed entry aborted it and left our hook in
    place on a machine being cleaned.

    It reads both paths from the real home, so the home is redirected rather
    than the paths passed in.
    """
    monkeypatch.setattr(codex_user.Path, "home", staticmethod(lambda: tmp_path))
    (tmp_path / ".codex" / "hooks").mkdir(parents=True)
    hooks_path = tmp_path / ".codex" / "hooks.json"
    script = tmp_path / ".codex" / "hooks" / "unbound.py"
    hooks_path.write_text(json.dumps({"hooks": {
        "PreToolUse": 1,                                     # non-list event
        "Stop": [
            "a-bare-string",                                  # non-dict item
            {"hooks": 1},                                     # scalar hooks
            {"hooks": ["bare"]},                              # non-dict hook
            {"hooks": [{"command": str(script)}]},            # ours
            {"hooks": [{"command": "/usr/local/bin/keep-me"}]},
        ],
    }}))

    status = codex_user.remove_hooks_from_config()

    after = json.loads(hooks_path.read_text())
    stop = after.get("hooks", {}).get("Stop", [])
    commands = [
        h.get("command")
        for item in stop if isinstance(item, dict)
        for h in (item.get("hooks") if isinstance(item.get("hooks"), list) else [])
        if isinstance(h, dict)
    ]
    assert status in ("cleared", "not_found"), status
    assert str(script) not in commands, "our hook survived the strip"
    assert "/usr/local/bin/keep-me" in commands, "a foreign hook was dropped"
    assert after["hooks"]["PreToolUse"] == 1, "a foreign event value was touched"


@pytest.fixture(scope="module")
def augment_mdm():
    return _load("t_augment_mdm", "augment/hooks/mdm/setup.py")


@pytest.mark.parametrize("command", NON_STRING_COMMANDS)
def test_augment_mdm_matcher_rejects_a_non_string(augment_mdm, command):
    """The MDM copy has a /opt/unbound membership branch the user-level one
    lacks, so a non-string raised here on every platform, not just Windows."""
    for is_windows in (False, True):
        assert augment_mdm._hook_command_matches(
            command, "cmd", Path("/tmp/unbound.py"), is_windows) is False


def test_the_augment_mdm_install_survives_a_scalar_hooks_value(augment_mdm,
                                                               tmp_path,
                                                               monkeypatch):
    """Calls the real writer, not a copy of its generator.

    The previous version of this test rebuilt the guarded comprehension in the
    test body, so it passed while setup_managed_hooks still aborted on the very
    shape it was meant to cover.
    """
    managed = tmp_path / "managed"
    managed.mkdir()
    settings = managed / "settings.json"
    settings.write_text(json.dumps({"hooks": {"PreToolUse": [
        {"matcher": "foreign", "hooks": 1},   # the shape that aborted the write
    ]}}))

    def fake_download(url, path):
        # A real download leaves the file there; the writer checks for it.
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        Path(path).write_text("# hook\n")
        return True

    monkeypatch.setattr(augment_mdm, "get_managed_settings_dir", lambda: managed)
    monkeypatch.setattr(augment_mdm, "download_file", fake_download)
    monkeypatch.setattr(augment_mdm, "rewrite_gateway_url_in_file",
                        lambda *a, **k: None)

    assert augment_mdm.setup_managed_hooks() is True

    after = json.loads(settings.read_text())
    blocks = after["hooks"]["PreToolUse"]
    assert {"matcher": "foreign", "hooks": 1} in blocks, "foreign item dropped"
    registered = [
        h.get("command")
        for item in blocks if isinstance(item, dict)
        for h in (item.get("hooks") if isinstance(item.get("hooks"), list) else [])
        if isinstance(h, dict)
    ]
    assert registered, "our hook was never registered"


@pytest.mark.parametrize("module_path,name", [
    ("claude-code/hooks/setup.py", "t_claude_user_strip"),
    ("augment/hooks/setup.py", "t_augment_user_strip"),
])
def test_the_user_level_strips_survive_bad_shapes(tmp_path, monkeypatch,
                                                  module_path, name):
    """Both strips iterated the event value and called .get on every element,
    so a malformed entry aborted the clean and left our hook behind."""
    module = _load(name, module_path)
    tool_dir = ".claude" if "claude" in module_path else ".augment"
    (tmp_path / tool_dir).mkdir()
    settings_path = tmp_path / tool_dir / "settings.json"
    script = tmp_path / tool_dir / "hooks" / "unbound.py"
    settings_path.write_text(json.dumps({"hooks": {
        "PreToolUse": 1,                                   # non-list event
        "Stop": [
            "a-bare-string",                                # non-dict item
            {"hooks": 1},                                   # scalar hooks
            {"hooks": [{"command": str(script)}]},          # ours
            {"hooks": [{"command": "/usr/local/bin/keep-me"}]},
        ],
    }}))
    monkeypatch.setattr(module.Path, "home", staticmethod(lambda: tmp_path))

    status = module.remove_hooks_from_settings()

    after = json.loads(settings_path.read_text())
    commands = [
        h.get("command")
        for item in after.get("hooks", {}).get("Stop", []) if isinstance(item, dict)
        for h in (item.get("hooks") if isinstance(item.get("hooks"), list) else [])
        if isinstance(h, dict)
    ]
    assert status in ("cleared", "not_found"), status
    assert str(script) not in commands, "our hook survived the strip"
    assert "/usr/local/bin/keep-me" in commands, "a foreign hook was dropped"



def test_the_augment_mdm_user_strip_survives_a_non_string_command(tmp_path,
                                                                  monkeypatch):
    """This strip has its own inline matcher, separate from the guarded one, and
    its /opt/unbound branch raised on `{"command": 1}` — aborting the clean and
    leaving our hook and script behind."""
    module = _load("t_augment_mdm_strip", "augment/hooks/mdm/setup.py")
    home = tmp_path / "u"
    (home / ".augment" / "hooks").mkdir(parents=True)
    script = home / ".augment" / "hooks" / "unbound.py"
    script.write_text("# hook\n")
    settings = home / ".augment" / "settings.json"
    settings.write_text(json.dumps({"hooks": {"Stop": [{"hooks": [
        {"command": 1},
        {"command": str(script)},
        {"command": "/usr/local/bin/keep-me"},
    ]}]}}))
    monkeypatch.setattr(module, "_run_as_user", lambda username, fn, *a: fn())

    module.remove_user_level_hooks_for_user("u", home)

    commands = [
        h.get("command")
        for item in json.loads(settings.read_text()).get("hooks", {}).get("Stop", [])
        for h in item.get("hooks", [])
    ]
    assert str(script) not in commands, "our hook survived the strip"
    assert "/usr/local/bin/keep-me" in commands, "a foreign hook was dropped"


@pytest.mark.parametrize("module_path,name", [
    ("claude-code/hooks/setup.py", "t_bc_claude_strip"),
    ("augment/hooks/setup.py", "t_bc_augment_strip"),
])
def test_uninstall_still_drops_an_item_with_no_hooks_key(tmp_path, monkeypatch,
                                                         module_path, name):
    """Backward-compat. Before these guards an item with no `hooks` key read as
    an empty list and was dropped on uninstall. The guards are only meant to
    stop crashes, so that must not change."""
    module = _load(name, module_path)
    tool_dir = ".claude" if "claude" in module_path else ".augment"
    (tmp_path / tool_dir / "hooks").mkdir(parents=True)
    script = tmp_path / tool_dir / "hooks" / "unbound.py"
    settings = tmp_path / tool_dir / "settings.json"
    settings.write_text(json.dumps({"hooks": {"Stop": [
        {"matcher": "no-hooks-key"},
        {"hooks": [{"command": str(script)}]},
        {"hooks": [{"command": "/usr/local/bin/keep-me"}]},
    ]}}))
    monkeypatch.setattr(module.Path, "home", staticmethod(lambda: tmp_path))

    module.remove_hooks_from_settings()

    stop = json.loads(settings.read_text()).get("hooks", {}).get("Stop", [])
    assert {"matcher": "no-hooks-key"} not in stop, "missing-key item kept"
    assert any(h.get("command") == "/usr/local/bin/keep-me"
               for item in stop for h in item.get("hooks", []))


def test_codex_user_uninstall_still_drops_an_item_with_no_hooks_key(codex_user,
                                                                    tmp_path,
                                                                    monkeypatch):
    monkeypatch.setattr(codex_user.Path, "home", staticmethod(lambda: tmp_path))
    (tmp_path / ".codex" / "hooks").mkdir(parents=True)
    script = tmp_path / ".codex" / "hooks" / "unbound.py"
    hooks_path = tmp_path / ".codex" / "hooks.json"
    hooks_path.write_text(json.dumps({"hooks": {"Stop": [
        {"matcher": "no-hooks-key"},
        {"hooks": [{"command": str(script)}]},
        {"hooks": [{"command": "/usr/local/bin/keep-me"}]},
    ]}}))

    codex_user.remove_hooks_from_config()

    stop = json.loads(hooks_path.read_text()).get("hooks", {}).get("Stop", [])
    assert {"matcher": "no-hooks-key"} not in stop, "missing-key item kept"


def test_gateway_uninstall_still_drops_a_group_with_no_hooks_key(tmp_path,
                                                                monkeypatch):
    gateway = _load("t_bc_gateway", "codex/gateway/mdm/setup.py")
    managed = tmp_path / "managed"
    (managed / "hooks").mkdir(parents=True)
    script = managed / "hooks" / "unbound.py"
    script.write_text("# hook\n")
    settings = managed / "hooks.json"
    settings.write_text(json.dumps({"hooks": {"Stop": [
        {"matcher": "no-hooks-key"},
        {"hooks": [{"command": str(script)}]},
        {"hooks": [{"command": "/usr/local/bin/keep-me"}]},
    ]}}))
    monkeypatch.setattr(gateway, "get_managed_settings_dir", lambda: managed)

    gateway.clear_managed_hooks()

    stop = json.loads(settings.read_text()).get("hooks", {}).get("Stop", [])
    assert {"matcher": "no-hooks-key"} not in stop, "missing-key group kept"
