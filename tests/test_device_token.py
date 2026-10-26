"""Every tool shares one UNBOUND_DEVICE_TOKEN; the per-tool key names still work as a fallback."""

import importlib.util
import json
import re
import subprocess

import pytest

from tests.conftest import REPO

LEGACY = {
    "claude-code": "UNBOUND_CLAUDE_API_KEY",
    "codex": "UNBOUND_CODEX_API_KEY",
    "cursor": "UNBOUND_CURSOR_API_KEY",
    "copilot": "UNBOUND_COPILOT_API_KEY",
    "augment": "UNBOUND_AUGMENT_API_KEY",
}
HOOKS = {
    "claude-code": REPO / "claude-code" / "hooks" / "unbound.py",
    "codex": REPO / "codex" / "hooks" / "unbound.py",
    "cursor": REPO / "cursor" / "unbound.py",
    "copilot": REPO / "copilot" / "hooks" / "unbound.py",
    "augment": REPO / "augment" / "hooks" / "unbound.py",
}
SETUPS = {
    "claude-code": REPO / "claude-code" / "hooks" / "setup.py",
    "codex": REPO / "codex" / "hooks" / "setup.py",
    "cursor": REPO / "cursor" / "setup.py",
    "copilot": REPO / "copilot" / "hooks" / "setup.py",
    "augment": REPO / "augment" / "hooks" / "setup.py",
}
MDM_SETUPS = {
    "claude-code": REPO / "claude-code" / "hooks" / "mdm" / "setup.py",
    "codex": REPO / "codex" / "hooks" / "mdm" / "setup.py",
    "cursor": REPO / "cursor" / "mdm" / "setup.py",
    "copilot": REPO / "copilot" / "hooks" / "mdm" / "setup.py",
    "augment": REPO / "augment" / "hooks" / "mdm" / "setup.py",
}
HOOK_HOME = {"claude-code": ".claude", "codex": ".codex", "cursor": ".cursor", "copilot": ".copilot", "augment": ".augment"}


def _load(path, name):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture
def home(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path))
    for name in ("UNBOUND_DEVICE_TOKEN", *LEGACY.values()):
        monkeypatch.delenv(name, raising=False)
    return tmp_path


def _write_config(home, body):
    (home / ".unbound").mkdir(exist_ok=True)
    (home / ".unbound" / "config.json").write_text(json.dumps(body))


def _hook_on_disk(home, tool):
    path = home / HOOK_HOME[tool] / "hooks" / "unbound.py"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("#")


@pytest.mark.parametrize("tool", sorted(HOOKS))
def test_hook_prefers_the_device_token_over_the_per_tool_key(home, monkeypatch, tool):
    hook = _load(HOOKS[tool], f"token_hook_{tool.replace('-', '_')}")
    monkeypatch.setenv("UNBOUND_DEVICE_TOKEN", "new")
    monkeypatch.setenv(LEGACY[tool], "old")
    assert hook.get_api_key() == "new"


@pytest.mark.parametrize("tool", sorted(HOOKS))
def test_hook_still_reads_the_per_tool_key_from_an_older_install(home, monkeypatch, tool):
    hook = _load(HOOKS[tool], f"token_hook_{tool.replace('-', '_')}")
    monkeypatch.setenv(LEGACY[tool], "old")
    assert hook.get_api_key() == "old"


@pytest.mark.parametrize("tool", sorted(HOOKS))
def test_hook_reads_config_api_key_then_device_token(home, tool):
    hook = _load(HOOKS[tool], f"token_hook_{tool.replace('-', '_')}")
    # An older writer (CLI login, pinned installer) updates only api_key, so it must win.
    _write_config(home, {"device_token": "stale", "api_key": "relogged"})
    assert hook.get_api_key() == "relogged"
    _write_config(home, {"device_token": "cfg-new"})
    assert hook.get_api_key() == "cfg-new"


@pytest.mark.parametrize("tool", sorted(SETUPS))
def test_setup_writes_both_config_fields(home, tool):
    setup = _load(SETUPS[tool], f"token_setup_{tool.replace('-', '_')}")
    _write_config(home, {"api_key": "old", "email": "a@b.co"})
    setup.write_unbound_config("k2")
    config = json.loads((home / ".unbound" / "config.json").read_text())
    assert (config["device_token"], config["api_key"], config["email"]) == ("k2", "k2", "a@b.co")


@pytest.mark.parametrize("tool", sorted(SETUPS))
def test_setup_removes_only_its_own_legacy_key(home, monkeypatch, tool):
    setup = _load(SETUPS[tool], f"token_setup_{tool.replace('-', '_')}")
    removed = []
    monkeypatch.setattr(setup, "remove_env_var", lambda name, *a: removed.append(name) or ("cleared", ""))
    setup.remove_legacy_key_env()
    assert removed == [LEGACY[tool]]


@pytest.mark.parametrize("tool", sorted(SETUPS))
def test_token_stays_only_while_another_tool_is_hooked(home, monkeypatch, tool):
    setup = _load(SETUPS[tool], f"token_setup_{tool.replace('-', '_')}")
    # System-wide dirs are left out so a real install on this machine can't leak in.
    monkeypatch.setattr(setup, "OTHER_HOOK_DIRS", tuple(d for d in setup.OTHER_HOOK_DIRS if d.startswith("~")))
    _hook_on_disk(home, tool)
    assert setup.device_token_in_use() is False
    _hook_on_disk(home, next(t for t in sorted(HOOK_HOME) if t != tool))
    assert setup.device_token_in_use() is True


@pytest.mark.parametrize("tool", sorted(MDM_SETUPS))
def test_mdm_token_stays_only_while_another_tool_is_hooked(home, monkeypatch, tool):
    mdm = _load(MDM_SETUPS[tool], f"token_mdm_{tool.replace('-', '_')}")
    monkeypatch.setattr(mdm, "OTHER_HOOK_DIRS", tuple(d for d in mdm.OTHER_HOOK_DIRS if d.startswith("~")))
    _hook_on_disk(home, tool)
    assert mdm.device_token_in_use(home) is False
    assert mdm.device_token_in_use(None) is False
    _hook_on_disk(home, next(t for t in sorted(HOOK_HOME) if t != tool))
    assert mdm.device_token_in_use(home) is True


@pytest.mark.parametrize("tool", sorted(MDM_SETUPS))
def test_windows_machine_token_stays_while_any_user_still_needs_it(home, tmp_path, monkeypatch, tool):
    mdm = _load(MDM_SETUPS[tool], f"token_mdm_{tool.replace('-', '_')}")
    remover = "remove_env_var_on_windows" if tool == "cursor" else "remove_env_var_on_windows_machine"
    removed = []
    monkeypatch.setattr(mdm.platform, "system", lambda: "Windows")
    monkeypatch.setattr(mdm, remover, lambda name, *a: removed.append(name) or "cleared")
    monkeypatch.setattr(mdm, "OTHER_HOOK_DIRS", tuple(d for d in mdm.OTHER_HOOK_DIRS if d.startswith("~")))
    alice, bob = tmp_path / "alice", tmp_path / "bob"
    _hook_on_disk(bob, next(t for t in sorted(HOOK_HOME) if t != tool))
    monkeypatch.setattr(mdm, "get_all_user_homes", lambda: [("alice", alice), ("bob", bob)])
    assert mdm._remove_env_var_for_all_users("UNBOUND_DEVICE_TOKEN", keep=mdm.device_token_in_use) is True
    assert removed == []
    monkeypatch.setattr(mdm, "get_all_user_homes", lambda: [("alice", alice)])
    assert mdm._remove_env_var_for_all_users("UNBOUND_DEVICE_TOKEN", keep=mdm.device_token_in_use) is True
    assert removed == ["UNBOUND_DEVICE_TOKEN"]


def test_every_config_writer_also_writes_device_token():
    # Readers move to device_token once api_key writes stop, so every writer must already set it.
    files = subprocess.run(["git", "grep", "-lE", r"config\[['\"]api_key['\"]\] = api_key", "--", "*.py"],
                           cwd=REPO, capture_output=True, text=True, check=True).stdout.split()
    assert files
    missing = [f for f in files if not re.search(r"config\[['\"]device_token['\"]\] = api_key", (REPO / f).read_text())]
    assert missing == []


@pytest.mark.parametrize("tool", sorted(SETUPS))
def test_relative_hook_dirs_never_count_as_in_use(home, tmp_path, monkeypatch, tool):
    # On macOS an unexpanded %ProgramData% entry is relative and would resolve against the cwd.
    setup = _load(SETUPS[tool], f"token_setup_{tool.replace('-', '_')}")
    mdm = _load(MDM_SETUPS[tool], f"token_mdm_{tool.replace('-', '_')}")
    (tmp_path / "%ProgramData%" / "X" / "hooks").mkdir(parents=True)
    (tmp_path / "%ProgramData%" / "X" / "hooks" / "unbound.py").write_text("#")
    monkeypatch.chdir(tmp_path)
    for m in (setup, mdm):
        monkeypatch.setattr(m, "OTHER_HOOK_DIRS", ("%ProgramData%/X",))
    assert setup.device_token_in_use() is False
    assert mdm.device_token_in_use(home) is False


GATEWAYS = {
    "claude-code": (REPO / "claude-code" / "gateway" / "setup.py", REPO / "claude-code" / "gateway" / "mdm" / "setup.py"),
    "codex": (REPO / "codex" / "gateway" / "setup.py", REPO / "codex" / "gateway" / "mdm" / "setup.py"),
}


@pytest.mark.parametrize("tool", sorted(GATEWAYS))
def test_gateway_switch_keeps_token_only_while_another_tool_is_hooked(home, monkeypatch, tool):
    user_path, mdm_path = GATEWAYS[tool]
    gw = _load(user_path, f"token_gw_{tool.replace('-', '_')}")
    gw_mdm = _load(mdm_path, f"token_gw_mdm_{tool.replace('-', '_')}")
    for m in (gw, gw_mdm):
        monkeypatch.setattr(m, "OTHER_HOOK_DIRS", tuple(d for d in m.OTHER_HOOK_DIRS if d.startswith("~")))
    _hook_on_disk(home, tool)
    assert gw.device_token_in_use() is False
    assert gw_mdm.device_token_in_use(home) is False
    _hook_on_disk(home, next(t for t in sorted(HOOK_HOME) if t != tool))
    assert gw.device_token_in_use() is True
    assert gw_mdm.device_token_in_use(home) is True
