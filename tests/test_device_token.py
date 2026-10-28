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
def test_hook_reads_only_the_device_token_env(home, monkeypatch, tool):
    hook = _load(HOOKS[tool], f"token_hook_{tool.replace('-', '_')}")
    monkeypatch.setenv(LEGACY[tool], "old")
    assert hook.get_api_key() is None
    monkeypatch.setenv("UNBOUND_DEVICE_TOKEN", "new")
    assert hook.get_api_key() == "new"


@pytest.mark.parametrize("tool", sorted(HOOKS))
def test_hook_reads_only_config_device_token(home, tool):
    hook = _load(HOOKS[tool], f"token_hook_{tool.replace('-', '_')}")
    _write_config(home, {"api_key": "old"})
    assert hook.get_api_key() is None
    _write_config(home, {"device_token": "cfg-new", "api_key": "old"})
    assert hook.get_api_key() == "cfg-new"


@pytest.mark.parametrize("tool", sorted(SETUPS))
def test_setup_writes_device_token_and_drops_api_key(home, tool):
    setup = _load(SETUPS[tool], f"token_setup_{tool.replace('-', '_')}")
    _write_config(home, {"api_key": "old", "email": "a@b.co"})
    setup.write_unbound_config("k2")
    config = json.loads((home / ".unbound" / "config.json").read_text())
    assert config == {"device_token": "k2", "email": "a@b.co"}


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


def test_no_config_writer_writes_api_key():
    # Nothing reads config.json api_key any more, so every writer drops it instead.
    writers = subprocess.run(["git", "grep", "-lE", r"config\[['\"]device_token['\"]\] = api_key", "--", "*.py"],
                             cwd=REPO, capture_output=True, text=True, check=True).stdout.split()
    assert writers
    wrong = [f for f in writers if re.search(r"config\[['\"]api_key['\"]\] =", (REPO / f).read_text())
             or not re.search(r"config\.pop\(['\"]api_key['\"], None\)", (REPO / f).read_text())]
    assert wrong == []


def test_hooks_have_no_per_tool_key_env():
    names = subprocess.run(["git", "grep", "-nE", r"UNBOUND_[A-Z]+_API_KEY", "--", *map(str, HOOKS.values())],
                           cwd=REPO, capture_output=True, text=True).stdout
    assert names == ""


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



@pytest.mark.parametrize("tool", sorted(GATEWAYS))
@pytest.mark.parametrize("bob_hooked", [True, False])
def test_gateway_mdm_decides_windows_machine_token_once(home, tmp_path, monkeypatch, tool, bob_hooked):
    gw_mdm = _load(GATEWAYS[tool][1], f"token_gw_mdm_{tool.replace('-', '_')}")
    removed = []
    monkeypatch.setattr(gw_mdm.platform, "system", lambda: "Windows")
    monkeypatch.setattr(gw_mdm, "OTHER_HOOK_DIRS", tuple(d for d in gw_mdm.OTHER_HOOK_DIRS if d.startswith("~")))
    monkeypatch.setattr(gw_mdm, "remove_env_var_from_user", lambda u, h, name, *a: removed.append(name) or "cleared")
    monkeypatch.setattr(gw_mdm, "check_admin_privileges", lambda: True)
    monkeypatch.setattr(gw_mdm, "get_device_identifier", lambda: "SERIAL")
    monkeypatch.setattr(gw_mdm, "detect_install_state", lambda: None)
    monkeypatch.setattr(gw_mdm, "fetch_api_key_from_mdm", lambda *a: "k")
    # Stops main right after the hook-key cleanup.
    monkeypatch.setattr(gw_mdm, "set_env_var_system_wide", lambda *a: (False, False))
    alice, bob = tmp_path / "alice", tmp_path / "bob"
    if bob_hooked:
        _hook_on_disk(bob, next(t for t in sorted(HOOK_HOME) if t != tool))
    monkeypatch.setattr(gw_mdm, "get_all_user_homes", lambda: [("alice", alice), ("bob", bob)])
    monkeypatch.setattr(gw_mdm.sys, "argv", ["setup.py", "--api-key", "admin"])
    assert not gw_mdm.main()
    assert ("UNBOUND_DEVICE_TOKEN" in removed) is (not bob_hooked)
