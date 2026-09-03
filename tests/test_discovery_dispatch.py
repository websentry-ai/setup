"""Cross-hook contract for dispatching daily discovery on Windows."""

import importlib.util
import json
import os
import time
from pathlib import Path

import pytest

from tests.conftest import REPO


HOOKS = {
    "claude-code": REPO / "claude-code" / "hooks" / "unbound.py",
    "cursor": REPO / "cursor" / "unbound.py",
    "copilot": REPO / "copilot" / "hooks" / "unbound.py",
    "codex": REPO / "codex" / "hooks" / "unbound.py",
    "augment": REPO / "augment" / "hooks" / "unbound.py",
}

TOOL_API_KEY_ENV = {
    "claude-code": "UNBOUND_CLAUDE_API_KEY",
    "cursor": "UNBOUND_CURSOR_API_KEY",
    "copilot": "UNBOUND_COPILOT_API_KEY",
    "codex": "UNBOUND_CODEX_API_KEY",
    "augment": "UNBOUND_AUGMENT_API_KEY",
}


@pytest.fixture(params=sorted(HOOKS))
def windows_hook(request, tmp_path, monkeypatch):
    tool = request.param
    spec = importlib.util.spec_from_file_location(
        "windows_discovery_%s" % tool.replace("-", "_"), HOOKS[tool]
    )
    hook = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(hook)
    assert hook.RUNNING_FROZEN is False

    monkeypatch.delenv(TOOL_API_KEY_ENV[tool], raising=False)
    monkeypatch.delenv("UNBOUND_BACKEND_URL", raising=False)

    state_dir = tmp_path / "state"
    state_dir.mkdir()
    config_path = state_dir / "config.json"
    config_path.write_text(
        json.dumps({"api_key": "test-key", "base_url": "https://backend.example"}),
        encoding="utf-8",
    )

    installer_dir = tmp_path / "installer"
    installer_dir.mkdir()
    install_sh = installer_dir / "install.sh"
    install_ps1 = installer_dir / "install.ps1"
    install_sh.write_text("#!/bin/bash\n", encoding="utf-8")
    install_ps1.write_text("param()\n", encoding="utf-8")

    monkeypatch.setattr(hook, "_is_windows", lambda: True, raising=False)
    monkeypatch.setenv("SystemRoot", r"C:\Windows")
    monkeypatch.setattr(hook, "UNBOUND_CONFIG_PATH", config_path)
    monkeypatch.setattr(hook, "DISCOVERY_CACHE_PATH", state_dir / "cache.json")
    monkeypatch.setattr(hook, "DISCOVERY_LOCK_PATH", state_dir / "discovery.lock")
    monkeypatch.setattr(hook, "DISCOVERY_DISPATCH_PATH", state_dir / "dispatch.lock")
    monkeypatch.setattr(hook, "DISCOVERY_INSTALL_DIR", installer_dir)
    monkeypatch.setattr(hook, "DISCOVERY_INSTALL_SH", install_sh)
    monkeypatch.setattr(hook, "DISCOVERY_INSTALL_PS1", install_ps1, raising=False)
    monkeypatch.setattr(hook, "log_error", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(hook.tempfile, "gettempdir", lambda: str(tmp_path / "temp"))

    calls = []

    class Process:
        pid = 1

    def record_popen(command, **kwargs):
        calls.append((command, kwargs))
        return Process()

    monkeypatch.setattr(hook.subprocess, "Popen", record_popen)
    return hook, calls, install_ps1


def test_windows_discovery_uses_powershell_installer(windows_hook):
    hook, calls, install_ps1 = windows_hook

    installer_path, installer_url = hook._discovery_installer()
    hook._dispatch_discovery()

    assert installer_path == install_ps1
    assert installer_url.endswith("/install.ps1")
    assert len(calls) == 1
    command, kwargs = calls[0]
    assert command == [
        r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
        "-NoProfile",
        "-NonInteractive",
        "-ExecutionPolicy",
        "Bypass",
        "-File",
        str(install_ps1),
    ]
    assert kwargs["env"]["UNBOUND_API_KEY"] == "test-key"
    assert kwargs["env"]["UNBOUND_DOMAIN"] == "https://backend.example"


def test_windows_discovery_download_uses_system_curl(windows_hook, monkeypatch):
    hook, calls, install_ps1 = windows_hook
    install_ps1.unlink()
    run_calls = []

    class Result:
        returncode = 0
        stderr = b""

    def record_run(command, **kwargs):
        run_calls.append((command, kwargs))
        Path(command[command.index("-o") + 1]).write_text("param()\n", encoding="utf-8")
        return Result()

    monkeypatch.setattr(hook.subprocess, "run", record_run)
    hook._dispatch_discovery()

    assert len(run_calls) == 1
    assert run_calls[0][0][0] == r"C:\Windows\System32\curl.exe"
    assert len(calls) == 1


def test_dispatch_claim_recovers_from_permission_error(windows_hook, monkeypatch):
    hook, calls, _install_ps1 = windows_hook
    marker = hook.DISCOVERY_DISPATCH_PATH
    marker.write_text("", encoding="utf-8")
    os.utime(marker, (0, 0))

    real_open = os.open
    denied = []

    def deny_first_claim(path, *args, **kwargs):
        if str(path) == str(marker) and not denied:
            denied.append(True)
            raise PermissionError(13, "Permission denied")
        return real_open(path, *args, **kwargs)

    monkeypatch.setattr(hook.os, "open", deny_first_claim)

    hook._dispatch_discovery()

    assert denied
    assert len(calls) == 1


def test_state_dir_healthy_home_is_not_relocated(windows_hook):
    hook, calls, _install_ps1 = windows_hook
    state_dir = hook.DISCOVERY_DISPATCH_PATH.parent

    hook._dispatch_discovery()

    assert hook.DISCOVERY_DISPATCH_PATH.parent == state_dir
    assert hook.DISCOVERY_CACHE_PATH.parent == state_dir
    assert hook.DISCOVERY_LOCK_PATH.parent == state_dir
    assert len(calls) == 1


def test_state_dir_denied_relocates_and_stamps_debounce(windows_hook, monkeypatch, tmp_path):
    hook, calls, _install_ps1 = windows_hook
    denied = hook.DISCOVERY_DISPATCH_PATH.parent

    real_access = os.access
    monkeypatch.setattr(
        hook.os, "access",
        lambda path, mode, *a, **k: False if str(path) == str(denied) else real_access(path, mode, *a, **k),
    )

    hook._dispatch_discovery()

    assert hook.DISCOVERY_DISPATCH_PATH.parent != denied
    assert hook.DISCOVERY_CACHE_PATH.parent == hook.DISCOVERY_DISPATCH_PATH.parent
    assert hook.DISCOVERY_LOCK_PATH.parent == hook.DISCOVERY_DISPATCH_PATH.parent
    assert len(calls) == 1
    assert json.loads(hook.DISCOVERY_CACHE_PATH.read_text(encoding="utf-8"))["last_run_at"]


def test_state_dir_unclearable_marker_relocates(windows_hook, monkeypatch, tmp_path):
    hook, calls, _install_ps1 = windows_hook
    poisoned = hook.DISCOVERY_DISPATCH_PATH
    poisoned.write_text("", encoding="utf-8")
    os.utime(poisoned, (0, 0))

    real_open = os.open

    def deny_poisoned(path, *a, **k):
        if str(path) == str(poisoned):
            raise PermissionError(13, "Permission denied")
        return real_open(path, *a, **k)

    monkeypatch.setattr(hook.os, "open", deny_poisoned)

    hook._dispatch_discovery()

    assert hook.DISCOVERY_DISPATCH_PATH != poisoned
    assert poisoned.exists()
    assert len(calls) == 1


@pytest.mark.parametrize("age", [0, 30])
def test_state_dir_keeps_fresh_marker_of_a_live_peer(windows_hook, age):
    hook, calls, _install_ps1 = windows_hook
    marker = hook.DISCOVERY_DISPATCH_PATH
    marker.write_text("", encoding="utf-8")
    stamp = time.time() - age
    os.utime(marker, (stamp, stamp))

    hook._dispatch_discovery()

    assert hook.DISCOVERY_DISPATCH_PATH.parent == marker.parent
    assert calls == []


def test_state_dir_private_candidate_is_hardened(windows_hook, tmp_path):
    hook, _calls, _install_ps1 = windows_hook

    good = tmp_path / "unbound-uid"
    assert hook._state_dir_reject_reason(good, private=True) is None
    assert good.stat().st_mode & 0o077 == 0

    dangling = tmp_path / "linked"
    dangling.symlink_to(tmp_path / "nowhere")
    assert "symlink" in hook._state_dir_reject_reason(dangling, private=True)

    not_a_dir = tmp_path / "regular-file"
    not_a_dir.write_text("", encoding="utf-8")
    assert hook._state_dir_reject_reason(not_a_dir, private=True) is not None

    world_writable = tmp_path / "ws"
    world_writable.mkdir()
    os.chmod(world_writable, 0o777)
    assert hook._state_dir_reject_reason(world_writable / "x", private=True) is not None


def test_state_dir_both_candidates_unusable_is_logged(windows_hook, monkeypatch, tmp_path):
    hook, _calls, _install_ps1 = windows_hook
    monkeypatch.setattr(hook.os, "access", lambda path, mode, *a, **k: False)

    logged = []
    monkeypatch.setattr(hook, "log_error", lambda msg, *a, **k: logged.append(msg))

    hook._dispatch_discovery()

    assert any("no usable state dir" in msg for msg in logged)


def test_debounce_holds_across_sessions_after_relocation(windows_hook, monkeypatch):
    hook, calls, _ = windows_hook
    poisoned = hook.DISCOVERY_DISPATCH_PATH
    poisoned.write_text("", encoding="utf-8")
    os.utime(poisoned, (0, 0))

    real_open = os.open

    def deny(path, *a, **k):
        if str(path) == str(poisoned):
            raise PermissionError(13, "Permission denied")
        return real_open(path, *a, **k)

    monkeypatch.setattr(hook.os, "open", deny)

    hook._dispatch_discovery()          # session 1: relocates, dispatches
    assert len(calls) == 1

    # session 2: fresh process => module constants are back at ~/.unbound
    hook.DISCOVERY_CACHE_PATH = poisoned.parent / "cache.json"
    hook.DISCOVERY_LOCK_PATH = poisoned.parent / "discovery.lock"
    hook.DISCOVERY_DISPATCH_PATH = poisoned
    hook._dispatch_discovery()

    assert len(calls) == 1, "24h debounce did not hold: dispatched again"


def test_non_windows_discovery_keeps_bash_installer(windows_hook, monkeypatch):
    hook, calls, _install_ps1 = windows_hook
    monkeypatch.setattr(hook, "_is_windows", lambda: False)

    hook._dispatch_discovery()

    assert len(calls) == 1
    assert calls[0][0] == [
        "bash",
        str(hook.DISCOVERY_INSTALL_SH),
        "--domain",
        "https://backend.example",
    ]


def test_unreadable_config_falls_back_to_env(request, windows_hook, monkeypatch):
    hook, calls, _install_ps1 = windows_hook
    tool = request.node.callspec.params["windows_hook"]

    real_open = Path.open

    def deny_config(self, *a, **k):
        if self == hook.UNBOUND_CONFIG_PATH:
            raise PermissionError(13, "Permission denied")
        return real_open(self, *a, **k)

    monkeypatch.setattr(Path, "open", deny_config)
    monkeypatch.setenv(TOOL_API_KEY_ENV[tool], "env-key")
    monkeypatch.setenv("UNBOUND_BACKEND_URL", "https://backend.example")

    hook._dispatch_discovery()

    assert len(calls) == 1
    assert calls[0][1]["env"]["UNBOUND_API_KEY"] == "env-key"


def test_unreadable_config_without_env_does_not_dispatch(request, windows_hook, monkeypatch):
    hook, calls, _install_ps1 = windows_hook
    tool = request.node.callspec.params["windows_hook"]

    real_open = Path.open

    def deny_config(self, *a, **k):
        if self == hook.UNBOUND_CONFIG_PATH:
            raise PermissionError(13, "Permission denied")
        return real_open(self, *a, **k)

    monkeypatch.setattr(Path, "open", deny_config)
    monkeypatch.delenv(TOOL_API_KEY_ENV[tool], raising=False)
    monkeypatch.delenv("UNBOUND_BACKEND_URL", raising=False)

    hook._dispatch_discovery()

    assert calls == []
