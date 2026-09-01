"""Cross-hook contract for dispatching daily discovery on Windows."""

import importlib.util
import json
import os
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


@pytest.fixture(params=sorted(HOOKS))
def windows_hook(request, tmp_path, monkeypatch):
    tool = request.param
    spec = importlib.util.spec_from_file_location(
        "windows_discovery_%s" % tool.replace("-", "_"), HOOKS[tool]
    )
    hook = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(hook)
    assert hook.RUNNING_FROZEN is False

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
