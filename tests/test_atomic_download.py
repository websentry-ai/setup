"""download_file never leaves the live hook partly written.

Claude Code runs the hook straight off disk on every event, so curl writing into the
live file let a hook that fired mid-download, or a dropped connection, run a truncated
script ("SyntaxError: '(' was never closed").
"""

import os
import subprocess
from pathlib import Path
from types import SimpleNamespace

import pytest

from tests.conftest import load_module

INSTALLERS = [
    "claude-code/hooks/mdm/setup.py", "claude-code/hooks/setup.py",
    "codex/hooks/mdm/setup.py", "codex/hooks/setup.py",
    "augment/hooks/mdm/setup.py", "augment/hooks/setup.py",
    "copilot/hooks/mdm/setup.py", "copilot/hooks/setup.py",
    "cursor/mdm/setup.py", "cursor/setup.py",
]
OLD = b"print('old, complete hook')\n"


def _fake_curl(body: bytes, returncode: int):
    def run(cmd, **_kwargs):
        Path(cmd[cmd.index("-o") + 1]).write_bytes(body)
        return SimpleNamespace(returncode=returncode, stdout=b"", stderr=b"")
    return run


@pytest.fixture
def live_hook(tmp_path):
    hook = tmp_path / "hooks" / "unbound.py"
    hook.parent.mkdir()
    hook.write_bytes(OLD)
    os.chmod(hook, 0o755)
    (hook.parent / "unbound.py.999.tmp").write_bytes(b"left by a killed run")
    return hook


@pytest.mark.parametrize("installer", INSTALLERS)
@pytest.mark.parametrize("failure", ["curl_error", "timeout"])
def test_failed_download_keeps_the_live_hook(installer, failure, live_hook, monkeypatch):
    mod = load_module(installer)
    if failure == "timeout":
        def run(cmd, **_kwargs):
            Path(cmd[cmd.index("-o") + 1]).write_bytes(b"except (Va")
            raise subprocess.TimeoutExpired(cmd, 30)
    else:
        run = _fake_curl(b"except (Va", 18)
    monkeypatch.setattr(mod.subprocess, "run", run)

    assert mod.download_file("https://example.invalid/unbound.py", live_hook) is False
    assert live_hook.read_bytes() == OLD
    assert live_hook.stat().st_mode & 0o777 == 0o755
    assert sorted(p.name for p in live_hook.parent.iterdir()) == ["unbound.py"]


@pytest.mark.parametrize("installer", INSTALLERS)
def test_successful_download_swaps_in_whole_and_keeps_mode(installer, live_hook, monkeypatch):
    mod = load_module(installer)
    new = f'GATEWAY = "{mod.DEFAULT_GATEWAY_URL}"\n'.encode() if hasattr(mod, "DEFAULT_GATEWAY_URL") else b"x = 1\n"
    monkeypatch.setattr(mod.subprocess, "run", _fake_curl(new, 0))

    # copilot/mdm stages the download and applies the gateway URL itself, in memory.
    custom = hasattr(mod, "rewrite_gateway_url_in_file")
    args = ("https://example.invalid/unbound.py", live_hook) + (("https://gw.acme.internal",) if custom else ())
    assert mod.download_file(*args) is True
    expected = new.replace(mod.DEFAULT_GATEWAY_URL.encode(), b"https://gw.acme.internal") if custom else new
    assert live_hook.read_bytes() == expected
    assert live_hook.stat().st_mode & 0o777 == 0o755
    assert sorted(p.name for p in live_hook.parent.iterdir()) == ["unbound.py"]


@pytest.mark.parametrize("installer", [i for i in INSTALLERS if i != "copilot/hooks/mdm/setup.py"])
def test_failed_gateway_rewrite_keeps_the_live_hook(installer, live_hook, monkeypatch):
    mod = load_module(installer)
    monkeypatch.setattr(mod.subprocess, "run", _fake_curl(f'GATEWAY = "{mod.DEFAULT_GATEWAY_URL}"\n'.encode(), 0))

    def disk_full(self, data, *_args, **_kwargs):
        Path.write_bytes(self, data.encode()[:5])
        raise OSError(28, "No space left on device")
    monkeypatch.setattr(Path, "write_text", disk_full)

    assert mod.download_file("https://example.invalid/unbound.py", live_hook, "https://gw.acme.internal") is False
    assert live_hook.read_bytes() == OLD
    assert sorted(p.name for p in live_hook.parent.iterdir()) == ["unbound.py"]
