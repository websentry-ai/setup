"""On Windows the device ID is the BIOS serial and nothing else. A failed or junk
read returns None, never a registry GUID or hostname, so setup and the scanner
cannot enroll and scan one machine under two IDs."""

import types

import pytest

from tests.conftest import load_module

MODULES = [
    "mdm/onboard.py",
    "claude-code/hooks/setup.py",
    "claude-code/hooks/mdm/setup.py",
    "cursor/mdm/setup.py",
    "codex/hooks/mdm/setup.py",
]


def _run_returning(calls, stdout="", returncode=0, raises=False):
    def fake(cmd, *args, **kwargs):
        calls.append(cmd)
        if raises:
            raise OSError("powershell missing")
        return types.SimpleNamespace(returncode=returncode, stdout=stdout, stderr="")
    return fake


def _windows(monkeypatch, module, **run_kwargs):
    calls = []
    monkeypatch.setattr(module.platform, "system", lambda: "Windows")
    monkeypatch.setattr(module.subprocess, "run", _run_returning(calls, **run_kwargs))
    return calls


@pytest.fixture(params=MODULES)
def module(request):
    return load_module(request.param)


def test_returns_the_bios_serial(module, monkeypatch):
    _windows(monkeypatch, module, stdout="FGV8B54\r\n")
    assert module.get_device_identifier() == "FGV8B54"


@pytest.mark.parametrize("stdout", ["", "   \n", "To Be Filled By O.E.M.", "Default string", "0"])
def test_unreadable_or_placeholder_serial_returns_none(module, monkeypatch, stdout):
    calls = _windows(monkeypatch, module, stdout=stdout)
    assert module.get_device_identifier() is None
    assert len(calls) == 1


def test_powershell_failure_returns_none_without_a_second_probe(module, monkeypatch):
    calls = _windows(monkeypatch, module, raises=True)
    assert module.get_device_identifier() is None
    assert len(calls) == 1


def test_nonzero_exit_returns_none(module, monkeypatch):
    _windows(monkeypatch, module, stdout="FGV8B54", returncode=1)
    assert module.get_device_identifier() is None


HOOKS = [
    "claude-code/hooks/unbound.py",
    "copilot/hooks/unbound.py",
    "cursor/unbound.py",
    "codex/hooks/unbound.py",
    "augment/hooks/unbound.py",
]


@pytest.fixture(params=HOOKS)
def hook(request, tmp_path, monkeypatch):
    mod = load_module(request.param)
    monkeypatch.setattr(mod, "IDENTITY_CACHE_PATH", tmp_path / "identity.json")
    return mod


def _hook_on(monkeypatch, hook, system, **run_kwargs):
    calls = []
    monkeypatch.setattr(hook.platform, "system", lambda: system)
    monkeypatch.setattr(hook.subprocess, "run", _run_returning(calls, **run_kwargs))
    return calls


def test_hook_probe_has_no_machine_guid_fallback(hook, monkeypatch):
    calls = _hook_on(monkeypatch, hook, "Windows", stdout="Default string")
    assert hook._get_device_serial() is None
    assert len(calls) == 1


def test_windows_cache_without_bios_marker_is_reprobed_and_rewritten(hook, monkeypatch):
    hook.IDENTITY_CACHE_PATH.write_text('{"device_serial": "81a7adce-guid"}')
    calls = _hook_on(monkeypatch, hook, "Windows", stdout="FGV8B54")
    assert hook._device_serial() == "FGV8B54"
    assert len(calls) == 1
    assert '"serial_source": "bios"' in hook.IDENTITY_CACHE_PATH.read_text()


def test_windows_cache_with_bios_marker_is_trusted(hook, monkeypatch):
    hook.IDENTITY_CACHE_PATH.write_text('{"device_serial": "FGV8B54", "serial_source": "bios"}')
    calls = _hook_on(monkeypatch, hook, "Windows", stdout="OTHER")
    assert hook._device_serial() == "FGV8B54"
    assert calls == []


def test_windows_stale_cache_is_not_returned_on_the_no_probe_path(hook, monkeypatch):
    hook.IDENTITY_CACHE_PATH.write_text('{"device_serial": "81a7adce-guid"}')
    calls = _hook_on(monkeypatch, hook, "Windows", stdout="FGV8B54")
    assert hook._device_serial(probe=False) is None
    assert calls == []


def test_non_windows_cache_is_unchanged(hook, monkeypatch):
    hook.IDENTITY_CACHE_PATH.write_text('{"device_serial": "C02ABC"}')
    calls = _hook_on(monkeypatch, hook, "Linux", stdout="X")
    assert hook._device_serial() == "C02ABC"
    assert calls == []
