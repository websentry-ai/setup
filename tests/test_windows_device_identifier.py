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


def test_hook_serial_probe_has_no_machine_guid_fallback(monkeypatch):
    hook = load_module("claude-code/hooks/unbound.py")
    calls = []
    monkeypatch.setattr(hook.platform, "system", lambda: "Windows")
    monkeypatch.setattr(hook.subprocess, "run", _run_returning(calls, stdout="Default string"))
    assert hook._get_device_serial() is None
    assert len(calls) == 1
