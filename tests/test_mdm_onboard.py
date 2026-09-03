"""Argument contract for the one-shot MDM onboard wrapper (mdm/onboard.py).

The dashboard's generated onboard command stopped including a discovery key
(unbound-fe #1999 / WEB-5597) because the backend now accepts the admin key for
discovery uploads. The wrapper must therefore treat --discovery-key as an
optional override and fall back to --api-key for the discovery step.
"""

import pytest

from tests.conftest import load_module


@pytest.fixture
def onboard(monkeypatch):
    """onboard.py with every side effect stubbed: no admin check, no downloads,
    no subprocesses. Records what each step would have been invoked with."""
    mod = load_module("mdm/onboard.py")
    calls = {"tools": [], "discovery": []}
    monkeypatch.setattr(mod, "check_admin_privileges", lambda: True)
    monkeypatch.setattr(mod, "run_tool", lambda name, url, args: calls["tools"].append((name, list(args))) or True)
    monkeypatch.setattr(mod, "run_discovery", lambda key, backend: calls["discovery"].append((key, backend)) or True)
    return mod, calls


def _run(monkeypatch, mod, argv):
    monkeypatch.setattr(mod.sys, "argv", ["onboard.py"] + argv)
    return mod.main()


def test_discovery_falls_back_to_api_key_when_no_discovery_key(onboard, monkeypatch):
    mod, calls = onboard

    rc = _run(monkeypatch, mod, ["--api-key", "ADMIN"])

    assert rc == 0
    assert calls["discovery"] == [("ADMIN", mod.DEFAULT_BACKEND_URL)]
    assert len(calls["tools"]) == len(mod.TOOLS)
    for _name, args in calls["tools"]:
        assert args == ["--api-key", "ADMIN"]


def test_explicit_discovery_key_still_honoured(onboard, monkeypatch):
    mod, calls = onboard

    rc = _run(monkeypatch, mod, ["--api-key", "ADMIN", "--discovery-key", "DISC"])

    assert rc == 0
    assert calls["discovery"] == [("DISC", mod.DEFAULT_BACKEND_URL)]
    # The discovery key is never forwarded to the per-tool MDM scripts.
    for _name, args in calls["tools"]:
        assert "--discovery-key" not in args
        assert "DISC" not in args


def test_backend_url_reaches_discovery_with_fallback_key(onboard, monkeypatch):
    mod, calls = onboard

    rc = _run(monkeypatch, mod, ["--api-key", "ADMIN", "--backend-url", "https://backend.example"])

    assert rc == 0
    assert calls["discovery"] == [("ADMIN", "https://backend.example")]


@pytest.mark.parametrize("argv", [
    ["--discovery-key", "DISC"],   # discovery key alone is not enough
    ["--api-key"],                 # flag with no value
    ["--api-key", ""],             # flag with an empty value
])
def test_missing_api_key_still_errors(onboard, monkeypatch, capsys, argv):
    mod, calls = onboard

    rc = _run(monkeypatch, mod, argv)

    assert rc == 1
    assert "--api-key is required" in capsys.readouterr().err
    assert calls["tools"] == []
    assert calls["discovery"] == []


def test_clear_needs_no_keys_and_skips_discovery(onboard, monkeypatch):
    mod, calls = onboard

    rc = _run(monkeypatch, mod, ["--clear"])

    assert rc == 0
    assert calls["discovery"] == []
    assert [args for _name, args in calls["tools"]] == [["--clear"]] * len(mod.TOOLS)
