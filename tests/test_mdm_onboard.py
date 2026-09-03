"""Argument and key-resolution contract for the one-shot MDM onboard wrapper
(mdm/onboard.py).

The dashboard's generated onboard command stopped including a discovery key
(unbound-fe #1999 / WEB-5597). The backend attributes an application-key
authenticated discovery report to that key's OWNER (ai-gateway-data
webapp/tasks/ai_tools_report_tasks.py), so scanning with the admin key would
file every device under the admin. The wrapper must instead exchange the admin
key + hardware serial for the device owner's key, and must never fall back to
the admin key when that exchange fails.
"""

import io
import json
import urllib.error

import pytest

from tests.conftest import load_module


class _Response(io.BytesIO):
    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()
        return False


@pytest.fixture
def onboard(monkeypatch):
    """onboard.py with every side effect stubbed: no admin check, no downloads,
    no subprocesses, a fixed serial, and a scripted key-exchange endpoint.
    Records what each step and the exchange would have been invoked with."""
    mod = load_module("mdm/onboard.py")
    calls = {"tools": [], "discovery": [], "exchange": []}
    exchange = {"responses": [json.dumps({"api_key": "OWNER"}).encode()]}

    def fake_urlopen(req, timeout=None):
        calls["exchange"].append((req.full_url, dict(req.header_items()), timeout))
        outcome = exchange["responses"][min(len(calls["exchange"]) - 1, len(exchange["responses"]) - 1)]
        if isinstance(outcome, Exception):
            raise outcome
        return _Response(outcome)

    monkeypatch.setattr(mod, "check_admin_privileges", lambda: True)
    monkeypatch.setattr(mod, "get_device_serial", lambda: "SER123")
    monkeypatch.setattr(mod.urllib.request, "urlopen", fake_urlopen)
    monkeypatch.setattr(mod, "run_tool", lambda name, url, args: calls["tools"].append((name, list(args))) or True)
    monkeypatch.setattr(mod, "run_discovery", lambda key, backend: calls["discovery"].append((key, backend)) or True)
    return mod, calls, exchange


def _run(monkeypatch, mod, argv):
    monkeypatch.setattr(mod.sys, "argv", ["onboard.py"] + argv)
    return mod.main()


def test_discovery_uses_owner_key_from_serial_exchange(onboard, monkeypatch, capsys):
    mod, calls, _ = onboard

    rc = _run(monkeypatch, mod, ["--api-key", "ADMIN"])

    assert rc == 0
    assert calls["discovery"] == [("OWNER", mod.DEFAULT_BACKEND_URL)]
    assert len(calls["tools"]) == len(mod.TOOLS)
    for _name, args in calls["tools"]:
        assert args == ["--api-key", "ADMIN"]

    [(url, headers, timeout)] = calls["exchange"]
    assert url == (mod.DEFAULT_BACKEND_URL
                   + "/api/v1/automations/mdm/get_application_api_key/?serial_number=SER123&app_type=default")
    assert headers["Authorization"] == "Bearer ADMIN"
    assert timeout == mod.KEY_EXCHANGE_TIMEOUT_SECONDS

    out = capsys.readouterr().out
    assert "[Discovery] scanning with the device owner's key (serial SER123)" in out
    assert "ADMIN" not in out and "OWNER" not in out  # keys are never printed


def test_explicit_discovery_key_wins_and_skips_exchange(onboard, monkeypatch):
    mod, calls, _ = onboard

    rc = _run(monkeypatch, mod, ["--api-key", "ADMIN", "--discovery-key", "DISC"])

    assert rc == 0
    assert calls["discovery"] == [("DISC", mod.DEFAULT_BACKEND_URL)]
    assert calls["exchange"] == []
    # The discovery key is never forwarded to the per-tool MDM scripts.
    for _name, args in calls["tools"]:
        assert "--discovery-key" not in args
        assert "DISC" not in args


def test_backend_url_used_for_exchange_and_discovery(onboard, monkeypatch):
    mod, calls, _ = onboard

    rc = _run(monkeypatch, mod, ["--api-key", "ADMIN", "--backend-url", "https://backend.example/"])

    assert rc == 0
    assert calls["exchange"][0][0].startswith("https://backend.example/api/v1/automations/mdm/get_application_api_key/?")
    assert calls["discovery"] == [("OWNER", "https://backend.example/")]


@pytest.mark.parametrize("responses, cause", [
    ([urllib.error.URLError("connection refused")] * 2, "connection refused"),
    ([urllib.error.HTTPError("u", 404, "Not Found", {}, None)] * 2, "HTTP 404"),
    ([json.dumps({"email": "x@y"}).encode()], "no api_key"),
    ([b"<html>"], "invalid JSON"),
])
def test_exchange_failure_fails_discovery_only(onboard, monkeypatch, capsys, responses, cause):
    mod, calls, exchange = onboard
    exchange["responses"] = responses

    rc = _run(monkeypatch, mod, ["--api-key", "ADMIN"])

    assert rc == 1
    assert calls["discovery"] == []                     # never scanned with the admin key
    assert len(calls["tools"]) == len(mod.TOOLS)        # steps 1-5 still ran
    assert len(calls["exchange"]) == (mod.KEY_EXCHANGE_ATTEMPTS if isinstance(responses[0], Exception) else 1)
    captured = capsys.readouterr()
    assert "cannot resolve the device owner's key" in captured.err
    assert cause in captured.err
    assert "Discovery" in captured.out.split("failure(s):")[-1]


def test_missing_serial_fails_discovery_only(onboard, monkeypatch, capsys):
    mod, calls, _ = onboard
    monkeypatch.setattr(mod, "get_device_serial", lambda: None)

    rc = _run(monkeypatch, mod, ["--api-key", "ADMIN"])

    assert rc == 1
    assert calls["discovery"] == []
    assert calls["exchange"] == []
    assert len(calls["tools"]) == len(mod.TOOLS)
    assert "hardware serial" in capsys.readouterr().err


@pytest.mark.parametrize("argv", [
    ["--discovery-key", "DISC"],   # discovery key alone is not enough
    ["--api-key"],                 # flag with no value
    ["--api-key", ""],             # flag with an empty value
])
def test_missing_api_key_still_errors(onboard, monkeypatch, capsys, argv):
    mod, calls, _ = onboard

    rc = _run(monkeypatch, mod, argv)

    assert rc == 1
    assert "--api-key is required" in capsys.readouterr().err
    assert calls["tools"] == []
    assert calls["discovery"] == []
    assert calls["exchange"] == []


def test_clear_needs_no_keys_and_skips_discovery(onboard, monkeypatch):
    mod, calls, _ = onboard

    rc = _run(monkeypatch, mod, ["--clear"])

    assert rc == 0
    assert calls["discovery"] == []
    assert calls["exchange"] == []
    assert [args for _name, args in calls["tools"]] == [["--clear"]] * len(mod.TOOLS)
