"""Shared MDM fixtures: a whole fake device (root, passwd list, privilege drop, curl and the
artifact fetch all faked). Nothing touches a real /Users, /home or system managed dir."""

import hashlib
import json

import pytest

from tests.opencode.conftest import UNBOUND_BANNER

PAYLOAD = UNBOUND_BANNER + b"export default {};\n"
DIGEST = hashlib.sha256(PAYLOAD).hexdigest()


class FakeRun:
    def __init__(self, stdout="", returncode=0):
        self.stdout = stdout
        self.stderr = ""
        self.returncode = returncode


@pytest.fixture
def device(oc_mdm_setup, monkeypatch, fake_fetch, fake_homes):
    mod = oc_mdm_setup
    monkeypatch.setattr(mod.platform, "system", lambda: "Darwin")
    monkeypatch.setattr(mod.os, "geteuid", lambda: 0)
    monkeypatch.setattr(mod, "get_device_identifier", lambda: "C02ABC123DEF")
    monkeypatch.setattr(mod, "get_all_user_homes", lambda: list(fake_homes))
    monkeypatch.setattr(mod, "_run_as_user", lambda username, fn, *a, **k: fn(*a, **k))
    monkeypatch.setattr(mod.random, "uniform", lambda a, b: 0)
    monkeypatch.setattr(mod.time, "sleep", lambda s: None)
    fake_fetch({mod.ARTIFACT_URL: PAYLOAD, mod.SHA_URL: f"{DIGEST}  opencode/index.js\n"}, module=mod)

    state = {"urls": [], "reports": [], "key_fetches": [], "report_rc": 0, "key": "oc-app-key-1"}

    def fake_run(cmd, **kw):
        url = next((str(a) for a in cmd if str(a).startswith("http")), "")
        state["urls"].append(url)
        assert "install-report" not in url
        if "get_application_api_key" in url:
            state["key_fetches"].append(url)
            return FakeRun(json.dumps({"api_key": state["key"], "email": "oc@acme.test"}) + "\n200")
        if "/setup/complete/" in url:
            payload = kw.get("input")
            state["reports"].append(json.loads(payload.decode() if isinstance(payload, bytes) else payload))
            return FakeRun(returncode=state["report_rc"])
        return FakeRun()

    monkeypatch.setattr(mod.subprocess, "run", fake_run)

    def run(*argv):
        monkeypatch.setattr(mod.sys, "argv", ["setup.py", *argv])
        return mod.main()

    state["run"] = run
    state["homes"] = fake_homes
    return state


