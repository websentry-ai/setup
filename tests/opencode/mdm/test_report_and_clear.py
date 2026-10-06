"""A whole fake device run: one key fetch, one setup_complete with install_mode mdm, the
right exit status, the closing notes, and a --clear that removes only our files.

Faked: root (geteuid), the passwd list (get_all_user_homes), the privilege drop (in-process),
curl (subprocess.run) and the artifact fetch. Nothing touches a real /Users or /home.
"""

import hashlib
import json
import os
from pathlib import Path

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


def _plugins(home):
    return home / ".config" / "opencode" / "plugins"


def _run_install(device):
    return device["run"]("--api-key", "ADMIN-TOKEN", "--backend-url", "https://backend.test")


class TestTheRun:
    def test_one_key_fetch_and_one_report(self, oc_mdm_setup, device):
        assert _run_install(device) is True
        assert len(device["key_fetches"]) == 1
        assert "app_type=opencode" in device["key_fetches"][0]
        assert device["reports"] == [{"tool_type": "opencode", "install_state": "fresh",
                                      "serial_number": "C02ABC123DEF", "hook_hash": DIGEST,
                                      "install_mode": "mdm"}]

    def test_every_home_gets_the_plugin_and_the_key(self, oc_mdm_setup, device):
        _run_install(device)
        for _, h in device["homes"]:
            assert (_plugins(h) / "unbound.js").read_bytes() == PAYLOAD
            assert 'export UNBOUND_OPENCODE_API_KEY="oc-app-key-1"' in (h / ".zprofile").read_text()
            assert json.loads((h / ".unbound" / "config.json").read_text())["api_key"] == "oc-app-key-1"

    def test_a_second_run_reports_persisted(self, oc_mdm_setup, device):
        _run_install(device)
        _run_install(device)
        assert device["reports"][-1]["install_state"] == "persisted"

    def test_the_closing_notes(self, oc_mdm_setup, device, capsys):
        _run_install(device)
        out = capsys.readouterr().out
        assert "restart opencode" in out and "desktop app" in out
        assert "opencode serve" in out and "--pure" in out and "OPENCODE_PURE" in out
        assert oc_mdm_setup.V2_STATUS_NOTE in out

    def test_the_v2_note_matches_the_user_installer(self, oc_mdm_setup, oc_setup):
        assert oc_mdm_setup.V2_STATUS_NOTE == oc_setup.V2_STATUS_NOTE
        assert "is enforced" in oc_mdm_setup.V2_STATUS_NOTE

    def test_the_source_reports_mdm_once_and_never_the_telemetry_endpoint(self, oc_mdm_setup):
        src = Path(oc_mdm_setup.__file__).read_text()
        assert src.count('install_mode="mdm"') == 1
        assert "install-report" not in src

    def test_no_url_in_the_run_is_the_telemetry_endpoint(self, oc_mdm_setup, device):
        _run_install(device)
        assert not [u for u in device["urls"] if "install-report" in u]


class TestFailures:
    def test_every_home_failed_still_reports_once_and_fails(self, oc_mdm_setup, device, monkeypatch):
        monkeypatch.setattr(oc_mdm_setup, "install_for_user", lambda *a: "failed: nope")
        assert _run_install(device) is False
        assert len(device["reports"]) == 1 and device["reports"][0]["install_mode"] == "mdm"

    def test_installed_but_keyless_everywhere_fails_naming_the_variable(
            self, oc_mdm_setup, device, monkeypatch, capsys):
        monkeypatch.setattr(oc_mdm_setup, "set_env_var_for_user", lambda *a: (False, False))
        monkeypatch.setattr(oc_mdm_setup, "write_unbound_config_for_user", lambda *a, **k: False)
        assert _run_install(device) is False
        out = capsys.readouterr().out
        assert "UNBOUND_OPENCODE_API_KEY" in out and "no account has a key" in out
        assert len(device["reports"]) == 1

    def test_a_report_failure_does_not_change_the_exit_status(self, oc_mdm_setup, device):
        device["report_rc"] = 22
        assert _run_install(device) is True

    def test_a_raising_report_does_not_change_the_exit_status(self, oc_mdm_setup, device, monkeypatch):
        def boom(*a, **k):
            raise RuntimeError("x")
        monkeypatch.setattr(oc_mdm_setup, "notify_setup_complete", boom)
        assert _run_install(device) is True

    def test_a_failed_key_fetch_touches_no_home(self, oc_mdm_setup, device):
        device["key"] = ""
        assert _run_install(device) is False
        for _, h in device["homes"]:
            assert not (h / ".config").exists() and not (h / ".zprofile").exists()
        assert device["reports"] == []

    def test_not_root_touches_nothing(self, oc_mdm_setup, device, monkeypatch):
        monkeypatch.setattr(oc_mdm_setup.os, "geteuid", lambda: 501)
        assert _run_install(device) is False
        assert device["key_fetches"] == []


class TestClear:
    def test_clear_removes_only_our_files_and_the_export(self, oc_mdm_setup, device):
        _run_install(device)
        (alice, ah), (bob, bh) = device["homes"]
        (_plugins(ah) / "other.js").write_text("// alice's own\n")
        (ah / ".zprofile").write_text((ah / ".zprofile").read_text() + "export EDITOR=vim\n")
        configs = {h: (h / ".unbound" / "config.json").read_bytes() for _, h in device["homes"]}
        n_reports = len(device["reports"])

        assert device["run"]("--clear") is True
        for _, h in device["homes"]:
            assert not (_plugins(h) / "unbound.js").exists()
            assert not (_plugins(h) / "unbound.js.sha256").exists()
            assert not (_plugins(h) / ".unbound-installed.json").exists()
            assert "UNBOUND_OPENCODE_API_KEY" not in (h / ".zprofile").read_text()
            assert (h / ".unbound" / "config.json").read_bytes() == configs[h]
            assert _plugins(h).is_dir()
        assert not (_plugins(bh) / "package.json").exists(), "bob's package.json was ours"
        assert (_plugins(ah) / "other.js").read_text() == "// alice's own\n"
        assert "export EDITOR=vim" in (ah / ".zprofile").read_text()
        assert len(device["reports"]) == n_reports, "clear posts nothing"

    def test_an_edited_package_json_survives_clear(self, oc_mdm_setup, device):
        _run_install(device)
        _, h = device["homes"][0]
        pkg = _plugins(h) / "package.json"
        pkg.write_text('{"type":"module","name":"mine"}')
        device["run"]("--clear")
        assert pkg.read_text() == '{"type":"module","name":"mine"}'

    def test_a_user_package_json_is_never_removed(self, oc_mdm_setup, device):
        _, h = device["homes"][0]
        _plugins(h).mkdir(parents=True)
        pkg = _plugins(h) / "package.json"
        pkg.write_text('{"type":"module"}')
        _run_install(device)
        device["run"]("--clear")
        assert pkg.read_text() == '{"type":"module"}'

    def test_clear_never_opens_the_shared_config(self, oc_mdm_setup, device, monkeypatch):
        _run_install(device)
        real_open = open

        def guarded(path, *a, **k):
            assert "config.json" not in str(path), "clear opened config.json"
            return real_open(path, *a, **k)

        monkeypatch.setattr("builtins.open", guarded)
        assert device["run"]("--clear") is True

    def test_clear_on_a_pristine_device_is_a_no_op(self, oc_mdm_setup, device):
        assert device["run"]("--clear") is True
        for _, h in device["homes"]:
            assert sorted(os.listdir(h)) == []

    def test_clear_needs_root(self, oc_mdm_setup, device, monkeypatch):
        monkeypatch.setattr(oc_mdm_setup.os, "geteuid", lambda: 501)
        assert device["run"]("--clear") is False
