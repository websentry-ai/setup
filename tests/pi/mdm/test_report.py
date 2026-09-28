"""The device report, and the endpoint this installer must NOT post to.

The ROADMAP and REQUIREMENTS both say the MDM installer posts `install-report`. RESEARCH §C5
shows that is the wrong endpoint: `POST /api/v1/automations/mdm/install-report/` is
device-level Jamf telemetry with no `tool_type` at all, posted once per device by the macOS
bootstrap's exit trap. A pi install reported there would carry no tool, so the console would
never show the device as having pi -- while the installer printed success. The correct
report is the one every other tool sends, `POST /api/v1/setup/complete/`, with
`install_mode: "mdm"`.

So the load-bearing assertion in this file is a negative: across a whole device run, no
captured curl argv contains the string `install-report`.
"""

import json
import re

import pytest

PAYLOAD = b"// the unbound pi extension\nmodule.exports = {};\n"
HEX64 = re.compile(r"^[0-9a-f]{64}$")


class FakeRun:
    def __init__(self, stdout="", returncode=0):
        self.stdout = stdout
        self.stderr = ""
        self.returncode = returncode


class Device:
    """A whole fake managed device: two homes, a serial, a key endpoint and a report sink."""

    def __init__(self, homes, urls, reports):
        self.homes = homes
        self.urls = urls        # every URL any curl in the run was pointed at
        self.reports = reports  # every parsed setup_complete body


@pytest.fixture
def device(pi_mdm_setup, monkeypatch, fake_fetch, tmp_path):
    import hashlib

    mod = pi_mdm_setup
    digest = hashlib.sha256(PAYLOAD).hexdigest()

    homes = []
    for name in ("alice", "bob"):
        home = tmp_path / "Users" / name
        home.mkdir(parents=True)
        homes.append((name, home))

    monkeypatch.setattr(mod.platform, "system", lambda: "Darwin")
    monkeypatch.setattr(mod.os, "geteuid", lambda: 0)
    monkeypatch.setattr(mod, "get_device_identifier", lambda: "C02ABC123DEF")
    monkeypatch.setattr(mod, "get_all_user_homes", lambda: list(homes))
    monkeypatch.setattr(mod, "_run_as_user",
                        lambda username, fn, *a, **k: fn(*a, **k))
    monkeypatch.setattr(mod.random, "uniform", lambda a, b: 0)
    monkeypatch.setattr(mod.time, "sleep", lambda s: None)
    fake_fetch({mod.ARTIFACT_URL: PAYLOAD, mod.SHA_URL: f"{digest}  pi/index.js\n"},
               module=mod)

    urls = []
    reports = []
    report_result = {"returncode": 0}

    def fake_run(cmd, **kw):
        url = next((str(a) for a in cmd if str(a).startswith("http")), "")
        urls.append(url)
        # The whole point of this module: never this endpoint, from anywhere in the run.
        assert "install-report" not in url, f"posted the device telemetry endpoint: {url}"
        if "get_application_api_key" in url:
            return FakeRun(json.dumps({"api_key": "pi-app-key-1", "email": "pi@acme.test",
                                       "first_name": "Pi", "last_name": "App"}) + "\n200")
        if "/setup/complete/" in url:
            payload = kw.get("input")
            if payload is not None:
                reports.append(json.loads(payload.decode() if isinstance(payload, bytes)
                                          else payload))
            return FakeRun(returncode=report_result["returncode"])
        return FakeRun()

    monkeypatch.setattr(mod.subprocess, "run", fake_run)
    monkeypatch.setattr(mod.sys, "argv",
                        ["setup.py", "--api-key", "ADMIN-TOKEN",
                         "--backend-url", "https://backend.test"])
    dev = Device(homes, urls, reports)
    dev.digest = digest
    dev.report_result = report_result
    return dev


def _installed(home):
    return home / ".pi" / "agent" / "extensions" / "unbound" / "index.js"


# --- exactly one report, with the right fields ---------------------------------------------


def test_a_device_run_posts_exactly_one_setup_complete(pi_mdm_setup, device):
    """One report per DEVICE, not one per user: the backend keys install state on the
    serial, so N identical posts would be N writes racing on one row."""
    assert pi_mdm_setup.main() is True
    assert len(device.reports) == 1, device.reports
    body = device.reports[0]
    assert body["tool_type"] == "pi"
    assert body["install_mode"] == "mdm"
    assert body["serial_number"] == "C02ABC123DEF"
    assert HEX64.match(body["hook_hash"]), body["hook_hash"]
    assert body["hook_hash"] == device.digest
    assert body["install_state"] == "fresh"
    # And every home really did get the bytes that digest belongs to.
    for _, home in device.homes:
        assert _installed(home).read_bytes() == PAYLOAD


def test_no_url_in_the_whole_run_contains_install_report(pi_mdm_setup, device):
    """Asserted twice over: the fixture fails on sight, and the URL list is checked here so
    the failure is legible even if the assertion inside the fake is ever relaxed."""
    assert pi_mdm_setup.main() is True
    assert device.urls, "no curl ran at all, so this assertion would be vacuous"
    assert not [u for u in device.urls if "install-report" in u]
    assert [u for u in device.urls if u.endswith("/api/v1/setup/complete/")]


def test_the_source_never_mentions_the_telemetry_endpoint(pi_mdm_setup):
    """The requirement text names it, so the easiest possible mistake is to add it back."""
    src = open(pi_mdm_setup.__file__, encoding="utf-8").read()
    assert "install-report" not in src
    assert "/api/v1/setup/complete/" in src


def test_install_state_is_read_before_any_home_is_written(pi_mdm_setup, device):
    """A state read after the loop would report 'fresh' forever, and the backend could never
    tell a first install from a re-push."""
    assert pi_mdm_setup.main() is True
    assert device.reports[0]["install_state"] == "fresh"
    assert pi_mdm_setup.main() is True
    assert device.reports[1]["install_state"] == "persisted"


def test_detect_install_state_is_device_scope(pi_mdm_setup, device):
    """One home already carrying the extension makes the DEVICE 'persisted'."""
    mod = pi_mdm_setup
    assert mod.detect_install_state(device.homes) == "fresh"
    _installed(device.homes[1][1]).parent.mkdir(parents=True)
    _installed(device.homes[1][1]).write_bytes(PAYLOAD)
    assert mod.detect_install_state(device.homes) == "persisted"
    # 'tampered' -- the backend's third value -- means "managed config present, hook script
    # gone". pi has no managed config to compare against, so it is never reportable here.
    assert mod.detect_install_state([]) == "fresh"
    assert mod.detect_install_state([("ghost", "relative/home")]) == "fresh"
    assert mod.detect_install_state(None) == "fresh"  # never raises, whatever it is handed


def test_the_report_carries_no_managed_flag(pi_mdm_setup, device):
    """`managed: True` is what gates tamper counting on the backend, and pi cannot be
    tamper-checked (no managed config), so claiming it would be a false signal."""
    assert pi_mdm_setup.main() is True
    assert "managed" not in device.reports[0]


def test_the_report_key_is_the_application_key_not_the_admin_token(pi_mdm_setup, device):
    """The report authenticates as the pi application, never as the org admin."""
    mod = pi_mdm_setup
    calls = []
    real = mod.notify_setup_complete
    monkeypatched = lambda api_key, *a, **k: calls.append(api_key) or real(api_key, *a, **k)
    with pytest.MonkeyPatch.context() as mp:
        mp.setattr(mod, "notify_setup_complete", monkeypatched)
        assert mod.main() is True
    assert calls == ["pi-app-key-1"]
    for url in device.urls:
        assert "ADMIN-TOKEN" not in url


# --- failure does not silence the report ---------------------------------------------------


def test_a_run_where_every_home_failed_still_reports(pi_mdm_setup, device, capsys):
    """A device that needs attention must not be the one the fleet view omits."""
    mod = pi_mdm_setup
    for _, home in device.homes:
        (home / ".pi").write_text("not a directory\n")  # mkdir -p cannot succeed under this
    assert mod.main() is False
    assert len(device.reports) == 1
    out = capsys.readouterr().out
    assert "failed" in out
    assert "reached no user" in out


def test_one_bad_home_still_covers_the_others_and_reports_once(pi_mdm_setup, device, capsys):
    mod = pi_mdm_setup
    (device.homes[0][1] / ".pi").write_text("not a directory\n")
    assert mod.main() is True
    assert len(device.reports) == 1
    assert not _installed(device.homes[0][1]).exists()
    assert _installed(device.homes[1][1]).read_bytes() == PAYLOAD
    out = capsys.readouterr().out
    assert "alice" in out and "bob" in out


def test_a_run_where_no_account_got_a_key_is_a_failure(pi_mdm_setup, device, monkeypatch,
                                                       capsys):
    """Installing the extension was the whole success condition, so a device where every rc
    write AND every config write failed still printed "Setup complete" and exited zero: an
    extension loaded in every home, resolving no key, enforcing nothing, and no failure for
    the MDM to remediate. The extension stays on disk -- removing it would be worse -- but
    the run is a failure."""
    mod = pi_mdm_setup
    monkeypatch.setattr(mod, "set_env_var_for_user", lambda *a, **k: (False, False))
    monkeypatch.setattr(mod, "write_unbound_config_for_user", lambda *a, **k: False)

    assert mod.main() is False
    out = capsys.readouterr().out
    assert "no account has a key" in out
    assert "Setup complete" not in out
    for _, home in device.homes:
        assert _installed(home).exists()
    assert len(device.reports) == 1, "a device that needs attention must still report"


@pytest.mark.parametrize("env_ok,config_ok", [(True, False), (False, True)])
def test_either_key_location_alone_is_coverage(pi_mdm_setup, device, monkeypatch,
                                               env_ok, config_ok):
    """One working key location is a working install: a symlinked config.json is refused by
    design, and an unwritable rc file is ordinary. Neither failure alone may fail the run."""
    mod = pi_mdm_setup
    monkeypatch.setattr(mod, "set_env_var_for_user", lambda *a, **k: (env_ok, env_ok))
    monkeypatch.setattr(mod, "write_unbound_config_for_user", lambda *a, **k: config_ok)

    assert mod.main() is True


def test_a_report_failure_does_not_change_the_exit_status(pi_mdm_setup, device, capsys):
    """The extension is installed and enforcing whether or not the backend heard about it;
    an MDM policy that went red on a telemetry hiccup would be re-run pointlessly."""
    device.report_result["returncode"] = 1
    assert pi_mdm_setup.main() is True
    assert len(device.reports) == 1
    assert "best-effort" in capsys.readouterr().out
    for _, home in device.homes:
        assert _installed(home).exists()


def test_a_raising_report_does_not_change_the_exit_status(pi_mdm_setup, device, monkeypatch,
                                                          capsys):
    """notify_setup_complete swallows internally, so this is belt-and-braces -- but the rule
    is absolute, and a raise escaping here would turn a green install into a red MDM policy."""
    monkeypatch.setattr(pi_mdm_setup, "notify_setup_complete",
                        lambda *a, **k: (_ for _ in ()).throw(OSError("network gone")))
    assert pi_mdm_setup.main() is True
    assert "best-effort" in capsys.readouterr().out
    for _, home in device.homes:
        assert _installed(home).exists()


def test_the_notify_body_is_by_presence(pi_mdm_setup, device):
    """The shared contract calls this directly with only (api_key, tool_type, backend_url)
    and asserts the body is exactly what it always was."""
    mod = pi_mdm_setup
    mod.notify_setup_complete("k", "claude-code", backend_url="https://b")
    body = device.reports[-1]
    assert body == {"tool_type": "claude-code"}


# --- MDM teardown --------------------------------------------------------------------------


def test_clear_removes_our_two_files_and_the_export_from_every_home(
        pi_mdm_setup, device, monkeypatch, capsys):
    mod = pi_mdm_setup
    assert mod.main() is True
    for _, home in device.homes:
        assert _installed(home).exists()
        assert (home / ".zprofile").read_text().count("UNBOUND_PI_API_KEY") == 1
        # A file we did not write, in the same directory, to prove the clear is surgical.
        (_installed(home).parent / "notes.md").write_text("alice's notes\n")

    monkeypatch.setattr(mod.sys, "argv", ["setup.py", "--clear"])
    device.reports.clear()
    before = len(device.urls)
    assert mod.clear_setup() is True

    for _, home in device.homes:
        extdir = _installed(home).parent
        assert not (extdir / "index.js").exists()
        assert not (extdir / "index.js.sha256").exists()
        assert extdir.is_dir(), "the directory itself was removed"
        assert (extdir / "notes.md").read_text() == "alice's notes\n"
        assert "UNBOUND_PI_API_KEY" not in (home / ".zprofile").read_text()
        assert "UNBOUND_PI_API_KEY" not in (home / ".bash_profile").read_text()

    assert device.reports == [], "the clear posted something"
    assert len(device.urls) == before, "the clear made a network call"
    assert "was NOT touched" in capsys.readouterr().out


def test_clear_never_opens_the_shared_config(pi_mdm_setup, device, monkeypatch):
    """~/.unbound/config.json's api_key is shared with five other tools, so removing it
    would log the user out of all of them. Asserted by byte-comparison, not by absence."""
    mod = pi_mdm_setup
    assert mod.main() is True
    snapshots = {}
    for _, home in device.homes:
        path = home / ".unbound" / "config.json"
        snapshots[path] = path.read_bytes()
    assert mod.clear_setup() is True
    for path, before in snapshots.items():
        assert path.read_bytes() == before


def test_clear_on_a_device_with_nothing_installed_is_a_no_op(pi_mdm_setup, device, capsys):
    mod = pi_mdm_setup
    assert mod.clear_setup() is True
    out = capsys.readouterr().out
    assert "not_found" in out
    for _, home in device.homes:
        assert not (home / ".pi").exists()
    assert device.reports == []


def test_clear_leaves_a_shadowed_file_and_a_disabled_one_alone(pi_mdm_setup, device):
    """--clear restores nothing: it never wrote the .ts, so it does not get to move it back,
    and it must not delete either the live file or the one we renamed."""
    mod = pi_mdm_setup
    _, home = device.homes[0]
    extdir = _installed(home).parent
    extdir.mkdir(parents=True)
    (extdir / "index.ts").write_text("// a fresh one, planted after the install\n")
    (extdir / "index.ts.unbound-disabled").write_text("// the one we moved aside\n")
    assert mod.clear_setup() is True
    assert (extdir / "index.ts").exists()
    assert (extdir / "index.ts.unbound-disabled").exists()


def test_clear_with_no_homes_is_not_a_failure(pi_mdm_setup, device, monkeypatch, capsys):
    mod = pi_mdm_setup
    monkeypatch.setattr(mod, "get_all_user_homes", lambda: [])
    assert mod.clear_setup() is True
    assert "No user home directories found" in capsys.readouterr().out


# --- the documented limitation -------------------------------------------------------------


def test_the_installer_header_states_the_bypass(pi_mdm_setup):
    """INST-03 asks for the limitation in writing. The installer's own header is where an
    operator reading the script will meet it."""
    src = open(pi_mdm_setup.__file__, encoding="utf-8").read()
    header = src.split('"""')[1]
    for needle in ("--no-extensions", "PI_CODING_AGENT_DIR", "noExtensions",
                   "coding-discovery-tool", "advisory"):
        assert needle in header, needle


def test_the_readme_states_the_limitation_and_the_runbook(pi_mdm_setup):
    from tests.conftest import REPO
    readme = (REPO / "pi" / "mdm" / "README.md").read_text(encoding="utf-8")
    for needle in ("--no-extensions", "PI_CODING_AGENT_DIR", "noExtensions",
                   "coding-discovery-tool", "sudo python3", "--clear",
                   "pi_mdm_api_key_sha256", "UNBOUND_PI_API_KEY", "mdm/onboard.py",
                   "/api/v1/setup/complete/", "install_mode"):
        assert needle in readme, needle
    assert len(readme.splitlines()) >= 25
