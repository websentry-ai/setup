"""The per-device application key: fetched once with app_type=opencode, exported as
UNBOUND_OPENCODE_API_KEY (safe-value gated, owner-only rc), and placed in config.json only
when absent or provably ours (opencode_mdm_api_key_sha256)."""

import hashlib
import json
import stat
import urllib.parse

import pytest


class FakeRun:
    def __init__(self, stdout="", returncode=0):
        self.stdout = stdout
        self.stderr = ""
        self.returncode = returncode


def _ok_body(key="oc-app-key-123"):
    return json.dumps({"api_key": key, "email": "oc@acme.test",
                       "first_name": "Open", "last_name": "Code"}) + "\n200"


@pytest.fixture
def curl(oc_mdm_setup, monkeypatch):
    class Calls(list):
        responses = None

    calls = Calls()
    responses = []

    def fake_run(cmd, **kw):
        headers = []
        for i, arg in enumerate(cmd):
            if arg == "-H" and i + 1 < len(cmd) and str(cmd[i + 1]).startswith("@"):
                with open(str(cmd[i + 1])[1:], encoding="utf-8") as f:
                    headers = [ln for ln in f.read().splitlines() if ln]
        calls.append({"argv": [str(a) for a in cmd], "headers": headers})
        return responses.pop(0) if responses else FakeRun()

    monkeypatch.setattr(oc_mdm_setup.subprocess, "run", fake_run)
    monkeypatch.setattr(oc_mdm_setup.random, "uniform", lambda a, b: 0)
    monkeypatch.setattr(oc_mdm_setup.time, "sleep", lambda s: None)
    calls.responses = responses
    return calls


def _query(call):
    url = next(a for a in call["argv"] if a.startswith("http"))
    return url, dict(urllib.parse.parse_qsl(urllib.parse.urlparse(url).query))


class TestFetch:
    def test_the_request_carries_app_type_opencode_and_the_serial(self, oc_mdm_setup, curl):
        curl.responses.append(FakeRun(_ok_body()))
        key = oc_mdm_setup.fetch_api_key_from_mdm("https://backend.test", None, "ADMIN", "C02 X&Y")
        assert key == "oc-app-key-123"
        url, q = _query(curl[0])
        assert "/api/v1/automations/mdm/get_application_api_key/" in url
        assert q == {"serial_number": "C02 X&Y", "app_type": "opencode"}

    def test_app_name_is_passed_when_given(self, oc_mdm_setup, curl):
        curl.responses.append(FakeRun(_ok_body()))
        oc_mdm_setup.fetch_api_key_from_mdm("https://backend.test", "acme", "ADMIN", "S")
        assert _query(curl[0])[1]["app_name"] == "acme"

    def test_the_admin_key_is_never_on_argv(self, oc_mdm_setup, curl):
        curl.responses.append(FakeRun(_ok_body()))
        oc_mdm_setup.fetch_api_key_from_mdm("https://backend.test", None, "ADMIN-SECRET", "S")
        assert all("ADMIN-SECRET" not in a for a in curl[0]["argv"])
        assert curl[0]["headers"] == ["Authorization: Bearer ADMIN-SECRET"]

    @pytest.mark.parametrize("stdout", ["", "nope\n500", "not json\n200", "[]\n200",
                                        json.dumps({"email": "x"}) + "\n200"])
    def test_every_bad_response_is_none(self, oc_mdm_setup, curl, stdout):
        curl.responses.append(FakeRun(stdout))
        assert oc_mdm_setup.fetch_api_key_from_mdm("https://b", None, "A", "S") is None


@pytest.fixture
def unix(oc_mdm_setup, monkeypatch):
    monkeypatch.setattr(oc_mdm_setup.platform, "system", lambda: "Darwin")
    return oc_mdm_setup


@pytest.fixture
def home(fake_homes):
    return fake_homes[0]


class TestRcExport:
    def test_the_export_lands_quoted_in_both_rc_files(self, unix, passthrough, home):
        user, h = home
        ok, changed = unix.set_env_var_for_user(user, h, unix.ENV_API_KEY, "oc-key_1.2:3")
        assert ok and changed
        for rc in (h / ".zprofile", h / ".bash_profile"):
            assert 'export UNBOUND_OPENCODE_API_KEY="oc-key_1.2:3"\n' in rc.read_text()

    @pytest.mark.parametrize("bad", ['k"; rm -rf ~; "', "k$(id)", "k`id`", "k\nx", "", "k k"])
    def test_an_unsafe_value_is_refused_before_any_file_is_touched(self, unix, passthrough, home, bad):
        user, h = home
        assert unix.set_env_var_for_user(user, h, unix.ENV_API_KEY, bad) == (False, False)
        assert not (h / ".zprofile").exists() and not (h / ".bash_profile").exists()
        assert passthrough == []

    def test_the_rc_file_loses_group_and_other_bits(self, unix, passthrough, home):
        user, h = home
        rc = h / ".zprofile"
        rc.write_text("export EDITOR=vim\n")
        rc.chmod(0o644)
        unix.set_env_var_for_user(user, h, unix.ENV_API_KEY, "k1")
        assert stat.S_IMODE(rc.stat().st_mode) & 0o077 == 0
        assert rc.read_text().startswith("export EDITOR=vim\n")

    def test_a_rotation_replaces_the_line(self, unix, passthrough, home):
        user, h = home
        unix.set_env_var_for_user(user, h, unix.ENV_API_KEY, "k1")
        unix.set_env_var_for_user(user, h, unix.ENV_API_KEY, "k2")
        text = (h / ".zprofile").read_text()
        assert text.count("UNBOUND_OPENCODE_API_KEY") == 1 and '"k2"' in text

    def test_the_export_runs_with_privileges_dropped(self, unix, monkeypatch, home):
        seen = []
        monkeypatch.setattr(unix, "_run_as_user", lambda u, fn, *a, **k: seen.append(u) or [True, True])
        user, h = home
        unix.set_env_var_for_user(user, h, unix.ENV_API_KEY, "k1")
        assert seen == [user]


class TestConfigJson:
    def _cfg(self, h):
        return h / ".unbound" / "config.json"

    def test_an_absent_key_is_written_with_provenance(self, unix, passthrough, home):
        user, h = home
        assert unix.write_unbound_config_for_user(user, h, "k1", urls={"base_url": "https://b"})
        cfg = json.loads(self._cfg(h).read_text())
        assert cfg["api_key"] == "k1" and cfg["base_url"] == "https://b"
        assert cfg["opencode_mdm_api_key_sha256"] == hashlib.sha256(b"k1").hexdigest()
        assert stat.S_IMODE(self._cfg(h).stat().st_mode) == 0o600

    def test_a_key_we_wrote_is_rotated(self, unix, passthrough, home):
        user, h = home
        unix.write_unbound_config_for_user(user, h, "k1")
        unix.write_unbound_config_for_user(user, h, "k2")
        assert json.loads(self._cfg(h).read_text())["api_key"] == "k2"

    def test_a_users_own_key_without_provenance_is_left_alone(self, unix, passthrough, home):
        user, h = home
        self._cfg(h).parent.mkdir(parents=True)
        self._cfg(h).write_text(json.dumps({"api_key": "users-own", "email": "a@b.c"}))
        unix.write_unbound_config_for_user(user, h, "k2", urls={"base_url": "https://b"})
        cfg = json.loads(self._cfg(h).read_text())
        assert cfg["api_key"] == "users-own" and cfg["email"] == "a@b.c"
        assert "opencode_mdm_api_key_sha256" not in cfg

    def test_pi_provenance_does_not_make_the_key_ours(self, unix, passthrough, home):
        """A key pi's MDM wrote is pi's to rotate, not ours."""
        user, h = home
        self._cfg(h).parent.mkdir(parents=True)
        self._cfg(h).write_text(json.dumps({
            "api_key": "pi-key", "pi_mdm_api_key_sha256": hashlib.sha256(b"pi-key").hexdigest()}))
        unix.write_unbound_config_for_user(user, h, "oc-key")
        assert json.loads(self._cfg(h).read_text())["api_key"] == "pi-key"
