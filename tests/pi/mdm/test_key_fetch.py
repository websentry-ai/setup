"""The per-application key fetch: `app_type=pi`, and an admin token that stays off the argv.

The token this script is handed is an ADMIN key -- it can mint application keys for the
whole org -- and it runs on a multi-user host where every local user can read
/proc/<pid>/cmdline and `ps`. So the assertion that matters most in this file is the
negative one: no element of the argv handed to subprocess.run contains any substring of it.
"""

import json

import pytest


class FakeRun:
    """Just enough of subprocess.CompletedProcess for curl_with_auth's caller."""

    def __init__(self, stdout="", returncode=0):
        self.stdout = stdout
        self.stderr = ""
        self.returncode = returncode


@pytest.fixture
def curl(pi_mdm_setup, monkeypatch):
    """Capture every curl invocation, with the auth header file's contents resolved.

    The header file is deleted in curl_with_auth's finally, so it is read here -- inside the
    fake run -- which is also the only moment the real curl would see it.
    """
    mod = pi_mdm_setup

    class Calls(list):
        """A list of captured invocations, carrying the queue of canned responses."""
        responses = None

    calls = Calls()
    responses = []
    calls.responses = responses

    def fake_run(cmd, **kw):
        headers = []
        for i, arg in enumerate(cmd):
            if arg == "-H" and i + 1 < len(cmd) and str(cmd[i + 1]).startswith("@"):
                with open(str(cmd[i + 1])[1:], encoding="utf-8") as f:
                    headers = [l for l in f.read().splitlines() if l]
        calls.append({"argv": list(cmd), "headers": headers, "input": kw.get("input")})
        return responses.pop(0) if responses else FakeRun()

    monkeypatch.setattr(mod.subprocess, "run", fake_run)
    return calls


@pytest.fixture
def no_jitter(pi_mdm_setup, monkeypatch):
    """Record the jitter sleep instead of serving it; a real 0-30 s wait per test is absurd."""
    mod = pi_mdm_setup
    events = []
    monkeypatch.setattr(mod.random, "uniform", lambda a, b: events.append(("uniform", a, b)) or 0)
    monkeypatch.setattr(mod.time, "sleep", lambda s: events.append(("sleep", s)))
    return events


def _ok_body(key="pi-app-key-123"):
    return json.dumps({"api_key": key, "email": "pi@acme.test",
                       "first_name": "Pi", "last_name": "Application"}) + "\n200"


# --- the request ---------------------------------------------------------------------------


def test_the_request_carries_app_type_pi(pi_mdm_setup, curl, no_jitter):
    """A wrong or missing app_type mints a `default` application key, and the device then
    looks set up while never appearing as a pi application."""
    curl.responses.append(FakeRun(_ok_body()))
    got = pi_mdm_setup.fetch_api_key_from_mdm("https://backend.test", "Acme pi",
                                              "ADMIN-SECRET-TOKEN", "C02ABC123")
    assert got == "pi-app-key-123"
    url = [a for a in curl[0]["argv"] if str(a).startswith("https://")][0]
    assert "/api/v1/automations/mdm/get_application_api_key/?" in url
    assert "app_type=pi" in url
    assert url.endswith("app_type=pi") or "&app_type=pi" in url


def test_the_params_are_urlencoded(pi_mdm_setup, curl, no_jitter):
    """A serial number containing a space or an `&` would otherwise truncate the query or
    inject a parameter of the attacker's choosing."""
    curl.responses.append(FakeRun(_ok_body()))
    pi_mdm_setup.fetch_api_key_from_mdm("https://backend.test", "Acme & Co pi",
                                        "ADMIN-SECRET-TOKEN", "SER 1&app_type=augment_code")
    url = [a for a in curl[0]["argv"] if str(a).startswith("https://")][0]
    assert "SER+1%26app_type%3Daugment_code" in url or "SER%201%26app_type%3D" in url
    assert "Acme+%26+Co+pi" in url or "Acme%20%26%20Co%20pi" in url
    # Exactly one app_type, and it is ours: the injected one must be encoded, not honoured.
    assert url.count("app_type=") == 1


def test_the_admin_key_never_appears_in_the_argv(pi_mdm_setup, curl, no_jitter):
    """`ps` on a shared host is the leak this defends against. Asserted against every argv
    element, and the key is proven to still reach curl through the 0600 header file."""
    secret = "ADMIN-SECRET-TOKEN-abcdef0123456789"
    curl.responses.append(FakeRun(_ok_body()))
    pi_mdm_setup.fetch_api_key_from_mdm("https://backend.test", None, secret, "C02ABC123")
    for element in curl[0]["argv"]:
        assert secret not in str(element)
    assert curl[0]["headers"] == [f"Authorization: Bearer {secret}"]


def test_the_retry_flags_are_the_analogs(pi_mdm_setup, curl, no_jitter):
    """A fleet push happens while devices wake from sleep, so the retry budget is the point."""
    curl.responses.append(FakeRun(_ok_body()))
    pi_mdm_setup.fetch_api_key_from_mdm("https://backend.test", None, "k", "C02ABC123")
    argv = [str(a) for a in curl[0]["argv"]]
    for flag in ("-fsSL", "--max-time", "--retry", "--retry-max-time", "--retry-connrefused"):
        assert flag in argv, flag
    assert argv[argv.index("--retry") + 1] == "7"
    assert argv[argv.index("--retry-max-time") + 1] == "180"


def test_the_jitter_sleep_happens_before_the_request(pi_mdm_setup, curl, no_jitter):
    """Without it a thousand devices retry in lockstep and turn a blip into an outage. The
    call is asserted, not the duration -- a test that actually slept would be the bug."""
    curl.responses.append(FakeRun(_ok_body()))
    pi_mdm_setup.fetch_api_key_from_mdm("https://backend.test", None, "k", "C02ABC123")
    assert no_jitter[0] == ("uniform", 0, pi_mdm_setup.MDM_RETRY_JITTER_SECONDS)
    assert no_jitter[1][0] == "sleep"
    assert len(curl) == 1  # and the sleep was recorded before the single request


# --- every failure is None, never a partial install ---------------------------------------


@pytest.mark.parametrize("stdout,why", [
    ("", "an empty response"),
    ("just one line", "no http status line"),
    ('{"api_key": "k"}\n401', "a 401"),
    ('{"api_key": "k"}\n500', "a 500"),
    ("not json at all\n200", "a non-JSON body"),
    ('["a", "list"]\n200', "a body that is not an object"),
    ('{"email": "a@b.c"}\n200', "a body with no api_key"),
    ('{"api_key": ""}\n200', "an empty api_key"),
])
def test_every_bad_response_yields_none(pi_mdm_setup, curl, no_jitter, stdout, why):
    curl.responses.append(FakeRun(stdout))
    assert pi_mdm_setup.fetch_api_key_from_mdm(
        "https://backend.test", None, "k", "C02ABC123") is None, why


def test_a_timeout_yields_none(pi_mdm_setup, monkeypatch, no_jitter):
    mod = pi_mdm_setup

    def boom(*a, **k):
        raise mod.subprocess.TimeoutExpired(cmd="curl", timeout=300)

    monkeypatch.setattr(mod.subprocess, "run", boom)
    assert mod.fetch_api_key_from_mdm("https://backend.test", None, "k", "C02") is None


def test_an_unwritable_header_file_yields_none(pi_mdm_setup, monkeypatch, no_jitter):
    """curl_with_auth returns None rather than falling back to an argv header -- degrading
    to the leaky path on a filesystem hiccup would defeat the whole point of it."""
    mod = pi_mdm_setup
    monkeypatch.setattr(mod, "curl_with_auth", lambda *a, **k: None)
    assert mod.fetch_api_key_from_mdm("https://backend.test", None, "k", "C02") is None


# --- a keyless device run is a refusal, not a silent inert install -------------------------


def test_a_failed_key_fetch_stops_the_device_run_before_any_home_is_touched(
        pi_mdm_setup, monkeypatch, tmp_path, capsys):
    """An extension with no key is inert but LOOKS installed, which is worse than nothing:
    the console would show the device covered while no policy is ever evaluated."""
    mod = pi_mdm_setup
    home = tmp_path / "Users" / "alice"
    home.mkdir(parents=True)
    monkeypatch.setattr(mod.platform, "system", lambda: "Darwin")
    monkeypatch.setattr(mod.os, "geteuid", lambda: 0)
    monkeypatch.setattr(mod, "get_device_identifier", lambda: "C02ABC123")
    monkeypatch.setattr(mod, "get_all_user_homes", lambda: [("alice", home)])
    monkeypatch.setattr(mod, "fetch_api_key_from_mdm", lambda *a, **k: None)
    monkeypatch.setattr(mod, "fetch_artifact",
                        lambda: pytest.fail("downloaded the artifact with no key in hand"))
    monkeypatch.setattr(mod, "install_for_user",
                        lambda *a, **k: pytest.fail("installed with no key"))
    monkeypatch.setattr(mod.sys, "argv", ["setup.py", "--api-key", "ADMIN"])

    assert mod.main() is False
    assert not (home / ".pi").exists()
    assert "keyless" in capsys.readouterr().out


def test_the_backend_url_is_normalized_before_the_request(pi_mdm_setup, curl, no_jitter):
    """A bare host from an MDM variable is common; a trailing slash would double up."""
    mod = pi_mdm_setup
    assert mod.parse_args(["setup.py", "--backend-url", "backend.acme.test/"])["backend_url"] \
        == "https://backend.acme.test"
    curl.responses.append(FakeRun(_ok_body()))
    mod.fetch_api_key_from_mdm("https://backend.test/", None, "k", "C02")
    url = [a for a in curl[0]["argv"] if str(a).startswith("https://")][0]
    assert url.startswith("https://backend.test/api/v1/")
