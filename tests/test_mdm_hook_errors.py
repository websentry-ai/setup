"""WEB-6392: the python MDM scripts (Linux and Windows) forward each tool's stuck hook errors, as the binary does.

A hook reports an error at most once a minute and never retries, so the rest wait in its error.log. Each
script's real main() runs over a sandbox home (the Run harness of test_mdm_setup_status) and sends to a real
HTTP server on 127.0.0.1, so the curl requests are the ones a device sends. Every script carries the same
forwarding code, kept equal by the parity tests at the end, so most behaviour is pinned through one tool."""

import inspect
import json
import os
import re
import stat
import sys
import threading
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from tests.conftest import REPO, load_module
from tests.test_mdm_setup_status import MODULES, Run

ERROR_LOGS = {"claude-code": ".claude/hooks/error.log", "cursor": ".cursor/hooks/error.log",
              "codex": ".codex/hooks/error.log", "copilot": ".copilot/hooks/error.log",
              "augment": ".augment/hooks/error.log"}
HOOK_SOURCES = {"claude-code": "claude-code", "cursor": "cursor", "codex": "codex", "copilot": "copilot",
                "augment": "augment_code"}
STATE = ".error_log_forwarded"
OK = {"status": "ok", "success": True, "accepted": 1}
REFUSED = {"success": False, "reason": "invalid_key"}
DEAD_GATEWAY = "http://127.0.0.1:9"


class _Recorder(BaseHTTPRequestHandler):
    def do_POST(self):
        raw = self.rfile.read(int(self.headers.get("Content-Length") or 0))
        try:
            body = json.loads(raw.decode("utf-8"))
        except ValueError:
            body = raw
        request = {"path": self.path, "headers": dict(self.headers), "body": body}
        self.server.requests.append(request)
        status, answer = self.server.answer(request)
        data = json.dumps(answer).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def log_message(self, *args):
        pass


@pytest.fixture
def gateway():
    server = ThreadingHTTPServer(("127.0.0.1", 0), _Recorder)
    server.requests = []
    server.answer = lambda request: (200, OK)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    server.url = "http://127.0.0.1:%d" % server.server_address[1]
    yield server
    server.shutdown()
    server.server_close()


def _like_the_real_run_as_user(username, fn, *args, _timeout=None, **kwargs):
    """The real one answers None when fn raises in the user's child."""
    try:
        return fn(*args, **kwargs)
    except Exception:
        return None


@pytest.fixture
def setup(tmp_path, monkeypatch, gateway):
    """One tool's main() over a sandbox home, pointed at the local gateway."""
    def make(tool):
        r = Run(tool, tmp_path, monkeypatch)
        monkeypatch.setattr(r.m, "_run_as_user", _like_the_real_run_as_user)
        point(r, gateway.url)
        return r
    return make


def point(r, gateway_url):
    r.mp.setattr(sys, "argv", ["setup.py", "--api-key", "admin-key", "--gateway-url", gateway_url])


REAL_CURSOR_CLEANUP = load_module(MODULES["cursor"]).remove_user_level_hooks
REAL_RUN_AS_USER = {tool: load_module(path)._run_as_user for tool, path in MODULES.items()}


def real_cursor_cleanup(r):
    """The harness stubs it; these tests need the rmtree of ~/.cursor/hooks it does."""
    r.mp.setattr(r.m, "remove_user_level_hooks", REAL_CURSOR_CLEANUP)


def _log(home, tool, lines, key="per-device-key"):
    """An error.log for the tool, and (unless key is None) the key a previous run left in the home's config."""
    path = home / ERROR_LOGS[tool]
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("".join(line + "\n" for line in lines))
    config = home / ".unbound" / "config.json"
    if key is not None and not config.exists():
        config.parent.mkdir(parents=True, exist_ok=True)
        config.write_text(json.dumps({"api_key": key, "device_token": key}))
    return path


# Entries are stamped an hour before the test run, so the seven-day limit never ages them out.
BASE = datetime.now(timezone.utc).replace(microsecond=123) - timedelta(hours=1)


def _utc(n, days_ago=0):
    return (BASE + timedelta(seconds=n) - timedelta(days=days_ago)).isoformat().replace("+00:00", "Z")


def _pacific(n, days_ago=0):
    """How Cursor's and Copilot's hooks stamp: local time with its offset."""
    return (BASE + timedelta(seconds=n) - timedelta(days=days_ago)).astimezone(timezone(timedelta(hours=-8))).isoformat()


def _forwarded(gateway):
    return [r for r in gateway.requests if r["path"] == "/v1/hooks/errors"]


def _messages(gateway):
    return [e["message"] for r in _forwarded(gateway) for e in r["body"]["errors"]]


def _other_home(r, name="bob"):
    other = r.home.parent / name
    other.mkdir()
    r.stub("get_all_user_homes", [("alice", r.home), (name, other)])
    return other


# --- Each script forwards its own tool's log -------------------------------------

@pytest.mark.parametrize("tool", sorted(MODULES))
def test_each_script_sends_only_its_own_tools_errors_newer_than_the_last_sent(setup, gateway, tool):
    r = setup(tool)
    for other in MODULES:
        _log(r.home, other, [f"{_utc(n)}: {other} e{n}" for n in range(3)])
    log = r.home / ERROR_LOGS[tool]
    log.with_name(STATE).write_text(_utc(0))
    assert r() is True
    [request] = _forwarded(gateway)
    # The key the home's hooks report with, not the one this run fetched.
    assert request["headers"]["Authorization"] == "Bearer per-device-key"
    body = request["body"]
    assert (body["hook_source"], body["hook_sha"]) == (HOOK_SOURCES[tool], "h" * 12)
    assert [(e["timestamp"], e["message"], e["category"]) for e in body["errors"]] == [
        (_utc(1), f"{tool} e1", "forwarded_error_log"), (_utc(2), f"{tool} e2", "forwarded_error_log")]
    assert log.with_name(STATE).read_text() == f"{_utc(2)} 1"


@pytest.mark.parametrize("tool", sorted(MODULES))
def test_an_unreachable_gateway_changes_nothing_about_the_run_and_the_next_run_sends_it_all(setup, gateway, tool):
    r = setup(tool)
    log = _log(r.home, tool, [f"{_utc(n)}: e{n}" for n in range(3)])
    point(r, DEAD_GATEWAY)
    assert r() is True
    assert r.report["status"] == "configured"
    assert not log.with_name(STATE).exists()
    point(r, gateway.url)
    assert r() is True
    assert _messages(gateway) == ["e0", "e1", "e2"]


@pytest.mark.parametrize("tool", sorted(MODULES))
def test_forwarding_that_fails_never_changes_the_exit_code(setup, gateway, monkeypatch, tool):
    r = setup(tool)
    _log(r.home, tool, [f"{_utc(0)}: e0"])

    def broken(*a, **k):
        raise RuntimeError("forwarding broke")

    monkeypatch.setattr(r.m, "_forward_home_errors", broken)
    assert r() is True
    assert r.report["status"] == "configured"


def test_errors_go_out_before_this_runs_key_is_fetched(setup, gateway):
    """Forwarding needs only the key the home already has, so a failed fetch doesn't hold it back."""
    r = setup("claude-code")
    r.stub("fetch_api_key_from_mdm", None)
    _log(r.home, "claude-code", [f"{_utc(0)}: e0"])
    assert r() is False
    assert _messages(gateway) == ["e0"]


# --- Batches, caps and the saved place --------------------------------------------

def test_errors_go_ten_to_a_request_and_none_is_sent_twice(setup, gateway):
    r = setup("claude-code")
    log = _log(r.home, "claude-code", [f"{_utc(n)}: e{n}" for n in range(25)])
    r()
    assert [len(req["body"]["errors"]) for req in _forwarded(gateway)] == [10, 10, 5]
    assert _messages(gateway) == [f"e{n}" for n in range(25)]
    assert log.with_name(STATE).read_text() == f"{_utc(24)} 1"
    gateway.requests.clear()
    r()
    assert _forwarded(gateway) == []


def test_a_flooded_log_sends_only_its_25_newest_and_nothing_older_than_a_week(setup, gateway):
    r = setup("claude-code")
    old = [f"{_utc(n, days_ago=8)}: old{n}" for n in range(2)]
    _log(r.home, "claude-code", old + [f"{_utc(n)}: e{n}" for n in range(30)])
    r()
    assert _messages(gateway) == [f"e{n}" for n in range(5, 30)]
    assert len(_forwarded(gateway)) == 3


def test_entries_older_than_seven_days_are_never_sent_even_after_an_older_place(setup, gateway):
    r = setup("claude-code")
    log = _log(r.home, "claude-code", [f"{_utc(0, days_ago=8)}: stale", f"{_utc(1)}: fresh"])
    log.with_name(STATE).write_text(_utc(0, days_ago=9))
    r()
    assert _messages(gateway) == ["fresh"]


def test_a_gateway_that_fails_stops_forwarding_for_the_run(setup, gateway):
    r = setup("claude-code")
    other = _other_home(r)
    _log(r.home, "claude-code", [f"{_utc(0)}: alice e0"])
    _log(other, "claude-code", [f"{_utc(1)}: bob e1"])
    gateway.answer = lambda request: (503, {})
    assert r() is True
    assert len(_forwarded(gateway)) == 1  # one short failure, not one per home
    assert not (r.home / ".claude/hooks" / STATE).exists() and not (other / ".claude/hooks" / STATE).exists()


def test_a_refused_key_skips_only_that_home(setup, gateway):
    r = setup("codex")
    other = _other_home(r)
    _log(r.home, "codex", [f"{_utc(0)}: alice's codex broke"], key="revoked-key")
    _log(other, "codex", [f"{_utc(1)}: bob's codex broke"], key="bob-key")
    gateway.answer = lambda request: (200, REFUSED) if request["headers"].get(
        "Authorization") == "Bearer revoked-key" else (200, OK)
    assert r() is True
    assert _messages(gateway) == ["alice's codex broke", "bob's codex broke"]
    assert (other / ".codex/hooks" / STATE).exists()
    assert not (r.home / ".codex/hooks" / STATE).exists()  # refused: retried next run


def test_a_4xx_is_a_refusal_and_saves_nothing(setup, gateway):
    r = setup("claude-code")
    log = _log(r.home, "claude-code", [f"{_utc(0)}: e0"])
    gateway.answer = lambda request: (401, {"error": "unauthorized"})
    assert r() is True
    assert len(_forwarded(gateway)) == 1
    assert not log.with_name(STATE).exists()


def test_an_entry_sharing_the_last_sent_timestamp_is_still_sent(setup, gateway):
    r = setup("claude-code")
    same = _utc(9)
    _log(r.home, "claude-code", [f"{_utc(n)}: e{n}" for n in range(9)] + [f"{same}: e9", f"{same}: e10"])
    # The batch boundary (ten a request) falls between e9 and e10; the second request fails.
    gateway.answer = lambda request: (503, {}) if len(_forwarded(gateway)) == 2 else (200, OK)
    r()
    assert _messages(gateway) == [f"e{n}" for n in range(11)]  # e10 was tried, not taken
    gateway.requests.clear()
    gateway.answer = lambda request: (200, OK)
    r()
    assert _messages(gateway) == ["e10"]
    gateway.requests.clear()
    r()
    assert _messages(gateway) == []


def test_a_log_whose_place_cannot_be_saved_is_not_forwarded_run_after_run(setup, gateway):
    r = setup("claude-code")
    other = _other_home(r)
    log = _log(r.home, "claude-code", [f"{_utc(n)}: e{n}" for n in range(3)])
    _log(other, "claude-code", [f"{_utc(5)}: bob's error"])
    log.parent.chmod(0o555)  # the user can't write .error_log_forwarded beside it
    try:
        r()
        r()
    finally:
        log.parent.chmod(0o755)
    assert _messages(gateway) == ["bob's error"]  # once: bob's place was saved
    assert not log.with_name(STATE).exists()


def test_a_save_that_fails_after_a_send_stops_that_home(setup, gateway, monkeypatch):
    r = setup("claude-code")
    _log(r.home, "claude-code", [f"{_utc(n)}: e{n}" for n in range(15)])
    # What the real privilege drop hands back when the write inside it fails.
    monkeypatch.setattr(r.m, "_save_forwarded", lambda log, state: None)
    r()
    # The first ten went out; with their place unsaved the rest wait rather than pile up repeats.
    assert [len(req["body"]["errors"]) for req in _forwarded(gateway)] == [10]


def test_a_home_with_no_key_yet_forwards_nothing(setup, gateway):
    r = setup("claude-code")
    other = _other_home(r)
    _log(r.home, "claude-code", [f"{_utc(0)}: e0"], key=None)
    _log(other, "claude-code", [f"{_utc(1)}: bob's error"])
    r()
    assert _messages(gateway) == ["bob's error"]


def test_errors_go_out_with_the_key_the_hooks_read_first(setup, gateway):
    """The hooks read cfg.get('api_key') or cfg.get('device_token')."""
    r = setup("copilot")
    (r.home / ".unbound").mkdir()
    (r.home / ".unbound" / "config.json").write_text(json.dumps({"device_token": "token-key-2", "api_key": "api-key-1"}))
    _log(r.home, "copilot", [f"{_pacific(0)}: request with api-key-1 failed"], key=None)
    r()
    [request] = _forwarded(gateway)
    assert request["headers"]["Authorization"] == "Bearer api-key-1"
    assert _messages(gateway) == ["request with [REDACTED] failed"]


# --- What reaches the gateway ----------------------------------------------------

def test_lines_before_the_first_entry_are_skipped_and_later_ones_continue_it(setup, gateway):
    r = setup("claude-code")
    _log(r.home, "claude-code", ["not an entry", f"{_utc(5)}: real one", "  continued text"])
    r()
    assert _messages(gateway) == ["real one\n  continued text"]


def test_a_multi_line_entry_goes_up_whole_cut_and_redacted(setup, gateway):
    r = setup("claude-code")
    vendor_key = "sk-" + "live-" + "1" * 12  # built at runtime so secret scanners skip this fixture
    _log(r.home, "claude-code", [
        f"{_utc(0)}: Traceback (most recent call last):",
        '  File "unbound.py", line 9, in post',
        f"    Authorization: Bearer {vendor_key}",
        "ValueError: boom " + "x" * 3000,
        f"{_utc(1)}: next entry",
        f"{_utc(2)}: " + "y" * 5000,
    ])
    r()
    first, second, third = _messages(gateway)
    assert first.startswith('Traceback (most recent call last):\n  File "unbound.py", line 9, in post\n')
    assert "Bearer [REDACTED]" in first and vendor_key not in first
    assert len(first) <= 2000
    assert (second, third) == ("next entry", "y" * 2000)


def test_the_homes_keys_and_common_credential_shapes_are_redacted(setup, gateway):
    r = setup("augment")
    vendor_key = "sk-" + "fake-" + "0" * 16  # built at runtime so secret scanners skip this fixture
    (r.home / ".unbound").mkdir()
    (r.home / ".unbound" / "config.json").write_text(json.dumps({"device_token": "token-key-2", "api_key": "api-key-1"}))
    _log(r.home, "augment", [
        f"{_utc(0)}: old token token-key-2 was refused for api-key-1",
        f"{_utc(1)}: header X-API-KEY: hdr-secret-9 and ANTHROPIC_API_KEY=env-secret-8 set",
        f"{_utc(2)}: vendor key {vendor_key} leaked",
        f"{_utc(3)}: GET https://api.example.com/v1?key=url-secret-7&page=2 failed",
        f'{_utc(4)}: config {{"password": "pw-secret-6", "token":"tok-secret-5"}}',
        f"{_utc(5)}: retry said bearer tok_lower and gave up"], key=None)
    r()
    body = json.dumps(_forwarded(gateway)[0]["body"])
    for secret in ("token-key-2", "api-key-1", "hdr-secret-9", "env-secret-8", vendor_key,
                   "url-secret-7", "pw-secret-6", "tok-secret-5", "tok_lower"):
        assert secret not in body, secret
    messages = _messages(gateway)
    assert messages[3] == "GET https://api.example.com/v1?key=[REDACTED]&page=2 failed"
    assert messages[5] == "retry said Bearer [REDACTED] and gave up"


def test_an_oversized_log_is_read_from_its_end(setup, gateway):
    r = setup("claude-code")
    old = [f"{_utc(0, days_ago=9)}: ancient {'x' * 200}"] * 25000  # over 5 MiB, all past the 7-day limit
    log = _log(r.home, "claude-code", old + [f"{_utc(0)}: broke", f"{_utc(1)}: broke again"])
    assert log.stat().st_size > r.m._USER_FILE_MAX_BYTES
    r()
    assert _messages(gateway) == ["broke", "broke again"]


def test_no_key_reaches_a_curl_command_line(setup, gateway, monkeypatch):
    """Any local user can read a process's argv with ps; the headers go in a 0600 file instead."""
    r = setup("claude-code")
    real_run, argvs, modes = r.m.subprocess.run, [], []

    def recording_run(cmd, *a, **k):
        if cmd and cmd[0] == "curl":
            argvs.append(list(cmd))
            for arg in cmd:
                if arg.startswith("@") and os.path.exists(arg[1:]):
                    modes.append(stat.S_IMODE(os.stat(arg[1:]).st_mode))
        return real_run(cmd, *a, **k)

    monkeypatch.setattr(r.m.subprocess, "run", recording_run)
    _log(r.home, "claude-code", [f"{_utc(0)}: e0"])
    assert r() is True
    assert argvs, "the run made no curl calls"
    assert not [a for argv in argvs for a in argv if "per-device-key" in a]
    assert modes and set(modes) == {0o600}
    assert _forwarded(gateway)[0]["headers"]["Authorization"] == "Bearer per-device-key"


# --- Setup runs as root over paths the user controls ------------------------------

def test_an_error_log_that_is_a_link_is_never_read_through(setup, gateway, tmp_path):
    r = setup("claude-code")
    other = _other_home(r)
    # alice points her log at a file she must not be able to make setup read and send.
    secret = tmp_path / "root-only.txt"
    secret.write_text(f"{_utc(0)}: root secret\n")
    log = r.home / ERROR_LOGS["claude-code"]
    _log(r.home, "codex", [])  # alice's key
    log.parent.mkdir(parents=True)
    log.symlink_to(secret)
    _log(other, "claude-code", [f"{_utc(1)}: bob's error"])
    r()
    assert _messages(gateway) == ["bob's error"]
    assert not log.with_name(STATE).exists()


def test_a_state_file_that_is_a_link_is_replaced_not_followed(setup, gateway, tmp_path):
    r = setup("claude-code")
    log = _log(r.home, "claude-code", [f"{_utc(0)}: e0", f"{_utc(1)}: e1"])
    # Read through, the link's target would say everything was already sent; written through, it gets overwritten.
    victim = tmp_path / "victim.txt"
    victim.write_text(_utc(100))
    log.with_name(STATE).symlink_to(victim)
    r()
    assert _messages(gateway) == ["e0", "e1"]
    assert victim.read_text() == _utc(100)
    state = log.with_name(STATE)
    assert not state.is_symlink() and state.read_text() == f"{_utc(1)} 1"


def test_a_config_that_is_a_link_gives_no_key(setup, gateway, tmp_path):
    r = setup("claude-code")
    elsewhere = tmp_path / "someone-elses-config.json"
    elsewhere.write_text(json.dumps({"api_key": "not-this-homes-key"}))
    (r.home / ".unbound").mkdir()
    (r.home / ".unbound" / "config.json").symlink_to(elsewhere)
    _log(r.home, "claude-code", [f"{_utc(0)}: e0"], key=None)
    other = _other_home(r)
    _log(other, "claude-code", [f"{_utc(1)}: bob's error"])
    r()
    assert _messages(gateway) == ["bob's error"]
    assert [req["headers"]["Authorization"] for req in _forwarded(gateway)] == ["Bearer per-device-key"]


# --- Cursor: its cleanup removes ~/.cursor/hooks, error.log and all ----------------

def test_cursor_errors_go_out_before_its_cleanup_removes_their_log(setup, gateway):
    r = setup("cursor")
    real_cursor_cleanup(r)
    _log(r.home, "cursor", [f"{_pacific(0)}: cursor broke", f"{_pacific(1)}: cursor broke again"])
    assert r() is True
    assert not (r.home / ".cursor/hooks").exists()  # the cleanup did run
    assert _messages(gateway) == ["cursor broke", "cursor broke again"]
    # Gone with its log, so nothing can be sent twice.
    gateway.requests.clear()
    r()
    assert _forwarded(gateway) == []


def test_cursor_errors_the_gateway_did_not_take_survive_its_cleanup_for_the_next_run(setup, gateway):
    r = setup("cursor")
    real_cursor_cleanup(r)
    log = _log(r.home, "cursor", [f"{_pacific(0)}: cursor broke", f"{_pacific(1)}: cursor broke again"])
    (log.parent / "unbound.py").write_text("# python-era hook")
    gateway.answer = lambda request: (503, {})
    assert r() is True
    assert log.exists()
    assert not (log.parent / "unbound.py").exists()  # the rest of the cleanup still ran
    assert [p.name for p in (r.home / ".cursor").iterdir()] == ["hooks"]  # nothing left set aside
    gateway.answer = lambda request: (200, OK)
    gateway.requests.clear()
    r()
    assert _messages(gateway) == ["cursor broke", "cursor broke again"]


def test_cursor_errors_set_aside_survive_a_new_log_a_hook_writes_during_its_cleanup(setup, gateway):
    """Cursor can run a hook while setup runs: its new error.log and the set-aside one are both kept."""
    r = setup("cursor")
    _log(r.home, "cursor", [f"{_pacific(0)}: cursor broke", f"{_pacific(1)}: cursor broke again"])

    def cleanup_then_a_hook_writes(username, home_dir):
        REAL_CURSOR_CLEANUP(username, home_dir)
        log = home_dir / ERROR_LOGS["cursor"]
        log.parent.mkdir(parents=True, exist_ok=True)
        log.write_text(f"{_pacific(2)}: cursor broke during setup\n")

    r.mp.setattr(r.m, "remove_user_level_hooks", cleanup_then_a_hook_writes)
    gateway.answer = lambda request: (503, {})
    assert r() is True
    real_cursor_cleanup(r)
    gateway.answer = lambda request: (200, OK)
    gateway.requests.clear()
    r()
    assert _messages(gateway) == ["cursor broke", "cursor broke again", "cursor broke during setup"]


@pytest.mark.parametrize("moved", ["nothing", "only its place"])
def test_a_cursor_log_that_cannot_be_set_aside_is_kept_by_its_cleanup(setup, gateway, moved):
    """The user may not be able to write ~/.cursor, so the move aside fails, for the log or for the log
    alone; the cleanup, which removes ~/.cursor/hooks as root, then keeps that log and removes the rest."""
    r = setup("cursor")
    real_cursor_cleanup(r)
    log = _log(r.home, "cursor", [f"{_pacific(0)}: cursor broke"])
    (log.parent / "unbound.py").write_text("# python-era hook")
    (log.parent / STATE).write_text("2000-01-01T00:00:00 1")

    def set_aside(log):
        if moved == "nothing":
            return []
        os.rename(log.with_name(STATE), r.m._set_aside_name(log.with_name(STATE)))
        return [STATE]

    r.mp.setattr(r.m, "_set_aside_unsent_log", set_aside)
    gateway.answer = lambda request: (503, {})
    assert r() is True
    assert "error.log" in [p.name for p in log.parent.iterdir()]
    assert not (log.parent / "unbound.py").exists()
    assert r.m.KEEP_UNSENT_HOOK_LOGS == set()
    gateway.answer = lambda request: (200, OK)
    gateway.requests.clear()
    r()
    assert _messages(gateway) == ["cursor broke"]


def test_a_cursor_log_an_earlier_run_could_not_put_back_is_forwarded(setup, gateway):
    """A restore that failed leaves the log at its set-aside name; the next run puts it back and sends it."""
    r = setup("cursor")
    _log(r.home, "cursor", [f"{_pacific(2)}: cursor broke later"])
    aside = r.home / ".cursor" / ".unbound-unsent-hooks-error.log"
    aside.write_text(f"{_pacific(0)}: cursor broke\n{_pacific(1)}: cursor broke again\n")
    assert r() is True
    assert _messages(gateway) == ["cursor broke", "cursor broke again", "cursor broke later"]
    assert not aside.exists()


def test_a_partly_sent_cursor_log_keeps_its_place_across_the_cleanup(setup, gateway):
    r = setup("cursor")
    real_cursor_cleanup(r)
    log = _log(r.home, "cursor", [f"{_pacific(n)}: e{n}" for n in range(15)])
    gateway.answer = lambda request: (503, {}) if len(_forwarded(gateway)) == 2 else (200, OK)
    r()
    assert log.with_name(STATE).read_text() == f"{_pacific(9)} 1"
    gateway.answer = lambda request: (200, OK)
    gateway.requests.clear()
    r()
    assert _messages(gateway) == [f"e{n}" for n in range(10, 15)]


def test_an_oversized_cursor_log_survives_its_cleanup_whole(setup, gateway):
    r = setup("cursor")
    real_cursor_cleanup(r)
    old = [f"{_pacific(0, days_ago=9)}: ancient {'x' * 200}"] * 25000  # over 5 MiB, all past the 7-day limit
    log = _log(r.home, "cursor", old + [f"{_pacific(0)}: cursor broke", f"{_pacific(1)}: cursor broke again"])
    size = log.stat().st_size
    gateway.answer = lambda request: (503, {})
    r()
    assert log.exists() and log.stat().st_size == size
    gateway.answer = lambda request: (200, OK)
    gateway.requests.clear()
    r()
    assert _messages(gateway) == ["cursor broke", "cursor broke again"]


def test_a_cursor_log_in_a_home_without_a_key_survives_its_cleanup(setup, gateway):
    r = setup("cursor")
    real_cursor_cleanup(r)
    log = _log(r.home, "cursor", [f"{_pacific(0)}: cursor broke"], key=None)
    r()
    assert _forwarded(gateway) == []
    assert log.exists()


# --- The five copies stay equal, and equal to the binary ---------------------------

SHARED_FUNCTIONS = ("_log_time", "_refuse_if_redirected", "_read_user_file", "_read_user_file_tail", "_replace_user_file", "_forwarded_place",
                    "_unsent_hook_errors", "_save_forwarded", "_redact_hook_error", "_post_hook_json",
                    "_post_hook_errors", "_writable_dir", "_home_device_key", "_forward_home_errors",
                    "forward_hook_errors")
SHARED_DATA = ("FORWARDED_STATE_NAME", "HOOK_ERRORS_PER_REQUEST", "HOOK_ERRORS_PER_RUN", "HOOK_ERROR_MAX_AGE",
               "FORWARDED_ERROR_CATEGORY", "HOOK_ERROR_TIMEOUT_SECONDS", "_HOOK_ERROR_LINE", "_USER_FILE_MAX_BYTES",
               "_USER_FILE_FLAGS", "_BEARER", "_NAMED_SECRET", "_URL_SECRET", "_VENDOR_KEY")
# What must read the same as the binary's (setup_cmd), so a Linux or Windows device forwards as a Mac does.
AS_THE_BINARY = ("FORWARDED_STATE_NAME", "HOOK_ERRORS_PER_REQUEST", "HOOK_ERRORS_PER_RUN", "HOOK_ERROR_MAX_AGE",
                 "FORWARDED_ERROR_CATEGORY", "_HOOK_ERROR_LINE", "_USER_FILE_MAX_BYTES", "_BEARER", "_NAMED_SECRET",
                 "_URL_SECRET", "_VENDOR_KEY")


@pytest.fixture(scope="module")
def binary():
    sys.path.insert(0, str(REPO / "binary" / "src"))
    from unbound_hook import setup_cmd
    return setup_cmd


def _value(module, name):
    obj = getattr(module, name)
    if isinstance(obj, re.Pattern):
        return obj.pattern, obj.flags
    return inspect.getsource(obj) if callable(obj) else obj


@pytest.mark.parametrize("name", SHARED_FUNCTIONS + SHARED_DATA)
def test_the_five_copies_are_identical(name):
    first = _value(load_module(MODULES["claude-code"]), name)
    assert all(_value(load_module(MODULES[tool]), name) == first for tool in MODULES), name


@pytest.mark.parametrize("name", AS_THE_BINARY)
def test_the_limits_and_redaction_are_the_binarys(binary, name):
    assert _value(load_module(MODULES["claude-code"]), name) == _value(binary, name)


@pytest.mark.parametrize("tool", sorted(MODULES))
def test_each_script_forwards_the_log_the_binary_does_for_its_tool(binary, tool):
    assert load_module(MODULES[tool]).HOOK_ERROR_LOG == binary._HOOK_ERROR_LOGS[tool]


@pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="FIFOs are POSIX")
@pytest.mark.parametrize("tool", ["copilot", "codex"])
def test_the_hook_hashed_before_install_is_read_as_a_users_file(tool, tmp_path):
    """Copilot and codex hash a hook in a user's home, before this run has replaced it, and root reads it.
    A FIFO there must not hang the run, and a link must not make root hash a file the user can't read."""
    m = load_module(MODULES[tool])
    hooks = tmp_path / "hooks"
    hooks.mkdir()
    real = hooks / "real.py"
    real.write_bytes(b"print('hook')\n")
    assert m.hook_script_hash(real) == "a1000e5bd44e3cdc4bfe2631b9dffa642fa8fd55bc86f07c2823eb7bdd4aacab"
    root_only = tmp_path / "root-only.py"
    root_only.write_bytes(b"secret\n")
    link = hooks / "link.py"
    link.symlink_to(root_only)
    assert m.hook_script_hash(link) is None
    fifo = hooks / "unbound.py"
    os.mkfifo(fifo)
    answer = []
    reader = threading.Thread(target=lambda: answer.append(m.hook_script_hash(fifo)), daemon=True)
    reader.start()
    reader.join(5)
    if reader.is_alive():  # release the blocked open before failing
        os.close(os.open(fifo, os.O_WRONLY | os.O_NONBLOCK))
        pytest.fail("hashing a FIFO blocked the run")
    assert answer == [None]



def _fork_as_this_user(monkeypatch, m, tool):
    """The real fork-and-drop runner, as a non-root test can run it: the drop to this same user is a no-op."""
    for name in ("setgroups", "setgid", "setuid"):
        monkeypatch.setattr(os, name, lambda *a: None)
    monkeypatch.setattr(m, "_run_as_user", REAL_RUN_AS_USER[tool])


@pytest.mark.skipif(not hasattr(os, "fork"), reason="the runner forks on POSIX only")
@pytest.mark.parametrize("tool", sorted(MODULES))
def test_a_step_run_as_the_user_ends_at_its_timeout(tool, monkeypatch):
    """The user can pause the child it runs in: a bounded call answers None (unknown) when the time is up."""
    import getpass
    import time
    m = load_module(MODULES[tool])
    _fork_as_this_user(monkeypatch, m, tool)
    monkeypatch.setattr(m.platform, "system", lambda: "Linux")
    started = time.monotonic()
    assert m._run_as_user(getpass.getuser(), time.sleep, 30, _timeout=1) is None
    assert time.monotonic() - started < 10
    assert m._run_as_user(getpass.getuser(), lambda a, b: a + b, 2, 3, _timeout=5) == 5


@pytest.mark.skipif(not hasattr(os, "fork"), reason="the runner forks on POSIX only")
def test_forwarding_a_user_pauses_does_not_hold_setup_up(setup, gateway, monkeypatch):
    """Forwarding runs before setup fetches its key: a paused read of the user's log ends at the bound."""
    import getpass
    import time
    r = setup("claude-code")
    _fork_as_this_user(monkeypatch, r.m, "claude-code")
    r.stub("get_all_user_homes", [(getpass.getuser(), r.home)])
    _log(r.home, "claude-code", [f"{_utc(0)}: claude broke"])
    r.mp.setattr(r.m, "_unsent_hook_errors", lambda log: time.sleep(60))
    r.mp.setattr(r.m, "HOOK_ERROR_USER_TIMEOUT", 1, raising=False)
    started = time.monotonic()
    assert r() is True
    assert time.monotonic() - started < 20
    assert _forwarded(gateway) == []

