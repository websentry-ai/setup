"""WEB-6392: what `unbound-hook setup` tells the backend about its own run.

Driven end to end through setup_cmd.run against a real HTTP server on 127.0.0.1,
so the curl requests are the ones a Mac sends. The vendored modules' root-only
primitives are stubbed by the `env` fixture, as in test_setup_migration.
"""

import json
import re
import threading
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from unbound_hook import __version__, setup_cmd
from test_setup_migration import env  # noqa: F401  (the shared sandbox fixture)

REAL_POST_JSON = setup_cmd._post_json
ISO_Z = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")


class _Recorder(BaseHTTPRequestHandler):
    def do_POST(self):
        length = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(length)
        try:
            body = json.loads(raw.decode("utf-8"))
        except ValueError:
            body = raw
        self.server.requests.append({"path": self.path, "headers": dict(self.headers), "body": body})
        status, answer = self.server.answer(self.path)
        data = json.dumps(answer).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def log_message(self, *args):
        pass


@pytest.fixture
def backend(monkeypatch):
    """A local stand-in for both the backend and the gateway. The env fixture keeps
    setup off the network; these tests let it talk to this server only."""
    server = ThreadingHTTPServer(("127.0.0.1", 0), _Recorder)
    server.requests = []
    server.answer = lambda path: (200, {"status": "ok", "success": True, "accepted": 1})
    threading.Thread(target=server.serve_forever, daemon=True).start()
    monkeypatch.setattr(setup_cmd, "_post_json", REAL_POST_JSON)
    server.url = "http://127.0.0.1:%d" % server.server_address[1]
    yield server
    server.shutdown()
    server.server_close()


def _run(backend, *extra):
    return setup_cmd.run(["--api-key", "admin-key", "--backend-url", backend.url,
                          "--gateway-url", backend.url, *extra])


def _run_reports(backend):
    return [r for r in backend.requests if r["path"] == "/api/v1/automations/mdm/install-report/"]


# --- Step 2: start and end reports -------------------------------------------

def test_setup_reports_its_start_first_and_its_end_last(env, backend):
    assert _run(backend) == 0
    reports = _run_reports(backend)
    assert [r["body"]["phase"] for r in reports] == ["start", "end"]
    assert backend.requests[0] is reports[0] and backend.requests[-1] is reports[-1]

    start, end = reports[0]["body"], reports[1]["body"]
    assert start["serial_number"] == end["serial_number"] == "TESTSERIAL1"
    assert start["install_mode"] == end["install_mode"] == "binary"
    assert start["runtime_version"] == __version__
    assert isinstance(start["os_version"], str) and start["os_version"]
    assert ISO_Z.match(start["timestamps"]["started_at"])
    assert ISO_Z.match(end["timestamps"]["completed_at"])
    assert end["user_homes"] == {"configured": 1, "skipped": 0}
    assert isinstance(end["preflight_warnings"], list)
    # A run report never carries a tool list: the backend would read it as a full snapshot.
    assert "components" not in start and "components" not in end
    # The same credentials onboard.sh's exit report uses: the MDM admin key.
    assert all(r["headers"]["X-API-KEY"] == "admin-key" for r in reports)


def test_a_run_without_managed_settings_reports_that_mode(env, backend):
    assert _run(backend, "--skip-managed-settings") == 0
    assert {r["body"]["install_mode"] for r in _run_reports(backend)} == {"binary-skip"}


def test_a_home_whose_config_write_failed_counts_as_skipped(env, backend, monkeypatch):
    monkeypatch.setattr(env["modules"]["cursor"], "write_unbound_config_for_user", lambda *a, **k: False)
    assert _run(backend) == 1  # cursor defers, as before
    end = _run_reports(backend)[-1]["body"]
    assert end["user_homes"] == {"configured": 0, "skipped": 1}


def test_a_missing_hook_binary_is_a_preflight_warning(env, backend, monkeypatch, tmp_path):
    monkeypatch.setattr(setup_cmd, "HOOK_BINARY", tmp_path / "gone" / "unbound-hook")
    assert _run(backend) == 0
    warnings = _run_reports(backend)[-1]["body"]["preflight_warnings"]
    assert warnings == [f"hook binary not found at {tmp_path / 'gone' / 'unbound-hook'}"]


def test_an_installed_hook_binary_leaves_no_preflight_warning(env, backend, monkeypatch, tmp_path):
    binary = tmp_path / "unbound-hook"
    binary.write_text("#!/bin/sh\n")
    monkeypatch.setattr(setup_cmd, "HOOK_BINARY", binary)
    assert _run(backend) == 0
    assert _run_reports(backend)[-1]["body"]["preflight_warnings"] == []


def test_a_device_without_a_serial_sends_no_run_report(env, backend, monkeypatch):
    for m in env["modules"].values():
        monkeypatch.setattr(m, "get_device_identifier", lambda: None)
    _run(backend)
    assert _run_reports(backend) == []


def test_an_unreachable_backend_changes_nothing_about_the_run(env, backend, capsys):
    rc = setup_cmd.run(["--api-key", "admin-key", "--backend-url", "http://127.0.0.1:9",
                        "--gateway-url", "http://127.0.0.1:9"])
    assert rc == 0
    assert (env["tmp"] / "managed-claude" / "managed-settings.json").exists()
    out = capsys.readouterr().out
    assert "[report] install-report start not sent" in out
    assert "[report] install-report end not sent" in out


def test_a_backend_error_changes_nothing_about_the_run(env, backend, capsys):
    backend.answer = lambda path: (500, {"error": "boom"})
    assert _run(backend) == 0
    assert [r["body"]["phase"] for r in _run_reports(backend)] == ["start", "end"]
    assert "[report] install-report end not sent: HTTP 500" in capsys.readouterr().out


# --- Step 3: every tool's outcome, every run -----------------------------------

# One footprint per tool that proves it is installed, under the patched machine root.
FOOTPRINTS = {
    "claude-code": "opt/homebrew/bin/claude",
    "cursor": "Applications/Cursor.app",
    "codex": "usr/local/bin/codex",
    "copilot": "Applications/Visual Studio Code.app",
    "augment": "opt/homebrew/bin/auggie",
}
TOOL_TYPES = {"claude-code": "claude-code", "cursor": "cursor", "codex": "codex",
              "copilot": "copilot", "augment": "augment_code"}
NAMES = {"claude-code": "Claude Code", "cursor": "Cursor", "codex": "Codex",
         "copilot": "GitHub Copilot", "augment": "Augment"}


def _install(root, relpath):
    path = root / relpath
    path.parent.mkdir(parents=True, exist_ok=True)
    path.mkdir() if relpath.endswith(".app") else path.write_text("")


@pytest.fixture
def machine(env, tmp_path, monkeypatch):
    root = tmp_path / "machine"
    root.mkdir()
    monkeypatch.setattr(setup_cmd, "_MACHINE_ROOT", root)
    return root


def _reports(env, tool):
    return [k for a, k in env["notified"] if a[1] == TOOL_TYPES[tool]]


def test_every_installed_tool_reports_configured_and_where_it_wrote(env, machine):
    for relpath in FOOTPRINTS.values():
        _install(machine, relpath)
    assert setup_cmd.run(["--api-key", "admin-key"]) == 0
    written = {
        "claude-code": str(env["tmp"] / "managed-claude" / "managed-settings.json"),
        "cursor": str(env["tmp"] / "enterprise-cursor" / "hooks.json"),
        "codex": str(env["tmp"] / "managed-codex" / "hooks.json"),
        "copilot": "~/.copilot/hooks/unbound.json",
        "augment": str(env["tmp"] / "managed-augment" / "settings.json"),
    }
    for tool in FOOTPRINTS:
        [report] = _reports(env, tool)
        assert (report["status"], report["reason"], report["written_to"]) == ("configured", None, written[tool])


@pytest.mark.parametrize("tool", sorted(FOOTPRINTS))
def test_a_tool_that_is_not_installed_is_reported_skipped_and_still_written(env, machine, tool):
    for other, relpath in FOOTPRINTS.items():
        if other != tool:
            _install(machine, relpath)
    assert setup_cmd.run(["--api-key", "admin-key"]) == 0
    [report] = _reports(env, tool)
    assert (report["status"], report["reason"]) == ("skipped", f"{NAMES[tool]} is not installed")
    # Reporting only: the config is written all the same, so the hook works once the tool arrives.
    assert report["written_to"]
    assert all(_reports(env, other)[0]["status"] == "configured" for other in FOOTPRINTS if other != tool)


@pytest.mark.parametrize("tool,relpath", [
    ("claude-code", "HOME/.local/bin/claude"), ("claude-code", "HOME/.claude.json"),
    ("claude-code", "HOME/.nvm/versions/node/v22.1.0/bin/claude"), ("claude-code", "Applications/Claude.app"),
    ("cursor", "HOME/Applications/Cursor.app"), ("cursor", "HOME/.local/bin/cursor-agent"),
    ("codex", "opt/homebrew/bin/codex"), ("codex", "HOME/.codex/auth.json"), ("codex", "Applications/Codex.app"),
    ("copilot", "usr/local/bin/copilot"), ("copilot", "HOME/.bun/bin/copilot"),
    ("copilot", "Applications/Visual Studio Code - Insiders.app"),
    ("augment", "usr/local/bin/auggie"), ("augment", "HOME/.local/bin/auggie"),
])
def test_each_install_location_counts_as_installed(env, machine, tool, relpath):
    if relpath.startswith("HOME/"):
        _install(env["home"], relpath[len("HOME/"):])
    else:
        _install(machine, relpath)
    setup_cmd.run(["--api-key", "admin-key"])
    assert _reports(env, tool)[0]["status"] == "configured"


def test_our_own_files_do_not_count_as_the_tool_being_installed(env, machine):
    # A re-run finds the files the first run wrote; none of them is the tool.
    setup_cmd.run(["--api-key", "admin-key"])
    env["notified"].clear()
    setup_cmd.run(["--api-key", "admin-key"])
    assert {k["status"] for _, k in env["notified"]} == {"skipped"}


def test_a_failed_write_is_reported_deferred_with_the_printed_reason(env, machine, monkeypatch):
    _install(machine, FOOTPRINTS["cursor"])
    monkeypatch.setattr(setup_cmd, "_write_cursor_enterprise_hooks", lambda m: (False, False))
    assert setup_cmd.run(["--api-key", "admin-key"]) == 1
    [report] = _reports(env, "cursor")
    assert (report["status"], report["reason"]) == ("deferred", "enterprise hooks.json write failed")


def test_a_deferred_tool_is_reported_even_when_it_is_not_installed(env, machine, monkeypatch):
    monkeypatch.setattr(setup_cmd, "_write_codex_system_hooks", lambda m: False)
    assert setup_cmd.run(["--api-key", "admin-key"]) == 1
    [report] = _reports(env, "codex")
    assert (report["status"], report["reason"]) == ("deferred", "codex system hooks.json write failed")


def test_a_skipped_scan_is_reported_skipped_not_configured(env, machine, capsys):
    env["tmp"].joinpath("unbound-discovery").write_text(
        "#!/bin/sh\necho 'Scan skipped: another scan is running'\nexit 0\n")
    assert setup_cmd.run(["--api-key", "admin-key"]) == 0
    out = capsys.readouterr().out
    assert "  discovery    skipped (another scan is running)" in out
    # The scan's own output still reaches the MDM log.
    assert "Scan skipped: another scan is running" in out.split("[discovery] coding-tool scan")[1]


def test_a_completed_scan_is_still_configured(env, machine, capsys):
    env["tmp"].joinpath("unbound-discovery").write_text("#!/bin/sh\necho 'Scan complete'\nexit 0\n")
    assert setup_cmd.run(["--api-key", "admin-key"]) == 0
    assert "  discovery    configured" in capsys.readouterr().out


@pytest.mark.parametrize("tool", sorted(TOOL_TYPES))
def test_the_notifier_sends_status_reason_and_where_it_wrote(tool, monkeypatch):
    from unbound_hook._loader import load_mdm_setup_module
    m = load_mdm_setup_module(tool)
    sent = []
    monkeypatch.setattr(m.subprocess, "run", lambda cmd, **kw: sent.append(json.loads(kw["input"])))
    m.notify_setup_complete("k", TOOL_TYPES[tool], backend_url="https://b", status="skipped",
                            reason="r" * 600, written_to="/p" * 300)
    m.notify_setup_complete("k", TOOL_TYPES[tool], backend_url="https://b")
    skipped, plain = sent
    assert (skipped["status"], skipped["reason"], skipped["written_to"]) == ("skipped", "r" * 500, ("/p" * 300)[:500])
    # An old-style call sends the body it always did: a missing status means configured.
    assert not {"status", "reason", "written_to"} & set(plain)


# --- Step 7: forward hook errors stuck in error.log ------------------------------

ERROR_LOGS = {"claude-code": ".claude/hooks/error.log", "cursor": ".cursor/hooks/error.log",
              "codex": ".codex/hooks/error.log", "copilot": ".copilot/hooks/error.log",
              "augment": ".augment/hooks/error.log"}
STATE = ".error_log_forwarded"


def _log(home, tool, lines):
    path = home / ERROR_LOGS[tool]
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("".join(line + "\n" for line in lines))
    return path


# Entries are stamped an hour before the test run, so the seven-day limit never ages them out.
BASE = datetime.now(timezone.utc).replace(microsecond=123) - timedelta(hours=1)


def _utc(n, days_ago=0):
    return (BASE + timedelta(seconds=n) - timedelta(days=days_ago)).isoformat().replace("+00:00", "Z")


def _pacific(n):
    """How Cursor's and Copilot's hooks stamp: local time with its offset."""
    return (BASE + timedelta(seconds=n)).astimezone(timezone(timedelta(hours=-8))).isoformat()


def _forwarded(backend):
    return [r for r in backend.requests if r["path"] == "/v1/hooks/errors"]


def test_errors_newer_than_the_last_forwarded_one_go_to_the_gateway(env, backend):
    log = _log(env["home"], "claude-code", [f"{_utc(n)}: gateway unreachable {n}" for n in range(3)])
    log.with_name(STATE).write_text(_utc(0))
    _run(backend)
    [request] = _forwarded(backend)
    assert request["headers"]["Authorization"] == "Bearer per-device-key"
    body = request["body"]
    assert body["hook_source"] == "claude-code" and len(body["hook_sha"]) == 12
    assert [(e["timestamp"], e["message"]) for e in body["errors"]] == [
        (_utc(1), "gateway unreachable 1"), (_utc(2), "gateway unreachable 2")]
    assert log.with_name(STATE).read_text() == _utc(2)


def test_errors_go_ten_to_a_request_and_none_is_sent_twice(env, backend):
    log = _log(env["home"], "claude-code", [f"{_utc(n)}: e{n}" for n in range(25)])
    _run(backend)
    assert [len(r["body"]["errors"]) for r in _forwarded(backend)] == [10, 10, 5]
    assert [e["message"] for r in _forwarded(backend) for e in r["body"]["errors"]] == [f"e{n}" for n in range(25)]
    assert log.with_name(STATE).read_text() == _utc(24)
    backend.requests.clear()
    _run(backend)
    assert _forwarded(backend) == []


def test_an_unreachable_gateway_saves_nothing_and_the_next_run_sends_it_all(env, backend):
    log = _log(env["home"], "claude-code", [f"{_utc(n)}: e{n}" for n in range(3)])
    rc = setup_cmd.run(["--api-key", "admin-key", "--backend-url", backend.url,
                        "--gateway-url", "http://127.0.0.1:9"])
    assert rc == 0
    assert not log.with_name(STATE).exists()
    _run(backend)
    assert [e["message"] for r in _forwarded(backend) for e in r["body"]["errors"]] == ["e0", "e1", "e2"]


def test_a_refused_request_saves_nothing(env, backend):
    log = _log(env["home"], "claude-code", [f"{_utc(0)}: e0"])
    # The gateway answers an unknown key with 200 and success false.
    backend.answer = lambda path: (200, {"success": False, "reason": "invalid_key"})
    assert _run(backend) == 0
    assert len(_forwarded(backend)) == 1
    assert not log.with_name(STATE).exists()


def test_each_tool_and_each_home_keeps_its_own_place(env, backend, monkeypatch, tmp_path):
    other = tmp_path / "other-home"
    other.mkdir()
    for m in env["modules"].values():
        monkeypatch.setattr(m, "get_all_user_homes", lambda: [("alice", env["home"]), ("bob", other)])
    # Cursor's and Copilot's hooks stamp local time with its offset.
    _log(env["home"], "cursor", [f"{_pacific(0)}: cursor broke"])
    _log(env["home"], "copilot", [f"{_pacific(1)}: copilot broke"])
    _log(env["home"], "codex", [f"{_utc(1)}: codex broke"])
    _log(other, "claude-code", [f"{_utc(2)}: bob's claude broke"])
    _log(other, "augment", [f"{_utc(3)}: auggie broke"])
    _run(backend)
    sent = {r["body"]["hook_source"]: [e["message"] for e in r["body"]["errors"]] for r in _forwarded(backend)}
    assert sent == {"cursor": ["cursor broke"], "copilot": ["copilot broke"], "codex": ["codex broke"],
                    "claude-code": ["bob's claude broke"], "augment_code": ["auggie broke"]}
    assert (env["home"] / ".copilot/hooks" / STATE).read_text() == _pacific(1)
    assert (other / ".claude/hooks" / STATE).exists() and not (env["home"] / ".claude/hooks" / STATE).exists()
    # Cursor's setup removes the python-era ~/.cursor/hooks, log and all, after its errors went out.
    assert not (env["home"] / ".cursor/hooks").exists()


def test_lines_that_are_not_log_entries_are_skipped(env, backend):
    _log(env["home"], "claude-code", ["not an entry", f"{_utc(5)}: real one", "  continued text"])
    _run(backend)
    assert [e["message"] for r in _forwarded(backend) for e in r["body"]["errors"]] == ["real one"]


# --- F9: the run reports' inputs fail open ---------------------------------------

def _first_call_raises(module, name, monkeypatch):
    """Raises on run()'s own call only: the tools call the same function afterwards."""
    real, calls = getattr(module, name), []

    def flaky(*a, **k):
        calls.append(1)
        if len(calls) == 1:
            raise RuntimeError(f"{name} broke")
        return real(*a, **k)
    monkeypatch.setattr(module, name, flaky)


def _installs_everything(env):
    assert (env["tmp"] / "managed-claude" / "managed-settings.json").exists()
    assert (env["tmp"] / "managed-codex" / "hooks.json").exists()
    assert (env["tmp"] / "enterprise-cursor" / "hooks.json").exists()
    assert (env["home"] / ".copilot" / "hooks" / "unbound.json").exists()
    assert len(env["notified"]) == 5


def test_a_serial_lookup_that_raises_costs_only_the_run_reports(env, backend, monkeypatch):
    _first_call_raises(env["modules"]["claude-code"], "get_device_identifier", monkeypatch)
    assert _run(backend) == 0
    _installs_everything(env)
    assert _run_reports(backend) == []


def test_a_home_lookup_that_raises_costs_only_the_home_counts(env, backend, monkeypatch):
    _first_call_raises(env["modules"]["claude-code"], "get_all_user_homes", monkeypatch)
    assert _run(backend) == 0
    _installs_everything(env)
    start, end = (r["body"] for r in _run_reports(backend))
    assert "user_homes" not in end
    assert "no user homes found" not in end["preflight_warnings"]


def test_preflight_checks_that_raise_cost_only_the_warnings(env, backend, monkeypatch):
    monkeypatch.setattr(setup_cmd, "_preflight_warnings", lambda homes: 1 / 0)
    assert _run(backend) == 0
    _installs_everything(env)
    assert _run_reports(backend)[-1]["body"]["preflight_warnings"] == []


# --- F7: a per-run cap and an age limit on forwarded errors ------------------------

def _messages(backend):
    return [e["message"] for r in _forwarded(backend) for e in r["body"]["errors"]]


def test_a_huge_log_sends_only_its_25_newest_entries(env, backend):
    # About 4 MB in 40,000 lines, just under the read cap: the gateway must not get 4,000 requests.
    lines = [f"{_utc(n / 100)}: flood {n} " + "x" * 50 for n in range(40000)]
    log = _log(env["home"], "claude-code", lines)
    assert 3.5e6 < log.stat().st_size < 4 * 1024 * 1024
    _run(backend)
    assert len(_forwarded(backend)) <= 3
    assert [m.split()[1] for m in _messages(backend)] == [str(n) for n in range(39975, 40000)]
    assert log.with_name(STATE).read_text() == _utc(39999 / 100)


def test_entries_older_than_seven_days_are_never_sent(env, backend):
    log = _log(env["home"], "claude-code", [f"{_utc(0, days_ago=8)}: stale", f"{_utc(1, days_ago=6)}: recent"])
    _run(backend)
    assert _messages(backend) == ["recent"]
    # Not even when the last forwarded entry is older still.
    log.write_text(f"{_utc(0, days_ago=8)}: stale again\n")
    log.with_name(STATE).write_text(_utc(0, days_ago=30))
    backend.requests.clear()
    _run(backend)
    assert _messages(backend) == []


def test_forwarded_errors_carry_a_category_of_their_own(env, backend):
    _log(env["home"], "claude-code", [f"{_utc(0)}: e0"])
    _run(backend)
    assert [e["category"] for r in _forwarded(backend) for e in r["body"]["errors"]] == ["forwarded_error_log"]
