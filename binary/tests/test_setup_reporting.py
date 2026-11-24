"""WEB-6392: what `unbound-hook setup` tells the backend about its own run.

Driven end to end through setup_cmd.run against a real HTTP server on 127.0.0.1,
so the curl requests are the ones a Mac sends. The vendored modules' root-only
primitives are stubbed by the `env` fixture, as in test_setup_migration.
"""

import json
import re
import threading
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
