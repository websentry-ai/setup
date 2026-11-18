"""Windows onboarding reports its result to the backend, so a device that fails
before check-in is visible on our side. The end-to-end cases run the shipped
mdm/onboard.ps1 under Windows PowerShell 5.1 against a local HTTP server, with only
the onboard.py download replaced. They skip off Windows; test.yml runs them on
windows-latest. The onboard.py half of the contract runs everywhere."""

import json
import os
import shutil
import socket
import subprocess
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from tests.conftest import REPO, load_module

onboard = load_module("mdm/onboard.py")

API_KEY = "unbound-test-key-do-not-log"
REPORT_PATH = "/api/v1/automations/mdm/install-report/"
# The fields MdmInstallService._validate_failure_payload reads. `components` would
# route the report down the full-snapshot branch and clear the failed step.
CONTRACT_FIELDS = {
    "serial_number", "step", "exit_code", "installer_version",
    "hostname", "os_version", "arch", "ts",
}

STUB_CHILD = """
import json, os, sys
failed = json.loads(os.environ.get("STUB_FAILED_STEPS", "null"))
if failed is not None:
    with open(os.environ["UNBOUND_ONBOARD_RESULT_FILE"], "w", encoding="utf-8") as f:
        json.dump({"failed_steps": failed}, f)
print("[stub] ran")
sys.exit(int(os.environ.get("STUB_EXIT", "0")))
"""

RUNNER = r"""
{no_python}
function Invoke-WebRequest {{
    [CmdletBinding()]
    param(
        [string]$Uri, [string]$Method, [hashtable]$Headers, [string]$ContentType, $Body,
        [int]$TimeoutSec, [int]$MaximumRedirection, [switch]$UseBasicParsing
    )
    if ($Uri -like '*raw.githubusercontent.com*') {{
        if ($env:STUB_DOWNLOAD_FAILS -eq '1') {{ throw 'The remote server returned an error: (308) Permanent Redirect.' }}
        return [pscustomobject]@{{ Content = (Get-Content -Raw -LiteralPath $env:STUB_CHILD_PATH) }}
    }}
    Microsoft.PowerShell.Utility\Invoke-WebRequest @PSBoundParameters
}}
& '{script}' {args}
exit $LASTEXITCODE
"""

NO_PYTHON = "\n".join(f"function {name} {{ throw 'not installed' }}" for name in ("py", "python3", "python"))


class _Backend:
    """Records every request. `status` is what the report endpoint answers."""

    def __init__(self, status=201, location=None):
        self.requests = []
        backend = self

        class Handler(BaseHTTPRequestHandler):
            def do_POST(self):
                length = int(self.headers.get("Content-Length") or 0)
                backend.requests.append({
                    "path": self.path,
                    "headers": dict(self.headers),
                    "body": self.rfile.read(length),
                })
                self.send_response(status)
                if location:
                    self.send_header("Location", location)
                self.send_header("Content-Length", "0")
                self.end_headers()

            def log_message(self, *args):
                pass

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.url = f"http://127.0.0.1:{self.server.server_address[1]}"
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    def close(self):
        self.server.shutdown()
        self.server.server_close()

    @property
    def reports(self):
        return [json.loads(r["body"]) for r in self.requests if r["path"] == REPORT_PATH]


@pytest.fixture
def backend():
    server = _Backend()
    yield server
    server.close()


def _run(tmp_path, backend_url, args=None, no_python=False, **env):
    script = tmp_path / "onboard.ps1"
    shutil.copy(str(REPO / "mdm" / "onboard.ps1"), str(script))
    child = tmp_path / "stub_child.py"
    child.write_text(STUB_CHILD)
    if args is None:
        args = f"-ApiKey '{API_KEY}' -BackendUrl '{backend_url}'"
    runner = tmp_path / "runner.ps1"
    runner.write_text(RUNNER.format(script=script, args=args, no_python=NO_PYTHON if no_python else ""))
    return subprocess.run(
        ["powershell.exe", "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", str(runner)],
        capture_output=True, text=True, timeout=180,
        env={**os.environ, "STUB_CHILD_PATH": str(child), **env},
    )


windows_only = pytest.mark.skipif(sys.platform != "win32", reason="needs Windows PowerShell 5.1")


@windows_only
def test_success_sends_the_setup_report_with_exit_code_zero(tmp_path, backend):
    result = _run(tmp_path, backend.url)
    assert result.returncode == 0, result.stderr
    assert len(backend.reports) == 1
    report = backend.reports[0]
    assert (report["step"], report["exit_code"]) == ("setup", 0)
    assert set(report) == CONTRACT_FIELDS
    assert report["serial_number"].strip()
    assert isinstance(report["ts"], int)
    assert backend.requests[0]["headers"]["X-API-KEY"] == API_KEY


@windows_only
def test_failing_setup_reports_its_exit_code_and_keeps_it(tmp_path, backend):
    result = _run(tmp_path, backend.url, STUB_EXIT="3")
    assert result.returncode == 3
    assert [(r["step"], r["exit_code"]) for r in backend.reports] == [("setup", 3)]


@windows_only
def test_failure_names_the_tools_onboard_py_listed(tmp_path, backend):
    result = _run(tmp_path, backend.url, STUB_EXIT="1",
                  STUB_FAILED_STEPS=json.dumps(["GitHub Copilot", "Discovery"]))
    assert result.returncode == 1
    assert backend.reports[0]["step"] == "setup:github_copilot,discovery"


@windows_only
def test_step_stays_within_the_backend_limit(tmp_path, backend):
    many = ["Claude Code", "Cursor", "Codex", "GitHub Copilot", "Augment", "Pi Coding Agent", "Discovery"]
    _run(tmp_path, backend.url, STUB_EXIT="1", STUB_FAILED_STEPS=json.dumps(many))
    assert len(backend.reports[0]["step"]) <= 64


@windows_only
def test_download_failure_is_reported_and_still_fails_the_run(tmp_path, backend):
    result = _run(tmp_path, backend.url, STUB_DOWNLOAD_FAILS="1")
    assert result.returncode == 1
    assert [(r["step"], r["exit_code"]) for r in backend.reports] == [("download_onboard_py", 1)]


@windows_only
def test_missing_python_is_reported(tmp_path, backend):
    result = _run(tmp_path, backend.url, no_python=True)
    assert result.returncode == 1
    assert [(r["step"], r["exit_code"]) for r in backend.reports] == [("find_python", 1)]


@windows_only
@pytest.mark.parametrize("child_exit", [0, 3])
@pytest.mark.parametrize("status", [400, 429, 500])
def test_rejected_report_never_changes_the_exit_code(tmp_path, child_exit, status):
    server = _Backend(status=status)
    try:
        result = _run(tmp_path, server.url, STUB_EXIT=str(child_exit))
    finally:
        server.close()
    assert result.returncode == child_exit
    assert f"HTTP {status}" in result.stdout + result.stderr


@windows_only
@pytest.mark.parametrize("child_exit", [0, 3])
def test_unreachable_backend_never_changes_the_exit_code(tmp_path, child_exit):
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
    result = _run(tmp_path, f"http://127.0.0.1:{port}", STUB_EXIT=str(child_exit))
    assert result.returncode == child_exit


@windows_only
def test_redirect_is_not_followed_with_the_key(tmp_path):
    server = _Backend(status=308, location="/somewhere-else/")
    try:
        result = _run(tmp_path, server.url)
    finally:
        server.close()
    assert result.returncode == 0
    assert [r["path"] for r in server.requests] == [REPORT_PATH]


@windows_only
def test_clear_sends_no_report(tmp_path, backend):
    result = _run(tmp_path, backend.url, args=f"-Clear -BackendUrl '{backend.url}'")
    assert result.returncode == 0
    assert backend.requests == []


@windows_only
@pytest.mark.parametrize("env", [{"STUB_EXIT": "3"}, {"STUB_DOWNLOAD_FAILS": "1"}])
def test_api_key_never_reaches_the_output_or_the_report_body(tmp_path, env):
    server = _Backend(status=500)
    try:
        result = _run(tmp_path, server.url, **env)
    finally:
        server.close()
    assert API_KEY not in result.stdout + result.stderr
    assert all(API_KEY.encode() not in r["body"] for r in server.requests)


# ---- onboard.py's half: the file that names the failed steps ----


def _main_with_failures(monkeypatch, failing):
    monkeypatch.setattr(onboard, "check_admin_privileges", lambda: True)
    monkeypatch.setattr(onboard, "run_tool", lambda name, url, args: name not in failing)
    monkeypatch.setattr(onboard, "should_install_pi", lambda: False)
    monkeypatch.setattr(onboard, "fetch_device_owner_key", lambda key, url: "owner-key")
    monkeypatch.setattr(onboard, "run_discovery", lambda key, url: "Discovery" not in failing)
    monkeypatch.setattr(onboard.sys, "argv", ["onboard.py", "--api-key", "K"])
    return onboard.main()


def test_main_lists_the_failed_steps_for_the_wrapper(monkeypatch, tmp_path):
    result_file = tmp_path / "result.json"
    monkeypatch.setenv(onboard.RESULT_FILE_ENV, str(result_file))
    assert _main_with_failures(monkeypatch, {"Cursor", "Discovery"}) == 1
    assert json.loads(result_file.read_text()) == {"failed_steps": ["Cursor", "Discovery"]}


def test_main_lists_nothing_on_success(monkeypatch, tmp_path):
    result_file = tmp_path / "result.json"
    monkeypatch.setenv(onboard.RESULT_FILE_ENV, str(result_file))
    assert _main_with_failures(monkeypatch, set()) == 0
    assert json.loads(result_file.read_text()) == {"failed_steps": []}


def test_main_writes_no_file_when_the_wrapper_did_not_ask(monkeypatch, tmp_path):
    monkeypatch.delenv(onboard.RESULT_FILE_ENV, raising=False)
    monkeypatch.chdir(tmp_path)
    assert _main_with_failures(monkeypatch, set()) == 0
    assert list(tmp_path.iterdir()) == []


def test_unwritable_result_file_never_changes_the_exit_code(monkeypatch, tmp_path):
    monkeypatch.setenv(onboard.RESULT_FILE_ENV, str(tmp_path / "missing-dir" / "result.json"))
    assert _main_with_failures(monkeypatch, set()) == 0
    assert _main_with_failures(monkeypatch, {"Cursor"}) == 1
