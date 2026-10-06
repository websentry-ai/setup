"""`mdm/jamf-setup.sh` runs after a pkg the admin deployed from their own Jamf.
Same sandbox as the onboard.sh tests: system tools are PATH stubs, and only a
private copy of the script has PREFIX and the root check rewritten.
"""

import json
import os
import subprocess
from pathlib import Path

import pytest

from tests.conftest import REPO
from tests.test_mdm_onboard_sh import (
    BASELINE_ARGV,
    BASH,
    HOOK_STUB,
    STUBS,
    TENANT_FRONTEND,
    VERSION,
    _write_exec,
    jamf,
)

pytestmark = pytest.mark.skipif(not os.path.exists(BASH), reason="needs /bin/bash")


def _script(prefix: Path) -> str:
    text = (REPO / "mdm/jamf-setup.sh").read_text()
    assert text.count('PREFIX="/opt/unbound"\n') == 1
    text = text.replace('PREFIX="/opt/unbound"\n', f'PREFIX="{prefix}"\n')
    assert text.count("[[ $EUID -eq 0 ]]") == 1
    return text.replace("[[ $EUID -eq 0 ]]", "[[ 0 -eq 0 ]]")


class Sandbox:
    def __init__(self, root: Path, hook_body=HOOK_STUB):
        self.root = root
        self.prefix = root / "prefix"
        self.bin = root / "bin"
        self.bin.mkdir()
        for name, body in STUBS.items():
            _write_exec(self.bin / name, f"#!/bin/bash\n{body}\n")
        hook_dir = self.prefix / VERSION / "unbound-hook"
        hook_dir.mkdir(parents=True)
        _write_exec(hook_dir / "unbound-hook", hook_body)
        (self.prefix / "current").symlink_to(self.prefix / VERSION)
        self.script = root / "jamf-setup.sh"
        self.script.write_text(_script(self.prefix))

    def run(self, *args):
        env = {
            "PATH": f"{self.bin}:/usr/bin:/bin:/usr/sbin:/sbin",
            "SANDBOX": str(self.root),
            "STUB_INSTALLED_VERSION": VERSION,
            "HOME": str(self.root),
        }
        return subprocess.run([BASH, str(self.script), *args], env=env,
                              capture_output=True, text=True, timeout=60)

    def _records(self, name):
        log = self.root / name
        if not log.exists():
            return []
        return [rec.split("\0") for rec in log.read_text().split("\0\n") if rec]

    def hook_calls(self):
        return self._records("hook-argv.log")

    def curl_calls(self):
        return self._records("curl.log")

    def reports(self):
        calls = self.curl_calls()
        assert all(any("install-report" in a for a in c) for c in calls), calls
        return [json.loads(c[c.index("-d") + 1]) for c in calls]


@pytest.fixture
def sandbox(tmp_path):
    return Sandbox(tmp_path)


def _setup_argv(sandbox, *args):
    result = sandbox.run(*args)
    assert result.returncode == 0, result.stderr
    calls = sandbox.hook_calls()
    assert len(calls) == 1, calls
    return calls[0]


def test_script_parses_under_system_bash():
    assert subprocess.run([BASH, "-n", str(REPO / "mdm/jamf-setup.sh")]).returncode == 0


@pytest.mark.parametrize("params", [
    ["K"],
    ["K", "", "", "", "", "", ""],
    ["K", "", "", "", "", "", "", "   "],
])
def test_api_key_alone_is_the_baseline(sandbox, params):
    assert _setup_argv(sandbox, *jamf(*params)) == BASELINE_ARGV


def test_tenant_urls_and_tokens_combine(sandbox):
    argv = _setup_argv(sandbox, *jamf(
        "K", "ignored-discovery-key", "https://tenant-backend.example.com",
        "https://tenant-api.example.com", "", "backfill", "skip-managed-settings",
        TENANT_FRONTEND))
    assert argv == [
        "setup", "--api-key", "K",
        "--backend-url", "https://tenant-backend.example.com",
        "--gateway-url", "https://tenant-api.example.com",
        "--frontend-url", TENANT_FRONTEND,
        "--backfill", "--skip-managed-settings",
    ]


@pytest.mark.parametrize("slot, value", [(8, "backfill"), (9, "clear"), (10, "backfill")])
def test_a_token_in_the_wrong_slot_does_nothing(sandbox, slot, value):
    params = ["K", "", "", "", "", "", ""]
    params[slot - 4] = value
    assert _setup_argv(sandbox, *jamf(*params)) == BASELINE_ARGV


def test_success_downloads_nothing_and_reports_once(sandbox):
    _setup_argv(sandbox, *jamf("K"))
    [report] = sandbox.reports()
    assert report["exit_code"] == 0 and report["step"] == "setup"
    assert report["installer_version"] == VERSION
    assert report["serial_number"] == "TESTSERIAL"
    [call] = sandbox.curl_calls()
    assert "https://backend.getunbound.ai/api/v1/automations/mdm/install-report/" in call
    assert "X-API-KEY: K" in call


def test_missing_runtime_fails_and_reports_the_step(sandbox):
    (sandbox.prefix / "current").unlink()
    result = sandbox.run(*jamf("K"))
    assert result.returncode == 1
    assert "add the pkg to this policy" in result.stderr
    assert "UNBOUND_INSTALL_FAILED step=runtime_check code=1" in result.stderr
    [report] = sandbox.reports()
    assert report["exit_code"] == 1 and report["step"] == "runtime_check"


def test_setup_failure_exit_code_is_kept(tmp_path):
    sandbox = Sandbox(tmp_path, hook_body="#!/bin/bash\nexit 3\n")
    result = sandbox.run(*jamf("K"))
    assert result.returncode == 3
    assert "UNBOUND_INSTALL_FAILED step=setup code=3" in result.stderr
    [report] = sandbox.reports()
    assert report["exit_code"] == 3


def test_missing_api_key_is_rejected_without_a_report(sandbox):
    result = sandbox.run(*jamf(""))
    assert result.returncode == 2
    assert "API key (parameter 4) is required" in result.stderr
    assert sandbox.hook_calls() == [] and sandbox.curl_calls() == []


@pytest.mark.parametrize("misplaced", ["--skip-managed-settings", "-x", " --backfill"])
def test_parameter_11_holding_a_flag_is_rejected(sandbox, misplaced):
    result = sandbox.run(*jamf("K", "", "", "", "", "", "", misplaced))
    assert result.returncode == 2
    assert "frontend url (parameter 11) must be a URL" in result.stderr
    assert sandbox.hook_calls() == []


def test_frontend_url_reaches_setup_as_one_unexpanded_argument(sandbox):
    url = "https://tenant-app.example.com/path with space?q=*"
    argv = _setup_argv(sandbox, *jamf("K", "", "", "", "", "", "", url))
    assert argv == BASELINE_ARGV + ["--frontend-url", url]


@pytest.mark.parametrize("key", ["K", ""])
def test_clear_tears_down_without_network(sandbox, key):
    result = sandbox.run(*jamf(key, "", "", "", "clear"))
    assert result.returncode == 0, result.stderr
    assert "UNBOUND_CLEAR_OK" in result.stdout
    assert sandbox.hook_calls() == [["clear"]]
    assert not sandbox.prefix.exists()
    assert sandbox.curl_calls() == []


@pytest.mark.parametrize("backend, expected", [
    ("backend.example.com", "https://backend.example.com"),
    ("https://backend.example.com/", "https://backend.example.com"),
    ("  backend.example.com//  ", "https://backend.example.com"),
    ("http://backend.example.com", "http://backend.example.com"),
])
def test_report_url_is_normalized_like_setup(sandbox, backend, expected):
    argv = _setup_argv(sandbox, *jamf("K", "", backend))
    [call] = sandbox.curl_calls()
    assert f"{expected}/api/v1/automations/mdm/install-report/" in call
    assert argv[argv.index("--backend-url") + 1] == backend
