"""The macOS runtime bootstrap (`mdm/onboard.sh.tmpl`) ends by handing its
parameters to `unbound-hook setup`. These tests run the rendered script end to
end under the host's `/bin/bash` and assert on the argv that handoff actually
receives. On macOS that is bash 3.2, the shell Jamf uses, and the only place the
`set -u` + empty-array behaviour is exercised; on Linux it is a newer bash.

The script is production-shaped: it insists on root, a fixed /opt/unbound
prefix and macOS system tools. Nothing in the template is loosened for that.
Instead the test renders the template the way the release workflow does and
then, on its own private copy only, points PREFIX and the download dir at a
temp dir and neutralises the two root checks; every system tool the script
shells out to is a stub on PATH. `rm` is a guard stub that only deletes inside
the sandbox, so a run can never touch the host's real /Library, /usr/local or
/tmp paths.
"""

import glob
import os
import re
import stat
import subprocess
from pathlib import Path

import pytest

from tests.conftest import REPO

BASH = "/bin/bash"
VERSION = "9.9.9"
TENANT_FRONTEND = "https://tenant-app.example.com"

BASELINE_ARGV = [
    "setup",
    "--api-key", "K",
    "--backend-url", "https://backend.getunbound.ai",
    "--gateway-url", "https://api.getunbound.ai",
]

pytestmark = pytest.mark.skipif(not os.path.exists(BASH), reason="needs /bin/bash")

STUBS = {
    "uname": 'echo Darwin',
    "sw_vers": 'echo 14.5',
    "df": 'printf "Filesystem 1M-blocks Used Available Capacity Mounted\\n/dev/x 100000 1 99999 1%% /\\n"',
    "hostname": 'echo test-host',
    "ioreg": 'echo \'    "IOPlatformSerialNumber" = "TESTSERIAL"\'',
    "launchctl": 'exit 0',
    "installer": 'exit 0',
    "shasum": 'exit 0',
    "pkgutil": (
        'if [[ "$1" == "--pkg-info" && -n "${STUB_INSTALLED_VERSION:-}" ]]; then\n'
        '  echo "version: $STUB_INSTALLED_VERSION"; exit 0\n'
        'fi\n'
        '[[ "$1" == "--pkg-info" ]] && exit 1\n'
        'exit 0'
    ),
    # Records every call; creates the -o target so the download path has a pkg.
    "curl": (
        'printf \'%s\\0\' "$@" >> "$SANDBOX/curl.log"; printf \'\\n\' >> "$SANDBOX/curl.log"\n'
        'out="" code=0\n'
        'while [[ $# -gt 0 ]]; do\n'
        '  case "$1" in -o) out="$2"; shift 2 ;; -w) code=1; shift 2 ;; *) shift ;; esac\n'
        'done\n'
        '[[ -n "$out" && "$out" != /dev/null ]] && : > "$out"\n'
        '[[ $code -eq 1 ]] && printf 200\n'
        'exit 0'
    ),
    # Deletes only inside the sandbox.
    "rm": (
        'keep=()\n'
        'for a in "$@"; do\n'
        '  case "$a" in\n'
        '    -*|"$SANDBOX"/*) keep+=("$a") ;;\n'
        '    *) echo "$a" >> "$SANDBOX/rm-refused.log" ;;\n'
        '  esac\n'
        'done\n'
        'exec /bin/rm "${keep[@]}"'
    ),
}

HOOK_STUB = (
    '#!/bin/bash\n'
    'printf \'%s\\0\' "$@" >> "$SANDBOX/hook-argv.log"\n'
    'printf \'\\n\' >> "$SANDBOX/hook-argv.log"\n'
    'exit 0\n'
)


def _write_exec(path: Path, body: str):
    path.write_text(body)
    path.chmod(path.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)


def _render(prefix: Path, download_root: Path) -> str:
    """Release-workflow substitutions, then the three test-only rewrites. Each
    rewrite asserts its match count so template drift fails loudly here rather
    than letting a run fall through to the real /opt/unbound."""
    text = (REPO / "mdm/onboard.sh.tmpl").read_text()
    for token, value in {
        "@VERSION@": VERSION,
        "@PKG_SHA256@": "0" * 64,
        "@ARTIFACT_URL@": "https://artifacts.invalid/unbound-runtime.pkg",
        "@TEAM_ID@": "",
        "@DISCOVERY_SOURCE@": "test",
    }.items():
        text = text.replace(token, value)
    assert not re.search(r"@[A-Z_]+@", text), "unrendered placeholder"

    assert text.count('PREFIX="/opt/unbound"\n') == 1
    text = text.replace('PREFIX="/opt/unbound"\n', f'PREFIX="{prefix}"\n')
    assert text.count("mktemp -d /tmp/unbound-onboard.XXXXXX") == 1
    text = text.replace("mktemp -d /tmp/unbound-onboard.XXXXXX",
                        f'mktemp -d "{download_root}/unbound-onboard.XXXXXX"')
    assert text.count("[[ $EUID -eq 0 ]]") == 2
    return text.replace("[[ $EUID -eq 0 ]]", "[[ 0 -eq 0 ]]")


class Sandbox:
    def __init__(self, root: Path):
        self.root = root
        self.prefix = root / "prefix"
        self.bin = root / "bin"
        self.bin.mkdir()
        for name, body in STUBS.items():
            _write_exec(self.bin / name, f"#!/bin/bash\n{body}\n")
        hook_dir = self.prefix / VERSION / "unbound-hook"
        hook_dir.mkdir(parents=True)
        _write_exec(hook_dir / "unbound-hook", HOOK_STUB)
        (self.prefix / "current").symlink_to(self.prefix / VERSION)
        self.script = root / "onboard.sh"
        self.downloads = root / "downloads"
        self.downloads.mkdir()
        self.script.write_text(_render(self.prefix, self.downloads))

    def run(self, *args, installed=VERSION):
        env = {
            "PATH": f"{self.bin}:/usr/bin:/bin:/usr/sbin:/sbin",
            "SANDBOX": str(self.root),
            "STUB_INSTALLED_VERSION": installed,
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


@pytest.fixture
def sandbox(tmp_path):
    return Sandbox(tmp_path)


def _setup_argv(sandbox, *args, **kw):
    result = sandbox.run(*args, **kw)
    assert result.returncode == 0, result.stderr
    calls = sandbox.hook_calls()
    assert len(calls) == 1, calls
    return calls[0]


def jamf(*params):
    """Jamf passes mount point, computer name and username as $1-$3."""
    return ["/", "test-mac", "someone", *params]


def test_rendered_script_parses_under_system_bash(sandbox):
    assert subprocess.run([BASH, "-n", str(sandbox.script)]).returncode == 0


def test_without_a_frontend_url_the_setup_argv_is_the_baseline(sandbox):
    assert _setup_argv(sandbox, "--api-key", "K") == BASELINE_ARGV


def test_frontend_url_flag_is_forwarded_to_setup(sandbox):
    argv = _setup_argv(sandbox, "--api-key", "K", "--frontend-url", TENANT_FRONTEND)
    assert argv == BASELINE_ARGV + ["--frontend-url", TENANT_FRONTEND]


def test_frontend_url_is_forwarded_after_a_fresh_install_too(sandbox):
    """No matching pkg receipt: the download/verify/install path runs first."""
    host_tmp_before = set(glob.glob("/tmp/unbound-onboard.*"))
    argv = _setup_argv(sandbox, "--api-key", "K", "--frontend-url", TENANT_FRONTEND,
                       installed="")
    assert argv == BASELINE_ARGV + ["--frontend-url", TENANT_FRONTEND]
    downloads = [c[c.index("-o") + 1] for c in sandbox.curl_calls() if "-o" in c and "-X" not in c]
    assert len(downloads) == 1 and downloads[0].startswith(str(sandbox.downloads))
    assert list(sandbox.downloads.iterdir()) == [], "download dir was not reaped"
    assert set(glob.glob("/tmp/unbound-onboard.*")) == host_tmp_before


def test_jamf_parameter_11_is_forwarded_to_setup(sandbox):
    argv = _setup_argv(sandbox, *jamf("K", "", "", "", "", "", "", TENANT_FRONTEND))
    assert argv == BASELINE_ARGV + ["--frontend-url", TENANT_FRONTEND]


@pytest.mark.parametrize("params", [
    ["K"],                                # $5-$11 absent (existing policies)
    ["K", "", "", "", "", "", ""],        # through $10, no $11
    ["K", "", "", "", "", "", "", ""],    # $11 present but empty
    ["K", "", "", "", "", "", "", "   "],  # whitespace-only counts as empty
])
def test_jamf_form_without_parameter_11_is_the_baseline(sandbox, params):
    assert _setup_argv(sandbox, *jamf(*params)) == BASELINE_ARGV


@pytest.mark.parametrize("value", ["", "   "])
def test_an_empty_frontend_url_flag_is_the_baseline(sandbox, value):
    assert _setup_argv(sandbox, "--api-key", "K", "--frontend-url", value) == BASELINE_ARGV


@pytest.mark.parametrize("misplaced", ["--skip-managed-settings", "-x", " --backfill"])
def test_jamf_parameter_11_holding_a_flag_is_rejected_before_any_work(sandbox, misplaced):
    """A token shifted into the URL slot must not be recorded as the frontend URL."""
    result = sandbox.run(*jamf("K", "", "", "", "", "", "", misplaced))
    assert result.returncode == 2
    assert "--frontend-url requires a value" in result.stderr
    assert "UNBOUND_INSTALL_FAILED step=parse_args code=2" in result.stderr
    assert sandbox.hook_calls() == []


def test_jamf_tenant_urls_and_tokens_combine(sandbox):
    argv = _setup_argv(sandbox, *jamf(
        "K", "", "https://tenant-backend.example.com", "https://tenant-api.example.com",
        "", "backfill", "skip-managed-settings", TENANT_FRONTEND))
    assert argv == [
        "setup", "--api-key", "K",
        "--backend-url", "https://tenant-backend.example.com",
        "--gateway-url", "https://tenant-api.example.com",
        "--frontend-url", TENANT_FRONTEND,
        "--backfill", "--skip-managed-settings",
    ]


def test_frontend_url_combines_with_backfill_and_skip_managed_settings(sandbox):
    argv = _setup_argv(sandbox, "--skip-managed-settings", "--frontend-url", TENANT_FRONTEND,
                       "--backfill", "--api-key", "K")
    assert argv == BASELINE_ARGV + [
        "--frontend-url", TENANT_FRONTEND, "--backfill", "--skip-managed-settings"]


def test_frontend_url_reaches_setup_as_one_unexpanded_argument(sandbox):
    """A URL is data: no word splitting, no glob expansion against the cwd."""
    url = "https://tenant-app.example.com/path with space?q=*"
    argv = _setup_argv(sandbox, "--api-key", "K", "--frontend-url", url)
    assert argv == BASELINE_ARGV + ["--frontend-url", url]


@pytest.mark.parametrize("tail", [[], ["--backfill"], ["-x"]])
def test_frontend_url_with_no_value_is_rejected_before_any_work(sandbox, tail):
    """Never a silent mis-parse: the following flag is not swallowed as the URL."""
    result = sandbox.run("--api-key", "K", "--frontend-url", *tail)
    assert result.returncode == 2
    assert "--frontend-url requires a value" in result.stderr
    assert "UNBOUND_INSTALL_FAILED step=parse_args code=2" in result.stderr
    assert sandbox.hook_calls() == []


def test_frontend_url_is_not_part_of_the_install_report(sandbox):
    _setup_argv(sandbox, "--api-key", "K", "--frontend-url", TENANT_FRONTEND)
    reports = [c for c in sandbox.curl_calls() if any("install-report" in a for a in c)]
    assert len(reports) == 1
    assert not any("tenant-app" in arg for arg in reports[0])
    assert any(arg.startswith("https://backend.getunbound.ai/") for arg in reports[0])


def test_clear_ignores_the_frontend_url(sandbox):
    result = sandbox.run("--clear", "--frontend-url", TENANT_FRONTEND)
    assert result.returncode == 0, result.stderr
    assert "UNBOUND_CLEAR_OK" in result.stdout
    assert sandbox.hook_calls() == [["clear"]]
    assert not sandbox.prefix.exists()


def test_jamf_clear_ignores_parameter_11(sandbox):
    result = sandbox.run(*jamf("K", "", "", "", "clear", "", "", TENANT_FRONTEND))
    assert result.returncode == 0, result.stderr
    assert "UNBOUND_CLEAR_OK" in result.stdout
    assert sandbox.hook_calls() == [["clear"]]
