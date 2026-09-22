"""Cross-repo contract: the device-deployment page in unbound-fe emits a copied
MDM command, and these installers consume it verbatim. The page passes the tenant
frontend host as `--frontend-url`; the subscription installers must parse that flag
and persist it to ~/.unbound/config.json, or a custom-tenant device silently falls
back to the default frontend.

CANONICAL_FE_COMMAND below is the exact string unbound-fe's commandBuilder emits
for a claude-code subscription install (pinned on the fe side by the
"emits the exact custom-tenant subscription command" test). These tests run the
REAL onboard.py / setup.py against it — no reimplementation of the parsers.
"""

import shlex
import subprocess
import sys
from pathlib import Path

import pytest

from tests.conftest import load_module

# onboard.sh.tmpl exits before parsing any args on non-macOS hosts, so its
# arg-loop assertions are only meaningful on Darwin (CI runs on Linux).
_macos_only = pytest.mark.skipif(
    sys.platform != "darwin",
    reason="onboard.sh.tmpl is macOS-only and exits before parsing args elsewhere",
)

# Exact output of unbound-fe buildCommand("macOS", key, "claude-code", "subscription")
# with tenant URLs NEXT_PUBLIC_BASE_URL / _GATEWAY_URL / _FRONTEND_DOMAIN set.
CANONICAL_FE_COMMAND = (
    'python3 -c "$(curl -fsSL https://getunbound.ai/setup/claude-code/hooks/mdm-install)" '
    "--api-key ubnd_ak_realkey123 "
    "--backend-url https://backend.acme.example.com "
    "--gateway-url https://api.acme.example.com "
    "--frontend-url https://app.acme.example.com"
)
FE_KEY = "ubnd_ak_realkey123"
FE_BACKEND = "https://backend.acme.example.com"
FE_GATEWAY = "https://api.acme.example.com"
FE_FRONTEND = "https://app.acme.example.com"

# Everything the installer actually receives (drop `python3 -c "<curl>"`).
INSTALLER_ARGV = shlex.split(CANONICAL_FE_COMMAND)[3:]

SUBSCRIPTION_TOOLS = [
    "claude-code/hooks/mdm/setup.py",
    "cursor/mdm/setup.py",
    "codex/hooks/mdm/setup.py",
    "copilot/hooks/mdm/setup.py",
]
GATEWAY_TOOLS = [
    "claude-code/gateway/mdm/setup.py",
    "codex/gateway/mdm/setup.py",
]


def test_installer_argv_is_derived_from_the_fe_command():
    """Guard the fixture: if the fe command drifts, the split below drifts with it."""
    assert INSTALLER_ARGV[0] == "--api-key"
    assert "--frontend-url" in INSTALLER_ARGV
    assert INSTALLER_ARGV[INSTALLER_ARGV.index("--frontend-url") + 1] == FE_FRONTEND


# ---------------------------------------------------------------------------
# T6 — the onboard-all orchestrator must forward the flag untouched to the
# per-tool scripts (it parses a few flags itself and passes the rest through).
# ---------------------------------------------------------------------------
def test_onboard_forwards_frontend_url_intact():
    onboard = load_module("mdm/onboard.py")
    api_key, _discovery, mdm_args, backend, _clear, _skip = onboard.parse_args(INSTALLER_ARGV)
    assert api_key == FE_KEY
    assert backend == FE_BACKEND
    # The flag and its value survive as an adjacent pair for the per-tool script.
    assert "--frontend-url" in mdm_args
    assert mdm_args[mdm_args.index("--frontend-url") + 1] == FE_FRONTEND


# ---------------------------------------------------------------------------
# Harness: drive a real installer main() far enough to reach the config write,
# stubbing only the OS/network leaves (including the hook-script download).
# write_unbound_config_for_user is captured, then a BaseException stops main
# before it mutates the machine.
# ---------------------------------------------------------------------------
class _StopAtPersist(BaseException):
    pass


# Patched only if the module actually defines them (the tools differ slightly).
def _stub_download_file(url, dest_path, *_args, **_kwargs):
    # Copilot curls the hook script (download_file) before the config write.
    # A live miss would fail the persist assertion even when the URL was parsed.
    dest = Path(dest_path)
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_text("# stub hook\n", encoding="utf-8")
    return True


_SAFE_STUBS = {
    "check_admin_privileges": lambda *a, **k: True,
    "get_device_identifier": lambda *a, **k: "DEV-SERIAL",
    "fetch_api_key_from_mdm": lambda *a, **k: "RESOLVED-KEY",
    "detect_install_state": lambda *a, **k: None,
    "_freeze_ownership_evidence": lambda *a, **k: None,
    "remove_env_var_from_user": lambda *a, **k: None,
    "remove_gateway_artifacts_for_user": lambda *a, **k: None,
    "remove_user_level_hooks_for_user": lambda *a, **k: None,
    "remove_user_level_hooks": lambda *a, **k: None,
    "set_env_var_system_wide": lambda *a, **k: (True, False),
    "set_env_var": lambda *a, **k: (True, False, "ok"),
    "download_file": _stub_download_file,
}


def _run_installer(relpath, argv, monkeypatch, tmp_path):
    """Run the shipped installer's main() against argv, returning the recorded
    (args, kwargs) of its write_unbound_config_for_user call."""
    mod = load_module(relpath)
    captured = {}

    def _capture_write(*args, **kwargs):
        captured["args"] = args
        captured["kwargs"] = kwargs
        raise _StopAtPersist

    for name, stub in _SAFE_STUBS.items():
        if hasattr(mod, name):
            monkeypatch.setattr(mod, name, stub)
    monkeypatch.setattr(mod, "get_all_user_homes", lambda *a, **k: [("tester", tmp_path)])
    monkeypatch.setattr(mod, "write_unbound_config_for_user", _capture_write)
    monkeypatch.setattr(mod.os, "geteuid", lambda: 0, raising=False)
    monkeypatch.setattr(mod.sys, "argv", ["setup.py"] + list(argv))

    try:
        mod.main()
    except _StopAtPersist:
        pass
    assert captured, "installer never reached the config write for argv=%r" % (argv,)
    return captured


# ---------------------------------------------------------------------------
# T7 / T8 — every subscription installer the page targets persists the frontend
# URL the page sent.
# ---------------------------------------------------------------------------
@pytest.mark.parametrize("relpath", SUBSCRIPTION_TOOLS)
def test_subscription_installer_persists_frontend_url(relpath, monkeypatch, tmp_path):
    call = _run_installer(relpath, INSTALLER_ARGV, monkeypatch, tmp_path)
    urls = call["kwargs"].get("urls")
    assert urls is not None, "%s did not pass urls= to the config write" % relpath
    assert urls.get("frontend_url") == FE_FRONTEND
    assert urls.get("base_url") == FE_BACKEND
    assert urls.get("gateway_url") == FE_GATEWAY


# ---------------------------------------------------------------------------
# T10 — the pre-fix command used --domain, which no MDM installer parses. Feeding
# it to the current installer must NOT persist a frontend URL. This is the exact
# bug the fe fix removes; it also fails on the reverted fe change for the same
# reason (the reverted page emits --domain).
# ---------------------------------------------------------------------------
def test_old_domain_command_does_not_persist_frontend_url(monkeypatch, tmp_path):
    old_argv = ["--domain" if t == "--frontend-url" else t for t in INSTALLER_ARGV]
    call = _run_installer("claude-code/hooks/mdm/setup.py", old_argv, monkeypatch, tmp_path)
    urls = call["kwargs"].get("urls")
    assert urls is not None
    assert urls.get("frontend_url") is None


# ---------------------------------------------------------------------------
# T9 — gateway-mode installers do not parse --frontend-url yet, so the page's
# frontend URL is dropped there. This asserts the correct contract (it SHOULD be
# forwarded) and is marked xfail(strict): it flips to a hard failure the moment a
# gateway installer starts forwarding it, forcing this marker to be removed then.
# ---------------------------------------------------------------------------
@pytest.mark.xfail(strict=True, reason="gateway-mode installers do not forward the frontend URL yet")
@pytest.mark.parametrize("relpath", GATEWAY_TOOLS)
def test_gateway_installer_forwards_frontend_url(relpath, monkeypatch, tmp_path):
    call = _run_installer(relpath, INSTALLER_ARGV, monkeypatch, tmp_path)
    serialized = repr((call["args"], call["kwargs"]))
    assert FE_FRONTEND in serialized


# ---------------------------------------------------------------------------
# T11 — the macOS Jamf bootstrap (onboard.sh) has a strict arg loop that aborts
# on any UNKNOWN flag, so it must explicitly recognize --frontend-url and forward
# it to the per-tool scripts. backend-url points at a dead local port so the
# failure-report POST can't reach a real backend. Root is required, so the run
# stops at the privilege gate — but only after the flag is accepted.
# ---------------------------------------------------------------------------
def _run_onboard_sh(*extra):
    script = Path(__file__).resolve().parent.parent / "mdm" / "onboard.sh.tmpl"
    return subprocess.run(
        ["bash", str(script), "--backend-url", "http://127.0.0.1:9", *extra],
        capture_output=True, text=True, timeout=30,
    )


@_macos_only
def test_onboard_sh_recognizes_frontend_url():
    proc = _run_onboard_sh("--frontend-url", FE_FRONTEND, "--api-key", "K")
    # The flag is understood: it is never reported as unknown. (The run then
    # halts at the root gate, which is exit 1, not the exit-2 unknown-arg path.)
    assert "Unknown argument" not in proc.stderr
    assert proc.returncode != 2


@_macos_only
def test_onboard_sh_treats_frontend_url_as_a_value_flag():
    proc = _run_onboard_sh("--frontend-url")
    # A value-taking flag rejects a missing value with exit 2 — proof it is
    # parsed as an adjacent token pair, not silently swallowed.
    assert proc.returncode == 2
    assert "--frontend-url requires a value" in proc.stderr
