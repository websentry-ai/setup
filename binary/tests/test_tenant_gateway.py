"""CLI-boundary tests for tenant gateway resolution in `unbound-hook hook`.

The contract under test: with UNBOUND_GATEWAY_URL absent from the environment,
the dispatcher routes the hook to `gateway_url` from ~/.unbound/config.json;
an exported UNBOUND_GATEWAY_URL always wins; and anything short of a clean
https URL (absent, blank, wrong type, http://, corrupt or missing config)
leaves the default gateway, stdout and the exit code exactly as they were.

conftest's runner always injects UNBOUND_GATEWAY_URL, so these tests use their
own runner that removes it. Routing is observed through a fake `curl` placed
first on PATH (the hook modules shell out to `curl`), which records the URL it
was asked for and never touches the network. The shim is mandatory: no test
here can reach a real gateway host.
"""

import json
import os
import stat
import subprocess
import sys

import pytest

from conftest import ENTRY
from test_hook_cli import EVENT_PAYLOADS

DEFAULT_GATEWAY = "https://api.getunbound.ai"
TENANT_GATEWAY = "https://tenant-api.example.com"

# One pre-tool event per tool; each posts to <gateway>/v1/hooks/pretool.
PRETOOL_EVENT = {
    "claude-code": "PreToolUse",
    "codex": "PreToolUse",
    "copilot": "PreToolUse",
    "augment": "PreToolUse",
    "cursor": "beforeShellExecution",
}

KEY_ENV = {
    "claude-code": "UNBOUND_CLAUDE_API_KEY",
    "codex": "UNBOUND_CODEX_API_KEY",
    "copilot": "UNBOUND_COPILOT_API_KEY",
    "augment": "UNBOUND_AUGMENT_API_KEY",
    "cursor": "UNBOUND_CURSOR_API_KEY",
}

CURL_SHIM = """#!/bin/sh
# Fake curl: record every URL argument, answer with an empty 2xx body.
for arg in "$@"; do
  case "$arg" in
    http://*|https://*) printf '%s\\n' "$arg" >> "$CURL_SHIM_LOG" ;;
  esac
done
cat > /dev/null
printf '{}'
exit 0
"""


@pytest.fixture
def curl_shim(tmp_path):
    shim_dir = tmp_path / "shim"
    shim_dir.mkdir()
    shim = shim_dir / "curl"
    shim.write_text(CURL_SHIM)
    shim.chmod(shim.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
    return shim_dir, tmp_path / "curl-urls.log"


def _write_config(home, raw):
    (home / ".unbound").mkdir(exist_ok=True)
    (home / ".unbound" / "config.json").write_text(raw, encoding="utf-8")


def _run_hook(tool, home, curl_shim, gateway_env=None):
    """Run `unbound-hook hook <tool> <event>` with no inherited gateway env.

    Returns (completed process, sorted list of URLs curl was asked for).
    """
    shim_dir, log = curl_shim
    if log.exists():
        log.unlink()
    env = {k: v for k, v in os.environ.items()
           if k != "UNBOUND_GATEWAY_URL" and not k.endswith("_API_KEY")}
    env.pop("UNBOUND_HOOK_FROZEN", None)
    env.update({
        "HOME": str(home),
        "PATH": f"{shim_dir}{os.pathsep}{env.get('PATH', '')}",
        "CURL_SHIM_LOG": str(log),
        KEY_ENV[tool]: "test-key",
        # Belt and braces for any non-curl client: a dead proxy.
        "HTTPS_PROXY": "http://127.0.0.1:9", "https_proxy": "http://127.0.0.1:9",
        "HTTP_PROXY": "http://127.0.0.1:9", "http_proxy": "http://127.0.0.1:9",
    })
    if gateway_env is not None:
        env["UNBOUND_GATEWAY_URL"] = gateway_env
    event = PRETOOL_EVENT[tool]
    got = subprocess.run(
        [sys.executable, str(ENTRY), "hook", tool, event],
        input=json.dumps(EVENT_PAYLOADS[tool][event]),
        capture_output=True, text=True, timeout=60, env=env,
    )
    urls = sorted(set(log.read_text().split())) if log.exists() else []
    return got, urls


def _assert_routed_to(urls, gateway):
    assert f"{gateway}/v1/hooks/pretool" in urls
    assert all(u.startswith(gateway + "/") for u in urls), urls


@pytest.mark.parametrize("tool", list(PRETOOL_EVENT))
def test_tenant_gateway_from_config_is_honoured(tool, sandbox_home, curl_shim):
    _write_config(sandbox_home, json.dumps(
        {"api_key": "test-key", "gateway_url": TENANT_GATEWAY}))
    got, urls = _run_hook(tool, sandbox_home, curl_shim)
    assert got.returncode == 0
    json.loads(got.stdout)
    _assert_routed_to(urls, TENANT_GATEWAY)


def test_trailing_slash_is_stripped(sandbox_home, curl_shim):
    _write_config(sandbox_home, json.dumps(
        {"api_key": "test-key", "gateway_url": TENANT_GATEWAY + "/"}))
    _, urls = _run_hook("claude-code", sandbox_home, curl_shim)
    _assert_routed_to(urls, TENANT_GATEWAY)


@pytest.mark.parametrize("tool", list(PRETOOL_EVENT))
def test_env_var_wins_over_config(tool, sandbox_home, curl_shim):
    _write_config(sandbox_home, json.dumps(
        {"api_key": "test-key", "gateway_url": TENANT_GATEWAY}))
    got, urls = _run_hook(tool, sandbox_home, curl_shim,
                          gateway_env="https://env-api.example.com")
    assert got.returncode == 0
    _assert_routed_to(urls, "https://env-api.example.com")


# Every config state that must leave the default gateway in place. `None`
# means no config.json at all.
DEFAULT_GATEWAY_CONFIGS = {
    "missing_file": None,
    "gateway_absent": json.dumps({"api_key": "test-key"}),
    "gateway_empty": json.dumps({"api_key": "test-key", "gateway_url": ""}),
    "gateway_blank": json.dumps({"api_key": "test-key", "gateway_url": "   "}),
    "gateway_null": json.dumps({"api_key": "test-key", "gateway_url": None}),
    "gateway_default": json.dumps({"api_key": "test-key", "gateway_url": DEFAULT_GATEWAY}),
    "gateway_default_slash": json.dumps({"api_key": "test-key", "gateway_url": DEFAULT_GATEWAY + "/"}),
    "gateway_http": json.dumps({"api_key": "test-key", "gateway_url": "http://tenant-api.example.com"}),
    "gateway_no_scheme": json.dumps({"api_key": "test-key", "gateway_url": "tenant-api.example.com"}),
    "gateway_no_host": json.dumps({"api_key": "test-key", "gateway_url": "https://"}),
    "gateway_whitespace": json.dumps({"api_key": "test-key", "gateway_url": "https://tenant-api.example.com /x"}),
    "gateway_newline": json.dumps({"api_key": "test-key", "gateway_url": "https://tenant-api.example.com\nX: y"}),
    "gateway_int": json.dumps({"api_key": "test-key", "gateway_url": 42}),
    "gateway_list": json.dumps({"api_key": "test-key", "gateway_url": [TENANT_GATEWAY]}),
    "gateway_dict": json.dumps({"api_key": "test-key", "gateway_url": {"url": TENANT_GATEWAY}}),
    "config_is_list": json.dumps([TENANT_GATEWAY]),
    "malformed_json": '{"api_key": "test-key", "gateway_url": "' + TENANT_GATEWAY,
    "empty_file": "",
    "oversized": json.dumps({"api_key": "test-key", "gateway_url": TENANT_GATEWAY,
                             "pad": "x" * (1024 * 1024)}),
}


@pytest.mark.parametrize("case", list(DEFAULT_GATEWAY_CONFIGS))
def test_unusable_config_keeps_default_gateway(case, sandbox_home, curl_shim):
    raw = DEFAULT_GATEWAY_CONFIGS[case]
    if raw is not None:
        _write_config(sandbox_home, raw)
    got, urls = _run_hook("claude-code", sandbox_home, curl_shim)
    assert got.returncode == 0
    json.loads(got.stdout)
    _assert_routed_to(urls, DEFAULT_GATEWAY)


def test_unreadable_config_keeps_default_gateway(sandbox_home, curl_shim):
    if hasattr(os, "geteuid") and os.geteuid() == 0:
        pytest.skip("root reads through file modes")
    _write_config(sandbox_home, json.dumps(
        {"api_key": "test-key", "gateway_url": TENANT_GATEWAY}))
    (sandbox_home / ".unbound" / "config.json").chmod(0)
    got, urls = _run_hook("claude-code", sandbox_home, curl_shim)
    assert got.returncode == 0
    json.loads(got.stdout)
    _assert_routed_to(urls, DEFAULT_GATEWAY)


def test_config_directory_keeps_default_gateway(sandbox_home, curl_shim):
    (sandbox_home / ".unbound" / "config.json").mkdir(parents=True)
    got, urls = _run_hook("claude-code", sandbox_home, curl_shim)
    assert got.returncode == 0
    json.loads(got.stdout)
    _assert_routed_to(urls, DEFAULT_GATEWAY)


@pytest.mark.parametrize("case", ["missing_file", "gateway_default", "malformed_json", "gateway_http"])
def test_default_tenant_output_is_unchanged(case, sandbox_home, curl_shim):
    """A default-tenant device answers exactly as it does with the default
    gateway exported explicitly (the pre-existing, env-driven path)."""
    raw = DEFAULT_GATEWAY_CONFIGS[case]
    if raw is not None:
        _write_config(sandbox_home, raw)
    ref, ref_urls = _run_hook("claude-code", sandbox_home, curl_shim,
                              gateway_env=DEFAULT_GATEWAY)
    got, urls = _run_hook("claude-code", sandbox_home, curl_shim)
    assert got.stdout == ref.stdout
    assert got.returncode == ref.returncode
    assert urls == ref_urls


@pytest.mark.parametrize("entry", ["run_skills_sync", "run_mcp_diagnostic"])
def test_detached_entries_resolve_gateway_before_import(entry, sandbox_home, monkeypatch):
    """sync-skills / mcp-diagnostic are separate processes: each must resolve
    the gateway itself, before the hook module is imported."""
    from unbound_hook import hook_cmd

    _write_config(sandbox_home, json.dumps(
        {"api_key": "test-key", "gateway_url": TENANT_GATEWAY}))
    monkeypatch.setenv("HOME", str(sandbox_home))
    # set-then-delete so monkeypatch restores the variable the helper exports
    monkeypatch.setenv("UNBOUND_GATEWAY_URL", "placeholder")
    monkeypatch.delenv("UNBOUND_GATEWAY_URL")
    seen = []

    def fake_load(tool):
        seen.append(os.environ.get("UNBOUND_GATEWAY_URL"))
        raise RuntimeError("stop before the real module loads")

    monkeypatch.setattr(hook_cmd, "load_hook_module", fake_load)
    assert getattr(hook_cmd, entry)(["claude-code"]) == 0
    assert seen == [TENANT_GATEWAY]
