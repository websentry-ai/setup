"""Pin the exact exec contract between the frozen hooks and the
unbound-discovery binary (B1 / cross-stream with the WEB-4787 entry wrapper).

The discovery binary's entry wrapper must accept exactly what these tests
assert the hooks exec:
  - full sweep:  <bin> --domain <backend_url>          (key via UNBOUND_API_KEY env)
  - mcp scan:    <bin> mcp-scan --name <n> --domain <backend_url>
                 (env: UNBOUND_API_KEY, UNBOUND_MCP_SERVER_JSON,
                  UNBOUND_MCP_SERVER_NAME, UNBOUND_MCP_DOMAIN)

If Stream B changes the wrapper's routing, these tests are the tripwire on
this side.
"""

import importlib.util
import json

import pytest

from conftest import REPO, TOOL_PY

MCP_SCAN_TOOLS = ("claude-code", "cursor", "codex")  # copilot has no mcp scan


@pytest.fixture
def frozen_module(tmp_path, monkeypatch, request):
    """Load a FRESH instance of a tool's hook module in frozen mode, with all
    filesystem touchpoints sandboxed and subprocess.Popen recorded."""
    tool = request.param
    monkeypatch.setenv("UNBOUND_HOOK_FROZEN", "1")
    spec = importlib.util.spec_from_file_location(
        f"frozen_contract_{tool.replace('-', '_')}", str(TOOL_PY[tool]))
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    assert m.RUNNING_FROZEN is True

    fake_bin = tmp_path / "unbound-discovery"
    fake_bin.write_text("#!/bin/sh\n")
    config = tmp_path / "config.json"
    config.write_text(json.dumps(
        {"api_key": "contract-key", "base_url": "https://backend.example"}))
    monkeypatch.setattr(m, "FROZEN_DISCOVERY_BIN", str(fake_bin))
    monkeypatch.setattr(m, "UNBOUND_CONFIG_PATH", config)
    for attr in ("DISCOVERY_CACHE_PATH", "DISCOVERY_LOCK_PATH",
                 "DISCOVERY_DISPATCH_PATH", "ERROR_LOG", "LAST_REPORT_FILE"):
        if hasattr(m, attr):
            monkeypatch.setattr(m, attr, tmp_path / f"sandbox-{attr}")

    calls = []

    class _Proc:
        pid = 0

    def record_popen(cmd, **kwargs):
        calls.append((cmd, kwargs))
        return _Proc()

    monkeypatch.setattr(m.subprocess, "Popen", record_popen)
    return m, calls


@pytest.mark.parametrize("frozen_module", list(TOOL_PY), indirect=True)
def test_frozen_discovery_exec_contract(frozen_module, monkeypatch):
    m, calls = frozen_module
    monkeypatch.setattr(m, "_hook_discovery_enabled_for_org", lambda: True)
    m._dispatch_discovery()
    assert len(calls) == 1, "expected exactly one discovery exec"
    cmd, kwargs = calls[0]
    assert cmd == [m.FROZEN_DISCOVERY_BIN, "--domain", "https://backend.example"]
    env = kwargs.get("env") or {}
    assert env.get("UNBOUND_API_KEY") == "contract-key"
    assert "--api-key" not in cmd, "key must travel via env, never argv"


@pytest.mark.parametrize("frozen_module", MCP_SCAN_TOOLS, indirect=True)
def test_frozen_mcp_scan_exec_contract(frozen_module):
    m, calls = frozen_module
    server_config = {"url": "https://mcp.example/sse", "type": "http"}
    m._dispatch_mcp_server_scan("contract-server", server_config)
    assert len(calls) == 1, "expected exactly one mcp-scan exec"
    cmd, kwargs = calls[0]
    assert cmd == [m.FROZEN_DISCOVERY_BIN, "mcp-scan",
                   "--name", "contract-server",
                   "--domain", "https://backend.example"]
    env = kwargs.get("env") or {}
    assert env.get("UNBOUND_API_KEY") == "contract-key"
    assert env.get("UNBOUND_MCP_SERVER_NAME") == "contract-server"
    assert env.get("UNBOUND_MCP_DOMAIN") == "https://backend.example"
    assert json.loads(env.get("UNBOUND_MCP_SERVER_JSON", "{}")) == server_config


@pytest.mark.parametrize("frozen_module", list(TOOL_PY), indirect=True)
def test_frozen_discovery_missing_binary_skips_without_exec(frozen_module, monkeypatch):
    m, calls = frozen_module
    monkeypatch.setattr(m, "_hook_discovery_enabled_for_org", lambda: True)
    monkeypatch.setattr(m, "FROZEN_DISCOVERY_BIN", str(REPO / "does-not-exist"))
    m._dispatch_discovery()
    assert calls == [], "must not exec (or fall back to download) when binary missing"
