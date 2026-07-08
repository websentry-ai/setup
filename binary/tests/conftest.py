import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[2]
SRC = REPO / "binary" / "src"
ENTRY = SRC / "entry.py"
BUILT_BINARY = Path(
    os.environ.get("UNBOUND_HOOK_BINARY", REPO / "binary" / "dist" / "unbound-hook" / "unbound-hook")
)

sys.path.insert(0, str(SRC))

TOOL_PY = {
    "claude-code": REPO / "claude-code" / "hooks" / "unbound.py",
    "cursor": REPO / "cursor" / "unbound.py",
    "copilot": REPO / "copilot" / "hooks" / "unbound.py",
    "codex": REPO / "codex" / "hooks" / "unbound.py",
    "augment": REPO / "augment" / "hooks" / "unbound.py",
}


def _run(cmd, payload, home, extra_env=None, stdin_close=False):
    env = {**os.environ, "HOME": str(home)}
    # Dead local port: hooks fail open on gateway errors, and tests must
    # never talk to the real gateway.
    env.setdefault("UNBOUND_GATEWAY_URL", "http://127.0.0.1:9")
    env.pop("UNBOUND_HOOK_FROZEN", None)
    env.pop("UNBOUND_CLAUDE_API_KEY", None)
    env.pop("UNBOUND_CURSOR_API_KEY", None)
    env.pop("UNBOUND_COPILOT_API_KEY", None)
    env.pop("UNBOUND_CODEX_API_KEY", None)
    env.pop("UNBOUND_AUGMENT_API_KEY", None)
    if extra_env:
        env.update(extra_env)
    return subprocess.run(
        cmd,
        input=None if stdin_close else payload,
        capture_output=True, text=True, timeout=60, env=env,
    )


def run_python_path(tool, payload, home, extra_env=None):
    """The existing serving path: python3 <tool's unbound.py>."""
    return _run([sys.executable, str(TOOL_PY[tool])], payload, home, extra_env)


def run_cli_dev(args, payload, home, extra_env=None, stdin_close=False):
    """The CLI via the dev entry (unfrozen unless UNBOUND_HOOK_FROZEN set)."""
    return _run([sys.executable, str(ENTRY)] + args, payload, home, extra_env, stdin_close)


def run_binary(args, payload, home, extra_env=None, stdin_close=False):
    """The built frozen binary (skip the test when not built)."""
    if not BUILT_BINARY.exists():
        pytest.skip(f"built binary not found at {BUILT_BINARY}; run binary/build.sh")
    return _run([str(BUILT_BINARY)] + args, payload, home, extra_env, stdin_close)


def run_go_binary(args, payload, home, extra_env=None, stdin_close=False):
    """The Go rewrite (WEB-4809); opt-in via UNBOUND_GO_BINARY, else skipped."""
    go_binary = os.environ.get("UNBOUND_GO_BINARY")
    if not go_binary:
        pytest.skip("UNBOUND_GO_BINARY not set; Go parity is opt-in")
    return _run([go_binary] + args, payload, home, extra_env, stdin_close)


@pytest.fixture
def sandbox_home(tmp_path):
    home = tmp_path / "home"
    home.mkdir()
    return home


@pytest.fixture
def discovery_enabled_home(sandbox_home):
    """Sandbox home where the org discovery flag is freshly cached as enabled
    and an api key exists — the state in which SessionStart would normally
    dispatch a discovery run."""
    import datetime
    (sandbox_home / ".unbound").mkdir()
    (sandbox_home / ".unbound" / "config.json").write_text(json.dumps(
        {"api_key": "test-key", "base_url": "https://backend.example"}))
    now = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    (sandbox_home / ".unbound" / "discovery-cache.json").write_text(json.dumps(
        {"hook_discovery": {"enabled": True, "fetched_at": now}}))
    return sandbox_home
