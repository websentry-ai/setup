#!/usr/bin/env python3
"""
End-to-end test for --clear across all setup scripts.

Seeds all env vars, files, and config entries with dummy data,
then runs --clear twice on each script and asserts the correct output.

Run from the repo root:
    python3 test_clear_e2e.py
"""

import subprocess, sys, json, os, platform
from pathlib import Path

REPO = Path(__file__).parent
DUMMY_KEY = "e2e-test-dummy-key-12345"
DUMMY_URL = "https://e2e-test.unbound.example.com"
HOME = Path.home()

_system = platform.system().lower()
_shell = os.environ.get("SHELL", "").lower()
if _system == "darwin":
    RC_FILE = HOME / (".zprofile" if "zsh" in _shell else ".bash_profile")
elif _system == "linux":
    RC_FILE = HOME / (".zshrc" if "zsh" in _shell else ".bashrc")
else:
    RC_FILE = None

ENV_VARS = [
    ("UNBOUND_CURSOR_API_KEY",  DUMMY_KEY),
    ("UNBOUND_CLAUDE_API_KEY",  DUMMY_KEY),
    ("UNBOUND_API_KEY",         DUMMY_KEY),
    ("ANTHROPIC_BASE_URL",      DUMMY_URL),
    ("UNBOUND_CODEX_API_KEY",   DUMMY_KEY),
    ("OPENAI_API_KEY",          DUMMY_KEY),
    ("OPENAI_BASE_URL",         DUMMY_URL),
    ("UNBOUND_COPILOT_API_KEY", DUMMY_KEY),
    ("GEMINI_API_KEY",          DUMMY_KEY),
    ("GOOGLE_GEMINI_BASE_URL",  DUMMY_URL),
    ("UNBOUND_OPENCLAW_API_KEY",DUMMY_KEY),
]

DUMMY_FILES = [
    HOME / ".cursor"  / "hooks.json",
    HOME / ".cursor"  / "hooks" / "unbound.py",
    HOME / ".claude"  / "hooks" / "unbound.py",
    HOME / ".claude"  / "anthropic_key.sh",
    HOME / ".codex"   / "hooks" / "unbound.py",
    HOME / ".copilot" / "hooks" / "unbound.py",
    HOME / ".copilot" / "hooks" / "unbound.json",
]

SCRIPTS = [
    ("cursor",              "cursor/setup.py"),
    ("claude-code/hooks",   "claude-code/hooks/setup.py"),
    ("claude-code/gateway", "claude-code/gateway/setup.py"),
    ("codex/hooks",         "codex/hooks/setup.py"),
    ("codex/gateway",       "codex/gateway/setup.py"),
    ("copilot/hooks",       "copilot/hooks/setup.py"),
    ("gemini-cli/gateway",  "gemini-cli/gateway/setup.py"),
    ("openclaw",            "openclaw/setup.py"),
]


def _merge_json(path, overlay):
    path.parent.mkdir(parents=True, exist_ok=True)
    base = {}
    if path.exists():
        try:
            base = json.loads(path.read_text())
        except json.JSONDecodeError:
            pass
    _deep_merge(base, overlay)
    path.write_text(json.dumps(base, indent=2))


def _deep_merge(base, overlay):
    for k, v in overlay.items():
        if k in base and isinstance(base[k], dict) and isinstance(v, dict):
            _deep_merge(base[k], v)
        elif k in base and isinstance(base[k], list) and isinstance(v, list):
            for item in v:
                if item not in base[k]:
                    base[k].insert(0, item)
        else:
            base[k] = v


def seed():
    print("Seeding dummy data...")

    if RC_FILE:
        with open(RC_FILE, "a") as f:
            for var, val in ENV_VARS:
                f.write(f'export {var}="{val}"\n')
        print(f"  {len(ENV_VARS)} env vars → {RC_FILE}")

    for p in DUMMY_FILES:
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text("# e2e test dummy\n")
    print(f"  {len(DUMMY_FILES)} dummy files created")

    # ~/.claude/settings.json — hooks entry + apiKeyHelper
    _merge_json(HOME / ".claude" / "settings.json", {
        "apiKeyHelper": str(HOME / ".claude" / "anthropic_key.sh"),
        "hooks": {
            "PreToolUse": [{"command": str(HOME / ".claude" / "hooks" / "unbound.py")}]
        },
    })
    print(f"  ~/.claude/settings.json seeded")

    # ~/.codex/hooks.json
    _merge_json(HOME / ".codex" / "hooks.json", {
        "hooks": {
            "PreToolUse": [{"command": str(HOME / ".codex" / "hooks" / "unbound.py")}]
        },
    })
    print(f"  ~/.codex/hooks.json seeded")

    # ~/.codex/config.toml — codex_hooks + openai_base_url
    config_toml = HOME / ".codex" / "config.toml"
    config_toml.parent.mkdir(parents=True, exist_ok=True)
    existing_lines = config_toml.read_text().splitlines() if config_toml.exists() else []
    existing_lines = [l for l in existing_lines
                      if not l.startswith("codex_hooks") and not l.startswith("openai_base_url")]
    existing_lines += [f'codex_hooks = true', f'openai_base_url = "{DUMMY_URL}"']
    config_toml.write_text("\n".join(existing_lines) + "\n")
    print(f"  ~/.codex/config.toml seeded")

    # ~/.openclaw/openclaw.json
    _merge_json(HOME / ".openclaw" / "openclaw.json", {
        "plugins": {
            "entries": {"unbound-openclaw-plugin": {}},
            "installs": {"unbound-openclaw-plugin": {"installPath": "/e2e-test/unbound-openclaw-plugin"}},
            "load": {"paths": ["/e2e-test/unbound-openclaw-plugin"]},
        },
        "models": {"providers": {"unbound": {"type": "e2e-test"}}},
        "agents": {"defaults": {"model": {"primary": "unbound/e2e-test-model"}}},
    })
    print(f"  ~/.openclaw/openclaw.json seeded")

    print()


def run_clear(script_path):
    result = subprocess.run(
        [sys.executable, str(REPO / script_path), "--clear"],
        capture_output=True, text=True,
    )
    return result.stdout


def body_lines(output):
    """Extract non-empty lines between the 2nd and 3rd === separators."""
    lines = output.strip().splitlines()
    body, sep_count, in_body = [], 0, False
    for line in lines:
        if line.startswith("="):
            sep_count += 1
            in_body = sep_count == 2
        elif in_body and line.strip():
            body.append(line.strip())
    return body


def assert_run(name, output, must_contain, must_not_contain=None):
    body = body_lines(output)
    body_str = "\n".join(body)
    ok = True
    for s in must_contain:
        if s not in body_str:
            print(f"  FAIL [{name}] expected '{s}'\n       got: {body_str!r}")
            ok = False
    for s in (must_not_contain or []):
        if s in body_str:
            print(f"  FAIL [{name}] unexpected '{s}'\n       got: {body_str!r}")
            ok = False
    if ok:
        print(f"  PASS [{name}]  → {body_str!r}")
    return ok


if __name__ == "__main__":
    seed()

    passed = True

    print("Run 1 — expect 'Cleared':")
    for name, script in SCRIPTS:
        out = run_clear(script)
        ok = assert_run(f"{name} run1", out,
                        must_contain=["Cleared"],
                        must_not_contain=["not set"])
        if not ok:
            print(f"    Full output:\n{out}")
        passed = passed and ok

    print()

    print("Run 2 — expect 'API_KEY not set, nothing to clear':")
    for name, script in SCRIPTS:
        out = run_clear(script)
        ok = assert_run(f"{name} run2", out,
                        must_contain=["API_KEY not set, nothing to clear"],
                        must_not_contain=["Cleared"])
        if not ok:
            print(f"    Full output:\n{out}")
        passed = passed and ok

    print()
    if passed:
        print("All tests passed.")
    else:
        print("Some tests failed.")
        sys.exit(1)
