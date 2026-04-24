#!/usr/bin/env python3
"""
Unbound MDM onboarding — runs the MDM setup for Claude Code, Cursor, and Codex
in one shot, forwarding the same arguments to each tool's per-tool MDM script.

Designed to be invoked exactly like the per-tool scripts:

  sudo python3 -c "$(curl -fsSL https://getunbound.ai/setup/mdm/onboard)" \
      --api-key YOUR_ADMIN_API_KEY

Optional overrides for tenant deployments:
  --backend-url <url>   (default https://backend.getunbound.ai)
  --gateway-url <url>   (default https://api.getunbound.ai)

To clear all three at once:
  sudo python3 -c "$(curl -fsSL https://getunbound.ai/setup/mdm/onboard)" --clear

Each per-tool MDM script runs in its own subprocess so a failure in one tool
doesn't abort the others. A summary at the end lists which tools succeeded
and which failed.
"""

import os
import platform
import subprocess
import sys
import tempfile
import urllib.request


_RAW = "https://raw.githubusercontent.com/websentry-ai/setup/refs/heads/main"
TOOLS = [
    ("Claude Code", f"{_RAW}/claude-code/hooks/mdm/setup.py"),
    ("Cursor",      f"{_RAW}/cursor/mdm/setup.py"),
    ("Codex",       f"{_RAW}/codex/hooks/mdm/setup.py"),
]

USAGE = (
    "Usage:\n"
    "  sudo python3 -c \"$(curl -fsSL https://getunbound.ai/setup/mdm/onboard)\" \\\n"
    "      --api-key YOUR_ADMIN_API_KEY [--backend-url <url>] [--gateway-url <url>]\n"
    "  sudo python3 -c \"$(curl -fsSL https://getunbound.ai/setup/mdm/onboard)\" --clear\n"
)


def check_admin_privileges() -> bool:
    """Best-effort root/admin check, mirroring the per-tool MDM scripts."""
    try:
        if platform.system().lower() == "windows":
            import ctypes
            return ctypes.windll.shell32.IsUserAnAdmin() != 0
        return os.geteuid() == 0
    except Exception:
        return False


def fetch_script(url: str) -> bytes:
    """Downloads `url` with explicit HTTP error checking. Raises on any failure
    (network, non-200, empty body) so the caller never silently runs an empty
    script — the silent-failure mode that `python3 -c "$(curl …)"` has when
    curl fails (`$(…)` returns empty, `python3 -c ""` exits 0)."""
    req = urllib.request.Request(url, headers={"User-Agent": "unbound-mdm-onboard/1.0"})
    with urllib.request.urlopen(req, timeout=30) as resp:
        status = getattr(resp, "status", resp.getcode())
        if status != 200:
            raise RuntimeError(f"HTTP {status}")
        body = resp.read()
        if not body or not body.strip():
            raise RuntimeError("empty response body")
        return body


def run_tool(name: str, url: str, args: list) -> bool:
    """Downloads and runs one per-tool MDM script in its own subprocess. Each
    tool gets a fresh interpreter so module-level globals (DEBUG flags, cached
    config, …) can't leak between tools. Returns True on success."""
    try:
        script = fetch_script(url)
    except Exception as e:
        print(f"❌ [{name}] failed to download from {url}: {e}", file=sys.stderr)
        return False

    fd, tmp_path = tempfile.mkstemp(
        suffix=".py", prefix=f"unbound-mdm-{name.lower().replace(' ', '-')}-",
    )
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(script)
        # Use sys.executable so we run with the same Python that's executing
        # this wrapper — avoids `python3` vs `python` vs `py` PATH issues
        # (notably on Windows where python3 may not be on PATH).
        result = subprocess.run([sys.executable, tmp_path] + args)
        return result.returncode == 0
    finally:
        try:
            os.unlink(tmp_path)
        except OSError:
            pass


def main() -> int:
    args = sys.argv[1:]

    if not args or ("--api-key" not in args and "--clear" not in args):
        print(USAGE, file=sys.stderr)
        return 1

    if not check_admin_privileges():
        if platform.system().lower() == "windows":
            print(
                "Error: MDM onboarding requires an elevated shell on Windows. "
                "Right-click PowerShell → Run as Administrator, then rerun.",
                file=sys.stderr,
            )
        else:
            print("This script requires administrator/root privileges. Re-run with sudo.", file=sys.stderr)
        return 1

    failures = []
    for name, url in TOOLS:
        print(f"\n{'=' * 60}\n[{name}] MDM setup\n{'=' * 60}\n")
        if not run_tool(name, url, args):
            failures.append(name)

    print(f"\n{'=' * 60}")
    if failures:
        print(f"❌ MDM onboarding finished with {len(failures)} failure(s): {', '.join(failures)}")
        print("Re-run the failed tool's per-tool MDM command to retry.")
        return 1
    print(f"✅ MDM onboarding complete for all {len(TOOLS)} tools: " + ", ".join(name for name, _ in TOOLS))
    return 0


if __name__ == "__main__":
    sys.exit(main())
