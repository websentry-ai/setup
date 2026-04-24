#!/usr/bin/env python3
"""
Unbound MDM onboarding — runs all four steps in one shot:

  1. Claude Code MDM setup
  2. Cursor MDM setup
  3. Codex MDM setup
  4. Coding-discovery scan

Steps 1-3 use --api-key (admin MDM key). Step 4 uses --discovery-key (a
separate discovery-specific key). The two are different credentials and the
backend distinguishes them; passing one in place of the other will be rejected.

Usage:

  sudo python3 -c "$(curl -fsSL https://getunbound.ai/setup/mdm/onboard)" \
      --api-key YOUR_ADMIN_API_KEY \
      --discovery-key YOUR_DISCOVERY_KEY

Optional overrides for tenant deployments (passed to MDM tools and reused as
the discovery --domain):
  --backend-url <url>   default https://backend.getunbound.ai
  --gateway-url <url>   default https://api.getunbound.ai  (MDM tools only)

To clear MDM setup for the three tools (no discovery — it's a one-shot scan,
nothing to clear):
  sudo python3 -c "$(curl -fsSL https://getunbound.ai/setup/mdm/onboard)" --clear

Each step runs in its own subprocess so a failure in one doesn't abort the
others. A summary at the end lists which steps succeeded and which failed.
"""

import os
import platform
import subprocess
import sys
import tempfile
import urllib.request


_RAW_SETUP = "https://raw.githubusercontent.com/websentry-ai/setup/refs/heads/main"
_RAW_DISCOVERY = "https://raw.githubusercontent.com/websentry-ai/coding-discovery-tool/main"

TOOLS = [
    ("Claude Code", f"{_RAW_SETUP}/claude-code/hooks/mdm/setup.py"),
    ("Cursor",      f"{_RAW_SETUP}/cursor/mdm/setup.py"),
    ("Codex",       f"{_RAW_SETUP}/codex/hooks/mdm/setup.py"),
]
DISCOVERY_INSTALL_SH = f"{_RAW_DISCOVERY}/install.sh"
DISCOVERY_INSTALL_PS1 = f"{_RAW_DISCOVERY}/install.ps1"
DEFAULT_BACKEND_URL = "https://backend.getunbound.ai"

USAGE = (
    "Usage:\n"
    "  sudo python3 -c \"$(curl -fsSL https://getunbound.ai/setup/mdm/onboard)\" \\\n"
    "      --api-key YOUR_ADMIN_API_KEY \\\n"
    "      --discovery-key YOUR_DISCOVERY_KEY \\\n"
    "      [--backend-url <url>] [--gateway-url <url>]\n"
    "\n"
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


def run_discovery(discovery_key: str, backend_url: str) -> bool:
    """Downloads and runs the coding-discovery installer. Mac/Linux use
    install.sh via bash; Windows uses install.ps1 via PowerShell. Both accept
    the discovery key + backend URL (called --domain by the discovery tool)."""
    is_windows = platform.system().lower() == "windows"
    url = DISCOVERY_INSTALL_PS1 if is_windows else DISCOVERY_INSTALL_SH
    try:
        script = fetch_script(url)
    except Exception as e:
        print(f"❌ [Discovery] failed to download {url}: {e}", file=sys.stderr)
        return False

    suffix = ".ps1" if is_windows else ".sh"
    fd, tmp_path = tempfile.mkstemp(suffix=suffix, prefix="unbound-discovery-")
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(script)
        if is_windows:
            cmd = [
                "powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", tmp_path,
                "-ApiKey", discovery_key,
                "-Domain", backend_url,
            ]
        else:
            os.chmod(tmp_path, 0o755)
            cmd = ["bash", tmp_path, "--api-key", discovery_key, "--domain", backend_url]
        result = subprocess.run(cmd)
        return result.returncode == 0
    finally:
        try:
            os.unlink(tmp_path)
        except OSError:
            pass


def parse_args(argv: list) -> tuple:
    """Splits argv into (discovery_key, mdm_args, backend_url, is_clear).

    --discovery-key is consumed here and NOT forwarded to the per-tool MDM
    scripts (they don't recognize it; would error). Everything else passes
    through. We also peek at --backend-url to default discovery's --domain.
    """
    discovery_key = None
    backend_url = None
    is_clear = False
    mdm_args = []
    i = 0
    while i < len(argv):
        token = argv[i]
        if token == "--discovery-key" and i + 1 < len(argv):
            discovery_key = argv[i + 1]
            i += 2
            continue
        if token == "--backend-url" and i + 1 < len(argv):
            backend_url = argv[i + 1]
            mdm_args.append(token)
            mdm_args.append(argv[i + 1])
            i += 2
            continue
        if token == "--clear":
            is_clear = True
        mdm_args.append(token)
        i += 1
    return discovery_key, mdm_args, backend_url, is_clear


def main() -> int:
    args = sys.argv[1:]

    if not args:
        print(USAGE, file=sys.stderr)
        return 1

    discovery_key, mdm_args, backend_url, is_clear = parse_args(args)

    # Validate flags. --clear short-circuits the key checks: nothing to
    # authenticate, just remove the configuration.
    if not is_clear:
        if "--api-key" not in mdm_args:
            print("Error: --api-key is required (the MDM admin key).\n", file=sys.stderr)
            print(USAGE, file=sys.stderr)
            return 1
        if not discovery_key:
            print("Error: --discovery-key is required (separate from --api-key).\n", file=sys.stderr)
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
        if not run_tool(name, url, mdm_args):
            failures.append(name)

    # Discovery is a one-shot scan — skip it on --clear (nothing to remove).
    if not is_clear:
        print(f"\n{'=' * 60}\n[Discovery] coding-tool scan\n{'=' * 60}\n")
        if not run_discovery(discovery_key, backend_url or DEFAULT_BACKEND_URL):
            failures.append("Discovery")

    print(f"\n{'=' * 60}")
    if failures:
        print(f"❌ MDM onboarding finished with {len(failures)} failure(s): {', '.join(failures)}")
        print("Re-run the failed step's individual command to retry.")
        return 1
    steps = [name for name, _ in TOOLS] + ([] if is_clear else ["Discovery"])
    print(f"✅ MDM onboarding complete: {', '.join(steps)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
