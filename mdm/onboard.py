#!/usr/bin/env python3
"""
Unbound MDM onboarding — runs all five steps in one shot:

  1. Claude Code MDM setup (with --backfill of historical transcripts)
  2. Cursor MDM setup
  3. Codex MDM setup (with --backfill of historical transcripts)
  4. GitHub Copilot MDM setup
  5. Coding-discovery scan

Steps 1-4 use --api-key (admin MDM key). Step 5 uses --discovery-key (a
separate discovery-specific key). The two are different credentials and the
backend distinguishes them; passing one in place of the other will be rejected.

Backfill must be explicitly enabled via --backfill flag (typically passed from
PowerShell's -Backfill parameter). When enabled, it seeds Claude Code and Codex
historical transcripts into analytics so the dashboard isn't empty until live
activity accumulates. Backfill is idempotent (Task-row gate + deterministic
uuid5 per record prevents duplication), so re-runs are safe. Cursor and GitHub
Copilot have no historical transcript store to backfill.

Usage:

  sudo python3 -c "$(curl -fsSL https://getunbound.ai/setup/mdm/onboard)" \
      --api-key YOUR_ADMIN_API_KEY \
      --discovery-key YOUR_DISCOVERY_KEY

Optional overrides for tenant deployments (passed to MDM tools and reused as
the discovery --domain):
  --backend-url <url>   default https://backend.getunbound.ai
  --gateway-url <url>   default https://api.getunbound.ai  (MDM tools only)

To clear MDM setup for the four tools (no discovery — it's a one-shot scan,
nothing to clear; backfill is also skipped because there's nothing to seed):
  sudo python3 -c "$(curl -fsSL https://getunbound.ai/setup/mdm/onboard)" --clear

Each step runs in its own subprocess so a failure in one doesn't abort the
others. A summary at the end lists which steps succeeded and which failed.
"""

import os
import platform
import signal
import subprocess
import sys
import tempfile
import urllib.request

# On Windows, when this script runs as a child of the MDM onboard wrapper its
# stdout is a non-console pipe defaulting to the legacy code page (cp1252),
# which can't encode the emoji we print — the first such print raises
# UnicodeEncodeError and crashes the step. Force UTF-8 so output never fails.
# mac/linux stdout is already UTF-8, so they are intentionally left untouched.
if platform.system().lower() == "windows":
    for _stream in (sys.stdout, sys.stderr):
        try:
            if _stream is not None:
                _stream.reconfigure(encoding="utf-8", errors="replace")
        except Exception:
            pass
    del _stream

_RAW_SETUP = "https://raw.githubusercontent.com/websentry-ai/setup/refs/heads/main"
_RAW_DISCOVERY = "https://raw.githubusercontent.com/websentry-ai/coding-discovery-tool/main"

# Per-step subprocess timeout. MDM scripts and the discovery installer do
# legitimate filesystem + network work, so this is a generous safety net
# rather than a tight bound — picked to surface a hung subprocess as a clear
# error instead of a silent indefinite hang on the wrapper.
SUBPROCESS_TIMEOUT_SECONDS = 600

# Coding discovery legitimately takes much longer than a per-tool setup (a full
# filesystem scan + per-user upload), so it gets its OWN, larger timeout instead
# of the tool one. Discovery self-enforces this via --timeout — on expiry it
# releases its lock and reports the run as failed, then exits — so it cleans up
# itself instead of being force-killed with a stale lock left behind. The parent
# waits a short grace beyond the discovery deadline before its own backstop kill,
# so the child's graceful self-timeout always fires first.
DISCOVERY_TIMEOUT_SECONDS = 1800   # 30 min; kept in sync with the discovery --timeout
DISCOVERY_KILL_GRACE_SECONDS = 120

# (display_name, url, supports_backfill). Only tools whose hook scripts
# accept `--backfill` get the flag appended; Cursor and GitHub Copilot have no
# historical transcript store and would just print "not supported" and continue.
TOOLS = [
    ("Claude Code",    f"{_RAW_SETUP}/claude-code/hooks/mdm/setup.py", True),
    ("Cursor",         f"{_RAW_SETUP}/cursor/mdm/setup.py",            False),
    ("Codex",          f"{_RAW_SETUP}/codex/hooks/mdm/setup.py",       True),
    ("GitHub Copilot", f"{_RAW_SETUP}/copilot/hooks/mdm/setup.py",     True),
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
    """Downloads `url` with explicit error checking. Raises on any failure
    (network, HTTP non-2xx, empty body) so the caller never silently runs an
    empty script — the silent-failure mode that `python3 -c "$(curl …)"` has
    when curl fails (`$(…)` returns empty, `python3 -c ""` exits 0).

    Note: urllib.request.urlopen raises HTTPError for any non-2xx response,
    so we don't need an explicit status-code check here — anything reaching
    `body = resp.read()` is already a 2xx."""
    req = urllib.request.Request(url, headers={"User-Agent": "unbound-mdm-onboard/1.0"})
    with urllib.request.urlopen(req, timeout=30) as resp:
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
        try:
            result = subprocess.run(
                [sys.executable, tmp_path] + args, timeout=SUBPROCESS_TIMEOUT_SECONDS,
            )
            return result.returncode == 0
        except subprocess.TimeoutExpired:
            print(
                f"❌ [{name}] timed out after {SUBPROCESS_TIMEOUT_SECONDS}s — child killed.",
                file=sys.stderr,
            )
            return False
    finally:
        try:
            os.unlink(tmp_path)
        except OSError:
            pass


def _terminate_discovery_tree(proc, grace: int = DISCOVERY_KILL_GRACE_SECONDS) -> None:
    """Kill the discovery subprocess AND its descendants. install.sh runs python
    (the process that holds the discovery lock) as a child of bash, so killing
    only the direct child would orphan a stuck discovery that keeps holding its
    lock with a live PID. SIGTERM the whole group first so discovery's own
    handler can release the lock and exit cleanly, then SIGKILL whatever ignores
    it. On Windows there are no POSIX groups, so taskkill /T kills the tree."""
    if platform.system().lower() == "windows":
        try:
            subprocess.run(
                ["taskkill", "/F", "/T", "/PID", str(proc.pid)],
                capture_output=True, timeout=30,
            )
        except Exception:
            try:
                proc.kill()
            except Exception:
                pass
        return

    try:
        pgid = os.getpgid(proc.pid)
    except OSError:
        pgid = None

    def _signal_group(sig: int) -> None:
        try:
            if pgid is not None:
                os.killpg(pgid, sig)
            else:
                proc.send_signal(sig)
        except OSError:
            pass

    _signal_group(signal.SIGTERM)
    try:
        proc.wait(timeout=min(grace, 15))  # let discovery clean up + self-exit
        return
    except subprocess.TimeoutExpired:
        pass
    _signal_group(signal.SIGKILL)
    try:
        proc.wait(timeout=10)
    except subprocess.TimeoutExpired:
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
            cmd = [
                "bash", tmp_path, "--api-key", discovery_key, "--domain", backend_url,
                "--timeout", str(DISCOVERY_TIMEOUT_SECONDS),
            ]
        # Backstop = discovery's own deadline + a short grace. Discovery should
        # hit its --timeout first and clean up; this only force-kills a child that
        # ignored its own deadline. (Windows install.ps1 isn't passed --timeout;
        # the discovery default already equals DISCOVERY_TIMEOUT_SECONDS.)
        backstop = DISCOVERY_TIMEOUT_SECONDS + DISCOVERY_KILL_GRACE_SECONDS
        # Run discovery in its OWN process group (POSIX) so the backstop kill can
        # take down the WHOLE tree (bash + the python discovery that holds the
        # lock), not just the direct child. Orphaning a stuck discovery would
        # leave its lock held by a live PID, which nothing else can recover.
        popen_kwargs = {"start_new_session": True} if not is_windows else {}
        proc = subprocess.Popen(cmd, **popen_kwargs)
        try:
            return proc.wait(timeout=backstop) == 0
        except subprocess.TimeoutExpired:
            print(
                f"❌ [Discovery] exceeded {backstop}s (self-timeout {DISCOVERY_TIMEOUT_SECONDS}s "
                f"+ {DISCOVERY_KILL_GRACE_SECONDS}s grace) — terminating discovery and its children.",
                file=sys.stderr,
            )
            _terminate_discovery_tree(proc)
            return False
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

    for name, url, supports_backfill in TOOLS:
        print(f"\n{'=' * 60}\n[{name}] MDM setup\n{'=' * 60}\n")
        # Pass through mdm_args as-is. Backfill is only enabled when the user
        # explicitly passes --backfill (typically via PowerShell's -Backfill flag).
        tool_args = list(mdm_args)
        if not run_tool(name, url, tool_args):
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
    steps = [name for name, *_ in TOOLS] + ([] if is_clear else ["Discovery"])
    print(f"✅ MDM onboarding complete: {', '.join(steps)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
