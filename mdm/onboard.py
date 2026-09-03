#!/usr/bin/env python3
"""
Unbound MDM onboarding — runs all six steps in one shot:

  1. Claude Code MDM setup (with --backfill of historical transcripts)
  2. Cursor MDM setup
  3. Codex MDM setup (with --backfill of historical transcripts)
  4. GitHub Copilot MDM setup
  5. Augment MDM setup
  6. Coding-discovery scan

Every step uses --api-key (the admin MDM key). The discovery scan authenticates
as the device's owner, whose key is resolved from the hardware serial, so no
separate discovery key is needed. --discovery-key is still accepted so existing
MDM policies keep working, but it is ignored.

Backfill must be explicitly enabled via --backfill flag (typically passed from
PowerShell's -Backfill parameter). When enabled, it seeds Claude Code and Codex
historical transcripts into analytics so the dashboard isn't empty until live
activity accumulates. Backfill is idempotent (Task-row gate + deterministic
uuid5 per record prevents duplication), so re-runs are safe. Cursor, GitHub
Copilot, and Augment have no historical transcript store to backfill.

Usage:

  sudo python3 -c "$(curl -fsSL https://getunbound.ai/setup/mdm/onboard)" \
      --api-key YOUR_ADMIN_API_KEY

Optional overrides for tenant deployments (passed to MDM tools and reused as
the discovery --domain):
  --backend-url <url>   default https://backend.getunbound.ai
  --gateway-url <url>   default https://api.getunbound.ai  (MDM tools only)

Claude Code only:
  --skip-managed-settings   install the hook script but leave
                            managed-settings.json alone, for orgs whose Claude
                            Code policy is managed remotely from the Anthropic
                            admin console.

To clear MDM setup for the four tools (no discovery — it's a one-shot scan,
nothing to clear; backfill is also skipped because there's nothing to seed):
  sudo python3 -c "$(curl -fsSL https://getunbound.ai/setup/mdm/onboard)" --clear

Each step runs in its own subprocess so a failure in one doesn't abort the
others. A summary at the end lists which steps succeeded and which failed.
"""

import json
import os
import platform
import random
import signal
import subprocess
import sys
import tempfile
import time
import urllib.parse

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
DISCOVERY_TIMEOUT_SECONDS = 12000   # 200 min; kept in sync with the discovery --timeout
DISCOVERY_KILL_GRACE_SECONDS = 120

# (display_name, url, supports_backfill, supports_skip_managed_settings). Only
# tools whose hook scripts accept `--backfill` get the flag appended; Cursor and
# GitHub Copilot have no historical transcript store and would just print "not
# supported" and continue. `--skip-managed-settings` is Claude Code's alone.
TOOLS = [
    ("Claude Code",    f"{_RAW_SETUP}/claude-code/hooks/mdm/setup.py", True,  True),
    ("Cursor",         f"{_RAW_SETUP}/cursor/mdm/setup.py",            False, False),
    ("Codex",          f"{_RAW_SETUP}/codex/hooks/mdm/setup.py",       True,  False),
    ("GitHub Copilot", f"{_RAW_SETUP}/copilot/hooks/mdm/setup.py",     True,  False),
    ("Augment",        f"{_RAW_SETUP}/augment/hooks/mdm/setup.py",     False, False),
]
DISCOVERY_INSTALL_SH = f"{_RAW_DISCOVERY}/install.sh"
DISCOVERY_INSTALL_PS1 = f"{_RAW_DISCOVERY}/install.ps1"
DEFAULT_BACKEND_URL = "https://backend.getunbound.ai"

# Spread a fleet-wide Jamf push across a window, like the per-tool MDM scripts.
MDM_RETRY_JITTER_SECONDS = 5

USAGE = (
    "Usage:\n"
    "  sudo python3 -c \"$(curl -fsSL https://getunbound.ai/setup/mdm/onboard)\" \\\n"
    "      --api-key YOUR_ADMIN_API_KEY \\\n"
    "      [--backend-url <url>] [--gateway-url <url>] [--skip-managed-settings]\n"
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
    when curl fails (`$(…)` returns empty, `python3 -c ""` exits 0)."""
    # -q first: this download is executed as root, so it must not inherit
    # TLS-weakening defaults (e.g. `insecure`) from an ambient curlrc.
    cmd = ["curl", "-q", "-fsSL", "--max-time", "30",
           "-H", "User-Agent: unbound-mdm-onboard/1.1", "--", url]
    try:
        result = subprocess.run(cmd, capture_output=True, timeout=45)
    except subprocess.TimeoutExpired:
        raise RuntimeError("request timed out after 45s")
    except FileNotFoundError:
        raise RuntimeError("curl not found on PATH")
    if result.returncode != 0:
        stderr = result.stderr.decode("utf-8", "replace").strip()
        raise RuntimeError(f"curl exited {result.returncode}: {stderr or 'no stderr'}")
    body = result.stdout
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
    host = platform.node() or "unknown-host"
    if platform.system().lower() == "windows":
        print(f"[Discovery] [{host}] force-killing discovery process tree (taskkill /T, pid={proc.pid}).", file=sys.stderr)
        try:
            subprocess.run(
                ["taskkill", "/F", "/T", "/PID", str(proc.pid)],
                capture_output=True, timeout=30,
            )
        except Exception as e:
            print(f"[Discovery] [{host}] taskkill failed ({e}); falling back to proc.kill().", file=sys.stderr)
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
        except OSError as e:
            print(f"[Discovery] [{host}] could not deliver signal {sig} (pgid={pgid}): {e}", file=sys.stderr)

    term_grace = min(grace, 15)
    print(
        f"[Discovery] [{host}] SIGTERM -> discovery group (pgid={pgid}); "
        f"waiting up to {term_grace}s for it to release its lock and exit.",
        file=sys.stderr,
    )
    _signal_group(signal.SIGTERM)
    try:
        proc.wait(timeout=term_grace)
        print(f"[Discovery] [{host}] discovery exited cleanly after SIGTERM.", file=sys.stderr)
        return
    except subprocess.TimeoutExpired:
        pass
    print(f"[Discovery] [{host}] discovery ignored SIGTERM; escalating to SIGKILL on the group.", file=sys.stderr)
    _signal_group(signal.SIGKILL)
    try:
        proc.wait(timeout=10)
        print(f"[Discovery] [{host}] discovery group reaped after SIGKILL.", file=sys.stderr)
    except subprocess.TimeoutExpired:
        print(f"[Discovery] [{host}] discovery not reaped within 10s of SIGKILL.", file=sys.stderr)


def get_device_identifier():
    """Hardware serial, resolved exactly as the per-tool MDM scripts resolve it
    (claude-code/hooks/mdm/setup.py). Steps 1-5 enroll the device under this
    value, so step 6 must use the same one or the backend resolves two owners
    for one machine. Each probe gets its own try so a missing tool falls through
    to the next instead of aborting the chain."""
    system = platform.system().lower()
    try:
        if system == "darwin":
            # ioreg's IOPlatformSerialNumber key is locale-stable; system_profiler's
            # "Serial Number" label is localized and fails on non-English macOS.
            result = subprocess.run(
                ["ioreg", "-rd1", "-c", "IOPlatformExpertDevice"],
                capture_output=True, text=True, timeout=10,
            )
            if result.returncode == 0:
                for line in result.stdout.split("\n"):
                    if "IOPlatformSerialNumber" in line:
                        parts = line.split("=")
                        if len(parts) >= 2:
                            serial = parts[1].strip().strip('"').strip()
                            if serial:
                                return serial
            return None

        if system == "linux":
            try:
                result = subprocess.run(
                    ["dmidecode", "-s", "system-serial-number"],
                    capture_output=True, text=True, timeout=10,
                    stderr=subprocess.DEVNULL,
                )
                if result.returncode == 0 and result.stdout.strip():
                    return result.stdout.strip()
            except Exception:
                pass
            for machine_id_path in ("/etc/machine-id", "/var/lib/dbus/machine-id"):
                try:
                    with open(machine_id_path, "r", encoding="utf-8") as f:
                        machine_id = f.read().strip()
                    if machine_id:
                        return machine_id
                except Exception:
                    continue
            try:
                result = subprocess.run(["hostname"], capture_output=True, text=True, timeout=10)
                if result.returncode == 0 and result.stdout.strip():
                    return result.stdout.strip()
            except Exception:
                pass
            return None

        if system == "windows":
            try:
                result = subprocess.run(
                    ["powershell", "-NoProfile", "-Command",
                     "(Get-CimInstance -ClassName Win32_BIOS).SerialNumber"],
                    capture_output=True, text=True, timeout=10,
                )
                if result.returncode == 0 and result.stdout.strip():
                    return result.stdout.strip()
            except Exception:
                pass
            try:
                import winreg
                with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE,
                                    r"SOFTWARE\Microsoft\Cryptography") as key:
                    value, _ = winreg.QueryValueEx(key, "MachineGuid")
                    if value:
                        return str(value).strip()
            except Exception:
                pass
            try:
                import socket
                return socket.gethostname()
            except Exception:
                return None
    except Exception as e:
        print(f"[Discovery] device identifier probe failed: {e}", file=sys.stderr)
        return None
    return None


def fetch_device_owner_key(admin_api_key: str, backend_url: str):
    """Resolves the API key of the user this device belongs to, from its hardware
    serial. This is what replaces the org discovery key: the scan authenticates as
    the owner, so the device is attributed to them. Returns None on any failure."""
    serial = get_device_identifier()
    if not serial:
        print(
            "❌ [Discovery] could not read this device's hardware serial number, "
            "so its owner cannot be resolved.",
            file=sys.stderr,
        )
        return None

    url = (
        f"{backend_url.rstrip('/')}/api/v1/automations/mdm/get_application_api_key/"
        f"?serial_number={urllib.parse.quote(serial)}&app_type=default"
    )
    # -q first: this runs as root, so it must not inherit TLS-weakening defaults
    # from an ambient curlrc.
    # Retries and jitter match the per-tool MDM scripts: a fleet-wide enrollment
    # hits this endpoint from every device at once, and it mints a key.
    time.sleep(random.uniform(0, MDM_RETRY_JITTER_SECONDS))
    # The admin key goes in via stdin (`-H @-`), never argv: this runs on a
    # multi-user host where /proc/<pid>/cmdline and `ps` are world-readable for
    # the whole retry window, and this key can mint a key for any serial.
    cmd = ["curl", "-q", "-sSL", "-w", "\n%{http_code}", "--max-time", "30",
           "--retry", "7", "--retry-max-time", "180", "--retry-connrefused",
           "-H", "@-", "--", url]
    try:
        result = subprocess.run(cmd, input=f"Authorization: Bearer {admin_api_key}\n",
                                capture_output=True, text=True, timeout=300)
    except Exception as e:
        print(f"❌ [Discovery] device-owner key lookup failed: {e}", file=sys.stderr)
        return None
    lines = result.stdout.strip().split("\n")
    if result.returncode != 0 or len(lines) < 2:
        stderr = result.stderr.strip()
        print(
            f"❌ [Discovery] device-owner key lookup failed: curl exited "
            f"{result.returncode}: {stderr or 'no stderr'}",
            file=sys.stderr,
        )
        return None
    http_code, body = lines[-1], "\n".join(lines[:-1])
    if http_code != "200":
        # Status only: MDM policy logs retain this, and the body is a
        # key-minting endpoint's response.
        print(f"❌ [Discovery] device-owner key lookup failed with status {http_code}.",
              file=sys.stderr)
        return None
    try:
        owner_key = json.loads(body).get("api_key")
    except Exception:
        print("❌ [Discovery] device-owner key lookup returned invalid JSON.", file=sys.stderr)
        return None
    if not owner_key:
        print("❌ [Discovery] the backend did not return a key for this device.", file=sys.stderr)
        return None
    return owner_key


def run_discovery(scan_key: str, backend_url: str) -> bool:
    """Downloads and runs the coding-discovery installer. Mac/Linux use
    install.sh via bash; Windows uses install.ps1 via PowerShell. Both read the
    scan key from UNBOUND_API_KEY and take the backend URL as --domain."""
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
                "-Domain", backend_url,
            ]
        else:
            os.chmod(tmp_path, 0o755)
            cmd = ["bash", tmp_path, "--domain", backend_url]
        # Key via env, never argv — the scan runs for hours and argv is visible
        # to every local user via ps. Both installers read UNBOUND_API_KEY.
        # Same contract as the binary path's _run_discovery.
        scan_env = {**os.environ, "UNBOUND_API_KEY": scan_key}
        # NOTE: we deliberately do NOT pass --timeout. install.sh is fetched from
        # coding-discovery-tool/main, and an older discovery there would reject an
        # unknown --timeout flag (argparse exits non-zero) and fail every
        # enrollment. Discovery self-times-out via its OWN default, which is kept
        # equal to DISCOVERY_TIMEOUT_SECONDS — so this stays correct and in sync
        # whether or not the companion discovery change has landed on main yet.
        #
        # Backstop = that deadline + a short grace. Discovery should hit its own
        # timeout first and clean up; this only force-kills a child that overran.
        backstop = DISCOVERY_TIMEOUT_SECONDS + DISCOVERY_KILL_GRACE_SECONDS
        # Run discovery in its OWN process group (POSIX) so the backstop kill can
        # take down the WHOLE tree (bash + the python discovery that holds the
        # lock), not just the direct child. Orphaning a stuck discovery would
        # leave its lock held by a live PID, which nothing else can recover.
        popen_kwargs = {"start_new_session": True} if not is_windows else {}
        proc = subprocess.Popen(cmd, env=scan_env, **popen_kwargs)
        try:
            return proc.wait(timeout=backstop) == 0
        except subprocess.TimeoutExpired:
            print(
                f"❌ [Discovery] [{platform.node() or 'unknown-host'}] exceeded {backstop}s "
                f"(self-timeout {DISCOVERY_TIMEOUT_SECONDS}s + {DISCOVERY_KILL_GRACE_SECONDS}s grace) "
                f"— terminating discovery (pid={proc.pid}) and its children.",
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
    """Splits argv into (api_key, discovery_key, mdm_args, backend_url, is_clear,
    skip_managed_settings).

    --discovery-key is consumed here and NOT forwarded to the per-tool MDM
    scripts (they don't recognize it; would error). --skip-managed-settings is
    consumed too and re-added per tool, since only Claude Code acts on it.
    Everything else passes through. We also peek at --api-key (to resolve the
    device owner) and --backend-url (to default discovery's --domain).
    """
    api_key = None
    discovery_key = None   # deprecated; "" when the flag came with no value
    backend_url = None
    is_clear = False
    skip_managed_settings = False
    mdm_args = []
    i = 0
    while i < len(argv):
        token = argv[i]
        if token == "--discovery-key":
            # Consumed with or without a value, so a valueless flag neither
            # reaches the per-tool MDM scripts (they reject unknown arguments)
            # nor swallows the flag that follows it.
            if i + 1 < len(argv) and not argv[i + 1].startswith("--"):
                discovery_key = argv[i + 1]
                i += 2
            else:
                discovery_key = ""
                i += 1
            continue
        if token == "--api-key" and i + 1 < len(argv):
            api_key = argv[i + 1]
            mdm_args.append(token)
            mdm_args.append(argv[i + 1])
            i += 2
            continue
        if token == "--backend-url" and i + 1 < len(argv):
            backend_url = argv[i + 1]
            mdm_args.append(token)
            mdm_args.append(argv[i + 1])
            i += 2
            continue
        if token == "--skip-managed-settings":
            skip_managed_settings = True
            i += 1
            continue
        if token == "--clear":
            is_clear = True
        mdm_args.append(token)
        i += 1
    return api_key, discovery_key, mdm_args, backend_url, is_clear, skip_managed_settings


def main() -> int:
    args = sys.argv[1:]

    if not args:
        print(USAGE, file=sys.stderr)
        return 1

    api_key, discovery_key, mdm_args, backend_url, is_clear, skip_managed_settings = parse_args(args)

    # Validate flags. --clear short-circuits the key checks: nothing to
    # authenticate, just remove the configuration.
    if not is_clear:
        if not api_key:
            print("Error: --api-key is required (the MDM admin key).\n", file=sys.stderr)
            print(USAGE, file=sys.stderr)
            return 1

    # Accepted and ignored so MDM policies that still pass it keep working.
    if discovery_key is not None:
        print(
            "Warning: --discovery-key is deprecated and ignored — the scan uses the "
            "device owner's key, resolved from the hardware serial.",
            file=sys.stderr,
        )

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

    for name, url, supports_backfill, supports_skip_settings in TOOLS:
        print(f"\n{'=' * 60}\n[{name}] MDM setup\n{'=' * 60}\n")
        # Pass through mdm_args as-is. Backfill is only enabled when the user
        # explicitly passes --backfill (typically via PowerShell's -Backfill flag).
        tool_args = list(mdm_args)
        if skip_managed_settings and supports_skip_settings:
            tool_args.append("--skip-managed-settings")
        if not run_tool(name, url, tool_args):
            failures.append(name)

    # Discovery is a one-shot scan — skip it on --clear (nothing to remove).
    discovery_skipped = False
    if not is_clear:
        print(f"\n{'=' * 60}\n[Discovery] coding-tool scan\n{'=' * 60}\n")
        discovery_backend = backend_url or DEFAULT_BACKEND_URL
        scan_key = fetch_device_owner_key(api_key, discovery_backend)
        if not scan_key:
            # No owner, no scan — but the tool installs above are done and
            # sound. Skipped, not failed, matching `unbound-hook setup`.
            discovery_skipped = True
        elif not run_discovery(scan_key, discovery_backend):
            failures.append("Discovery")

    print(f"\n{'=' * 60}")
    if failures:
        print(f"❌ MDM onboarding finished with {len(failures)} failure(s): {', '.join(failures)}")
        print("Re-run the failed step's individual command to retry.")
        return 1
    steps = [name for name, *_ in TOOLS]
    if not is_clear:
        steps.append("Discovery (skipped)" if discovery_skipped else "Discovery")
    print(f"✅ MDM onboarding complete: {', '.join(steps)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
