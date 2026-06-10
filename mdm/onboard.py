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

Optional overrides for tenant deployments. All three are written into every
user's ~/.unbound/config.json so unbound-cli works on the device without a
manual `unbound config urls`:
  --backend-url <url>    default https://backend.getunbound.ai
  --gateway-url <url>    default https://api.getunbound.ai   (also passed to MDM tools)
  --frontend-url <url>   default https://gateway.getunbound.ai

To clear MDM setup for the four tools (no discovery — it's a one-shot scan,
nothing to clear; backfill is also skipped because there's nothing to seed):
  sudo python3 -c "$(curl -fsSL https://getunbound.ai/setup/mdm/onboard)" --clear

Each step runs in its own subprocess so a failure in one doesn't abort the
others. A summary at the end lists which steps succeeded and which failed.
"""

import json
import os
import platform
import signal
import stat
import subprocess
import sys
import tempfile
import urllib.request
from pathlib import Path
from typing import List, Tuple

try:
    import pwd
except ImportError:  # Windows has no pwd module
    pwd = None

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
DEFAULT_GATEWAY_URL = "https://api.getunbound.ai"
DEFAULT_FRONTEND_URL = "https://gateway.getunbound.ai"

USAGE = (
    "Usage:\n"
    "  sudo python3 -c \"$(curl -fsSL https://getunbound.ai/setup/mdm/onboard)\" \\\n"
    "      --api-key YOUR_ADMIN_API_KEY \\\n"
    "      --discovery-key YOUR_DISCOVERY_KEY \\\n"
    "      [--backend-url <url>] [--gateway-url <url>] [--frontend-url <url>]\n"
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
    req = urllib.request.Request(url, headers={"User-Agent": "unbound-mdm-onboard/1.1"})
    with urllib.request.urlopen(req, timeout=30) as resp:
        body = resp.read()
        if not body or not body.strip():
            raise RuntimeError("empty response body")
        return body


def _run_as_user(username, fn, *args, **kwargs):
    """Fork and execute fn(*args, **kwargs) as the unprivileged user `username`.
    Returns whatever fn returns on success, or None on failure.

    Security-critical: writing inside a user's home dir as root invites
    symlink-following privilege escalation (e.g. `ln -s /etc ~/.unbound`). After
    the privilege drop, symlinks targeting root-only paths fail with EACCES. On
    Windows (no fork) fn runs directly. Mirrors the per-tool MDM setups."""
    if platform.system().lower() == "windows":
        try:
            return fn(*args, **kwargs)
        except Exception:
            return None
    if pwd is None:
        return None
    try:
        info = pwd.getpwnam(username)
    except KeyError:
        return None
    uid, gid = info.pw_uid, info.pw_gid

    r_fd, w_fd = os.pipe()
    pid = os.fork()
    if pid == 0:
        os.close(r_fd)
        try:
            os.setgroups([])
            os.setgid(gid)
            os.setuid(uid)
            result = fn(*args, **kwargs)
            import pickle
            os.write(w_fd, pickle.dumps(result, protocol=pickle.HIGHEST_PROTOCOL))
            os.close(w_fd)
            os._exit(0)
        except Exception:
            try:
                os.close(w_fd)
            except OSError:
                pass
            os._exit(1)
    else:
        os.close(w_fd)
        data = b""
        while True:
            try:
                chunk = os.read(r_fd, 65536)
            except OSError:
                break
            if not chunk:
                break
            data += chunk
        os.close(r_fd)
        try:
            _, status = os.waitpid(pid, 0)
        except OSError:
            return None
        if os.WEXITSTATUS(status) != 0:
            return None
        try:
            import pickle
            return pickle.loads(data) if data else None
        except Exception:
            return None


def get_all_user_homes() -> List[Tuple[str, Path]]:
    """Enumerate (username, home_dir) for every real local user. Mirrors the
    per-tool MDM setups' enumeration so URL persistence reaches the same users."""
    user_homes: List[Tuple[str, Path]] = []
    system = platform.system().lower()
    try:
        if system == "darwin" and pwd is not None:
            for user in pwd.getpwall():
                home_dir = Path(user.pw_dir)
                if (user.pw_uid >= 500 and home_dir.exists() and home_dir.is_dir()
                        and str(home_dir).startswith("/Users/")
                        and user.pw_name not in ("Shared", "Guest")):
                    user_homes.append((user.pw_name, home_dir))
        elif system == "linux" and pwd is not None:
            for user in pwd.getpwall():
                home_dir = Path(user.pw_dir)
                if (user.pw_uid >= 1000 and home_dir.exists() and home_dir.is_dir()
                        and str(home_dir).startswith("/home/")):
                    user_homes.append((user.pw_name, home_dir))
        elif system == "windows":
            users_dir = Path(os.environ.get("SystemDrive", "C:") + r"\Users")
            if users_dir.exists():
                for user_dir in users_dir.iterdir():
                    if user_dir.is_dir() and user_dir.name not in (
                        "Public", "Default", "Default User", "Administrator", "All Users"
                    ):
                        user_homes.append((user_dir.name, user_dir))
    except Exception:
        return []
    return user_homes


def _write_urls_for_user(username: str, home_dir: Path, explicit: dict, defaults: dict):
    """Merge the tenant URL keys into ~/.unbound/config.json for one user,
    preserving existing keys (e.g. the api_key a tool step wrote). Privilege-
    drops to the user and is symlink-safe (O_NOFOLLOW).

    `explicit` (values from --*-url flags) always wins. `defaults` only fills a
    key the user hasn't set themselves, so a no-flags run never clobbers a URL a
    user configured via `unbound config urls`."""
    config_dir = home_dir / ".unbound"
    config_file = config_dir / "config.json"

    def _write():
        is_windows = platform.system().lower() == "windows"
        # Windows has no fork/privilege-drop and no O_NOFOLLOW: a non-admin user
        # can plant ~/.unbound as a directory junction/symlink and redirect this
        # admin-context write into an admin-only path. The config.json checks
        # below only guard the file, not the dir, so reject a reparse-point
        # .unbound here before mkdir/open touches it.
        if is_windows and config_dir.exists():
            reparse = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0)
            if getattr(os.lstat(str(config_dir)), "st_file_attributes", 0) & reparse:
                raise OSError(".unbound is a reparse point")
        config_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
        if not is_windows:
            os.chmod(config_dir, 0o700)
        # Read any existing config so its keys (e.g. the api_key a tool step
        # wrote) survive the merge. The O_NOFOLLOW + O_NONBLOCK + regular-file
        # open atomically rejects a symlink swap (no lstat→open TOCTOU window)
        # and a planted FIFO/device that would otherwise hang this root run.
        config = {}
        try:
            rfd = os.open(str(config_file),
                          os.O_RDONLY | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_NOFOLLOW", 0))
            if not stat.S_ISREG(os.fstat(rfd).st_mode):
                os.close(rfd)
                raise OSError("config.json is not a regular file")
            with os.fdopen(rfd, "r", encoding="utf-8") as f:
                config = json.loads(f.read())
        except FileNotFoundError:
            config = {}
        except (json.JSONDecodeError, OSError):
            config = {}
        if not isinstance(config, dict):
            config = {}
        for k, v in defaults.items():
            if not config.get(k):
                config[k] = v
        config.update(explicit)
        # O_NOFOLLOW blocks a symlink swap on config.json; O_NONBLOCK + the
        # regular-file check stop a user-planted FIFO/device from hanging this
        # root run on open() (the loop is sequential, so one wedge stalls all).
        flags = (os.O_WRONLY | os.O_CREAT | os.O_TRUNC
                 | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_NOFOLLOW", 0))
        fd = os.open(str(config_file), flags, 0o600)
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            os.close(fd)
            raise OSError("config.json is not a regular file")
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(json.dumps(config, indent=2))
        return True

    return _run_as_user(username, _write)


def persist_urls_for_all_users(backend_url, gateway_url, frontend_url) -> None:
    """Write base_url / gateway_url / frontend_url into every real user's
    ~/.unbound/config.json so unbound-cli works on this MDM-managed device with
    no manual `unbound config urls`. Best-effort: never fails the onboarding.

    Each argument is the value from its --*-url flag or None. Explicitly-passed
    URLs always win; the public defaults only fill a key a user hasn't set, so a
    no-flags run never overwrites a URL the user configured themselves."""
    explicit = {
        "base_url": backend_url,
        "gateway_url": gateway_url,
        "frontend_url": frontend_url,
    }
    explicit = {k: v for k, v in explicit.items() if v}
    defaults = {
        "base_url": DEFAULT_BACKEND_URL,
        "gateway_url": DEFAULT_GATEWAY_URL,
        "frontend_url": DEFAULT_FRONTEND_URL,
    }
    written = 0
    for username, home_dir in get_all_user_homes():
        # _run_as_user swallows the child's exception and returns None, so a
        # failed write surfaces only as a None here — warn rather than fail
        # silently (a try/except around this call would be dead code).
        if _write_urls_for_user(username, home_dir, explicit, defaults) is not None:
            written += 1
        else:
            print(f"⚠️  [config] could not persist URLs for {username}", file=sys.stderr)
    print(f"✅ Persisted tenant URLs to ~/.unbound/config.json for {written} user(s).")


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
        proc = subprocess.Popen(cmd, **popen_kwargs)
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
    """Splits argv into (discovery_key, mdm_args, backend_url, gateway_url,
    frontend_url, is_clear).

    --discovery-key and --frontend-url are consumed here and NOT forwarded to the
    per-tool MDM scripts (they don't recognize them). We persist all three URLs
    into each user's config.json ourselves. --backend-url and --gateway-url are
    captured AND forwarded (the tool scripts need them to configure the gateway).
    """
    discovery_key = None
    backend_url = None
    gateway_url = None
    frontend_url = None
    is_clear = False
    mdm_args = []
    i = 0
    while i < len(argv):
        token = argv[i]
        if token == "--discovery-key" and i + 1 < len(argv):
            discovery_key = argv[i + 1]
            i += 2
            continue
        if token == "--frontend-url" and i + 1 < len(argv):
            frontend_url = argv[i + 1]
            i += 2
            continue
        if token == "--backend-url" and i + 1 < len(argv):
            backend_url = argv[i + 1]
            mdm_args.append(token)
            mdm_args.append(argv[i + 1])
            i += 2
            continue
        if token == "--gateway-url" and i + 1 < len(argv):
            gateway_url = argv[i + 1]
            mdm_args.append(token)
            mdm_args.append(argv[i + 1])
            i += 2
            continue
        if token == "--clear":
            is_clear = True
        mdm_args.append(token)
        i += 1
    return discovery_key, mdm_args, backend_url, gateway_url, frontend_url, is_clear


def main() -> int:
    args = sys.argv[1:]

    if not args:
        print(USAGE, file=sys.stderr)
        return 1

    discovery_key, mdm_args, backend_url, gateway_url, frontend_url, is_clear = parse_args(args)

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

    # Persist the tenant URLs into every user's ~/.unbound/config.json (merged
    # with the per-user api_key the tool steps wrote) so unbound-cli works on this
    # MDM-managed device with no manual `unbound config urls`. Skipped on --clear.
    if not is_clear:
        persist_urls_for_all_users(backend_url, gateway_url, frontend_url)

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
