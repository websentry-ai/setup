#!/usr/bin/env python3
"""
Unbound MDM onboarding — runs all six steps in one shot:

  1. Claude Code MDM setup (with --backfill of historical transcripts)
  2. Cursor MDM setup
  3. Codex MDM setup (with --backfill of historical transcripts)
  4. GitHub Copilot MDM setup (with --backfill of historical transcripts)
  5. Augment MDM setup
  6. Coding-discovery scan

Pi Coding Agent MDM setup also runs, after the tool steps and before the
discovery scan, but only on a device where pi is detected: the `pi` binary on
PATH, in a machine bin dir or in any user's bin dirs, or `.pi/agent/auth.json` /
`.pi/agent/sessions` in any user's home. A device without pi skips it, which is
reported as skipped and is not a failure. A device where that could not be
checked (a home that cannot be read, say) gets Pi set up. Every other tool
installs unconditionally.

Every step uses --api-key (the admin MDM key). The discovery scan authenticates
as the device's owner, whose key is resolved from the hardware serial, so no
separate discovery key is needed. --discovery-key is still accepted so existing
MDM policies keep working, but it is ignored.

Backfill must be explicitly enabled via --backfill flag (typically passed from
PowerShell's -Backfill parameter). When enabled, it seeds Claude Code, Codex and
GitHub Copilot historical transcripts into analytics so the dashboard isn't empty
until live activity accumulates. Backfill is idempotent (Task-row gate +
deterministic uuid5 per record prevents duplication), so re-runs are safe. Cursor
and Augment have no historical transcript store to backfill.

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

The Pi clear step always runs, detected or not: a device whose pi was
uninstalled still carries the extension and the rc export.

Each step runs in its own subprocess so a failure in one doesn't abort the
others. A summary at the end lists which steps succeeded and which failed.
"""

import json
import os
import platform
import random
import signal
import stat
import subprocess
import sys
import tempfile
import time
import urllib.parse

_RAW_SETUP = "https://raw.githubusercontent.com/websentry-ai/setup/refs/heads/main"
_RAW_DISCOVERY = "https://raw.githubusercontent.com/websentry-ai/coding-discovery-tool/main"

# Per-step subprocess timeout. MDM scripts and the discovery installer do
# legitimate filesystem + network work, so this is a generous safety net
# rather than a tight bound — picked to surface a hung subprocess as a clear
# error instead of a silent indefinite hang on the wrapper.
SUBPROCESS_TIMEOUT_SECONDS = 600
# A tool running --backfill stops starting batches at 10 min and kills its own
# backfill at 11 (from its start), so this watchdog only catches a hang past both.
BACKFILL_SUBPROCESS_TIMEOUT_SECONDS = 720

# Coding discovery legitimately takes much longer than a per-tool setup (a full
# filesystem scan + per-user upload), so it gets its OWN, larger timeout instead
# of the tool one. Discovery self-enforces this via --timeout — on expiry it
# releases its lock and reports the run as failed, then exits — so it cleans up
# itself instead of being force-killed with a stale lock left behind. The parent
# waits a short grace beyond the discovery deadline before its own backstop kill,
# so the child's graceful self-timeout always fires first.
DISCOVERY_TIMEOUT_SECONDS = 12000   # 200 min; kept in sync with the discovery --timeout
DISCOVERY_KILL_GRACE_SECONDS = 120

# (display_name, url, supports_backfill, supports_skip_managed_settings). Only tools
# whose flag is True get `--backfill` appended. Cursor and Augment have no historical
# transcript store. `--skip-managed-settings` is Claude Code's alone.
TOOLS = [
    ("Claude Code",    f"{_RAW_SETUP}/claude-code/hooks/mdm/setup.py", True,  True),
    ("Cursor",         f"{_RAW_SETUP}/cursor/mdm/setup.py",            False, False),
    ("Codex",          f"{_RAW_SETUP}/codex/hooks/mdm/setup.py",       True,  False),
    ("GitHub Copilot", f"{_RAW_SETUP}/copilot/hooks/mdm/setup.py",     True,  False),
    ("Augment",        f"{_RAW_SETUP}/augment/hooks/mdm/setup.py",     False, False),
]

# Pi is deliberately NOT a row in TOOLS: it is the one step that runs only where
# pi is present, because pi/mdm/setup.py installs into every user home without
# checking. Same tuple shape as a TOOLS row.
PI_TOOL = ("Pi Coding Agent", f"{_RAW_SETUP}/pi/mdm/setup.py", False, False)
PI_BIN_NAME = "pi"
# Files only pi itself writes. Never `.pi/agent/extensions/unbound/`: Unbound's own
# installer creates that, so it would make every onboarded device look like it has pi.
PI_MARKERS = (".pi/agent/auth.json", ".pi/agent/sessions")
# Where a per-user CLI lands, relative to a home. PATH alone is not enough: under
# sudo and under MDM it is a minimal system PATH that lacks these. `.pi/agent/bin`
# is where pi's own installer puts the binary.
PI_HOME_BIN_DIRS = (".pi/agent/bin", ".local/bin", ".bun/bin", ".npm-global/bin", ".volta/bin",
                    ".yarn/bin", "AppData/Roaming/npm", "AppData/Local/Microsoft/WinGet/Links")
PI_MACHINE_BIN_DIRS = ("/opt/homebrew/bin", "/usr/local/bin", "/usr/bin", "/snap/bin")
# Dirs the OS package manager owns, where a bare `pi` may be another program: Debian
# and Ubuntu ship a digits-of-pi calculator at /usr/bin/pi.
PI_OS_PACKAGE_BIN_DIRS = ("/usr/bin", "/bin")
# Where account homes live, as pi/mdm/setup.py requires before it installs into one.
PI_HOME_PREFIXES = {"darwin": "/Users/", "linux": "/home/"}
# Directories under the users root that are not accounts. Linux has no entry: a user
# named Shared or Guest there is a real one, and pi/mdm/setup.py installs for them.
PI_SKIP_HOME_NAMES = {
    "darwin": ("Shared", "Guest"),
    "windows": ("Public", "Default", "Default User", "All Users"),
}
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
        # tool_arguments() only passes --backfill to tools that support it.
        timeout = (BACKFILL_SUBPROCESS_TIMEOUT_SECONDS if "--backfill" in args
                   else SUBPROCESS_TIMEOUT_SECONDS)
        try:
            result = subprocess.run(
                [sys.executable, tmp_path] + args, timeout=timeout,
            )
            return result.returncode == 0
        except subprocess.TimeoutExpired:
            print(
                f"❌ [{name}] timed out after {timeout}s — child killed.",
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


def tool_arguments(mdm_args, supports_backfill, supports_skip_settings,
                   skip_managed_settings):
    """The arguments one tool's installer is called with. A tool that does not declare
    backfill never receives the flag, whoever asked for it."""
    args = [arg for arg in mdm_args if supports_backfill or arg != "--backfill"]
    if skip_managed_settings and supports_skip_settings:
        args.append("--skip-managed-settings")
    return args


def _pi_stat(path, errors):
    """os.stat that tells "not there" from "could not look". A path that is absent
    returns None. Anything else that stops the look (no permission, an I/O error) is
    recorded in `errors`, so a device where pi could not be ruled out is not reported
    as a device without pi."""
    try:
        return os.stat(path)
    except (FileNotFoundError, NotADirectoryError):
        return None
    except OSError as e:
        errors.append(e)
        return None


def _pi_listdir(path, errors) -> list:
    """os.listdir with the same split as _pi_stat."""
    try:
        return sorted(os.listdir(path))
    except (FileNotFoundError, NotADirectoryError):
        return []
    except OSError as e:
        errors.append(e)
        return []


def _account_homes(system) -> list:
    """Home directories from the account database, which is where pi/mdm/setup.py
    finds the users it installs for. A listing of the users root alone misses a home
    that is not its direct child, such as /home/DOMAIN/alice. Windows has no such
    database to read; its profile directories are the list.

    A database that cannot be read yields nothing and is NOT counted as a place that
    could not be inspected. pi/mdm/setup.py reads the same database and finds no
    homes during the same outage, so forcing the Pi step would only fail the
    enrollment of a device that may never have had pi."""
    prefix = PI_HOME_PREFIXES.get(system)
    if not prefix:
        return []
    try:
        import pwd
        entries = pwd.getpwall()
    except Exception:
        return []
    return [entry.pw_dir for entry in entries if (entry.pw_dir or "").startswith(prefix)]


def all_user_homes(system=None, users_root=None, account_homes=None, errors=None) -> list:
    """Every real user's home on this device, plus the home of whoever is running
    this. The tools belong to users other than root, so detection has to look in
    all of them: every home the account database names, and every directory under
    the users root for accounts the database does not enumerate."""
    system = system or platform.system().lower()
    if errors is None:
        errors = []
    if users_root is None:
        if system == "windows":
            users_root = os.environ.get("SystemDrive", "C:") + os.sep + "Users"
        elif system == "darwin":
            users_root = "/Users"
        else:
            users_root = "/home"
    if account_homes is None:
        account_homes = _account_homes(system)
    skip = PI_SKIP_HOME_NAMES.get(system, ())

    candidates = list(account_homes)
    for name in _pi_listdir(users_root, errors):
        if not name.startswith("."):
            candidates.append(os.path.join(users_root, name))

    homes = [os.path.expanduser("~")]
    for home in candidates:
        if os.path.basename(home.rstrip("/" + os.sep)) in skip or home in homes:
            continue
        found = _pi_stat(home, errors)
        if found is not None and stat.S_ISDIR(found.st_mode):
            homes.append(home)
    return homes


def pi_detected(homes=None, path_dirs=None, machine_bin_dirs=None, system=None,
                os_package_bin_dirs=None) -> bool:
    """True when the Pi Coding Agent is present for any user on this device: its
    binary in a bin dir, or a file pi writes for itself in a home. Existence checks
    only -- this runs as root over paths any local user can create, so nothing
    found is ever opened, read or executed.

    Raises when nothing was found but some place could not be inspected, so the
    caller sets Pi up instead of reporting a device that may well have it as clean."""
    system = system or platform.system().lower()
    errors = []
    if homes is None:
        homes = all_user_homes(system, errors=errors)
    if path_dirs is None:
        path_dirs = [d for d in os.environ.get("PATH", "").split(os.pathsep) if d]
    if machine_bin_dirs is None:
        machine_bin_dirs = () if system == "windows" else PI_MACHINE_BIN_DIRS
    if os_package_bin_dirs is None:
        os_package_bin_dirs = () if system == "windows" else PI_OS_PACKAGE_BIN_DIRS
    os_owned = set(os.path.realpath(d) for d in os_package_bin_dirs)

    bin_dirs = list(path_dirs) + list(machine_bin_dirs)
    for home in homes:
        for rel in PI_HOME_BIN_DIRS:
            bin_dirs.append(os.path.join(home, *rel.split("/")))
        # nvm keeps one bin dir per installed Node version.
        nvm = os.path.join(home, ".nvm", "versions", "node")
        for version in _pi_listdir(nvm, errors):
            bin_dirs.append(os.path.join(nvm, version, "bin"))

    if system == "windows":
        names = [PI_BIN_NAME + ext for ext in (".exe", ".cmd", ".ps1", "")]
    else:
        names = [PI_BIN_NAME]
    for bin_dir in bin_dirs:
        # In a dir the OS package manager owns, a regular file named `pi` is the
        # OS's own program. npm links the agent in, so there only a symlink counts.
        links_only = os.path.realpath(bin_dir) in os_owned
        for name in names:
            path = os.path.join(bin_dir, name)
            if _pi_stat(path, errors) is None:
                continue
            if not links_only or os.path.islink(path):
                return True

    for home in homes:
        for rel in PI_MARKERS:
            if _pi_stat(os.path.join(home, *rel.split("/")), errors) is not None:
                return True

    if errors:
        raise errors[0]
    return False


def should_install_pi() -> bool:
    """Whether the Pi step runs on install. A detector that breaks must lean towards
    governing: skipping would leave a pi that may well be there with no extension."""
    try:
        return pi_detected()
    except Exception as e:
        print(f"Warning: could not tell whether pi is installed ({e}); "
              "setting up the Pi Coding Agent anyway.", file=sys.stderr)
        return True


def _stdout_never_raises() -> None:
    """MDM gives this a non-console pipe, which on Windows defaults to cp1252 and
    raises UnicodeEncodeError on the first non-ASCII status line."""
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")
        except (AttributeError, ValueError, OSError):
            pass


def main() -> int:
    _stdout_never_raises()
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
        tool_args = tool_arguments(mdm_args, supports_backfill, supports_skip_settings,
                                   skip_managed_settings)
        if not run_tool(name, url, tool_args):
            failures.append(name)

    # Pi installs only where pi is detected. --clear never asks: a device whose pi
    # was uninstalled still carries the extension and the rc export.
    pi_name, pi_url, pi_backfill, pi_skip_settings = PI_TOOL
    pi_skipped = False
    if is_clear or should_install_pi():
        print(f"\n{'=' * 60}\n[{pi_name}] MDM setup\n{'=' * 60}\n")
        pi_args = tool_arguments(mdm_args, pi_backfill, pi_skip_settings, skip_managed_settings)
        if not run_tool(pi_name, pi_url, pi_args):
            failures.append(pi_name)
    else:
        pi_skipped = True
        print(f"\n[{pi_name}] pi was not detected on this device; skipping its setup. "
              "This is not a failure.")

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
    steps.append(f"{pi_name} (skipped)" if pi_skipped else pi_name)
    if not is_clear:
        steps.append("Discovery (skipped)" if discovery_skipped else "Discovery")
    print(f"✅ MDM onboarding complete: {', '.join(steps)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
