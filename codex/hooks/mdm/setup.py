#!/usr/bin/env python3

import os
import signal
import select
import random
import stat
import re
import shutil
import sys
import time
import platform
import subprocess
import hashlib
import json
import shlex
import tempfile
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Tuple, List, Optional, Dict
try:
    import pwd
except ImportError:
    pwd = None

DEBUG = False
SCRIPT_URL = "https://raw.githubusercontent.com/websentry-ai/setup/refs/heads/main/codex/hooks/unbound.py"
DEFAULT_GATEWAY_URL = "https://api.getunbound.ai"
MDM_RETRY_JITTER_SECONDS = 30  # spreads a fleet-wide MDM push so retries do not re-synchronise

BACKFILL_CHUNK_BYTES = 14 * 1024 * 1024
BACKFILL_TOOL_TYPE = "codex"
BACKFILL_MAX_FILE_BYTES = 50 * 1024 * 1024
BACKFILL_MAX_LINES_PER_FILE = 50000
BACKFILL_MAX_SESSIONS_PER_RUN = 5000
BACKFILL_MAX_AGE_DAYS = 30
BACKFILL_STATE_FILE = '.unbound_last_backfill'
# An S3 PUT is given up on only after this long below this speed, then re-sent on a fresh link.
BACKFILL_PUT_STALL_SECONDS = 60
BACKFILL_PUT_STALL_BYTES_PER_SECOND = 1024
BACKFILL_PUT_ATTEMPTS = 3
BACKFILL_PUT_MAX_SECONDS = 300  # one chunk's PUT attempts share this, so retries cannot stack past a watchdog
BACKFILL_PUT_MIN_SECONDS = 45  # with less than this left of it, no further attempt starts
# Run as a script (onboard's 720s per-tool watchdog), the backfill stops itself here; the packaged binary sets no stop.
_SCRIPT_START = time.time()
BACKFILL_SOFT_STOP_SECONDS = 600
BACKFILL_FROM_S3_RESERVE_SECONDS = 40
# What a re-walk needs before its first chunk: the config request's retries (about 66s) and the walk itself.
BACKFILL_START_MARGIN_SECONDS = 120
_backfill_stop_at: Optional[float] = None
ROLLOUT_FILENAME_RE = re.compile(
    r'^rollout-\d{4}-\d{2}-\d{2}T\d{2}-\d{2}-\d{2}-'
    r'([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})$'
)


def normalize_url(value: str) -> str:
    value = (value or "").strip()
    if not value:
        return value
    if not (value.startswith("http://") or value.startswith("https://")):
        value = f"https://{value}"
    return value.rstrip("/")


def debug_print(message: str) -> None:
    if DEBUG:
        print(f"[DEBUG] {message}")


def _become_user(info) -> None:
    """Drop to the user with their own groups, as codex runs: a file shared through a
    group must read the same here as it does to codex."""
    try:
        os.initgroups(info.pw_name, info.pw_gid)
    except OSError:
        os.setgroups([])
    os.setgid(info.pw_gid)
    os.setuid(info.pw_uid)


# A limit for every privilege-dropped call, set by a caller that must not be held by
# a user pausing one (the binary's setup); None (a backfill's case) waits as long as it takes.
_RUN_AS_USER_TIMEOUT = None


def _run_as_user(username, fn, *args, _timeout=None, **kwargs):
    """Fork and execute fn(*args, **kwargs) as the unprivileged user `username`.
    Returns whatever fn returns on success, or None on failure.

    Security-critical primitive: any MDM op that writes inside a user's
    home dir must go through this. Running file ops as root against
    attacker-controlled paths invites symlink-following privilege
    escalation (e.g. `ln -s /Library/LaunchDaemons ~/.unbound` redirecting
    a root chmod/chown). After privilege drop, symlinks targeting
    root-only paths fail naturally with EACCES.

    On Windows (no fork, single-user MDM context, not vulnerable to this
    class), executes fn directly.
    """
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

    r_fd, w_fd = os.pipe()
    pid = os.fork()
    if pid == 0:
        os.close(r_fd)
        try:
            _become_user(info)
            # setuid alone leaves $HOME pointing at root, so a Path.home() /
            # expanduser('~') inside fn would resolve to root's home, not the
            # user's. Callers pass explicit home_dir today; this hardens against
            # a future slip and keeps the env consistent with the dropped uid.
            os.environ['HOME'] = info.pw_dir
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
        # A list, not bytes +=: bytes concatenation copies the whole buffer per chunk,
        # so a multi-GB pickle made this read quadratic and pinned a core past the timeout.
        chunks = []
        # The child runs as the user, who can pause it: a caller can bound the wait
        # (a backfill can't be bounded; a quick check can).
        limit = _RUN_AS_USER_TIMEOUT if _timeout is None else _timeout
        deadline = None if limit is None else time.monotonic() + limit
        while True:
            remaining = None if deadline is None else deadline - time.monotonic()
            if remaining is not None and (remaining <= 0 or not select.select([r_fd], [], [], remaining)[0]):
                try:
                    os.kill(pid, signal.SIGKILL)
                except OSError:
                    pass
                break
            try:
                chunk = os.read(r_fd, 1 << 20)
            except OSError:
                break
            if not chunk:
                break
            chunks.append(chunk)
        os.close(r_fd)
        data = b''.join(chunks)
        del chunks
        try:
            if deadline is None:
                _, status = os.waitpid(pid, 0)
            else:  # paused after closing the pipe, it would still hold the wait
                while True:
                    done, status = os.waitpid(pid, os.WNOHANG)
                    if done:
                        break
                    if time.monotonic() > deadline:
                        os.kill(pid, signal.SIGKILL)
                        os.waitpid(pid, 0)
                        return None
                    time.sleep(0.05)
        except OSError:
            return None
        if os.WEXITSTATUS(status) != 0:
            return None
        try:
            import pickle
            return pickle.loads(data) if data else None
        except Exception:
            return None


def check_admin_privileges() -> bool:
    try:
        system = platform.system().lower()
        if system in ["darwin", "linux"]:
            return os.geteuid() == 0
        if system == "windows":
            import ctypes
            try:
                return bool(ctypes.windll.shell32.IsUserAnAdmin())
            except Exception:
                return False
        return False
    except Exception as e:
        debug_print(f"Failed to check privileges: {e}")
        return False


_PLACEHOLDER_SERIALS = {
    '', '0', '00000000', '000000000', '0000000000', '000000000000', 'none',
    'na', 'n/a', 'unknown', 'default', 'default string',
    'to be filled by o.e.m.', 'to be filled by oem', 'serialnumber',
    'system serial number', 'serial number', 'chassis serial number',
    'system manufacturer', 'not applicable', 'not specified',
    'not available', 'oem', 'o.e.m.', 'invalid', '123456789', 'xxxxxxxx',
    'xxxxxxxxxxxxxx',
}


def get_device_identifier() -> Optional[str]:
    system = platform.system().lower()
    try:
        if system == "darwin":
            # ioreg's IOPlatformSerialNumber key is locale-stable; system_profiler's
            # "Serial Number" label is localized and fails on non-English macOS.
            result = subprocess.run(
                ["/usr/sbin/ioreg", "-rd1", "-c", "IOPlatformExpertDevice"],
                capture_output=True,
                text=True,
                timeout=10
            )
            if result.returncode == 0:
                for line in result.stdout.split('\n'):
                    if 'IOPlatformSerialNumber' in line:
                        parts = line.split('=')
                        if len(parts) >= 2:
                            serial = parts[1].strip().strip('"').strip()
                            if serial:
                                return serial
            return None

        elif system == "linux":
            try:
                result = subprocess.run(
                    ["dmidecode", "-s", "system-serial-number"],
                    capture_output=True,
                    text=True,
                    timeout=10,
                    stderr=subprocess.DEVNULL
                )
                if result.returncode == 0:
                    device_id = result.stdout.strip()
                    if device_id:
                        return device_id
            except Exception:
                debug_print("dmidecode failed, trying machine-id")

            for machine_id_path in ['/etc/machine-id', '/var/lib/dbus/machine-id']:
                try:
                    with open(machine_id_path, 'r', encoding='utf-8') as f:
                        device_id = f.read().strip()
                        if device_id:
                            return device_id
                except Exception:
                    continue

            try:
                result = subprocess.run(
                    ["hostname"],
                    capture_output=True,
                    text=True,
                    timeout=10
                )
                if result.returncode == 0:
                    hostname = result.stdout.strip()
                    if hostname:
                        return hostname
            except Exception:
                pass

            return None

        elif system == "windows":
            try:
                result = subprocess.run(
                    ["powershell", "-NoProfile", "-Command",
                     "(Get-CimInstance -ClassName Win32_BIOS).SerialNumber"],
                    capture_output=True, text=True, timeout=10,
                )
                serial = result.stdout.strip() if result.returncode == 0 else ""
                if serial and serial.lower() not in _PLACEHOLDER_SERIALS:
                    return serial
            except Exception:
                pass
            return None

    except Exception as e:
        debug_print(f"Failed to get device identifier: {e}")
        return None


def get_all_user_homes() -> List[Tuple[str, Path]]:
    user_homes = []
    system = platform.system().lower()

    try:
        if system == "darwin":
            for user in pwd.getpwall():
                uid = user.pw_uid
                username = user.pw_name
                home_dir = Path(user.pw_dir)

                if uid >= 500 and home_dir.exists() and home_dir.is_dir():
                    if str(home_dir).startswith('/Users/') and username not in ['Shared', 'Guest']:
                        user_homes.append((username, home_dir))
                        debug_print(f"Found user: {username} -> {home_dir}")

        elif system == "linux":
            for user in pwd.getpwall():
                uid = user.pw_uid
                username = user.pw_name
                home_dir = Path(user.pw_dir)

                if uid >= 1000 and home_dir.exists() and home_dir.is_dir():
                    if str(home_dir).startswith('/home/'):
                        user_homes.append((username, home_dir))
                        debug_print(f"Found user: {username} -> {home_dir}")

        elif system == "windows":
            system_drive = os.environ.get("SystemDrive", "C:")
            users_dir = Path(system_drive + r"\Users")
            if users_dir.exists():
                try:
                    for user_dir in users_dir.iterdir():
                        if user_dir.is_dir() and user_dir.name not in ['Public', 'Default User', 'Administrator', 'All Users']:
                            user_homes.append((user_dir.name, user_dir))
                            debug_print(f"Found user: {user_dir.name} -> {user_dir}")
                except Exception as e:
                    debug_print(f"Error scanning Windows users directory: {e}")

        return user_homes
    except Exception as e:
        debug_print(f"Error enumerating users: {e}")
        return []


def append_to_file(file_path: Path, line: str, var_name: str = None) -> bool:
    try:
        file_path.parent.mkdir(parents=True, exist_ok=True)

        lines = []
        if file_path.exists():
            try:
                with open(file_path, "r", encoding="utf-8") as f:
                    lines = f.readlines()
            except Exception:
                lines = []

        if var_name:
            export_prefix = f"export {var_name}="
            lines = [l for l in lines if not l.strip().startswith(export_prefix)]

        normalized_line = line.rstrip()
        line_exists = any(l.rstrip() == normalized_line for l in lines)

        if not line_exists:
            lines.append(f"{line}\n")
            with open(file_path, "w", encoding="utf-8") as f:
                f.writelines(lines)
            return True
        elif var_name:
            with open(file_path, "w", encoding="utf-8") as f:
                f.writelines(lines)
            return True

        return True
    except Exception as e:
        print(f"Failed to modify {file_path}: {e}")
        return False


def check_env_var_exists(rc_file: Path, var_name: str, value: str) -> bool:
    if not rc_file.exists():
        return False
    try:
        with open(rc_file, 'r', encoding='utf-8') as f:
            lines = f.readlines()
        export_line = f'export {var_name}="{value}"'
        return any(l.rstrip() == export_line for l in lines)
    except Exception:
        return False


def set_env_var_for_user(username: str, home_dir: Path, var_name: str, value: str) -> Tuple[bool, bool]:
    """Set env var in user's shell rc files. Privilege-drops on Unix."""
    system = platform.system().lower()

    if system == "windows":
        debug_print(f"Writing to system registry (Windows)")
        try:
            subprocess.run(
                ["setx", var_name, value, "/M"],
                check=False, capture_output=True, timeout=10,
            )
            debug_print(f"Set {var_name} system-wide on Windows")
            return True, True
        except Exception as e:
            debug_print(f"Failed to set {var_name} on Windows: {e}")
            return False, False

    if system == "darwin":
        rc_files = [home_dir / ".zprofile", home_dir / ".bash_profile"]
    elif system == "linux":
        rc_files = [home_dir / ".zshrc", home_dir / ".bashrc"]
    else:
        return False, False

    debug_print(f"Writing to shell files: {[str(f) for f in rc_files]}")
    export_line = f'export {var_name}="{value}"'

    def _do():
        _success = False
        _changed = False
        for rc_file in rc_files:
            try:
                exists_already = check_env_var_exists(rc_file, var_name, value)
                if append_to_file(rc_file, export_line, var_name):
                    debug_print(f"Updated {rc_file}")
                    _success = True
                    if not exists_already:
                        _changed = True
            except Exception as e:
                debug_print(f"Failed to update {rc_file}: {e}")
        return _success, _changed

    _repair_user_ownership(username, rc_files)
    result = _run_as_user(username, _do)
    if result is None:
        debug_print(f"Could not set env var for {username}")
        return False, False
    return result


def set_env_var_system_wide(var_name: str, value: str) -> Tuple[bool, bool]:
    try:
        # On Windows, `setx /M` writes machine-wide in one call — no per-user iteration.
        if platform.system().lower() == "windows":
            return set_env_var_for_user(None, None, var_name, value)

        user_homes = get_all_user_homes()

        if not user_homes:
            print("No user home directories found")
            return False, False

        success_count = 0
        changed_count = 0

        for username, home_dir in user_homes:
            debug_print(f"Setting {var_name} for user: {username}")
            success, changed = set_env_var_for_user(username, home_dir, var_name, value)
            if success:
                success_count += 1
            if changed:
                changed_count += 1

        if success_count > 0:
            print(f"   Set for {success_count} user(s)")
            return True, changed_count > 0
        else:
            print("Failed to set environment variable for any users")
            return False, False

    except Exception as e:
        print(f"Failed to set system-wide environment variable: {e}")
        return False, False


def fetch_api_key_from_mdm(base_url: str, app_name: str, auth_api_key: str, device_id: str) -> Optional[str]:
    params = f"serial_number={device_id}&app_type=codex"
    if app_name:
        params = f"app_name={app_name}&{params}"
    url = f"{base_url.rstrip('/')}/api/v1/automations/mdm/get_application_api_key/?{params}"

    debug_print(f"Fetching API key from: {url}")

    try:
        time.sleep(random.uniform(0, MDM_RETRY_JITTER_SECONDS))
        result = subprocess.run(
            ["curl", "-fsSL", "-w", "\n%{http_code}",
             "--max-time", "30", "--retry", "7", "--retry-max-time", "180", "--retry-connrefused",
             "-H", f"Authorization: Bearer {auth_api_key}", url],
            capture_output=True,
            text=True,
            timeout=300
        )

        output_lines = result.stdout.strip().split('\n')
        if len(output_lines) < 2:
            print("Invalid response from server")
            return None

        http_code = output_lines[-1]
        response_body = '\n'.join(output_lines[:-1])

        debug_print(f"HTTP status: {http_code}")
        debug_print(f"Response length: {len(response_body)}")

        if http_code != "200":
            print(f"API request failed with status {http_code}")
            return None

        try:
            data = json.loads(response_body)
            api_key = data.get("api_key")
            if not api_key:
                print("No api_key in response")
                return None
            user_email = data.get("email")
            first_name = data.get("first_name")
            last_name = data.get("last_name")
            print(f"User email: {user_email}")
            print(f"Name: {first_name} {last_name}")
            return api_key
        except json.JSONDecodeError:
            print("Invalid JSON response from server")
            return None

    except subprocess.TimeoutExpired:
        print("Request timed out")
        return None
    except Exception as e:
        debug_print(f"Request failed: {e}")
        print("Failed to fetch API key")
        return None


def remove_env_var_on_windows_machine(var_name: str) -> str:
    """Remove machine-wide (HKLM) env var on Windows.

    Returns "cleared", "not_found", or "failed".
    """
    reg_path = "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Environment"
    try:
        query = subprocess.run(
            ["reg", "query", reg_path, "/V", var_name],
            capture_output=True, timeout=10,
        )
        if query.returncode != 0:
            return "not_found"
        subprocess.run(
            ["reg", "delete", reg_path, "/F", "/V", var_name],
            check=True, capture_output=True, timeout=10,
        )
        debug_print(f"Removed {var_name} from system environment")
        return "cleared"
    except subprocess.CalledProcessError:
        return "failed"
    except Exception as e:
        debug_print(f"Failed to remove {var_name}: {e}")
        return "failed"


def remove_env_var_from_user(username: str, home_dir: Path, var_name: str) -> str:
    """Remove env var from user's shell rc files. Privilege-drops on Unix.

    Returns "cleared", "not_found", or "failed".
    """
    system = platform.system().lower()

    if system == "windows":
        return remove_env_var_on_windows_machine(var_name)

    if system == "darwin":
        rc_files = [home_dir / ".zprofile", home_dir / ".bash_profile"]
    elif system == "linux":
        rc_files = [home_dir / ".zshrc", home_dir / ".bashrc"]
    else:
        return "failed"

    export_prefix = f"export {var_name}="

    def _do():
        cleared = False
        had_error = False
        for rc_file in rc_files:
            if not rc_file.exists():
                continue
            try:
                with open(rc_file, 'r', encoding='utf-8') as f:
                    lines = f.readlines()
                new_lines = [l for l in lines if not l.strip().startswith(export_prefix)]
                if len(new_lines) < len(lines):
                    flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC | getattr(os, 'O_NOFOLLOW', 0)
                    fd = os.open(str(rc_file), flags, 0o644)
                    with os.fdopen(fd, 'w', encoding='utf-8') as f:
                        f.writelines(new_lines)
                    debug_print(f"Removed {var_name} from {rc_file}")
                    cleared = True
            except Exception as e:
                debug_print(f"Failed to update {rc_file}: {e}")
                had_error = True
        if cleared:
            return "cleared"
        if had_error:
            return "failed"
        return "not_found"

    result = _run_as_user(username, _do)
    if result in ("cleared", "not_found", "failed"):
        return result
    return "failed"


def _repair_user_ownership(username: str, paths: List[Path]) -> None:
    """Root-context best-effort: reclaim ownership of any of `paths` that exist
    as a real, user-home file/dir owned by another user, so the upcoming
    privilege-dropped write can touch it. A prior root-context run can leave
    ~/.unbound or a shell rc file root-owned, which the dropped user then can't
    write (EACCES).

    Runs as root on user-controlled paths, so it is hardened against a local
    escalation: open with O_NOFOLLOW (a symlink fails ELOOP) and fchown the
    resulting fd, so the inode inspected is the inode chowned — no path TOCTOU.
    Refuse any regular file with extra hard links (st_nlink != 1): a hardlink to
    a sensitive root-owned file (e.g. /etc/shadow) would otherwise be handed to
    the user. Directories can't be hard-linked and a non-root user can't create
    a root-owned dir, so they're safe to reclaim. No-op on Windows / without
    pwd; only fires on the abnormal uid-mismatch case; never raises."""
    if platform.system().lower() == "windows" or pwd is None:
        return
    try:
        info = pwd.getpwnam(username)
    except KeyError:
        return
    uid, gid = info.pw_uid, info.pw_gid
    o_nofollow = getattr(os, "O_NOFOLLOW", None)
    if o_nofollow is None:
        return  # can't open safely without the symlink guard — skip, don't degrade it
    flags = os.O_RDONLY | o_nofollow | getattr(os, "O_NONBLOCK", 0)
    for path in paths:
        try:
            fd = os.open(str(path), flags)
        except OSError:
            continue  # missing, a symlink (O_NOFOLLOW -> ELOOP), or no access
        try:
            st = os.fstat(fd)
            safe = stat.S_ISDIR(st.st_mode) or (stat.S_ISREG(st.st_mode) and st.st_nlink == 1)
            if safe and st.st_uid != uid:
                os.fchown(fd, uid, gid)
        except OSError as e:
            debug_print(f"_repair_user_ownership: could not chown {path}: {e}")
        finally:
            os.close(fd)


def write_unbound_config_for_user(username: str, home_dir: Path, api_key: str, urls: dict = None) -> bool:
    """Write API key to ~/.unbound/config.json for a given user.
    Privilege-drops to the target user before any FS op."""
    config_dir = home_dir / ".unbound"
    config_file = config_dir / "config.json"

    # A prior root-context run may have left these root-owned; repair ownership
    # (symlink-guarded) before dropping so the write below doesn't fail EACCES.
    _repair_user_ownership(username, [config_dir, config_file])

    def _write():
        if platform.system().lower() == "windows":
            config_dir.mkdir(parents=True, exist_ok=True)
        else:
            config_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
        if platform.system().lower() != "windows":
            try:
                os.chmod(config_dir, 0o700)
            except OSError:
                pass
        config = {}
        if config_file.exists():
            try:
                with open(config_file, 'r', encoding='utf-8') as f:
                    config = json.loads(f.read())
            except (json.JSONDecodeError, OSError):
                config = {}
        config['device_token'] = api_key
        config['api_key'] = api_key  # read by older CLIs and hooks
        if urls:
            config.update({k: v for k, v in urls.items() if v})
        flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC | getattr(os, 'O_NOFOLLOW', 0)
        fd = os.open(str(config_file), flags, 0o600)
        with os.fdopen(fd, 'w', encoding='utf-8') as f:
            f.write(json.dumps(config, indent=2))
        return True

    if _run_as_user(username, _write) is None:
        debug_print(f"Could not write config for {username}")
        return False
    return True


def _read_config_lines(config_path: Path):
    """config.toml's lines, or None if it isn't a regular file: a FIFO would hang setup."""
    fd = os.open(str(config_path), os.O_RDONLY | getattr(os, 'O_NONBLOCK', 0))
    with os.fdopen(fd, 'r', encoding='utf-8') as f:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            return None
        return f.readlines()


def remove_gateway_artifacts_for_user(username: str, home_dir: Path) -> None:
    """Remove OPENAI_API_KEY env var and openai_base_url from ~/.codex/config.toml.
    Privilege-drops to the target user before any FS op."""
    # remove_env_var_from_user already privilege-drops internally.
    remove_env_var_from_user(username, home_dir, "OPENAI_API_KEY")

    config_path = home_dir / ".codex" / "config.toml"
    if not config_path.exists():
        return

    def _strip():
        lines = _read_config_lines(config_path)
        if lines is None:
            return False
        new_lines = [l for l in lines if not l.strip().startswith('openai_base_url')]
        if len(new_lines) == len(lines):
            return False
        flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC | getattr(os, 'O_NOFOLLOW', 0)
        fd = os.open(str(config_path), flags, 0o644)
        with os.fdopen(fd, 'w', encoding='utf-8') as f:
            f.writelines(new_lines)
        return True

    if _run_as_user(username, _strip):
        debug_print(f"Removed openai_base_url from {config_path}")


def _command_targets_hook(command: str, target: Path) -> bool:
    if not isinstance(command, str) or not command:
        # A non-string command is not ours; the checks below would raise on it.
        return False
    # Binary install: command invokes the /opt/unbound hook binary (require both
    # the prefix and the binary name so a foreign hook merely mentioning the path
    # isn't matched). Mirrors the managed _is_unbound_hook_command matcher.
    if "/opt/unbound/" in command and "unbound-hook" in command:
        return True
    try:
        tokens = shlex.split(command, posix=(os.name != "nt"))
    except ValueError:
        return False
    tokens = [t.strip().strip('"').strip("'") for t in tokens]
    tokens = [t for t in tokens if t]
    if not tokens:
        return False
    launcher = os.path.basename(tokens[0]).lower()
    if launcher.endswith(".exe"):
        launcher = launcher[:-4]
    if launcher in ("py", "python", "python2", "python3"):
        tokens = tokens[1:]
        while tokens and tokens[0].startswith("-"):
            tokens = tokens[1:]
    if not tokens:
        return False
    normalized_target = os.path.normcase(os.path.normpath(str(target)))
    return os.path.normcase(os.path.normpath(tokens[0])) == normalized_target


def remove_user_level_hooks_for_user(username: str, home_dir: Path) -> None:
    """Strip Unbound's hook entries from ~/.codex/hooks.json and delete
    ~/.codex/hooks/unbound.py for a given user. Without this, MDM-managed
    hooks fire alongside leftover user-level ones and every event runs twice.
    Only entries pointing to our own unbound.py are removed; unrelated user
    hooks are preserved. The hooks feature flag in config.toml is left
    alone — MDM still relies on it. Privilege-drops to the target user."""
    hooks_path = home_dir / ".codex" / "hooks.json"
    script_path = home_dir / ".codex" / "hooks" / "unbound.py"

    def _is_unbound(cmd: str) -> bool:
        return _command_targets_hook(cmd, script_path)

    def _clean():
        # safe_to_unlink stays True only if the JSON no longer references
        # script_path. If the read/write fails partway, we leave the script
        # in place so a dangling hook entry doesn't point at a missing file.
        safe_to_unlink = True
        if hooks_path.exists():
            try:
                with open(hooks_path, 'r', encoding='utf-8') as f:
                    config = json.load(f)
                if isinstance(config, dict) and isinstance(config.get("hooks"), dict):
                    hooks_block = config["hooks"]
                    modified = False
                    for event in list(hooks_block.keys()):
                        event_config = hooks_block[event]
                        if not isinstance(event_config, list):
                            continue
                        new_event_config = []
                        for item in event_config:
                            if isinstance(item, dict) and isinstance(item.get("hooks"), list):
                                hooks_list = item["hooks"]
                                new_hooks = [
                                    h for h in hooks_list
                                    if not (isinstance(h, dict) and _is_unbound(h.get("command", "")))
                                ]
                                if len(new_hooks) == len(hooks_list):
                                    # No Unbound hooks here — preserve as-is so
                                    # we don't silently drop pre-existing empty
                                    # items the user authored.
                                    new_event_config.append(item)
                                else:
                                    modified = True
                                    if new_hooks:
                                        item["hooks"] = new_hooks
                                        new_event_config.append(item)
                            else:
                                new_event_config.append(item)
                        if new_event_config:
                            hooks_block[event] = new_event_config
                        else:
                            del hooks_block[event]
                            modified = True
                    if not hooks_block:
                        del config["hooks"]
                        modified = True
                    if modified:
                        flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC | getattr(os, 'O_NOFOLLOW', 0)
                        fd = os.open(str(hooks_path), flags, 0o644)
                        with os.fdopen(fd, 'w', encoding='utf-8') as f:
                            json.dump(config, f, indent=2)
                        debug_print(f"Stripped Unbound hooks from {hooks_path}")
            except Exception as e:
                safe_to_unlink = False
                debug_print(f"Failed to clean {hooks_path}: {e}")

        if safe_to_unlink and script_path.exists():
            try:
                script_path.unlink()
                debug_print(f"Removed {script_path}")
            except Exception as e:
                debug_print(f"Failed to remove {script_path}: {e}")
        return True

    _run_as_user(username, _clean)


def remove_hook_logs_for_user(username: str, home_dir: Path) -> None:
    """Remove the hook's own logs (agent-audit.log, error.log) from a user's
    ~/.codex/hooks on CLEAR/nuke — they exist only because of us. Kept separate
    from remove_user_level_hooks_for_user (which also runs at setup) so logs are
    dropped ONLY on clear. Privilege-drops to the user; unlink() removes the dir
    entry (a symlink, never its target)."""
    if home_dir is None:
        return  # Windows machine-wide placeholder — no per-user dir to clean
    hooks_dir = home_dir / ".codex" / "hooks"

    def _clear():
        for _log in ("agent-audit.log", "error.log"):
            try:
                (hooks_dir / _log).unlink()
                debug_print(f"Removed {hooks_dir / _log}")
            except FileNotFoundError:
                pass
            except Exception as e:
                debug_print(f"Failed to remove {hooks_dir / _log}: {e}")

    _run_as_user(username, _clear)


def get_managed_settings_dir() -> Path:
    """Codex's system config folder. A hooks.json here is a managed hook: codex runs it for every user
    without asking them to trust it."""
    system = platform.system().lower()
    if system in ("darwin", "linux"):
        return Path("/etc/codex")
    elif system == "windows":
        return Path(os.environ.get("ProgramData", r"C:\ProgramData")) / "OpenAI" / "Codex"
    raise OSError(f"Unsupported operating system: {system}")


def download_file(url: str, dest_path: Path, gateway_url: Optional[str] = None) -> bool:
    # Fetch beside dest_path and swap in whole: a hook firing mid-download, or a
    # dropped connection, must never leave the live file partly written.
    tmp_path = dest_path.with_name(f"{dest_path.name}.{os.getpid()}.tmp")
    try:
        dest_path.parent.mkdir(parents=True, exist_ok=True)
        # Only temps a killed run left behind: a live download is never older than
        # curl's 30s timeout, and must not lose its file to a concurrent run.
        for stale in dest_path.parent.glob(f"{dest_path.name}.*.tmp"):
            try:
                if time.time() - stale.stat().st_mtime > 300:
                    stale.unlink()
            except FileNotFoundError:
                pass
        debug_print(f"Downloading {url} to {dest_path}")
        result = subprocess.run(
            ["curl", "-fsSL", "-o", str(tmp_path), url],
            capture_output=True,
            timeout=30
        )
        if result.returncode != 0:
            return False
        if gateway_url:
            rewrite_gateway_url_in_file(tmp_path, gateway_url)
        if dest_path.exists():
            shutil.copymode(dest_path, tmp_path)
        os.replace(tmp_path, dest_path)
        debug_print(f"File downloaded successfully: {dest_path}")
        return True
    except (subprocess.TimeoutExpired, OSError, ValueError) as e:
        print(f"Failed to download {url}: {e}")
        return False
    finally:
        try:
            if tmp_path.exists():
                tmp_path.unlink()
        except OSError:
            pass


def rewrite_gateway_url_in_file(path: Path, gateway_url: str) -> None:
    """Replace the hardcoded default gateway URL inside a downloaded unbound.py."""
    if not gateway_url or gateway_url == DEFAULT_GATEWAY_URL:
        return
    # Raises on failure: download_file must never swap in a half-rewritten hook.
    text = path.read_text(encoding="utf-8")
    new_text = text.replace(f'"{DEFAULT_GATEWAY_URL}"', json.dumps(gateway_url))
    if new_text != text:
        path.write_text(new_text, encoding="utf-8")


def setup_managed_hooks(gateway_url: str = DEFAULT_GATEWAY_URL) -> bool:
    """
    Set up system-wide managed hooks for Codex.
    Downloads unbound.py and configures hooks.json with hooks.
    """
    system = platform.system().lower()
    try:
        managed_dir = get_managed_settings_dir()
        settings_path = managed_dir / "hooks.json"
        hooks_dir = managed_dir / "hooks"
        script_path = hooks_dir / "unbound.py"

        # Create directories
        managed_dir.mkdir(parents=True, exist_ok=True)
        hooks_dir.mkdir(parents=True, exist_ok=True)
        debug_print(f"Created managed settings directory: {managed_dir}")

        # Download unbound.py script
        if not download_file(SCRIPT_URL, script_path, gateway_url):
            print("Failed to download unbound.py")
            return False
        debug_print(f"Downloaded hook script: {script_path}")

        # Make script executable on Unix systems
        if system in ["darwin", "linux"]:
            os.chmod(script_path, 0o755)
            debug_print("Set script as executable")

        # Read existing settings or create new
        settings = {}
        if settings_path.exists():
            try:
                with open(settings_path, 'r', encoding='utf-8') as f:
                    settings = json.load(f) or {}
            except Exception:
                settings = {}

        # Configure hooks - quote the path to handle spaces (e.g. macOS
        # "Application Support"). On Windows, invoke via `py -3` (falling back
        # to `python`) so the hook can actually execute the .py file.
        if system == "windows":
            launcher = "py -3" if shutil.which("py") else "python"
            hook_command = f'{launcher} "{script_path}"'
        else:
            hook_command = f'"{script_path}"'
        hooks_config = {
            "PreToolUse": [
                {
                    "matcher": "*",
                    "hooks": [
                        {
                            "type": "command",
                            "command": hook_command,
                            "timeout": 15000
                        }
                    ]
                }
            ],
            "PostToolUse": [
                {
                    "matcher": "*",
                    "hooks": [
                        {
                            "type": "command",
                            "command": hook_command,
                            "timeout": 60
                        }
                    ]
                }
            ],
            "UserPromptSubmit": [
                {
                    "hooks": [
                        {
                            "type": "command",
                            "command": hook_command,
                            "timeout": 60
                        }
                    ]
                }
            ],
            "Stop": [
                {
                    "hooks": [
                        {
                            "type": "command",
                            "command": hook_command,
                            "timeout": 60
                        }
                    ]
                }
            ],
            "SessionStart": [
                {
                    "matcher": "*",
                    "hooks": [
                        {
                            "type": "command",
                            "command": hook_command,
                            "timeout": 60
                        }
                    ]
                }
            ]
        }

        # Replace only our entries; codex rejects the whole file over any top-level key but these two.
        hooks = settings.get("hooks") if isinstance(settings.get("hooks"), dict) else {}
        mine = lambda h: isinstance(h, dict) and _is_unbound_hook_command(h.get("command"), script_path)
        for event, ours in hooks_config.items():
            kept = []
            for g in hooks.get(event) if isinstance(hooks.get(event), list) else []:
                handlers = g.get("hooks") if isinstance(g, dict) and isinstance(g.get("hooks"), list) else None
                rest = [h for h in handlers if not mine(h)] if handlers else None
                if rest is None or rest:
                    kept.append({**g, "hooks": rest} if rest is not None and len(rest) != len(handlers) else g)
            hooks[event] = kept + ours
        settings = {k: v for k, v in settings.items() if k == "description"}
        settings["hooks"] = hooks
        settings_path.write_text(json.dumps(settings, indent=2), encoding="utf-8")
        debug_print(f"Created managed settings: {settings_path}")

        # Set permissions - readable by all users
        if system in ["darwin", "linux"]:
            os.chmod(managed_dir, 0o755)
            os.chmod(hooks_dir, 0o755)
            os.chmod(settings_path, 0o644)
            os.chmod(script_path, 0o755)

        return True

    except Exception as e:
        print(f"Failed to setup managed hooks: {e}")
        debug_print(f"Error details: {e}")
        return False


def configure_codex_hooks_for_user(username: str, home_dir: Path, gateway_url: str = DEFAULT_GATEWAY_URL) -> bool:
    """Register Unbound's codex hooks per-user in ~/.codex/hooks.json — the
    layer codex actually discovers hooks from. Downloads unbound.py to
    ~/.codex/hooks/ and merge-registers the bare script path, mirroring the
    user-level configure_codex_hooks exactly. Privilege-drops to the target
    user; merge is idempotent and preserves other tools' hooks."""
    hooks_dir = home_dir / ".codex" / "hooks"
    script_path = hooks_dir / "unbound.py"
    hooks_path = home_dir / ".codex" / "hooks.json"
    is_windows = platform.system().lower() == "windows"

    if is_windows:
        launcher = "py -3" if shutil.which("py") else "python"
        hook_command = f'{launcher} "{script_path}"'
    else:
        hook_command = str(script_path)

    def _install():
        if not download_file(SCRIPT_URL, script_path, gateway_url):
            return False
        try:
            current_mode = script_path.stat().st_mode
            os.chmod(script_path, current_mode | 0o111)
        except OSError:
            pass

        if hooks_path.exists():
            with open(hooks_path, 'r', encoding='utf-8') as f:
                config = json.load(f)
        else:
            config = {}

        hooks_config = {
            "PreToolUse": [
                {
                    "matcher": "*",
                    "hooks": [
                        {
                            "type": "command",
                            "command": hook_command,
                            "timeout": 15000
                        }
                    ]
                }
            ],
            "PostToolUse": [
                {
                    "matcher": "*",
                    "hooks": [
                        {
                            "type": "command",
                            "command": hook_command,
                            "timeout": 60
                        }
                    ]
                }
            ],
            "UserPromptSubmit": [
                {
                    "hooks": [
                        {
                            "type": "command",
                            "command": hook_command,
                            "timeout": 60
                        }
                    ]
                }
            ],
            "Stop": [
                {
                    "hooks": [
                        {
                            "type": "command",
                            "command": hook_command,
                            "timeout": 60
                        }
                    ]
                }
            ],
            "SessionStart": [
                {
                    "matcher": "*",
                    "hooks": [
                        {
                            "type": "command",
                            "command": hook_command,
                            "timeout": 60
                        }
                    ]
                }
            ]
        }

        if "hooks" not in config:
            config["hooks"] = {}

        for event, new_config in hooks_config.items():
            if event not in config["hooks"]:
                config["hooks"][event] = new_config
                continue
            existing_config = config["hooks"][event]
            our_hook_exists = False
            for existing_item in existing_config:
                if not isinstance(existing_item, dict):
                    continue
                # .get's default only applies to a missing key, so a scalar
                # here would be iterated and raise before the command check ran.
                existing_hooks = existing_item.get("hooks")
                for hook in existing_hooks if isinstance(existing_hooks, list) else []:
                    if not isinstance(hook, dict):
                        continue
                    if _command_targets_hook(hook.get("command", ""), script_path):
                        our_hook_exists = True
                        break
            if not our_hook_exists:
                existing_config.extend(new_config)

        flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC | getattr(os, 'O_NOFOLLOW', 0)
        fd = os.open(str(hooks_path), flags, 0o644)
        with os.fdopen(fd, 'w', encoding='utf-8') as f:
            json.dump(config, f, indent=2)
        return True

    return bool(_run_as_user(username, _install))


def _is_unbound_hook_command(cmd: str, script_path: Path) -> bool:
    """A hook command is ours if it points at OUR managed python hook
    (script_path) or the /opt/unbound hook binary. Both forms are recognized so a
    binary-install hook is stripped on clear instead of being orphaned. Matches the
    specific script path (NOT a bare 'unbound.py' substring) and requires both the
    install prefix and the binary name, so a foreign hook in a shared/Enterprise
    config that merely references some other unbound.py / mentions /opt/unbound/
    isn't stripped."""
    if not isinstance(cmd, str) or not cmd:
        # A non-string command is not ours; the checks below would raise on it.
        return False
    return str(script_path) in cmd or ("/opt/unbound/" in cmd and "unbound-hook" in cmd)


def clear_managed_hooks() -> str:
    """Strip ONLY our hook entries from the managed Codex config (hooks.json),
    preserving any foreign content.

    Returns "cleared", "not_found", or "failed".
    """
    try:
        managed_dir = get_managed_settings_dir()
        settings_path = managed_dir / "hooks.json"
        hooks_dir = managed_dir / "hooks"
        script_path = hooks_dir / "unbound.py"

        cleared_any = False
        had_error = False

        if script_path.exists():
            try:
                script_path.unlink()
                debug_print(f"Removed {script_path}")
                cleared_any = True
            except Exception as e:
                debug_print(f"Failed to remove {script_path}: {e}")
                had_error = True

        if hooks_dir.exists():
            try:
                if not any(hooks_dir.iterdir()):
                    hooks_dir.rmdir()
                    debug_print(f"Removed empty directory {hooks_dir}")
            except Exception as e:
                debug_print(f"Could not remove directory {hooks_dir}: {e}")

        if settings_path.exists():
            try:
                with open(settings_path, "r", encoding="utf-8") as f:
                    settings = json.load(f)
                modified = False
                hooks_block = settings.get("hooks") if isinstance(settings, dict) else None
                if isinstance(hooks_block, dict):
                    for event in list(hooks_block.keys()):
                        event_config = hooks_block[event]
                        if not isinstance(event_config, list):
                            continue
                        new_config = []
                        for item in event_config:
                            # Only touch items with a real list of hooks; preserve
                            # everything else untouched (foreign items, dicts with
                            # no/"null" hooks). Drop an item only when every hook in
                            # it was ours.
                            if isinstance(item, dict) and isinstance(item.get("hooks"), list):
                                hooks = item["hooks"]
                                new_hooks = [
                                    h for h in hooks
                                    if not (isinstance(h, dict) and _is_unbound_hook_command(h.get("command", ""), script_path))
                                ]
                                if len(new_hooks) != len(hooks):
                                    modified = True
                                    if new_hooks:
                                        item["hooks"] = new_hooks
                                        new_config.append(item)
                                else:
                                    new_config.append(item)
                            else:
                                new_config.append(item)
                        if new_config:
                            hooks_block[event] = new_config
                        else:
                            del hooks_block[event]
                            modified = True
                    if not hooks_block:
                        del settings["hooks"]
                if modified:
                    if isinstance(settings, dict) and not settings:
                        settings_path.unlink()
                        debug_print(f"Removed empty {settings_path}")
                    else:
                        with open(settings_path, "w", encoding="utf-8") as f:
                            json.dump(settings, f, indent=2)
                        debug_print("Stripped our hooks from hooks.json")
                    cleared_any = True
            except Exception as e:
                debug_print(f"Failed to update hooks.json: {e}")
                had_error = True

        if cleared_any:
            return "cleared"
        if had_error:
            return "failed"
        return "not_found"

    except Exception as e:
        debug_print(f"Error clearing managed hooks: {e}")
        return "failed"


_HOOKS_FLAG_RE = re.compile(r'^(codex_hooks|hooks)\s*=')


# TOML spells this header several ways and allows a trailing comment. Missing one both
# strips the wrong lines and appends a second [features], which TOML rejects outright.
_FEATURES_HEADER_RE = re.compile(r'^\[\s*(?:features|"features"|\'features\')\s*\]\s*(#.*)?$')

# features as an inline table cannot take an appended header without redefining it.
_FEATURES_INLINE_RE = re.compile(r'^features\s*=\s*\{(.*?)\}\s*(#.*)?$')


def _is_features_header(stripped) -> bool:
    return bool(_FEATURES_HEADER_RE.match(stripped))


def _features_hooks_flags(lines):
    """The hooks feature flag lines present inside [features], in either spelling. Scoped to
    that table: a hooks key in some other table is not this flag and must not be read as one."""
    found, in_features = [], False
    for stripped in _config_lines(lines):
        if stripped is None:
            continue
        if stripped.startswith('['):
            in_features = _is_features_header(stripped)
            continue
        if in_features and _HOOKS_FLAG_RE.match(stripped):
            found.append(stripped)
    return found


try:
    import tomllib
except ImportError:  # system python older than 3.11
    tomllib = None


def _write_is_safe(text, want_enabled) -> bool:
    """Whether text is a config Codex can load with the flag in the intended state. Every
    edit is checked against this before it reaches disk, so a line-scan mistake is discarded
    rather than written."""
    if tomllib is None:
        # No parser to check the result with, so only edit files without the constructs the
        # line scan can misread. A config left alone beats a config written blind.
        if '"""' in text or "'''" in text:
            return False
        depth = 0
        for line in text.splitlines():
            _, extra = _scan_code(line)
            depth += extra
            if depth:
                return False  # a multi-line array
        return True
    try:
        features = tomllib.loads(text).get('features')
    except Exception:
        return False
    if features is None:
        features = {}
    if not isinstance(features, dict) or 'codex_hooks' in features:
        return False
    return features.get('hooks') is True if want_enabled else 'hooks' not in features


def _find_delim(text, delim, start=0) -> int:
    """Index of the closing delimiter, skipping backslash escapes. A backslash consumes the
    character after it, so an escaped quote can never be read as part of a terminator.
    Multi-line literal strings take no escapes, so only the basic form needs the walk."""
    if delim != '"""':
        return text.find(delim, start)
    i, n = start, len(text)
    while i < n:
        if text[i] == '\\':
            i += 2
            continue
        if text.startswith(delim, i):
            return i
        i += 1
    return -1


def _inline_with_flag(stripped):
    """An inline features table rewritten to carry hooks = true, or None when its values are
    too complex to split on commas. Refusing there keeps a user from opting out of enforcement
    by writing the table inline, without risking their values."""
    match = _FEATURES_INLINE_RE.match(stripped)
    if not match:
        return None
    inner = match.group(1)
    if any(ch in inner for ch in '"\'{}[]'):
        return None
    entries = [part.strip() for part in inner.split(',')]
    entries = [part for part in entries if part and not _HOOKS_FLAG_RE.match(part)]
    entries.append('hooks = true')
    comment = match.group(2)
    return 'features = { ' + ', '.join(entries) + ' }' + ('  ' + comment if comment else '') + '\n'


def _scan_code(text):
    """(unclosed multi-line delimiter, net bracket depth change) for the code on one line.
    Brackets and quotes inside comments or strings are not counted, and the same-line close
    of a triple-quoted value skips escapes so it cannot end on an escaped quote."""
    i, n, depth = 0, len(text), 0
    while i < n:
        ch = text[i]
        if ch == '#':
            break
        if text.startswith('"""', i) or text.startswith("'''", i):
            delim = text[i:i + 3]
            end = _find_delim(text, delim, i + 3)
            if end == -1:
                return delim, depth
            i = end + 3
            continue
        if ch == '"':
            i += 1
            while i < n:
                if text[i] == '\\':
                    i += 2
                    continue
                if text[i] == '"':
                    i += 1
                    break
                i += 1
            continue
        if ch == "'":
            end = text.find("'", i + 1)
            if end == -1:
                break
            i = end + 1
            continue
        if ch == '[':
            depth += 1
        elif ch == ']':
            depth -= 1
        i += 1
    return None, depth


def _config_lines(lines):
    """Yield each line stripped, or None for anything that is not a statement of its own:
    the interior of a multi-line string and the continuation lines of a multi-line array.
    Either one can hold text that looks like a table header or like our flag."""
    delim, depth = None, 0
    for line in lines:
        if delim is not None:
            yield None
            end = _find_delim(line, delim)
            if end == -1:
                continue
            delim, extra = _scan_code(line[end + 3:])
            depth += extra
            continue
        if depth > 0:
            yield None
            delim, extra = _scan_code(line)
            depth += extra
            continue
        yield line.strip()
        delim, extra = _scan_code(line)
        depth += extra


def _strip_hooks_flags(lines):
    """Drop the hooks feature flag from [features], in either spelling. Matching is anchored
    and scoped to that table so [hooks.state] and its entries are left alone."""
    out, in_features = [], False
    for line, stripped in zip(lines, _config_lines(lines)):
        if stripped is None:
            out.append(line)
            continue
        if stripped.startswith('['):
            in_features = _is_features_header(stripped)
            out.append(line)
            continue
        if in_features and _HOOKS_FLAG_RE.match(stripped):
            continue
        out.append(line)
    return out


def enable_codex_hooks_feature_for_user(username: str, home_dir: Path) -> None:
    """Enable codex_hooks feature flag in user's ~/.codex/config.toml.
    Privilege-drops to the target user before any FS op."""
    config_path = home_dir / ".codex" / "config.toml"

    def _enable():
        config_path.parent.mkdir(parents=True, exist_ok=True)
        lines = []
        if config_path.exists():
            lines = _read_config_lines(config_path)
            if lines is None:
                print(f"{username}'s config.toml is not a regular file; hooks not enforced")
                return False
        # Covers the inline spelling too, so a daily re-run does not rewrite a config that is
        # already correct.
        if tomllib is not None and _write_is_safe(''.join(lines), True):
            return False  # already exactly right

        # This runs from a daily cron, so a machine still carrying the old spelling has to be
        # migrated rather than skipped for having the new one alongside it. The check is scoped
        # to [features]: a hooks key in another table is an unrelated setting.
        if _features_hooks_flags(lines) == ['hooks = true']:
            return False  # already exactly right

        lines = _strip_hooks_flags(lines)
        features_idx = next((i for i, s in enumerate(_config_lines(lines))
                             if s is not None and _is_features_header(s)), None)
        if features_idx is not None:
            lines.insert(features_idx + 1, 'hooks = true\n')
        else:
            merged = False
            for i, stripped in enumerate(_config_lines(lines)):
                if stripped is None:
                    continue
                if stripped.startswith('['):
                    break  # an inline features table is a top-level key, not a nested one
                rewritten = _inline_with_flag(stripped)
                if rewritten:
                    lines[i] = rewritten
                    merged = True
                    break
                if _FEATURES_INLINE_RE.match(stripped):
                    print(f"features is an inline table in {username}'s config.toml; hooks not enforced")
                    return False
            if not merged:
                if lines and not lines[-1].endswith('\n'):
                    lines.append('\n')
                lines.append('\n[features]\nhooks = true\n')

        if not _write_is_safe(''.join(lines), True):
            print(f"could not enable hooks in {username}'s config.toml without breaking it")
            return False
        flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC | getattr(os, 'O_NOFOLLOW', 0)
        fd = os.open(str(config_path), flags, 0o600)
        with os.fdopen(fd, 'w', encoding='utf-8') as f:
            f.writelines(lines)
        return True

    result = _run_as_user(username, _enable)
    if result is True:
        debug_print(f"Enabled codex_hooks feature for {username}")
    elif result is False:
        debug_print(f"codex_hooks already enabled for {username}")
    else:
        debug_print(f"Failed to enable codex_hooks for {username}")


# A FIFO would hang provisioning and an oversized file would exhaust memory, so the read
# is capped and restricted to a regular file.
_HOOKS_JSON_MAX_BYTES = 4 * 1024 * 1024
# The hook script is a few hundred KB; past this it is not the file we wrote.
_HOOK_SCRIPT_MAX_BYTES = 8 * 1024 * 1024


def _load_hooks_json(hooks_path):
    """('absent'|'refused'|'unusable'|'ok', config). Opened without following
    symlinks and size-capped, because these are user-owned paths read by a
    root/SYSTEM process.

    'refused' is our own restriction — a symlink or an unreadable mode — and says
    nothing about the file. 'unusable' means the content is there and codex cannot
    load hooks out of it either, which is a fact about the install, not about us.
    """
    try:
        fd = os.open(str(hooks_path),
                     os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0) | getattr(os, 'O_NONBLOCK', 0))
    except FileNotFoundError:
        return 'absent', None
    except OSError:
        return 'refused', None  # includes a symlink refused by O_NOFOLLOW
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode):
            os.close(fd)
            return 'unusable', None
        if info.st_size > _HOOKS_JSON_MAX_BYTES:
            os.close(fd)
            return 'unusable', None
    except OSError:
        os.close(fd)
        return 'refused', None
    try:
        handle = os.fdopen(fd, 'r', encoding='utf-8')
    except OSError:
        os.close(fd)
        return 'refused', None
    try:
        with handle as f:
            return 'ok', json.load(f)
    except ValueError:
        return 'unusable', None
    except OSError:
        return 'refused', None


def _hooks_still_registered(hooks_path):
    """True when hooks.json still registers a command, False when none does, None when that
    cannot be determined. The feature flag is one switch over every hook a user has, so
    clearing it while somebody else's entry remains turns their tooling off; None keeps the
    flag and marks the uninstall incomplete rather than guessing either way. Call this only
    after our own entries have been stripped."""
    status, config = _load_hooks_json(hooks_path)
    if status == 'absent':
        return False
    if status != 'ok':
        return None
    events = config.get('hooks')
    if not isinstance(events, dict):
        return False
    for entries in events.values():
        for item in entries if isinstance(entries, list) else []:
            if isinstance(item, dict) and item.get('hooks'):
                return True
    return False


def _unbound_hook_registered(hooks_path, script_path):
    """True when OUR hook is registered for this user, False when it is not, None
    only when we declined to read the file. Ownership uses the same rule the
    uninstall strips by, so registration and removal cannot disagree about what is
    ours. Content codex cannot load hooks from counts as not registered, because
    that is exactly what it means for codex."""
    status, config = _load_hooks_json(hooks_path)
    if status in ('absent', 'unusable'):
        return False
    if status != 'ok':
        return None
    events = config.get('hooks') if isinstance(config, dict) else None
    if not isinstance(events, dict):
        return False
    for entries in events.values():
        for item in entries if isinstance(entries, list) else []:
            if not isinstance(item, dict):
                continue
            hooks = item.get('hooks')
            # Shape-guard before iterating: a scalar here is truthy, so
            # `or []` would iterate an int and abort detection for every
            # profile on the device, not just this one.
            for hook in hooks if isinstance(hooks, list) else []:
                if isinstance(hook, dict) and _is_unbound_hook_command(
                        hook.get('command', ''), script_path):
                    return True
    return False


def disable_codex_hooks_feature_for_user(username: str, home_dir: Path) -> None:
    """Remove the hooks feature flag, in either spelling, from user's ~/.codex/config.toml.
    Privilege-drops to the target user before any FS op."""
    config_path = home_dir / ".codex" / "config.toml"
    if not config_path.exists():
        return

    def _disable():
        # Runs after the privilege drop: reading a user-owned path as root invites a
        # symlink or FIFO pointed at a file only root can open.
        registered = _hooks_still_registered(home_dir / ".codex" / "hooks.json")
        if registered is None:
            print(f"could not read {username}'s hooks.json; hooks feature flag left set")
            return False
        if registered:
            debug_print(f"hooks feature flag kept for {username}: other hooks still registered")
            return False
        lines = _read_config_lines(config_path)
        if lines is None:
            return False
        new_lines = _strip_hooks_flags(lines)
        if len(new_lines) == len(lines):
            return False
        if not _write_is_safe(''.join(new_lines), False):
            print(f"could not clear the hooks flag in {username}'s config.toml; left unchanged")
            return False
        flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC | getattr(os, 'O_NOFOLLOW', 0)
        fd = os.open(str(config_path), flags, 0o600)
        with os.fdopen(fd, 'w', encoding='utf-8') as f:
            f.writelines(new_lines)
        return True

    if _run_as_user(username, _disable):
        debug_print(f"Removed hooks feature flag for {username}")


def _remove_env_var_for_all_users(var_name: str, keep=lambda home_dir: False) -> bool:
    """Removes var_name for every user except those keep() names; False when any removal failed."""
    if platform.system().lower() == "windows":
        # One machine-wide value: it stays if any user still needs it.
        # A planted hook file only keeps a value every user can already read; unbound-hook clear drops it regardless.
        if keep(None) or any(keep(home_dir) for _, home_dir in get_all_user_homes()):
            return True
        return remove_env_var_on_windows_machine(var_name) in ("cleared", "not_found")
    ok = True
    for username, home_dir in get_all_user_homes():
        if not keep(home_dir) and remove_env_var_from_user(username, home_dir, var_name) not in ("cleared", "not_found"):
            ok = False
    return ok


def _config_has_key(home_dir: Optional[Path] = None) -> bool:
    try:
        cfg = json.loads(((home_dir or Path.home()) / ".unbound" / "config.json").read_text(encoding="utf-8"))
        return bool(cfg.get("api_key") or cfg.get("device_token"))
    except Exception:
        return False


# Temporary: removes the per-tool key env var older installs wrote. Delete once fleets have re-run setup.
def remove_legacy_key_env() -> None:
    try:
        _remove_env_var_for_all_users("UNBOUND_CODEX_API_KEY")
        # Env copy goes only once config.json holds the key; the Default profile gets one too, so later Windows profiles inherit it.
        _remove_env_var_for_all_users("UNBOUND_DEVICE_TOKEN", keep=lambda home_dir: home_dir is not None and not _config_has_key(home_dir))
    except Exception:
        pass


# Other Unbound tools' hook dirs; the shared UNBOUND_DEVICE_TOKEN stays while any of them holds a hook.
OTHER_HOOK_DIRS = (
    "~/.claude", "~/.cursor", "~/.copilot", "~/.augment",
    "/Library/Application Support/ClaudeCode", "/etc/claude-code", "%ProgramFiles%/ClaudeCode",
    "/Library/Application Support/Cursor", "/etc/cursor", "%ProgramData%/Cursor",
    "/etc/augment", "%ProgramData%/Augment",
)


def device_token_in_use(home_dir: Optional[Path]) -> bool:
    for d in OTHER_HOOK_DIRS:
        if d.startswith("~"):
            if home_dir is None:
                continue
            d = str(home_dir) + d[1:]
        p = Path(os.path.expandvars(d))
        # A relative path is another OS's entry (/etc on Windows, an unexpanded %VAR% elsewhere).
        if p.is_absolute() and (p / "hooks" / "unbound.py").exists():
            return True
    return False


def clear_setup() -> bool:
    print("=" * 60)
    print("Codex Hooks - Clearing MDM Setup")
    print("=" * 60)

    if not check_admin_privileges():
        print("This script requires administrator/root privileges")
        print("   Please re-run with sudo.")
        return False

    teardown_failed = False

    print("\nClearing environment variables...")
    # Windows `reg delete HKLM\...` is machine-wide; fall through with a
    # placeholder so the removal runs even if C:\Users has no profiles.
    user_homes = get_all_user_homes() or ([(None, None)] if platform.system().lower() == "windows" else [])

    if not user_homes:
        print("   No user home directories found")
    else:
        cleared = 0
        not_found = 0
        failed = 0
        for username, home_dir in user_homes:
            status = remove_env_var_from_user(username, home_dir, "UNBOUND_CODEX_API_KEY")
            remove_hook_logs_for_user(username, home_dir)
            if status == "cleared":
                cleared += 1
            elif status == "not_found":
                not_found += 1
            else:
                failed += 1
            # Per-user codex config — skip when falling through on Windows.
            if home_dir is not None:
                # Setup registers our hook in the user's own hooks.json, so uninstall has to
                # take it out there too; leaving it points a live entry at a deleted script.
                # It also has to happen before the flag is cleared, since the flag is kept
                # whenever a hook is still registered.
                remove_user_level_hooks_for_user(username, home_dir)
                disable_codex_hooks_feature_for_user(username, home_dir)

        if cleared:
            print(f"Cleared for {cleared} user(s)")
        elif not_found:
            print(f"API_KEY not set, nothing to clear for {not_found} user(s)")
        if failed:
            teardown_failed = True
            print(f"Failed to clear API_KEY for {failed} user(s)")

    print("\nClearing managed hooks...")
    status = clear_managed_hooks()
    managed_dir = get_managed_settings_dir()
    if status == "cleared":
        print(f"Cleared managed hooks from {managed_dir}")
    elif status == "not_found":
        print(f"Managed hooks not found in {managed_dir}")
    else:
        teardown_failed = True
        print(f"Failed to clear managed hooks in {managed_dir}")

    if not _remove_env_var_for_all_users("UNBOUND_DEVICE_TOKEN", keep=device_token_in_use):
        teardown_failed = True
        print("Failed to clear UNBOUND_DEVICE_TOKEN")

    print("\n" + "=" * 60)
    print("Clear Complete!")
    print("=" * 60)

    return not teardown_failed


def _backfill_session_id_from_filename(transcript_path: Path) -> Optional[str]:
    # Only `rollout-<isots>-<uuid>.jsonl` — never a generic stem fallback.
    m = ROLLOUT_FILENAME_RE.match(transcript_path.stem)
    return m.group(1) if m else None


def _backfill_collect_session(transcript_path: Path) -> Optional[Dict]:
    """Read a transcript and return {session_id, entries} for server-side parsing.
    The client only JSON-decodes lines and resolves a session id (preferring
    the session_meta payload, falling back to the rollout filename UUID). All
    semantic parsing happens server-side."""
    entries = []
    session_id = None
    try:
        with open(transcript_path, 'r', encoding='utf-8') as f:
            for lineno, line in enumerate(f):
                if lineno >= BACKFILL_MAX_LINES_PER_FILE:
                    break
                if not line.strip():
                    continue
                try:
                    entry = json.loads(line)
                except json.JSONDecodeError:
                    continue
                entries.append(entry)
                if not session_id:
                    sid = entry.get('sessionId') or entry.get('session_id')
                    payload = entry.get('payload')
                    if not sid and isinstance(payload, dict):
                        sid = payload.get('id') or payload.get('session_id')
                    if sid:
                        session_id = sid
    except (OSError, UnicodeDecodeError):
        return None
    except Exception:
        return None

    # session_meta absent → recover from rollout-<ts>-<uuid>.jsonl filename only;
    # never fall back to a generic stem.
    if not session_id:
        session_id = _backfill_session_id_from_filename(transcript_path)

    if not session_id or not entries:
        return None
    return {'session_id': session_id, 'entries': entries}


def _backfill_state_path(home: Path) -> Path:
    return home / '.codex' / 'hooks' / BACKFILL_STATE_FILE


def _backfill_read_cutoff(home: Path) -> float:
    """mtime cutoff for transcript selection: the last successful backfill when
    cached (so cron reruns only seed sessions touched since), else 30 days ago."""
    default_cutoff = time.time() - (BACKFILL_MAX_AGE_DAYS * 86400)
    try:
        last = float(_backfill_state_path(home).read_text().strip())
    except (OSError, ValueError):
        return default_cutoff
    # Ignore corrupt or future timestamps (clock skew).
    if last <= 0 or last > time.time():
        return default_cutoff
    return last


def _backfill_write_cutoff(home: Path, ts: float) -> None:
    # Write via temp + atomic replace so an overlapping cron run never reads a
    # half-written timestamp.
    try:
        path = _backfill_state_path(home)
        path.parent.mkdir(parents=True, exist_ok=True)
        tmp = path.parent / f'{path.name}.{os.getpid()}.tmp'
        tmp.write_text(str(ts))
        os.replace(tmp, path)
    except OSError as e:
        debug_print(f"failed to persist backfill timestamp: {e}")


def _backfill_iter_transcripts(root: Path, cutoff_mtime: float):
    # Skip hidden, symlinked, oversized (50MB cap), or files older than cutoff.
    for p in root.rglob('rollout-*.jsonl'):
        if p.name.startswith('.'):
            continue
        if not p.is_file() or p.is_symlink():
            continue
        try:
            st = p.stat()
            if st.st_size > BACKFILL_MAX_FILE_BYTES:
                continue
            if st.st_mtime < cutoff_mtime:
                continue
        except OSError:
            continue
        yield p


def _backfill_is_user_message_payload(payload) -> bool:
    # Mirror server-side parse_codex_session's user-message-start gate:
    # response_item with payload.type='message' role='user', non-empty joined
    # text, and not a Codex prelude (AGENTS.md / environment_context wrapper).
    if not isinstance(payload, dict):
        return False
    if payload.get('type') != 'message' or payload.get('role') != 'user':
        return False
    text_parts = []
    for c in payload.get('content') or []:
        if isinstance(c, dict):
            text = c.get('text') or c.get('content') or ''
            if isinstance(text, str) and text:
                text_parts.append(text)
    joined = '\n\n'.join(text_parts)
    if not joined:
        return False
    stripped = joined.lstrip()
    if stripped.startswith('# AGENTS.md') or stripped.startswith('<environment_context>'):
        return False
    return True


def _backfill_exchange_boundaries(entries: List[Dict]) -> List[int]:
    boundaries = []
    for i, entry in enumerate(entries):
        if not isinstance(entry, dict):
            continue
        if entry.get('type') != 'response_item':
            continue
        if _backfill_is_user_message_payload(entry.get('payload')):
            boundaries.append(i)
    return boundaries


def _backfill_slice_session(session: Dict, max_chunk_bytes: int):
    """Yield session payloads ≤ max_chunk_bytes. Sessions that already fit are
    yielded as-is. Oversized sessions are split at server-side exchange
    boundaries; each slice carries record_index_base = cumulative exchange
    count of all earlier slices so the server's per-record UUID5 seed stays
    globally stable per (org, tool, session, record_index)."""
    session_id = session.get('session_id')
    entries = session.get('entries') or []
    try:
        if len(json.dumps(session).encode('utf-8')) <= max_chunk_bytes:
            yield session
            return
        # +2 for the `, ` separator json.dumps puts between array elements.
        entry_sizes = [len(json.dumps(e).encode('utf-8')) + 2 for e in entries]
    except (TypeError, ValueError):
        debug_print(f"skipping unserializable session {session_id}")
        return

    boundaries = _backfill_exchange_boundaries(entries)
    n = len(entries)
    record_index_base = 0
    start_idx = 0
    while start_idx < n:
        ends = [b for b in boundaries if b > start_idx]
        if not ends or ends[-1] < n:
            ends.append(n)

        wrap = len(json.dumps({
            'session_id': session_id,
            'record_index_base': record_index_base,
            'entries': [],
        }).encode('utf-8'))
        cum = wrap
        cursor = start_idx
        last_fit_end = None
        last_fit_base_count = 0
        for end_idx in ends:
            cum += sum(entry_sizes[cursor:end_idx])
            cursor = end_idx
            # -2: last entry has no trailing `, ` and `[]` was counted in wrap.
            if cum - 2 > max_chunk_bytes:
                break
            last_fit_end = end_idx
            last_fit_base_count = sum(1 for b in boundaries if start_idx <= b < end_idx)

        if last_fit_end is None:
            debug_print(f"skipped session {session_id}: smallest exchange slice exceeds {max_chunk_bytes} bytes")
            return

        yield {
            'session_id': session_id,
            'record_index_base': record_index_base,
            'entries': entries[start_idx:last_fit_end],
        }
        record_index_base += last_fit_base_count
        start_idx = last_fit_end


def _backfill_collect_sessions(home_dir: Path, force_epoch=None,
                               force_days=None) -> Tuple[List[Dict], bool, bool]:
    # Returns (sessions, capped, forced); capped=True means the per-run cap was hit and
    # older files remain unprocessed, so this home's cutoff must not advance.
    sessions_root = home_dir / '.codex' / 'sessions'
    if not sessions_root.exists():
        # Three values like every other exit: the caller unpacks one shape, and a
        # profile with no history here was not behind the request either.
        return [], False, False
    cutoff_mtime = _backfill_read_cutoff(home_dir)
    forced = force_epoch is not None and force_epoch > cutoff_mtime
    if forced:
        # The organization's window when it set one, otherwise this installer's own
        # default. Widen only: a window narrower than what this device had already
        # reached would skip the band in between, and the successful run then advances
        # the cutoff past it, so that history is never visited again.
        window = time.time() - ((force_days or BACKFILL_MAX_AGE_DAYS) * 86400)
        cutoff_mtime = min(cutoff_mtime, window)
    sessions = []
    capped = False
    for transcript_path in sorted(_backfill_iter_transcripts(sessions_root, cutoff_mtime)):
        if len(sessions) >= BACKFILL_MAX_SESSIONS_PER_RUN:
            capped = True
            break
        session = _backfill_collect_session(transcript_path)
        if session:
            sessions.append(session)
    return sessions, capped, forced


def _backfill_edr_headers(extra: Optional[Dict[str, str]] = None) -> Dict[str, str]:
    # Stable, identifiable UA + ops headers so SOC tooling can whitelist by signature.
    headers = {
        'User-Agent': f'Unbound-Setup/{BACKFILL_TOOL_TYPE}-backfill ({platform.platform()})',
        'X-Unbound-Operation': 'backfill',
        'X-Unbound-Tool': BACKFILL_TOOL_TYPE,
    }
    if extra:
        headers.update(extra)
    return headers


def _backfill_http_request(url: str, method: str, headers: Dict[str, str], body: Optional[bytes] = None, timeout: int = 30) -> Tuple[int, bytes]:
    # curl subprocess, not urllib: the frozen binary ships no CA bundle, so
    # Python's ssl fails CERTIFICATE_VERIFY_FAILED; curl uses the system trust
    # store (the corporate-CA/Zscaler contract every other call here relies on).
    # --retry rides out transient backend errors (5xx/429/timeout/conn-refused)
    # so a flaky gateway during onboard doesn't drop a chunk; --max-time caps
    # each attempt and the subprocess budget below outlasts all the retries.
    cmd = ["curl", "-sS", "-X", method, "-w", "\n%{http_code}", "--max-time", str(timeout)]
    if method == 'PUT':
        # A slow upload runs to the total cap, a stalled one is cut; the caller re-sends, on a fresh link.
        cmd += ["--speed-limit", str(BACKFILL_PUT_STALL_BYTES_PER_SECOND),
                "--speed-time", str(BACKFILL_PUT_STALL_SECONDS), "--retry", "0"]
        process_timeout = timeout + 20
    else:
        cmd += ["--retry", "3", "--retry-delay", "2", "--retry-connrefused"]
        process_timeout = timeout * 4 + 20
    for header_name, header_value in headers.items():
        cmd += ["-H", f"{header_name}: {header_value}"]
    if body is not None:
        cmd += ["--data-binary", "@-"]
    cmd += ["--", url]  # -- stops option parsing so a '-'-leading URL can't be read as a flag
    try:
        result = subprocess.run(cmd, input=body, capture_output=True, timeout=process_timeout)
    except subprocess.TimeoutExpired as e:
        # Not str(e): it carries the whole curl command, auth header and upload link included.
        debug_print(f"{method} request timed out after {e.timeout}s")
        return -28, b''  # curl's own timeout exit, negated
    except OSError as e:
        debug_print(f"HTTP request failed: {e}")
        return 0, b''
    # A transport failure reads as curl's exit code negated, so it can be told from an HTTP status.
    transport_failure = -abs(result.returncode)
    if result.returncode != 0:
        # curl transport error (DNS/TLS/refused); -sS keeps the message on stderr.
        debug_print(f"curl exit {result.returncode}: {(result.stderr or b'').decode('utf-8', 'replace').strip()}")
    out = result.stdout or b''
    # curl appended "\n<http_code>" after the response body; split it off.
    sep = out.rfind(b'\n')
    if sep == -1:
        debug_print(f"HTTP request failed: curl exit {result.returncode}")
        return transport_failure, b''
    try:
        code = int(out[sep + 1:].strip() or b'0')
    except ValueError:
        debug_print(f"HTTP request failed: curl exit {result.returncode}")
        return transport_failure, b''
    # An interim status such as 100 from a transfer that then died is the transport failure, not an answer.
    if result.returncode != 0 and code < 200:
        return transport_failure, b''
    return code, out[:sep]


def _backfill_force_config(api_key: str, backend_url: str) -> Tuple[Optional[float], Optional[int]]:
    """When the organization last asked every device to re-walk its full history, and how
    far back that walk should reach. Either may be None.

    A device honours the request only if its own last backfill predates it, so the request
    expires by itself once each device has acted on it -- nobody has to switch it back off.
    The window is optional: without one the walk uses this installer's own default, which
    is what every device did before the organization could set it."""
    try:
        code, body = _backfill_http_request(
            # tool_type is a metrics label only; the request itself is org-wide.
            f"{backend_url.rstrip('/')}/api/v1/coding-tools/backfill/config/"
            f"?tool_type={BACKFILL_TOOL_TYPE}",
            method='GET',
            headers=_backfill_edr_headers({'Authorization': f'Bearer {api_key}'}),
            timeout=15,
        )
        if code < 200 or code >= 300:
            debug_print(f"backfill config request failed: HTTP {code}")
            return None, None
        config = json.loads(body.decode('utf-8'))
        requested = config.get('force_backfill_requested_epoch')
        if isinstance(requested, bool) or not isinstance(requested, (int, float)):
            return None, None
        days = config.get('force_backfill_days')
        # bool is an int subclass, so True would otherwise read as a one-day window.
        if isinstance(days, bool) or not isinstance(days, int) or days < 1:
            days = None
        return float(requested), days
    except Exception as e:
        debug_print(f"backfill config read failed: {e}")
        return None, None


def _backfill_run_seconds_left() -> float:
    # What a PUT may still take before the soft stop, leaving from-s3 its turn; unbounded when no stop is set.
    if _backfill_stop_at is None:
        return float('inf')
    return _backfill_stop_at - time.time() - BACKFILL_FROM_S3_RESERVE_SECONDS


def _backfill_out_of_run_time() -> bool:
    return _backfill_run_seconds_left() < BACKFILL_PUT_MIN_SECONDS


class _BackfillOutOfTime(Exception):
    """A chunk was left unsent because it would not fit before the soft stop; carries the sessions sent so far."""


def _backfill_upload_chunk(api_key: str, backend_url: str, sessions: List[Dict],
                           force: bool = False) -> Optional[bool]:
    # None when the run's soft stop left no time for the PUT: a stop, not a failed upload.
    payload = {'tool_type': BACKFILL_TOOL_TYPE, 'sessions': sessions}
    if force:
        # Marks this upload as the org's requested re-walk. The server still checks the
        # request itself, so this only narrows what force applies to; it cannot grant it.
        payload['force'] = True
    payload_bytes = json.dumps(payload).encode('utf-8')

    auth_headers = _backfill_edr_headers({
        'Authorization': f'Bearer {api_key}',
        'Content-Type': 'application/json',
    })

    chunk_started = time.time()

    def put_seconds_left() -> int:
        return int(min(BACKFILL_PUT_MAX_SECONDS - (time.time() - chunk_started), _backfill_run_seconds_left()))

    for _ in range(BACKFILL_PUT_ATTEMPTS):
        if put_seconds_left() < BACKFILL_PUT_MIN_SECONDS:
            debug_print("S3 PUT not retried: the chunk's time is used up")
            return None if _backfill_out_of_run_time() else False
        code, body = _backfill_http_request(
            f"{backend_url.rstrip('/')}/api/v1/coding-tools/backfill/upload-url/",
            method='POST',
            headers=auth_headers,
            body=json.dumps({'tool_type': BACKFILL_TOOL_TYPE}).encode('utf-8'),
            timeout=30,
        )
        if code < 200 or code >= 300:
            debug_print(f"upload-url request failed: HTTP {code}")
            return False
        try:
            url_resp = json.loads(body.decode('utf-8'))
        except (ValueError, UnicodeDecodeError):
            debug_print("upload-url response was not JSON")
            return False

        upload_url = url_resp.get('upload_url')
        object_key = url_resp.get('object_key')
        if not upload_url or not object_key:
            debug_print("upload-url response missing fields")
            return False

        # Measured after the link request, which comes out of the same budget.
        put_cap = put_seconds_left()
        if put_cap < BACKFILL_PUT_MIN_SECONDS:
            debug_print("S3 PUT not started: the link request used the chunk's time")
            return None if _backfill_out_of_run_time() else False
        put_started = time.time()
        code, put_answer = _backfill_http_request(
            upload_url,
            method='PUT',
            headers=_backfill_edr_headers({'Content-Type': 'application/json'}),
            body=payload_bytes,
            timeout=put_cap,
        )
        if 200 <= code < 300:
            break
        debug_print(f"S3 PUT failed: HTTP {code}")
        timed_out_at_s3 = code == 408 or (code == 400 and b'RequestTimeout' in put_answer)
        if (0 <= code < 500 and not timed_out_at_s3) or (code < 0 and time.time() - put_started >= put_cap - 1):
            # Refused, or still moving when the cap cut it: another attempt would end the same way.
            return False
        # A stall (S3 calls it out itself after ~20s of silence), another transport failure or a 5xx:
        # the next attempt asks for a fresh link.
    else:
        return False

    code, _ = _backfill_http_request(
        f"{backend_url.rstrip('/')}/api/v1/coding-tools/backfill/from-s3/",
        method='POST',
        headers=auth_headers,
        body=json.dumps({'tool_type': BACKFILL_TOOL_TYPE, 'object_key': object_key}).encode('utf-8'),
        timeout=30,
    )
    if code < 200 or code >= 300:
        debug_print(f"from-s3 request failed: HTTP {code}")
        return False

    return True


def _backfill_send_sessions(api_key: str, backend_url: str, sessions: List[Dict],
                            forced: bool = False) -> Tuple[int, int, int]:
    """Return (sessions_sent, chunks_sent, chunks_failed). sessions_sent counts
    distinct input session_ids that landed at least one successful chunk."""
    chunks_total = 0
    chunks_sent = 0
    sessions_sent_ids: set = set()
    current_chunk: List[Dict] = []
    current_size = 2

    def _flush():
        nonlocal current_chunk, current_size, chunks_total, chunks_sent
        if not current_chunk:
            return
        if _backfill_out_of_run_time():
            raise _BackfillOutOfTime(len(sessions_sent_ids))
        landed = _backfill_upload_chunk(api_key, backend_url, current_chunk, forced)
        if landed is None:
            raise _BackfillOutOfTime(len(sessions_sent_ids))
        chunks_total += 1
        if landed:
            chunks_sent += 1
            for s in current_chunk:
                sessions_sent_ids.add(s.get('session_id'))
        current_chunk = []
        current_size = 2

    for session in sessions:
        for slice_session in _backfill_slice_session(session, BACKFILL_CHUNK_BYTES):
            try:
                slice_bytes = len(json.dumps(slice_session).encode('utf-8'))
            except (TypeError, ValueError):
                continue
            if slice_bytes > BACKFILL_CHUNK_BYTES:
                continue
            if current_chunk and current_size + slice_bytes + 1 > BACKFILL_CHUNK_BYTES:
                _flush()
            current_chunk.append(slice_session)
            current_size += slice_bytes + 1

    _flush()
    return len(sessions_sent_ids), chunks_sent, chunks_total - chunks_sent


@contextmanager
def _backfill_soft_stop(soft_stop_seconds: int):
    """For main()'s uploads: they stop themselves before onboard's per-tool watchdog would kill the installer."""
    global _backfill_stop_at
    _backfill_stop_at = _SCRIPT_START + soft_stop_seconds
    try:
        yield
    finally:
        _backfill_stop_at = None


def run_backfill(api_key: str, backend_url: str, user_homes: List[Tuple[str, Path]]) -> None:
    """Walk every user's ~/.codex/sessions and seed historical sessions.

    MDM /get_application_api_key/ returns one per-device key and attribution is
    by device, so all profiles' history is seeded under that single key — the
    same model as install, which configures every user profile."""
    if os.environ.get('UNBOUND_BACKFILL_DISABLED') == '1':
        debug_print("UNBOUND_BACKFILL_DISABLED=1 — skipping backfill")
        return

    try:
        if not user_homes:
            debug_print("no user homes found — skipping backfill")
            return
        if _backfill_run_seconds_left() < BACKFILL_PUT_MIN_SECONDS + BACKFILL_START_MARGIN_SECONDS:
            # The config request and the walk come before the first chunk and are not free either.
            print("[backfill] Skipped — no time left in this run; history is sent on the next run.")
            return

        started_at = time.time()
        # Fetched once, before privileges are dropped: one call per device, not per profile.
        force_epoch, force_days = _backfill_force_config(api_key, backend_url)
        # Kept apart by whether the profile they came from is actually behind the org's
        # request. Merging them would assert force over a profile that never asked for
        # it, letting its settled sessions be reopened.
        forced_sessions = []
        sessions = []
        collected_homes: List[Tuple[str, Path]] = []
        for username, home_dir in user_homes:
            result = _run_as_user(username, _backfill_collect_sessions, home_dir,
                                  force_epoch, force_days)
            if result is None:
                # Could not read this user's home (fork/perms) — don't advance its
                # cutoff, or we'd permanently skip its history on the next run.
                continue
            user_sessions, capped, home_forced = result
            if user_sessions:
                debug_print(f"Found {len(user_sessions)} sessions for user: {username}")
                (forced_sessions if home_forced else sessions).extend(user_sessions)
            # Capped homes still have unprocessed files — leave their cutoff so the
            # overflow stays eligible on the next run.
            if not capped:
                collected_homes.append((username, home_dir))

        total = len(forced_sessions) + len(sessions)
        if not total:
            for username, home_dir in collected_homes:
                _run_as_user(username, _backfill_write_cutoff, home_dir, started_at)
            print("[backfill] No past sessions found.")
            return

        print(f"[backfill] Found {total} past sessions. Uploading (this may take a few minutes)...")
        sessions_sent = 0
        chunks_failed = 0
        out_of_time = False
        for batch, forced in ((forced_sessions, True), (sessions, False)):
            if not batch:
                continue
            try:
                sent, _, failed = _backfill_send_sessions(api_key, backend_url, batch, forced)
            except _BackfillOutOfTime as stop:
                sessions_sent += stop.args[0]
                out_of_time = True
                break
            sessions_sent += sent
            chunks_failed += failed

        if out_of_time:
            # The cutoff stays where it was, so the next run starts this history again.
            print(f"[backfill] Queued {sessions_sent} past sessions. More history remains for the next run.")
        elif sessions_sent == 0:
            print(f"[backfill] No sessions queued (all {chunks_failed} uploads failed).")
        elif chunks_failed:
            print(f"[backfill] Done — queued {sessions_sent} past sessions ({chunks_failed} chunks failed).")
        else:
            for username, home_dir in collected_homes:
                _run_as_user(username, _backfill_write_cutoff, home_dir, started_at)
            print(f"[backfill] Done — queued {sessions_sent} past sessions for processing.")
    except Exception as e:
        print(f"[backfill] Skipped due to error: {e}", file=sys.stderr)


def _is_our_hook_file(path) -> bool:
    """A real file at exactly this path. lstat, not exists: these live in
    user-writable homes, and a symlink there is not something we installed."""
    try:
        return stat.S_ISREG(path.lstat().st_mode)
    except OSError:
        return False


def _installed_hook_script() -> Optional[Path]:
    """The managed hook script, else the per-user one from the first home that has one."""
    managed = get_managed_settings_dir() / "hooks" / "unbound.py"
    if _is_our_hook_file(managed):
        return managed
    for _username, home_dir in get_all_user_homes():
        candidate = home_dir / ".codex" / "hooks" / "unbound.py"
        if _is_our_hook_file(candidate):
            return candidate
    return None


def detect_install_state() -> Optional[str]:
    """Inspect the install target BEFORE this run reasserts it.
    Codex discovers hooks from the user layer, so the install writes nothing to
    the managed dir. Setup installs for every profile it finds, so the state is
    per profile: the pair is the hook script and our entry in that user's
    hooks.json, and either one alone leaves Codex unenforced for them.
    'fresh' (no profile has either), 'persisted' (at least one has both),
    'tampered' (any profile has one without the other), None on any error.
    Tampered wins, matching the copilot detector.
    A hooks.json we declined to read leaves the answer undetermined rather than
    assumed: None omits install_state from the report, so the stored state is left
    alone instead of being guessed healthy or guessed tampered."""
    try:
        managed_script = get_managed_settings_dir() / "hooks" / "unbound.py"
        script = _is_our_hook_file(managed_script)
        registered = _unbound_hook_registered(managed_script.parent.parent / "hooks.json", managed_script)
        if script or registered:
            return None if registered is None else ('persisted' if script and registered else 'tampered')
        any_complete = False
        indeterminate = False
        for _username, home_dir in get_all_user_homes():
            script_path = home_dir / ".codex" / "hooks" / "unbound.py"
            script = _is_our_hook_file(script_path)
            registered = _unbound_hook_registered(
                home_dir / ".codex" / "hooks.json", script_path)
            if registered is None:
                # We declined to read it, so this profile is evidence of nothing.
                # Never let the script stand in for the registration.
                indeterminate = True
                continue
            if not script and not registered:
                continue
            if script and registered:
                any_complete = True
            else:
                return 'tampered'
        if indeterminate:
            return None
        return 'persisted' if any_complete else 'fresh'
    except Exception as e:
        debug_print(f"detect_install_state failed: {e}")
        return None


def hook_script_hash(script_path) -> Optional[str]:
    """sha256 of the hook script this run installed, so the backend can tell which
    hook version a device is running. None when absent or unreadable.

    Codex installs per user, so this path sits in a user-writable home and is read
    here by a root/SYSTEM process. Symlinks are refused and the size is capped, so
    the path cannot be swapped between install and report to make setup hash a file
    it should not read, or block on something that never ends."""
    if script_path is None:
        return None
    try:
        fd = os.open(str(script_path),
                     os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0) | getattr(os, 'O_NONBLOCK', 0))
    except OSError:
        return None
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_size > _HOOK_SCRIPT_MAX_BYTES:
            return None
        digest = hashlib.sha256()
        while True:
            chunk = os.read(fd, 65536)
            if not chunk:
                break
            digest.update(chunk)
        return digest.hexdigest()
    except OSError:
        return None
    finally:
        os.close(fd)


TOOL_NAME, TOOL_CLI = "Codex", "codex"
HOOK_ERROR_LOG = (".codex/hooks/error.log", "codex")  # this tool's log under a home, and its hook_source
_CODEX_HOME_FILES = (".codex/auth.json", ".codex/sessions")  # codex's own, never setup's
# Per OS: (machine-wide paths, paths under a home), beside the CLI's own folders.
TOOL_FOOTPRINTS = {
    "darwin": (("Applications/Codex.app",), _CODEX_HOME_FILES + ("Applications/Codex.app",)),
    "linux": ((), _CODEX_HOME_FILES),
    "windows": ((), _CODEX_HOME_FILES),
}

# --- Whether the tool is installed (WEB-6392) ---------------------------------------------
# For the setup/complete status only: a tool with none of its files on disk is reported skipped,
# "<Tool> is not installed", and its config is written all the same. Existence checks only (and
# ~/.npmrc, read without following a link, for its prefix); a check that fails counts as installed.
# Every tool's MDM script runs on its own, so each one carries this same code with its own
# footprints, kept equal by tests/test_tool_installed.py; the unbound-hook binary calls it too.
_UNIX_HOME_CLI_DIRS = (
    ".local/bin", ".bun/bin", ".npm-global/bin", ".nvm/versions/node/*/bin", ".volta/bin",
    ".local/share/fnm/node-versions/*/installation/bin", ".fnm/node-versions/*/installation/bin",
    ".asdf/shims", ".local/share/mise/shims", ".local/share/mise/installs/*/*/bin",
    ".nodenv/shims", ".nodenv/versions/*/bin", ".yarn/bin", ".config/yarn/global/node_modules/.bin")
# Where a CLI lands, per OS: (machine-wide folders, folders under a user's home).
_CLI_DIRS = {
    "darwin": (("opt/homebrew/bin", "usr/local/bin", "opt/local/bin"), _UNIX_HOME_CLI_DIRS + ("Library/pnpm",)),
    "linux": (("usr/local/bin", "usr/bin", "snap/bin", "var/lib/flatpak/exports/bin"),
              _UNIX_HOME_CLI_DIRS + (".local/share/pnpm", ".local/share/flatpak/exports/bin")),
    "windows": (("ProgramData/chocolatey/bin", "Program Files/nodejs"),
                ("AppData/Roaming/npm", "AppData/Local/pnpm", "AppData/Local/Volta/bin", "AppData/Roaming/nvm/*",
                 "scoop/shims", ".local/bin", ".bun/bin")),
}
_CLI_SUFFIXES = {"windows": ("", ".exe", ".cmd", ".ps1")}


def _install_root(system: str) -> Path:
    return Path((os.environ.get("SystemDrive") or "C:") + "\\") if system == "windows" else Path("/")


def _found(root: Path, relpath: str) -> bool:
    """Something is at relpath; a place that can't be looked at counts as found."""
    try:
        return any(root.glob(relpath)) if "*" in relpath else (root / relpath).exists()
    except OSError:
        return True


def _npmrc_cli_dir(home: Path, system: str) -> Optional[Path]:
    """Where npm puts CLIs for a prefix the user set in ~/.npmrc, or None."""
    try:
        fd = os.open(str(home / ".npmrc"), os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0))
    except OSError:
        return None
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            return None
        text = os.read(fd, 65536).decode("utf-8", "replace")
    except OSError:
        return None
    finally:
        os.close(fd)
    for line in text.splitlines():
        key, sep, value = line.partition("=")
        if sep and key.strip() == "prefix":
            value = value.strip().strip("\"'")
            for token in ("${HOME}", "$HOME"):
                value = value.replace(token, str(home))
            if value.startswith("~/"):
                value = str(home) + value[1:]
            if not os.path.isabs(value):
                return None
            return Path(value) if system == "windows" else Path(value) / "bin"
    return None


def tool_installed(user_homes, system: Optional[str] = None, machine_root: Optional[Path] = None) -> bool:
    """Whether any of this tool's footprints is on the machine or in a user's home."""
    try:
        system = system or platform.system().lower()
        root = machine_root if machine_root is not None else _install_root(system)
        machine_dirs, home_dirs = _CLI_DIRS.get(system, ((), ()))
        machine_files, home_files = TOOL_FOOTPRINTS.get(system, ((), ()))
        names = [TOOL_CLI + suffix for suffix in _CLI_SUFFIXES.get(system, ("",))]
        machine = [f"{d}/{n}" for d in machine_dirs for n in names] + list(machine_files)
        per_home = [f"{d}/{n}" for d in home_dirs for n in names] + list(home_files)
        if any(_found(root, rel) for rel in machine):
            return True
        for _, home in user_homes:
            if home is None:
                continue
            npm_dir = _npmrc_cli_dir(Path(home), system)
            if any(_found(Path(home), rel) for rel in per_home) or (
                    npm_dir is not None and any(_found(npm_dir, n) for n in names)):
                return True
        return False
    except Exception:
        return True


# --- Stuck hook errors (WEB-6392) -----------------------------------------------------------
# A hook reports an error to the gateway at most once a minute and never retries, so the rest wait in
# its error.log. Each run sends this tool's entries (HOOK_ERROR_LOG) newer than the last one forwarded,
# per home and with that home's own key, as the unbound-hook binary does on a Mac. Every tool's MDM script
# runs on its own, so each one carries this same code, kept equal by tests/test_mdm_hook_errors.py.
# Beside each error.log: "<timestamp> <n>", the newest entry the gateway accepted and how many entries
# stamped exactly then were sent (two can share a stamp, and a request can end between them).
FORWARDED_STATE_NAME = ".error_log_forwarded"
HOOK_ERRORS_PER_REQUEST = 10  # the gateway takes at most ten
# error.log is the user's to write: per home, a run sends at most the newest 25 (what a hook keeps) and
# nothing older than a week, so a flooded or first-seen log costs at most three requests.
HOOK_ERRORS_PER_RUN = 25
HOOK_ERROR_MAX_AGE = timedelta(days=7)
# Sentry groups by category: forwarded entries group together, apart from the hook's live reports.
FORWARDED_ERROR_CATEGORY = "forwarded_error_log"
HOOK_ERROR_TIMEOUT_SECONDS = 5  # forwarding must never hold setup up
HOOK_ERROR_USER_TIMEOUT = 30  # a step run as the user, who can pause it, ends after this
_HOOK_ERROR_LINE = re.compile(r"^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})): (.*)$")
_USER_FILE_MAX_BYTES = 4 * 1024 * 1024
# A user's file: never followed if it is a link, never waited on if it is a FIFO, never text-mode on Windows.
_USER_FILE_FLAGS = getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_BINARY", 0)
_BEARER = re.compile(r"(?i)\bBearer\s+\S+")
_NAMED_SECRET = re.compile(r"""(?i)\b([A-Za-z0-9_-]*(?:api[_-]?key|token|secret|password|passwd))("?\s*[:=]\s*"?)([^\s"',;&}]+)""")
_URL_SECRET = re.compile(r"(?i)([?&](?:key|token|api_key|access_token|sig|signature)=)[^&\s\"]+")
_VENDOR_KEY = re.compile(r"\bsk-[A-Za-z0-9_-]{10,}")


def _log_time(text):
    """An entry's timestamp as an aware datetime (hooks write UTC 'Z' or local time with its offset), else None."""
    try:
        when = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except (TypeError, ValueError):
        return None
    return when if when.tzinfo else None


def _refuse_links_on_the_way(path: Path) -> None:
    """Windows: SYSTEM opens a user's path itself, so a link or junction anywhere on it is refused before the
    open, and _refuse_if_redirected checks the opened file after it. A part not made yet is skipped."""
    if os.name != "nt":
        return
    path = Path(os.path.abspath(str(path)))
    for part in (path, *path.parents):
        try:
            st = os.lstat(part)
        except FileNotFoundError:
            continue
        if stat.S_ISLNK(st.st_mode) or getattr(st, "st_file_attributes", 0) & 0x400:  # a reparse point
            raise OSError(f"{part} is a link or junction")


def _refuse_if_redirected(fd: int, path: Path) -> None:
    """Windows has no O_NOFOLLOW, and SYSTEM opens a user's files itself: the file opened must be the one at
    the path asked for, with no link or junction anywhere on the way. Closes fd and raises OSError if not."""
    if os.name != "nt":
        return
    import ctypes
    import msvcrt
    from ctypes import wintypes
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.GetFinalPathNameByHandleW.argtypes = (wintypes.HANDLE, wintypes.LPWSTR, wintypes.DWORD, wintypes.DWORD)
    kernel32.GetFinalPathNameByHandleW.restype = wintypes.DWORD
    kernel32.GetLongPathNameW.argtypes = (wintypes.LPCWSTR, wintypes.LPWSTR, wintypes.DWORD)
    kernel32.GetLongPathNameW.restype = wintypes.DWORD

    def plain(name):
        return "\\\\" + name[8:] if name.startswith("\\\\?\\UNC\\") else name[4:] if name.startswith("\\\\?\\") else name

    final, asked = ctypes.create_unicode_buffer(32768), ctypes.create_unicode_buffer(32768)
    got = kernel32.GetFinalPathNameByHandleW(msvcrt.get_osfhandle(fd), final, len(final), 0)
    # The path asked for in its long form (a temp folder is often given as C:\\Users\\RUNNER~1\\...).
    wanted = kernel32.GetLongPathNameW(os.path.abspath(str(path)), asked, len(asked))
    # A hard link has no other path to find, so a file with more than one name is refused as well.
    if not (0 < got < len(final) and 0 < wanted < len(asked) and os.fstat(fd).st_nlink == 1
            and os.path.normcase(plain(final.value)) == os.path.normcase(plain(asked.value))):
        os.close(fd)
        raise OSError(f"{path} is reached through a link or junction")


def _read_user_file(path: Path) -> bytes:
    """A user's regular file, whole and within _USER_FILE_MAX_BYTES. Raises OSError for anything else."""
    _refuse_links_on_the_way(path)
    fd = os.open(str(path), os.O_RDONLY | _USER_FILE_FLAGS)
    _refuse_if_redirected(fd, path)
    if not stat.S_ISREG(os.fstat(fd).st_mode):
        os.close(fd)
        raise OSError(f"{path} is not a regular file")
    with os.fdopen(fd, "rb") as f:
        data = f.read(_USER_FILE_MAX_BYTES + 1)
    if len(data) > _USER_FILE_MAX_BYTES:
        raise OSError(f"{path} is larger than {_USER_FILE_MAX_BYTES} bytes")
    return data


def _read_user_file_tail(path: Path, max_bytes: int) -> bytes:
    """A user's regular file's last max_bytes, from a whole line on: a long log is read from its end."""
    _refuse_links_on_the_way(path)
    fd = os.open(str(path), os.O_RDONLY | _USER_FILE_FLAGS)
    _refuse_if_redirected(fd, path)
    st = os.fstat(fd)
    if not stat.S_ISREG(st.st_mode):
        os.close(fd)
        raise OSError(f"{path} is not a regular file")
    with os.fdopen(fd, "rb") as f:
        if st.st_size <= max_bytes:
            return f.read(max_bytes)
        f.seek(st.st_size - max_bytes)
        data = f.read(max_bytes)
    return data.split(b"\n", 1)[1] if b"\n" in data else b""


def _replace_user_file(path: Path, data: bytes) -> None:
    """Write data (0600) beside path and rename it over: a link or FIFO there is replaced, not written
    through, and a failed write leaves the old file in place."""
    tmp = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    _refuse_links_on_the_way(tmp)
    if os.path.lexists(tmp):
        tmp.unlink()
    fd = os.open(str(tmp), os.O_WRONLY | os.O_CREAT | os.O_EXCL | _USER_FILE_FLAGS, 0o600)
    try:
        _refuse_if_redirected(fd, tmp)
        with os.fdopen(fd, "wb") as f:
            f.write(data)
        os.replace(tmp, path)
    except BaseException:
        try:
            tmp.unlink()
        except OSError:
            pass
        raise


def _forwarded_place(log: Path):
    """(timestamp, how many entries stamped then were sent) from the state file; (None, 0) for none.
    A bare timestamp, as written before the count, means every entry stamped then was sent."""
    try:
        parts = _read_user_file(log.with_name(FORWARDED_STATE_NAME)).decode().split()
    except (OSError, UnicodeDecodeError):
        return None, 0
    last = _log_time(parts[0]) if parts else None
    sent_then = int(parts[1]) if len(parts) == 2 and parts[1].isdigit() else float("inf")
    return last, sent_then if last else 0


def _unsent_hook_errors(log: Path) -> list:
    """Runs as the home's user: the newest HOOK_ERRORS_PER_RUN entries after the last one forwarded and
    newer than HOOK_ERROR_MAX_AGE, oldest first. Each carries the 'state' to save once it is sent."""
    floor = datetime.now(timezone.utc) - HOOK_ERROR_MAX_AGE
    last, sent_then = _forwarded_place(log)
    entries, seen_then, current = [], 0, None
    for line in _read_user_file_tail(log, _USER_FILE_MAX_BYTES).decode("utf-8", "replace").splitlines():
        match = _HOOK_ERROR_LINE.match(line)
        if not match:  # a message's own later lines (a traceback); they go with the entry they follow
            if current is not None:
                current["message"] = (current["message"] + "\n" + line)[:2000]
            continue
        when, current = _log_time(match.group(1)), None
        if when is None or when <= floor:
            continue
        if last is not None and when <= last:
            seen_then += when == last
            if when < last or seen_then <= sent_then:
                continue  # sent already
        current = {"timestamp": match.group(1), "message": match.group(2)[:2000],
                   "category": FORWARDED_ERROR_CATEGORY}
        entries.append((when, current))
    entries.sort(key=lambda entry: entry[0])  # stable: entries sharing a stamp keep the log's order
    chosen = entries[-HOOK_ERRORS_PER_RUN:]
    for i, (when, entry) in enumerate(chosen):
        same = sum(1 for other, _ in chosen[:i + 1] if other == when) + (sent_then if when == last else 0)
        entry["state"] = f"{entry['timestamp']} {same}"
    return [entry for _, entry in chosen]


def _save_forwarded(log: Path, state: str) -> bool:
    """Runs as the home's user."""
    _replace_user_file(log.with_name(FORWARDED_STATE_NAME), state.encode("utf-8"))
    return True


def _redact_hook_error(message: str, secrets) -> str:
    """The home's own keys, then common credential shapes, each value replaced and its name kept."""
    for secret in secrets:
        if secret:
            message = message.replace(secret, "[REDACTED]")
    message = _BEARER.sub("Bearer [REDACTED]", message)
    message = _NAMED_SECRET.sub(r"\1\2[REDACTED]", message)
    message = _URL_SECRET.sub(r"\1[REDACTED]", message)
    return _VENDOR_KEY.sub("[REDACTED]", message)


def _post_hook_json(url, body, headers):
    """POST a JSON body with curl (the system trust store, as every call here uses). Returns (http status,
    response bytes); status 0 when nothing came back. Never raises. The headers carry the key, and any local
    user can read a process's argv, so they go to curl in a 0600 file (-H @file) that is removed afterwards."""
    header_file = None
    try:
        fd, header_file = tempfile.mkstemp(prefix=".unbound-headers.")
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write("".join(f"{name}: {value}\n" for name, value in
                            {"Content-Type": "application/json", **headers}.items()))
        cmd = ["curl", "-sS", "-m", str(HOOK_ERROR_TIMEOUT_SECONDS), "-X", "POST", "-w", "\n%{http_code}",
               "-H", f"@{header_file}", "--data-binary", "@-", "--", url]
        result = subprocess.run(cmd, input=json.dumps(body).encode("utf-8"),
                                capture_output=True, timeout=HOOK_ERROR_TIMEOUT_SECONDS + 3)
        answer, _, code = (result.stdout or b"").rpartition(b"\n")
        return int(code.strip() or 0), answer
    except Exception:
        return 0, b""
    finally:
        if header_file:
            try:
                os.unlink(header_file)
            except OSError:
                pass


def _post_hook_errors(url, api_key, hook_source, hook_sha, batch, secrets=()) -> str:
    """The hook's own request shape and auth. 'sent' when the gateway took them; 'down' when it gave no
    answer or a 5xx; 'refused' when it answered no. It refuses only a key (200 with success false, or a
    4xx), never an entry, so a refusal is about this home's key and not about what the log holds."""
    errors = [{**{k: v for k, v in entry.items() if k != "state"},
               "message": _redact_hook_error(entry["message"], (api_key, *secrets))}
              for entry in batch]
    code, answer = _post_hook_json(url, {"errors": errors, "hook_source": hook_source, "hook_sha": hook_sha},
                                   {"Authorization": f"Bearer {api_key}"})
    if code <= 0 or code >= 500:
        return "down"
    try:
        taken = 200 <= code < 300 and json.loads(answer.decode("utf-8")).get("success") is True
    except (ValueError, AttributeError):
        taken = False
    return "sent" if taken else "refused"


def _writable_dir(path: Path) -> bool:
    """Runs as the home's user: the forwarded place can be saved in this folder."""
    return os.access(path, os.W_OK | os.X_OK)


def _home_device_key(home: Path):
    """Runs as the home's user: (the key its hooks report errors with, every key in ~/.unbound/config.json
    to redact), or None before setup first wrote it."""
    try:
        config = json.loads(_read_user_file(home / ".unbound" / "config.json").decode("utf-8"))
    except (OSError, ValueError):
        return None
    # The hooks' own order (cfg.get('api_key') or cfg.get('device_token')): their errors are this key's.
    if not isinstance(config, dict):
        return None
    key = config.get("api_key") or config.get("device_token")
    secrets = tuple(v for v in (config.get("api_key"), config.get("device_token")) if isinstance(v, str) and v)
    return (key, secrets) if isinstance(key, str) and key else None


def _forward_home_errors(username, log, send):
    """(entries sent, 'sent' or the verdict that stopped it, whether every unsent entry went out). The place
    is saved after each accepted request; where it can't be saved nothing more is sent, or every run would
    send the same entries again."""
    if _run_as_user(username, _writable_dir, log.parent, _timeout=HOOK_ERROR_USER_TIMEOUT) is not True:
        print(f"[errors] {log} skipped: its forwarded place can't be saved beside it")
        return 0, "sent", False
    entries = _run_as_user(username, _unsent_hook_errors, log, _timeout=HOOK_ERROR_USER_TIMEOUT)
    if entries is None:
        return 0, "sent", False
    for start in range(0, len(entries), HOOK_ERRORS_PER_REQUEST):
        batch = entries[start:start + HOOK_ERRORS_PER_REQUEST]
        verdict = send(batch)
        if verdict != "sent":
            return start, verdict, False
        if _run_as_user(username, _save_forwarded, log, batch[-1]["state"], _timeout=HOOK_ERROR_USER_TIMEOUT) is not True:
            print(f"[errors] {log}: forwarded place not saved; the rest waits for the next run")
            return start + len(batch), "sent", False
    return len(entries), "sent", True


def forward_hook_errors(user_homes, gateway_url, hook_path) -> list:
    """Forward every home's unsent error.log entries for this tool, with that home's own key, before this run
    changes anything. A gateway that is down ends forwarding for the run, so it costs one short timeout; a
    refused key is that home's own and skips only that home. Either way nothing is marked sent, and the next
    run retries. Never raises. Returns the (username, log) of every log not fully sent."""
    relpath, hook_source = HOOK_ERROR_LOG
    unsent, sent, down = [], 0, False
    try:
        hook_sha = (hook_script_hash(hook_path) or "unknown")[:12]
        url = gateway_url.rstrip("/") + "/v1/hooks/errors"
        for username, home_dir in user_homes:
            log = Path(home_dir) / relpath if home_dir is not None else None
            if log is None or not os.path.lexists(log):
                continue
            found = None if down else _run_as_user(username, _home_device_key, Path(home_dir),
                                                   _timeout=HOOK_ERROR_USER_TIMEOUT)
            if not found:
                unsent.append((username, log))  # the gateway is down, or no hook here has a key yet
                continue
            api_key, secrets = found
            count, verdict, done = _forward_home_errors(
                username, log, lambda batch: _post_hook_errors(url, api_key, hook_source, hook_sha, batch, secrets))
            sent += count
            if not done:
                unsent.append((username, log))
            if verdict == "refused":
                print(f"[errors] {TOOL_NAME} hook errors in {home_dir} not forwarded (key refused); the next run retries")
            elif verdict == "down":
                down = True
                print(f"[errors] {TOOL_NAME} hook errors not forwarded (gateway down); the next run retries")
    except Exception as e:
        print(f"[errors] {TOOL_NAME} hook errors not forwarded: {e}")
    if sent:
        print(f"[errors] forwarded {sent} {TOOL_NAME} hook errors")
    return unsent


def notify_setup_complete(api_key: str, tool_type: str, backend_url: str = "https://backend.getunbound.ai", install_state: Optional[str] = None, serial_number: Optional[str] = None,
                          hook_hash: Optional[str] = None, install_mode: Optional[str] = None,
                          status: Optional[str] = None, reason: Optional[str] = None,
                          written_to: Optional[str] = None):
    """Notify backend how tool setup ended. Never fails the setup. status is configured, skipped or
    deferred; left out, the backend reads configured, as from older installers."""
    try:
        url = f"{backend_url.rstrip('/')}/api/v1/setup/complete/"
        body = {"tool_type": tool_type, "managed": True}
        if install_state is not None:
            body["install_state"] = install_state
        if serial_number is not None:
            body["serial_number"] = serial_number
        if hook_hash is not None:
            body["hook_hash"] = hook_hash
        if install_mode is not None:
            body["install_mode"] = install_mode
        for key, value in (("status", status), ("reason", reason), ("written_to", written_to)):
            if value is not None:
                body[key] = str(value)[:500]  # the backend's limit
        data = json.dumps(body)
        subprocess.run(
            ["curl", "-fsSL", "-X", "POST",
             "-H", f"X-API-KEY: {api_key}",
             "-H", "Content-Type: application/json",
             "--data-binary", "@-", url],
            input=data.encode(),
            capture_output=True,
            timeout=10,
        )
        debug_print("Setup completion notification sent")
    except Exception as e:
        debug_print(f"Could not notify backend: {e}")


def _stdout_never_raises() -> None:
    """MDM gives this a non-console pipe, which on Windows defaults to cp1252 and
    raises UnicodeEncodeError on the first non-ASCII status line."""
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")
        except (AttributeError, ValueError, OSError):
            pass


def main():
    _stdout_never_raises()
    global DEBUG

    clear_mode = "--clear" in sys.argv
    # MDM deployments always run with debug logging enabled — administrators
    # need full diagnostic output for troubleshooting across managed devices.
    DEBUG = True

    if clear_mode:
        return clear_setup()

    print("=" * 60)
    print("Codex Hooks - MDM Setup")
    print("=" * 60)

    if not check_admin_privileges():
        if platform.system().lower() == "windows":
            sys.exit(
                "Error: MDM setup requires an elevated shell on Windows. "
                "Right-click PowerShell \u2192 Run as Administrator, then rerun."
            )
        print("This script requires administrator/root privileges")
        print("   Please re-run with sudo.")
        return False

    base_url = "https://backend.getunbound.ai"
    gateway_url = DEFAULT_GATEWAY_URL
    frontend_url = None
    app_name = None
    auth_api_key = None
    backfill_mode = False

    args = sys.argv[1:]
    i = 0
    while i < len(args):
        if args[i] == "--backend-url" and i + 1 < len(args):
            base_url = normalize_url(args[i + 1])
            i += 2
        elif args[i] == "--gateway-url" and i + 1 < len(args):
            gateway_url = normalize_url(args[i + 1])
            i += 2
        elif args[i] == "--frontend-url" and i + 1 < len(args):
            frontend_url = args[i + 1]
            i += 2
        elif args[i] == "--app_name" and i + 1 < len(args):
            app_name = args[i + 1]
            i += 2
        elif args[i] == "--api-key" and i + 1 < len(args):
            auth_api_key = args[i + 1]
            i += 2
        elif args[i] == "--debug":
            i += 1
        elif args[i] == "--backfill":
            backfill_mode = True
            i += 1
        else:
            i += 1

    if not auth_api_key:
        print("\nMissing required argument: --api-key")
        print("Usage: sudo python3 setup.py --api-key <api_key> [--backend-url <url>] [--app_name <app_name>] [--debug] [--backfill]")
        print("   Or: sudo python3 setup.py --clear [--debug]")
        return False

    # Before this run changes anything, with the key each home's hooks already report with.
    forward_hook_errors(get_all_user_homes(), gateway_url, _installed_hook_script())

    print("\nGetting device identifier...")
    device_id = get_device_identifier()
    if not device_id:
        print("Failed to get device identifier")
        return False
    debug_print(f"Device identifier: {device_id}")
    print("Device identifier retrieved")

    print("\nFetching API key from MDM...")
    api_key = fetch_api_key_from_mdm(base_url, app_name, auth_api_key, device_id)
    if not api_key:
        return False
    print("API key received")

    tool_present = tool_installed(get_all_user_homes())  # before this run writes anything

    def report(status, reason=None, **fields):
        """This tool's setup/complete for the run, whatever happened (WEB-6392). Configured on a device
        without the tool reads skipped: its config is written all the same."""
        if status == "configured" and not tool_present:
            status, reason = "skipped", f"{TOOL_NAME} is not installed"
        notify_setup_complete(api_key, "codex", backend_url=base_url, serial_number=device_id,
                              install_mode="mdm", status=status, reason=reason, **fields)

    print("\nSetting environment variables system-wide...")
    # Remove leftover gateway setup env vars
    for username, home_dir in get_all_user_homes():
        remove_env_var_from_user(username, home_dir, "OPENAI_API_KEY")


    url_ok, _ = set_env_var_system_wide("UNBOUND_BACKEND_URL", base_url)
    if not url_ok:
        print("Failed to set UNBOUND_BACKEND_URL")
        report("deferred", "Failed to set UNBOUND_BACKEND_URL")
        return False

    state = detect_install_state()
    # /etc/codex/hooks.json is a managed hook: codex runs it for every user, even under
    # allow_managed_hooks_only. Codex reads it since 0.115 (managed, no trust prompt, since 0.129).
    # Windows stays per-user: users can write under %ProgramData%.
    system_wide = platform.system().lower() != "windows"
    if system_wide and not setup_managed_hooks(gateway_url):
        print("Failed to set up codex managed hooks")
        report("deferred", "Failed to set up codex managed hooks")
        return False

    print("\nConfiguring Codex user hooks...")
    installed = 0
    config_ok = True
    user_homes = get_all_user_homes()
    for username, home_dir in user_homes:
        remove_gateway_artifacts_for_user(username, home_dir)
        config_ok = write_unbound_config_for_user(username, home_dir, api_key, urls={"base_url": base_url, "gateway_url": gateway_url, "frontend_url": frontend_url}) and config_ok
        enable_codex_hooks_feature_for_user(username, home_dir)
        if system_wide:
            remove_user_level_hooks_for_user(username, home_dir)  # codex would run a leftover copy twice
            installed += 1
        elif configure_codex_hooks_for_user(username, home_dir, gateway_url):
            print(f"Registered codex hooks for {username}")
            installed += 1

    success = bool(user_homes) and installed == len(user_homes) and config_ok
    if not user_homes:
        failure = "No user home directories found"
    elif installed < len(user_homes):
        failure = f"Registered codex hooks for {installed} of {len(user_homes)} user(s) — {len(user_homes) - installed} failed"
    elif not config_ok:
        failure = "Could not write ~/.unbound/config.json for every user"
    else:
        failure = None
    print(failure or f"Registered codex hooks for {installed} user(s)")

    print("\n" + "=" * 60)
    print("Setup Complete!" if success else "Setup Failed")
    print("=" * 60)

    if success:
        # After the new hooks are in place: an older codex hook reads only the per-tool var.
        remove_legacy_key_env()
        report("configured", install_state=state, hook_hash=hook_script_hash(_installed_hook_script()),
               written_to=str(get_managed_settings_dir() / "hooks.json") if system_wide else "~/.codex/hooks.json")
    else:
        report("deferred", failure)

    if success and backfill_mode:
        with _backfill_soft_stop(BACKFILL_SOFT_STOP_SECONDS):
            run_backfill(api_key, base_url, get_all_user_homes())

    return success


if __name__ == "__main__":
    try:
        ok = main()
    except KeyboardInterrupt:
        print("\n\nSetup cancelled.")
        sys.exit(1)
    except Exception as e:
        print(f"\nError: {e}")
        sys.exit(1)
    sys.exit(0 if ok else 1)
