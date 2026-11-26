#!/usr/bin/env python3

import os
import random
import stat
import shutil
import sys
import platform
import subprocess
import hashlib
import json
import re
import tempfile
import time
import signal
import select
import urllib.parse
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Tuple, List, Optional, Dict
try:
    import pwd
except ImportError:
    pwd = None

DEBUG = False
SCRIPT_URL = "https://raw.githubusercontent.com/websentry-ai/setup/refs/heads/main/augment/hooks/unbound.py"
DEFAULT_GATEWAY_URL = "https://api.getunbound.ai"
MDM_RETRY_JITTER_SECONDS = 30  # spreads a fleet-wide MDM push so retries do not re-synchronise


# --- Augment settings blocks (mirrors augment/hooks/setup.py) ----------------
# Block-level metadata (sibling to `hooks`, not the hook entry) we opt into; Auggie
# excludes all of it by default. userContext=context.userEmail, MCPMetadata=accurate MCP names.
_HOOK_METADATA = {
    "PreToolUse": {"includeUserContext": True, "includeMCPMetadata": True},
    "PostToolUse": {"includeUserContext": True, "includeMCPMetadata": True},
    "Stop": {"includeConversationData": True, "includeUserContext": True},
    "SessionStart": {"includeUserContext": True},
}


def build_hooks_block(hook_command: str, extra: Optional[Dict] = None) -> Dict:
    """The Augment `hooks` block. No UserPromptSubmit (Augment has no such event).
    Timeouts are in milliseconds. `extra` (e.g. {"shell": "powershell"}) is merged
    into every hook entry for the Windows launcher. Each block gets the block-level
    metadata flags in _HOOK_METADATA (see the note above)."""
    def _hook(timeout: int) -> Dict:
        entry = {"type": "command", "command": hook_command, "timeout": timeout}
        if extra:
            entry = {**entry, **extra}
        return entry

    return {
        "PreToolUse": [{"matcher": ".*", "hooks": [_hook(15000)], "metadata": dict(_HOOK_METADATA["PreToolUse"])}],
        "PostToolUse": [{"matcher": ".*", "hooks": [_hook(10000)], "metadata": dict(_HOOK_METADATA["PostToolUse"])}],
        "Stop": [{"hooks": [_hook(10000)], "metadata": dict(_HOOK_METADATA["Stop"])}],
        "SessionStart": [{"hooks": [_hook(60000)], "metadata": dict(_HOOK_METADATA["SessionStart"])}],
        "SessionEnd": [{"hooks": [_hook(10000)]}],
    }


_HIGH_RISK_SHELL_REGEX = (
    r"(rm\s+-rf|"
    r"(curl|wget)\b[^\n]*\|\s*(sudo\s+)?(ba)?sh|"
    r"\bsudo\b|"
    r"chmod\s+(-[A-Za-z]*\s+)*777|"
    r"git\s+push\b[^\n]*(--force|-f)\b|"
    r"cat\b[^\n]*(/etc/shadow|\.aws/credentials|\.ssh/id_|\.netrc|\.env))"
)


def build_tool_permissions_block() -> List[Dict]:
    """Seeded ask-user rules (Option 1): pause on the highest-risk shell calls and
    on any MCP tool call. The gateway remains the authoritative policy surface."""
    return [
        {
            "toolName": "launch-process",
            "shellInputRegex": _HIGH_RISK_SHELL_REGEX,
            "eventType": "tool-call",
            "permission": {"type": "ask-user"},
        },
        {
            # DEFER (schema TBC): the "mcp:.*" toolName pattern is unverified
            # against a live Augment instance — confirm before relying on it.
            # Gateway deny remains authoritative regardless.
            "toolName": "mcp:.*",
            "eventType": "tool-call",
            "permission": {"type": "ask-user"},
        },
    ]


def _tool_permission_identity(rule: Dict) -> Tuple:
    """Identity tuple used to dedupe / match our rules on merge and clear.
    Mirrors augment/hooks/setup.py."""
    if not isinstance(rule, dict):
        return (None, None)
    return (rule.get("toolName"), rule.get("shellInputRegex"))


_OUR_TOOL_PERMISSION_IDENTITIES = {
    _tool_permission_identity(r) for r in build_tool_permissions_block()
}


def _hook_command_matches(existing_cmd: str, hook_command: str, script_path: Path, is_windows: bool) -> bool:
    """An existing hook entry is ours if its command matches our python hook
    (exactly, or — on Windows, where it's wrapped in a `py -3 "..."` launcher —
    by script path) OR references the /opt/unbound hook binary. Without the binary
    case a binary-install hook is never recognized, so clear leaves it behind and
    orphans the managed config. Mirrors augment/hooks/setup.py."""
    if not isinstance(existing_cmd, str) or not existing_cmd:
        # A non-string command is not ours, and the membership tests below
        # raise on an int or a bool.
        return False
    if existing_cmd == hook_command:
        return True
    if "/opt/unbound/" in existing_cmd and "unbound-hook" in existing_cmd:
        return True
    return is_windows and str(script_path) in existing_cmd


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


def curl_with_auth(auth_headers: List[str], curl_args: List[str], *,
                   input=None, text: bool = False, timeout: int = 30):
    """Run curl with secret auth header(s) kept OFF the argv.

    On an MDM/multi-user host the curl argv is world-readable via
    /proc/<pid>/cmdline and `ps`, so passing `Authorization: Bearer <key>` /
    `X-API-KEY: <key>` as `-H "<header>"` would leak the secret — including the
    PRIVILEGED admin key used by fetch_api_key_from_mdm. Write the auth header
    line(s) to a 0600 temp file and pass `-H @<tmpfile>` instead; the temp file
    is deleted in a finally. `curl_args` is everything except the auth header
    (flags + URL). Returns the CompletedProcess, or None if the header file
    could not be written."""
    fd, tmp_path = tempfile.mkstemp(prefix=".curlhdr.", suffix=".txt")
    try:
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                f.write("\n".join(auth_headers) + "\n")
        except OSError:
            try:
                os.unlink(tmp_path)
            except OSError:
                pass
            return None
        cmd = ["curl", *curl_args, "-H", f"@{tmp_path}"]
        return subprocess.run(cmd, input=input, capture_output=True, text=text, timeout=timeout)
    finally:
        try:
            os.unlink(tmp_path)
        except OSError:
            pass


def _run_as_user(username, fn, *args, _timeout=None, **kwargs):
    """Fork and execute fn(*args, **kwargs) as the unprivileged user `username`.
    Returns whatever fn returns on success, or None on failure.

    Security-critical primitive: any MDM op that writes inside a user's
    home dir must go through this. Running file ops as root against
    attacker-controlled paths invites symlink-following privilege
    escalation. After privilege drop, symlinks targeting root-only paths
    fail naturally with EACCES.

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
    uid, gid = info.pw_uid, info.pw_gid

    r_fd, w_fd = os.pipe()
    pid = os.fork()
    if pid == 0:
        os.close(r_fd)
        try:
            os.setgroups([])
            os.setgid(gid)
            os.setuid(uid)
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
        # The child runs as the user, who can pause it: a caller can bound the wait (WEB-6392).
        deadline = None if _timeout is None else time.monotonic() + _timeout
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
    # URL-encode params: device_id (a serial number) and app_name can contain
    # '&', ' ', '=', etc., which would otherwise inject/truncate query params.
    query = [("serial_number", device_id), ("app_type", "augment_code")]
    if app_name:
        query.insert(0, ("app_name", app_name))
    params = urllib.parse.urlencode(query)
    url = f"{base_url.rstrip('/')}/api/v1/automations/mdm/get_application_api_key/?{params}"

    debug_print(f"Fetching API key from: {url}")

    try:
        time.sleep(random.uniform(0, MDM_RETRY_JITTER_SECONDS))
        # The privileged admin key goes off-argv via a 0600 temp header file.
        result = curl_with_auth(
            [f"Authorization: Bearer {auth_api_key}"],
            ["-fsSL", "-w", "\n%{http_code}",
             "--max-time", "30", "--retry", "7", "--retry-max-time", "180", "--retry-connrefused",
             url],
            text=True,
            timeout=300,
        )
        if result is None:
            print("Failed to fetch API key")
            return None

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
    the user.

    Directories are opened with O_DIRECTORY (so a non-dir can never satisfy the
    dir branch) and reclaimed ONLY when root- or self-owned (st_uid in {0, uid})
    — that is the only case this function exists for (a prior root-context run
    left ~/.unbound root-owned). A directory owned by some OTHER non-root user is
    NOT reclaimed: handing another user's dir to this user would be an
    over-reach. No-op on Windows / without pwd; only fires on the abnormal
    uid-mismatch case; never raises."""
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
    o_directory = getattr(os, "O_DIRECTORY", 0)
    base_flags = os.O_RDONLY | o_nofollow | getattr(os, "O_NONBLOCK", 0)
    for path in paths:
        # Try the directory open first (O_DIRECTORY succeeds only for real dirs,
        # symlink-guarded by O_NOFOLLOW). On ENOTDIR fall back to the file open
        # with the unchanged file-branch flags.
        try:
            fd = os.open(str(path), base_flags | o_directory)
        except OSError:
            try:
                fd = os.open(str(path), base_flags)
            except OSError:
                continue  # missing, a symlink (O_NOFOLLOW -> ELOOP), or no access
        try:
            st = os.fstat(fd)
            if stat.S_ISDIR(st.st_mode):
                # Only reclaim the root-leftover (or already-self-owned) case;
                # never grab a dir owned by another non-root user.
                if st.st_uid != uid and st.st_uid in (0, uid):
                    os.fchown(fd, uid, gid)
            elif stat.S_ISREG(st.st_mode) and st.st_nlink == 1:
                if st.st_uid != uid:
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


def remove_user_level_hooks_for_user(username: str, home_dir: Path) -> None:
    """Strip Unbound's hook entries (and our toolPermissions rules) from
    ~/.augment/settings.json and delete ~/.augment/hooks/unbound.py for a given
    user. Without this, MDM-managed hooks fire alongside leftover user-level ones
    and every event runs twice. Only entries pointing to our own unbound.py /
    our own rules are removed; unrelated user config is preserved.
    Privilege-drops to the target user."""
    settings_path = home_dir / ".augment" / "settings.json"
    script_path = home_dir / ".augment" / "hooks" / "unbound.py"
    hook_command = str(script_path)
    is_windows = platform.system().lower() == "windows"

    our_identities = {(r.get("toolName"), r.get("shellInputRegex")) for r in build_tool_permissions_block()}

    def _is_unbound(cmd: str) -> bool:
        if not isinstance(cmd, str):
            # Not ours, and the membership tests below raise on an int or bool.
            return False
        return (cmd == hook_command
                or (is_windows and bool(cmd) and hook_command in cmd)
                or ("/opt/unbound/" in cmd and "unbound-hook" in cmd))

    def _clean():
        # safe_to_unlink stays True only if the JSON no longer references
        # script_path. If the read/write fails partway, we leave the script
        # in place so a dangling hook entry doesn't point at a missing file.
        safe_to_unlink = True
        if settings_path.exists():
            try:
                with open(settings_path, 'r', encoding='utf-8') as f:
                    settings = json.load(f)
                modified = False
                if isinstance(settings, dict) and isinstance(settings.get("hooks"), dict):
                    hooks_block = settings["hooks"]
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
                                    new_event_config.append(item)
                                else:
                                    modified = True
                                    if new_hooks:
                                        item["hooks"] = new_hooks
                                        # Symmetry with install: drop the flag we set
                                        # when our hook leaves a surviving shared block.
                                        meta = item.get("metadata")
                                        if isinstance(meta, dict):
                                            for k in _HOOK_METADATA.get(event, {}):
                                                meta.pop(k, None)
                                            if not meta:
                                                item.pop("metadata", None)
                                        new_event_config.append(item)
                            else:
                                new_event_config.append(item)
                        if new_event_config:
                            hooks_block[event] = new_event_config
                        else:
                            del hooks_block[event]
                            modified = True
                    if not hooks_block:
                        del settings["hooks"]
                        modified = True
                # Strip our toolPermissions rules, preserving foreign ones.
                if isinstance(settings, dict) and isinstance(settings.get("toolPermissions"), list):
                    perms = settings["toolPermissions"]
                    new_perms = [
                        r for r in perms
                        if not (isinstance(r, dict) and (r.get("toolName"), r.get("shellInputRegex")) in our_identities)
                    ]
                    if len(new_perms) != len(perms):
                        modified = True
                        if new_perms:
                            settings["toolPermissions"] = new_perms
                        else:
                            del settings["toolPermissions"]
                if modified:
                    flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC | getattr(os, 'O_NOFOLLOW', 0)
                    fd = os.open(str(settings_path), flags, 0o644)
                    with os.fdopen(fd, 'w', encoding='utf-8') as f:
                        json.dump(settings, f, indent=2)
                    debug_print(f"Stripped Unbound config from {settings_path}")
            except Exception as e:
                safe_to_unlink = False
                debug_print(f"Failed to clean {settings_path}: {e}")

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
    ~/.augment/hooks on CLEAR/nuke — they exist only because of us. Kept separate
    from remove_user_level_hooks_for_user (which also runs at setup) so logs are
    dropped ONLY on clear. Privilege-drops to the user; unlink() removes the dir
    entry (a symlink, never its target)."""
    if home_dir is None:
        return  # Windows machine-wide placeholder — no per-user dir to clean
    hooks_dir = home_dir / ".augment" / "hooks"

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
    """Get the system-wide managed settings directory for Augment."""
    system = platform.system().lower()
    if system in ("darwin", "linux"):
        return Path("/etc/augment")
    elif system == "windows":
        program_data = os.environ.get("ProgramData", r"C:\ProgramData")
        return Path(program_data) / "Augment"
    else:
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
    Set up system-wide managed hooks for Augment.
    Downloads unbound.py and MERGES our hook entries + toolPermissions rules into
    /etc/augment/settings.json. /etc/augment/settings.json is SHARED with the
    org's own Augment config, so this must never clobber foreign hooks /
    permissions: append our hook entry per event only if our command isn't
    already present, append our toolPermissions rules only if our identity tuple
    isn't present, and preserve all foreign entries, rules, and other top-level
    keys. Mirrors the per-user configure_augment_settings discipline.
    """
    system = platform.system().lower()
    try:
        managed_dir = get_managed_settings_dir()
        hooks_dir = managed_dir / "hooks"
        script_path = hooks_dir / "unbound.py"
        settings_path = managed_dir / "settings.json"

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

        # Read existing settings or create new (preserve other top-level keys).
        settings = {}
        if settings_path.exists():
            try:
                with open(settings_path, 'r', encoding='utf-8') as f:
                    settings = json.load(f) or {}
            except Exception:
                settings = {}
        if not isinstance(settings, dict):
            settings = {}

        # Configure hooks - quote the path to handle spaces. On Windows, invoke
        # via `py -3` (falling back to `python`) and run each hook through
        # PowerShell so the quoted launcher parses correctly.
        is_windows = system == "windows"
        if is_windows:
            launcher = "py -3" if shutil.which("py") else "python"
            hook_command = f'{launcher} "{script_path}"'
            extra = {"shell": "powershell"}
        else:
            hook_command = f'"{script_path}"'
            extra = None

        # MERGE per-entry (settings.json is shared with the org's own config):
        # append our hook entry per event only if our command isn't already
        # present; preserve every foreign entry and other top-level key.
        hooks_config = build_hooks_block(hook_command, extra=extra)
        if not isinstance(settings.get("hooks"), dict):
            settings["hooks"] = {}
        for event, new_config in hooks_config.items():
            existing_config = settings["hooks"].get(event)
            if isinstance(existing_config, list):
                our_hook_exists = any(
                    _hook_command_matches(hook.get("command", ""), hook_command, script_path, is_windows)
                    for item in existing_config if isinstance(item, dict)
                    # .get's default only covers a missing key, so a scalar
                    # would be iterated and raise, aborting the write.
                    for hook in (item.get("hooks") if isinstance(item.get("hooks"), list) else [])
                    if isinstance(hook, dict)
                )
                if not our_hook_exists:
                    existing_config.extend(new_config)
            elif existing_config is None:
                settings["hooks"][event] = new_config
            # A foreign non-list hooks[event] is left untouched — never clobber an
            # org's own Augment config in the shared settings file.

        # Set the _HOOK_METADATA flags on our own blocks, even when the hook
        # already exists, so already-installed devices pick them up on re-run.
        for event, flags in _HOOK_METADATA.items():
            blocks = settings["hooks"].get(event)
            if not isinstance(blocks, list):
                continue
            for item in blocks:
                if not isinstance(item, dict):
                    continue
                item_hooks = item.get("hooks")
                if not isinstance(item_hooks, list):
                    # .get's default only covers a missing key, so a scalar
                    # would be iterated here and raise before the isinstance
                    # filter below ever runs.
                    continue
                if any(_hook_command_matches(hook.get("command", ""), hook_command, script_path, is_windows)
                       for hook in item_hooks if isinstance(hook, dict)):
                    metadata = item.get("metadata")
                    if not isinstance(metadata, dict):
                        metadata = {}
                        item["metadata"] = metadata
                    metadata.update(flags)

        # Merge toolPermissions, preserving foreign rules. Match on our identity
        # (toolName + shellInputRegex) so re-running never duplicates.
        existing_perms = settings.get("toolPermissions")
        if not isinstance(existing_perms, list):
            existing_perms = []
        existing_identities = {_tool_permission_identity(r) for r in existing_perms if isinstance(r, dict)}
        for rule in build_tool_permissions_block():
            if _tool_permission_identity(rule) not in existing_identities:
                existing_perms.append(rule)
                existing_identities.add(_tool_permission_identity(rule))
        settings["toolPermissions"] = existing_perms

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


def verify_managed_hooks_installed() -> bool:
    """True only if the managed hooks are actually present on disk: the managed
    script /etc/augment/hooks/unbound.py exists AND our hook command (which
    embeds that script path) appears in /etc/augment/settings.json's hooks.

    Gate for the install ordering: user-level hooks must not be stripped until
    managed hooks are confirmed in place, otherwise a silent managed-write failure
    leaves the user with NO functional hooks. Returns False (do not strip) on any
    read/parse error."""
    try:
        managed_dir = get_managed_settings_dir()
        script_path = managed_dir / "hooks" / "unbound.py"
        settings_path = managed_dir / "settings.json"
        if not script_path.exists() or not settings_path.exists():
            return False
        with open(settings_path, "r", encoding="utf-8") as f:
            settings = json.load(f)
        hooks_block = settings.get("hooks") if isinstance(settings, dict) else None
        if not isinstance(hooks_block, dict):
            return False
        # Our managed hook command always embeds the managed script path.
        return str(script_path) in json.dumps(hooks_block)
    except Exception as e:
        debug_print(f"verify_managed_hooks_installed failed: {e}")
        return False


def clear_managed_hooks() -> str:
    """Strip ONLY our hook entries and toolPermissions rules from the managed
    Augment config, preserving foreign content.

    /etc/augment/settings.json is SHARED with the org's own Augment config, so
    this removes only hook entries whose command matches our managed script_path
    and only toolPermissions rules in our identity set; foreign hooks, foreign
    rules, and other top-level keys are preserved; now-empty event arrays/blocks
    are dropped. The settings.json file is unlinked ONLY when it is left empty
    (no foreign top-level key and no foreign hook/permission remains) — never
    when any foreign content survives.

    Returns "cleared", "not_found", or "failed".
    """
    try:
        managed_dir = get_managed_settings_dir()
        hooks_dir = managed_dir / "hooks"
        script_path = hooks_dir / "unbound.py"
        settings_path = managed_dir / "settings.json"
        is_windows = platform.system().lower() == "windows"
        # Our managed install writes the quoted-path command form.
        hook_command = f'"{script_path}"'

        def _is_unbound(cmd: str) -> bool:
            return _hook_command_matches(cmd, hook_command, script_path, is_windows)

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
                if isinstance(settings, dict):
                    # Strip our hook entries, preserving foreign entries; drop
                    # now-empty event arrays and the whole block if it empties.
                    hooks_block = settings.get("hooks")
                    if isinstance(hooks_block, dict):
                        for event in list(hooks_block.keys()):
                            event_config = hooks_block[event]
                            if not isinstance(event_config, list):
                                continue
                            new_config = []
                            for item in event_config:
                                # Only touch items with a real list of hooks;
                                # preserve everything else (foreign items, dicts
                                # with no/"null" hooks). Drop an item only when
                                # every hook in it was ours.
                                if isinstance(item, dict) and isinstance(item.get("hooks"), list):
                                    hooks_list = item["hooks"]
                                    new_hooks = [h for h in hooks_list if not (isinstance(h, dict) and _is_unbound(h.get("command", "")))]
                                    if len(new_hooks) != len(hooks_list):
                                        modified = True
                                        if new_hooks:
                                            item["hooks"] = new_hooks
                                            # Symmetry with install: drop the flag we
                                            # set when our hook is removed from a block
                                            # that survives (shared with a foreign
                                            # hook). An ours-only block is dropped whole.
                                            meta = item.get("metadata")
                                            if isinstance(meta, dict):
                                                for k in _HOOK_METADATA.get(event, {}):
                                                    meta.pop(k, None)
                                                if not meta:
                                                    item.pop("metadata", None)
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

                    # Strip our toolPermissions rules, preserving foreign ones.
                    perms = settings.get("toolPermissions")
                    if isinstance(perms, list):
                        new_perms = [
                            r for r in perms
                            if not (isinstance(r, dict) and _tool_permission_identity(r) in _OUR_TOOL_PERMISSION_IDENTITIES)
                        ]
                        if len(new_perms) != len(perms):
                            modified = True
                        if new_perms:
                            settings["toolPermissions"] = new_perms
                        else:
                            settings.pop("toolPermissions", None)

                if modified:
                    # Unlink only if NOTHING foreign remains (no other top-level
                    # key, no foreign hook/permission). Otherwise rewrite in place.
                    if isinstance(settings, dict) and not settings:
                        settings_path.unlink()
                        debug_print(f"Removed empty settings {settings_path}")
                    else:
                        with open(settings_path, "w", encoding="utf-8") as f:
                            json.dump(settings, f, indent=2)
                        debug_print(f"Stripped our hooks/toolPermissions from {settings_path}")
                    cleared_any = True
            except Exception as e:
                debug_print(f"Failed to update {settings_path}: {e}")
                had_error = True

        if cleared_any:
            return "cleared"
        if had_error:
            return "failed"
        return "not_found"

    except Exception as e:
        debug_print(f"Error clearing managed hooks: {e}")
        return "failed"


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
        _remove_env_var_for_all_users("UNBOUND_AUGMENT_API_KEY")
        # Env copy goes only once config.json holds the key; the Default profile gets one too, so later Windows profiles inherit it.
        _remove_env_var_for_all_users("UNBOUND_DEVICE_TOKEN", keep=lambda home_dir: home_dir is not None and not _config_has_key(home_dir))
    except Exception:
        pass


# Other Unbound tools' hook dirs; the shared UNBOUND_DEVICE_TOKEN stays while any of them holds a hook.
OTHER_HOOK_DIRS = (
    "~/.claude", "~/.codex", "~/.cursor", "~/.copilot",
    "/Library/Application Support/ClaudeCode", "/etc/claude-code", "%ProgramFiles%/ClaudeCode",
    "/etc/codex", "%ProgramData%/OpenAI/Codex", "/Library/Application Support/Cursor", "/etc/cursor",
    "%ProgramData%/Cursor",
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
    print("Augment Code Hooks - Clearing MDM Setup")
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
            status = remove_env_var_from_user(username, home_dir, "UNBOUND_AUGMENT_API_KEY")
            remove_hook_logs_for_user(username, home_dir)
            if status == "cleared":
                cleared += 1
            elif status == "not_found":
                not_found += 1
            else:
                failed += 1

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


def _unbound_hooks_registered(config_path, script_path) -> Optional[bool]:
    """True when settings.json registers OUR hook on any event. Any event, not the
    enforcing one alone: the install writes them together, and under-matching reports
    'fresh', which the backend counts as a removal, so demanding one named event would
    accuse every device whose augment ships a different event set. False when it does
    not, None when it could not be read. Unparseable raises, because augment refuses
    such a file too. Same rule the uninstall strips by."""
    if not config_path.exists():
        return False
    try:
        with open(config_path, "r", encoding="utf-8") as f:
            settings = json.load(f)
    except OSError as e:
        debug_print(f"Could not read {config_path}: {e}")
        return None
    is_windows = platform.system().lower() == "windows"
    hook_command = f'"{script_path}"'
    events = settings.get("hooks") if isinstance(settings, dict) else None
    for entries in events.values() if isinstance(events, dict) else ():
        for item in entries if isinstance(entries, list) else []:
            hooks = item.get("hooks") if isinstance(item, dict) else None
            for hook in hooks if isinstance(hooks, list) else []:
                if isinstance(hook, dict) and _hook_command_matches(
                        hook.get("command", ""), hook_command, script_path, is_windows):
                    return True
    return False


def detect_install_state() -> Optional[str]:
    """Inspect the managed-settings target BEFORE it gets overwritten.
    'fresh' (neither our hook entries nor the script), 'persisted' (both),
    'tampered' (one without the other), None when settings.json was unreadable."""
    try:
        managed_dir = get_managed_settings_dir()
        script_path = managed_dir / "hooks" / "unbound.py"
        # settings.json is shared with the org's own Augment config, so the file
        # existing is not our install; only our own hook entries are.
        try:
            registered = _unbound_hooks_registered(
                managed_dir / "settings.json", script_path)
        except ValueError:
            # Augment refuses a settings.json it cannot parse, ours included, so
            # enforcement is dead rather than unknown.
            return 'tampered'
        if registered is None:
            return None
        if registered == script_path.exists():
            return 'persisted' if registered else 'fresh'
        return 'tampered'
    except Exception as e:
        debug_print(f"detect_install_state failed: {e}")
        return None


def hook_script_hash(script_path) -> Optional[str]:
    """sha256 of the hook script this run installed, so the backend can tell which
    hook version a device is running. None when absent or unreadable."""
    try:
        return hashlib.sha256(Path(script_path).read_bytes()).hexdigest()
    except Exception:
        return None


TOOL_NAME, TOOL_CLI = "Augment", "auggie"
HOOK_ERROR_LOG = (".augment/hooks/error.log", "augment_code")  # this tool's log under a home, and its hook_source
# The Auggie CLI, or the Augment extension alone in VS Code, VS Code Insiders or Cursor.
_AUGMENT_EXTENSIONS = tuple(f"{editor}/extensions/augment.vscode-augment-*"
                            for editor in (".vscode", ".vscode-insiders", ".cursor"))
# Per OS: (machine-wide paths, paths under a home), beside the CLI's own folders.
TOOL_FOOTPRINTS = {system: ((), _AUGMENT_EXTENSIONS) for system in ("darwin", "linux", "windows")}

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
        # X-API-KEY off-argv via 0600 temp header file; body off-argv via stdin.
        curl_with_auth(
            [f"X-API-KEY: {api_key}"],
            ["-fsSL", "-X", "POST",
             "-H", "Content-Type: application/json",
             "--data-binary", "@-", url],
            input=data.encode(),
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

    if "--backfill" in sys.argv:
        print("[backfill] Augment backfill is not supported.")

    if clear_mode:
        return clear_setup()

    print("=" * 60)
    print("Augment Code Hooks - MDM Setup")
    print("=" * 60)

    if not check_admin_privileges():
        if platform.system().lower() == "windows":
            sys.exit(
                "Error: MDM setup requires an elevated shell on Windows. "
                "Right-click PowerShell → Run as Administrator, then rerun."
            )
        print("This script requires administrator/root privileges")
        print("   Please re-run with sudo.")
        return False

    base_url = "https://backend.getunbound.ai"
    gateway_url = DEFAULT_GATEWAY_URL
    frontend_url = None
    app_name = None
    auth_api_key = None

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
        else:
            i += 1

    if not auth_api_key:
        print("\nMissing required argument: --api-key")
        print("Usage: sudo python3 setup.py --api-key <api_key> [--backend-url <url>] [--app_name <app_name>] [--debug]")
        print("   Or: sudo python3 setup.py --clear [--debug]")
        return False

    # Before this run changes anything, with the key each home's hooks already report with.
    forward_hook_errors(get_all_user_homes(), gateway_url, get_managed_settings_dir() / "hooks" / "unbound.py")

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
        notify_setup_complete(api_key, "augment_code", backend_url=base_url, serial_number=device_id,
                              install_mode="mdm", status=status, reason=reason, **fields)

    print("\nSetting environment variables system-wide...")

    url_ok, _ = set_env_var_system_wide("UNBOUND_BACKEND_URL", base_url)
    if not url_ok:
        print("Failed to set UNBOUND_BACKEND_URL")
        report("deferred", "Failed to set UNBOUND_BACKEND_URL")
        return False

    # Write the per-user unbound config now (needed by the managed hook; harmless
    # before the managed write). User-level hook REMOVAL is deferred until the
    # managed hooks are confirmed in place — see below.
    user_homes = get_all_user_homes()
    config_ok = True
    for username, home_dir in user_homes:
        config_ok = write_unbound_config_for_user(username, home_dir, api_key, urls={"base_url": base_url, "gateway_url": gateway_url, "frontend_url": frontend_url}) and config_ok
    remove_legacy_key_env()

    state = detect_install_state()

    print("\nConfiguring Augment managed hooks...")
    if not setup_managed_hooks(gateway_url=gateway_url):
        print("Failed to configure managed hooks")
        report("deferred", "Failed to configure managed hooks")
        return False
    managed_dir = get_managed_settings_dir()
    print(f"Created managed hooks in {managed_dir}")

    # Only NOW strip leftover user-level Unbound hooks (so managed hooks don't
    # fire twice). Verify the managed hooks are actually present first: if the
    # managed write silently produced nothing usable, removing user-level hooks
    # would leave the user with NO functional hooks. On failed verification, keep
    # the user-level hooks so the user stays covered.
    if verify_managed_hooks_installed():
        for username, home_dir in user_homes:
            remove_user_level_hooks_for_user(username, home_dir)
    else:
        print("Managed hooks could not be verified; leaving user-level hooks in place.")

    if not config_ok:
        print("Could not write ~/.unbound/config.json for every user")
        report("deferred", "Could not write ~/.unbound/config.json for every user")
        return False

    print("\n" + "=" * 60)
    print("Setup Complete!")
    print("=" * 60)

    report("configured", install_state=state, hook_hash=hook_script_hash(get_managed_settings_dir() / "hooks" / "unbound.py"),
           written_to=str(get_managed_settings_dir() / "settings.json"))

    return True


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
