#!/usr/bin/env python3

import os
import stat
import shutil
import sys
import time
import platform
import subprocess
import json
import tempfile
import urllib.parse
from pathlib import Path
from typing import Tuple, List, Optional, Dict
try:
    import pwd
except ImportError:
    pwd = None

DEBUG = False
SCRIPT_URL = "https://raw.githubusercontent.com/websentry-ai/setup/refs/heads/main/augment/hooks/unbound.py"
DEFAULT_GATEWAY_URL = "https://api.getunbound.ai"

BACKFILL_CHUNK_BYTES = 14 * 1024 * 1024
BACKFILL_TOOL_TYPE = "augment_code"
BACKFILL_MAX_FILE_BYTES = 50 * 1024 * 1024
BACKFILL_MAX_LINES_PER_FILE = 50000
BACKFILL_MAX_SESSIONS_PER_RUN = 5000
BACKFILL_MAX_AGE_DAYS = 30
BACKFILL_STATE_FILE = '.unbound_last_backfill'


# --- Augment settings blocks (mirrors augment/hooks/setup.py) ----------------
# No per-hook `metadata` is seeded. Auggie rejects a `metadata` property on a
# hook entry ("Unknown property metadata ... will be ignored") and shows a
# "Some plugin hooks use unsupported configuration" warning on every run. It is
# also unnecessary: Auggie delivers the turn conversation by DEFAULT on the Stop
# event (event._exchange.exchange.{request_message, response_text}) — which is
# what the end-of-turn analytics read.


def build_hooks_block(hook_command: str, extra: Optional[Dict] = None) -> Dict:
    """The Augment `hooks` block. No UserPromptSubmit (Augment has no such event).
    Timeouts are in milliseconds. `extra` (e.g. {"shell": "powershell"}) is merged
    into every hook entry for the Windows launcher. No per-hook metadata is
    emitted — Auggie rejects it and the turn conversation arrives by default on
    Stop (see the note above)."""
    def _hook(timeout: int) -> Dict:
        entry = {"type": "command", "command": hook_command, "timeout": timeout}
        if extra:
            entry = {**entry, **extra}
        return entry

    return {
        "PreToolUse": [{"matcher": ".*", "hooks": [_hook(15000)]}],
        "PostToolUse": [{"matcher": ".*", "hooks": [_hook(10000)]}],
        "Stop": [{"hooks": [_hook(10000)]}],
        "SessionStart": [{"hooks": [_hook(60000)]}],
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
    """An existing hook entry is ours if its command matches exactly, or (on
    Windows, where it's wrapped in a `py -3 "..."` launcher) references our
    script path. Mirrors augment/hooks/setup.py."""
    return existing_cmd == hook_command or (is_windows and bool(existing_cmd) and str(script_path) in existing_cmd)


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


def _run_as_user(username, fn, *args, **kwargs):
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
        data = b''
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


def get_device_identifier() -> Optional[str]:
    system = platform.system().lower()
    try:
        if system == "darwin":
            # ioreg's IOPlatformSerialNumber key is locale-stable; system_profiler's
            # "Serial Number" label is localized and fails on non-English macOS.
            result = subprocess.run(
                ["ioreg", "-rd1", "-c", "IOPlatformExpertDevice"],
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
                    capture_output=True,
                    text=True,
                    timeout=10
                )
                if result.returncode == 0:
                    serial = result.stdout.strip()
                    if serial:
                        return serial
            except Exception:
                debug_print("PowerShell BIOS query failed, trying registry MachineGuid")

            try:
                import winreg
                with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE,
                                    r"SOFTWARE\Microsoft\Cryptography") as key:
                    value, _ = winreg.QueryValueEx(key, "MachineGuid")
                    if value:
                        return str(value).strip()
            except Exception:
                debug_print("MachineGuid registry read failed, falling back to hostname")

            try:
                import socket
                return socket.gethostname()
            except Exception:
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
                        if user_dir.is_dir() and user_dir.name not in ['Public', 'Default', 'Default User', 'Administrator', 'All Users']:
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
        # The privileged admin key goes off-argv via a 0600 temp header file.
        result = curl_with_auth(
            [f"Authorization: Bearer {auth_api_key}"],
            ["-fsSL", "-w", "\n%{http_code}",
             "--max-time", "30", "--retry", "3", "--retry-delay", "2", "--retry-connrefused",
             url],
            text=True,
            timeout=140,
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


def write_unbound_config_for_user(username: str, home_dir: Path, api_key: str, urls: dict = None) -> None:
    """Write API key to ~/.unbound/config.json for a given user.
    Privilege-drops to the target user before any FS op."""
    config_dir = home_dir / ".unbound"
    config_file = config_dir / "config.json"

    # A prior root-context run may have left these root-owned; repair ownership
    # (symlink-guarded) before dropping so the write below doesn't fail EACCES.
    _repair_user_ownership(username, [config_dir, config_file])

    def _write():
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
        config['api_key'] = api_key
        if urls:
            config.update({k: v for k, v in urls.items() if v})
        flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC | getattr(os, 'O_NOFOLLOW', 0)
        fd = os.open(str(config_file), flags, 0o600)
        with os.fdopen(fd, 'w', encoding='utf-8') as f:
            f.write(json.dumps(config, indent=2))
        return True

    if _run_as_user(username, _write) is None and platform.system().lower() != "windows":
        debug_print(f"Could not write config for {username}")


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
        return cmd == hook_command or (is_windows and bool(cmd) and hook_command in cmd)

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


def download_file(url: str, dest_path: Path) -> bool:
    try:
        dest_path.parent.mkdir(parents=True, exist_ok=True)
        debug_print(f"Downloading {url} to {dest_path}")
        result = subprocess.run(
            ["curl", "-fsSL", "-o", str(dest_path), url],
            capture_output=True,
            timeout=30
        )
        if result.returncode == 0:
            debug_print(f"File downloaded successfully: {dest_path}")
        return result.returncode == 0
    except (subprocess.TimeoutExpired, FileNotFoundError) as e:
        print(f"Failed to download {url}: {e}")
        return False


def rewrite_gateway_url_in_file(path: Path, gateway_url: str) -> None:
    """Replace the hardcoded default gateway URL inside a downloaded unbound.py."""
    if not gateway_url or gateway_url == DEFAULT_GATEWAY_URL:
        return
    try:
        text = path.read_text(encoding="utf-8")
        new_text = text.replace(f'"{DEFAULT_GATEWAY_URL}"', f'"{gateway_url}"')
        if new_text != text:
            path.write_text(new_text, encoding="utf-8")
    except Exception as e:
        debug_print(f"Could not rewrite gateway URL in {path}: {e}")


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
        if not download_file(SCRIPT_URL, script_path):
            print("Failed to download unbound.py")
            return False
        debug_print(f"Downloaded hook script: {script_path}")
        rewrite_gateway_url_in_file(script_path, gateway_url)

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
                    for hook in item.get("hooks", [])
                )
                if not our_hook_exists:
                    existing_config.extend(new_config)
            elif existing_config is None:
                settings["hooks"][event] = new_config
            # A foreign non-list hooks[event] is left untouched — never clobber an
            # org's own Augment config in the shared settings file.

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
                                if isinstance(item, dict):
                                    hooks = item.get("hooks", [])
                                    new_hooks = [h for h in hooks if not _is_unbound(h.get("command", ""))]
                                    if new_hooks != hooks:
                                        modified = True
                                    if new_hooks:
                                        item["hooks"] = new_hooks
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


def clear_setup():
    print("=" * 60)
    print("Augment Code Hooks - Clearing MDM Setup")
    print("=" * 60)

    if not check_admin_privileges():
        print("This script requires administrator/root privileges")
        print("   Please re-run with sudo.")
        return

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
            print(f"Failed to clear API_KEY for {failed} user(s)")

    print("\nClearing managed hooks...")
    status = clear_managed_hooks()
    managed_dir = get_managed_settings_dir()
    if status == "cleared":
        print(f"Cleared managed hooks from {managed_dir}")
    elif status == "not_found":
        print(f"Managed hooks not found in {managed_dir}")
    else:
        print(f"Failed to clear managed hooks in {managed_dir}")

    print("\n" + "=" * 60)
    print("Clear Complete!")
    print("=" * 60)


def _backfill_collect_session(transcript_path: Path) -> Optional[Dict]:
    """Read a transcript and return {session_id, entries} for server-side parsing."""
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
                    if sid:
                        session_id = sid
    except (OSError, UnicodeDecodeError):
        return None
    except Exception:
        return None

    if not session_id or not entries:
        return None
    return {'session_id': session_id, 'entries': entries}


def _backfill_state_path(home: Path) -> Path:
    return home / '.augment' / 'hooks' / BACKFILL_STATE_FILE


def _backfill_read_cutoff(home: Path) -> float:
    """mtime cutoff for transcript selection: the last successful backfill when
    cached (so cron reruns only seed sessions touched since), else 30 days ago."""
    default_cutoff = time.time() - (BACKFILL_MAX_AGE_DAYS * 86400)
    try:
        last = float(_backfill_state_path(home).read_text().strip())
    except (OSError, ValueError):
        return default_cutoff
    if last <= 0 or last > time.time():
        return default_cutoff
    return last


def _backfill_write_cutoff(home: Path, ts: float) -> None:
    try:
        path = _backfill_state_path(home)
        path.parent.mkdir(parents=True, exist_ok=True)
        tmp = path.parent / f'{path.name}.{os.getpid()}.tmp'
        tmp.write_text(str(ts))
        os.replace(tmp, path)
    except OSError as e:
        debug_print(f"failed to persist backfill timestamp: {e}")


def _backfill_iter_transcripts(root: Path, cutoff_mtime: float):
    for p in root.rglob('*.jsonl'):
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


def _backfill_slice_session(session: Dict, max_chunk_bytes: int):
    """Yield session payloads ≤ max_chunk_bytes, splitting oversized sessions into
    fixed-size entry runs each carrying a cumulative record_index_base."""
    session_id = session.get('session_id')
    entries = session.get('entries') or []
    try:
        if len(json.dumps(session).encode('utf-8')) <= max_chunk_bytes:
            yield session
            return
        entry_sizes = [len(json.dumps(e).encode('utf-8')) + 2 for e in entries]
    except (TypeError, ValueError):
        debug_print(f"skipping unserializable session {session_id}")
        return

    n = len(entries)
    record_index_base = 0
    start_idx = 0
    while start_idx < n:
        wrap = len(json.dumps({
            'session_id': session_id,
            'record_index_base': record_index_base,
            'entries': [],
        }).encode('utf-8'))
        cum = wrap
        end_idx = start_idx
        while end_idx < n and (cum + entry_sizes[end_idx] - 2) <= max_chunk_bytes:
            cum += entry_sizes[end_idx]
            end_idx += 1
        if end_idx == start_idx:
            debug_print(f"skipped session {session_id}: entry exceeds {max_chunk_bytes} bytes")
            return
        yield {
            'session_id': session_id,
            'record_index_base': record_index_base,
            'entries': entries[start_idx:end_idx],
        }
        record_index_base += (end_idx - start_idx)
        start_idx = end_idx


def _backfill_collect_sessions(home_dir: Path) -> Tuple[List[Dict], bool]:
    # Must run inside _run_as_user (reads transcripts as the target user).
    # Returns (sessions, capped); capped=True means the per-run cap was hit and
    # older files remain unprocessed, so this home's cutoff must not advance.
    projects_root = home_dir / '.augment' / 'projects'
    if not projects_root.exists():
        return [], False
    cutoff_mtime = _backfill_read_cutoff(home_dir)
    sessions = []
    capped = False
    for transcript_path in sorted(_backfill_iter_transcripts(projects_root, cutoff_mtime)):
        if len(sessions) >= BACKFILL_MAX_SESSIONS_PER_RUN:
            capped = True
            break
        session = _backfill_collect_session(transcript_path)
        if session:
            sessions.append(session)
    return sessions, capped


def _backfill_edr_headers(extra: Optional[Dict[str, str]] = None) -> Dict[str, str]:
    headers = {
        'User-Agent': f'Unbound-Setup/{BACKFILL_TOOL_TYPE}-backfill ({platform.platform()})',
        'X-Unbound-Operation': 'backfill',
        'X-Unbound-Tool': BACKFILL_TOOL_TYPE,
    }
    if extra:
        headers.update(extra)
    return headers


# Header names whose values are secrets and must be kept OFF the curl argv
# (/proc/<pid>/cmdline + `ps` are world-readable on a shared host). Lower-cased
# for case-insensitive matching against caller-supplied header dicts.
_BACKFILL_SECRET_HEADERS = frozenset({'authorization', 'x-api-key'})


def _backfill_http_request(url: str, method: str, headers: Dict[str, str], body: Optional[bytes] = None, timeout: int = 30) -> Tuple[int, bytes]:
    cmd = ["curl", "-sS", "-X", method, "-w", "\n%{http_code}",
           "--max-time", str(timeout), "--retry", "3", "--retry-delay", "2", "--retry-connrefused"]
    # Secret auth headers (Authorization/X-API-KEY) must not appear on the argv;
    # write them to a 0600 temp file and pass via -H @<file>. Non-secret headers
    # (UA, ops, Content-Type, presigned S3 PUT with no auth) stay inline.
    secret_headers = []
    for header_name, header_value in headers.items():
        if header_name.lower() in _BACKFILL_SECRET_HEADERS:
            secret_headers.append(f"{header_name}: {header_value}")
        else:
            cmd += ["-H", f"{header_name}: {header_value}"]
    secret_hdr_path = None
    if secret_headers:
        fd, secret_hdr_path = tempfile.mkstemp(prefix=".curlhdr.", suffix=".txt")
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                f.write("\n".join(secret_headers) + "\n")
        except OSError as e:
            try:
                os.unlink(secret_hdr_path)
            except OSError:
                pass
            debug_print(f"HTTP request failed: could not write auth header file: {e}")
            return 0, b''
        cmd += ["-H", f"@{secret_hdr_path}"]
    if body is not None:
        cmd += ["--data-binary", "@-"]
    cmd += ["--", url]
    try:
        result = subprocess.run(cmd, input=body, capture_output=True, timeout=timeout * 4 + 20)
    except (subprocess.TimeoutExpired, OSError) as e:
        debug_print(f"HTTP request failed: {e}")
        return 0, b''
    finally:
        if secret_hdr_path is not None:
            try:
                os.unlink(secret_hdr_path)
            except OSError:
                pass
    if result.returncode != 0:
        debug_print(f"curl exit {result.returncode}: {(result.stderr or b'').decode('utf-8', 'replace').strip()}")
    out = result.stdout or b''
    sep = out.rfind(b'\n')
    if sep == -1:
        debug_print(f"HTTP request failed: curl exit {result.returncode}")
        return 0, b''
    try:
        code = int(out[sep + 1:].strip() or b'0')
    except ValueError:
        debug_print(f"HTTP request failed: curl exit {result.returncode}")
        return 0, b''
    return code, out[:sep]


def _backfill_upload_chunk(api_key: str, backend_url: str, sessions: List[Dict]) -> bool:
    payload_bytes = json.dumps({'tool_type': BACKFILL_TOOL_TYPE, 'sessions': sessions}).encode('utf-8')

    auth_headers = _backfill_edr_headers({
        'Authorization': f'Bearer {api_key}',
        'Content-Type': 'application/json',
    })

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

    code, _ = _backfill_http_request(
        upload_url,
        method='PUT',
        headers=_backfill_edr_headers({'Content-Type': 'application/json'}),
        body=payload_bytes,
        timeout=30,
    )
    if code < 200 or code >= 300:
        debug_print(f"S3 PUT failed: HTTP {code}")
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


def _backfill_send_sessions(api_key: str, backend_url: str, sessions: List[Dict]) -> Tuple[int, int, int]:
    """Return (sessions_sent, chunks_sent, chunks_failed)."""
    chunks_total = 0
    chunks_sent = 0
    sessions_sent_ids: set = set()
    current_chunk: List[Dict] = []
    current_size = 2

    def _flush():
        nonlocal current_chunk, current_size, chunks_total, chunks_sent
        if not current_chunk:
            return
        chunks_total += 1
        if _backfill_upload_chunk(api_key, backend_url, current_chunk):
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


def run_backfill(api_key: str, backend_url: str, user_homes: List[Tuple[str, Path]]) -> None:
    """Walk every user's ~/.augment/projects and seed historical sessions."""
    if os.environ.get('UNBOUND_BACKFILL_DISABLED') == '1':
        debug_print("UNBOUND_BACKFILL_DISABLED=1 — skipping backfill")
        return

    try:
        if not user_homes:
            debug_print("no user homes found — skipping backfill")
            return

        started_at = time.time()
        sessions = []
        collected_homes: List[Tuple[str, Path]] = []
        for username, home_dir in user_homes:
            result = _run_as_user(username, _backfill_collect_sessions, home_dir)
            if result is None:
                continue
            user_sessions, capped = result
            if user_sessions:
                debug_print(f"Found {len(user_sessions)} sessions for user: {username}")
                sessions.extend(user_sessions)
            if not capped:
                collected_homes.append((username, home_dir))

        if not sessions:
            for username, home_dir in collected_homes:
                _run_as_user(username, _backfill_write_cutoff, home_dir, started_at)
            print("[backfill] No past sessions found.")
            return

        print(f"[backfill] Found {len(sessions)} past sessions. Uploading (this may take a few minutes)...")
        sessions_sent, _, chunks_failed = _backfill_send_sessions(api_key, backend_url, sessions)

        if sessions_sent == 0:
            print(f"[backfill] No sessions queued (all {chunks_failed} uploads failed).")
        elif chunks_failed:
            print(f"[backfill] Done — queued {sessions_sent} past sessions ({chunks_failed} chunks failed).")
        else:
            for username, home_dir in collected_homes:
                _run_as_user(username, _backfill_write_cutoff, home_dir, started_at)
            print(f"[backfill] Done — queued {sessions_sent} past sessions for processing.")
    except Exception as e:
        print(f"[backfill] Skipped due to error: {e}", file=sys.stderr)


def detect_install_state() -> Optional[str]:
    """Inspect the managed-settings target BEFORE it gets overwritten.
    Existence-based: the self-update rewrites these files, so content checks
    are unreliable — only file existence is trustworthy.
    'fresh' (config absent), 'persisted' (config + unbound.py both present),
    'tampered' (config present but hook script missing), or None on any error."""
    try:
        managed_dir = get_managed_settings_dir()
        config_path = managed_dir / "settings.json"
        script_path = managed_dir / "hooks" / "unbound.py"
        if not config_path.exists():
            return 'fresh'
        return 'persisted' if script_path.exists() else 'tampered'
    except Exception as e:
        debug_print(f"detect_install_state failed: {e}")
        return None


def notify_setup_complete(api_key: str, tool_type: str, backend_url: str = "https://backend.getunbound.ai", install_state: Optional[str] = None, serial_number: Optional[str] = None):
    """Notify backend that tool setup completed. Never fails the setup."""
    try:
        url = f"{backend_url.rstrip('/')}/api/v1/setup/complete/"
        body = {"tool_type": tool_type, "managed": True}
        if install_state is not None:
            body["install_state"] = install_state
        if serial_number is not None:
            body["serial_number"] = serial_number
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


def main():
    global DEBUG

    clear_mode = "--clear" in sys.argv
    # MDM deployments always run with debug logging enabled — administrators
    # need full diagnostic output for troubleshooting across managed devices.
    DEBUG = True

    if clear_mode:
        clear_setup()
        return

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
        return

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
        return

    print("\nGetting device identifier...")
    device_id = get_device_identifier()
    if not device_id:
        print("Failed to get device identifier")
        return
    debug_print(f"Device identifier: {device_id}")
    print("Device identifier retrieved")

    print("\nFetching API key from MDM...")
    api_key = fetch_api_key_from_mdm(base_url, app_name, auth_api_key, device_id)
    if not api_key:
        return
    print("API key received")

    print("\nSetting environment variables system-wide...")
    success, _ = set_env_var_system_wide("UNBOUND_AUGMENT_API_KEY", api_key)
    if not success:
        print("Failed to set UNBOUND_AUGMENT_API_KEY")
        return
    debug_print("UNBOUND_AUGMENT_API_KEY set successfully")

    # Write the per-user unbound config now (needed by the managed hook; harmless
    # before the managed write). User-level hook REMOVAL is deferred until the
    # managed hooks are confirmed in place — see below.
    user_homes = get_all_user_homes()
    for username, home_dir in user_homes:
        write_unbound_config_for_user(username, home_dir, api_key, urls={"base_url": base_url, "gateway_url": gateway_url, "frontend_url": frontend_url})

    state = detect_install_state()

    print("\nConfiguring Augment managed hooks...")
    if not setup_managed_hooks(gateway_url=gateway_url):
        print("Failed to configure managed hooks")
        return
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

    print("\n" + "=" * 60)
    print("Setup Complete!")
    print("=" * 60)

    notify_setup_complete(api_key, "augment_code", backend_url=base_url, install_state=state, serial_number=device_id)

    if backfill_mode:
        run_backfill(api_key, base_url, get_all_user_homes())


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\nSetup cancelled.")
    except Exception as e:
        print(f"\nError: {e}")
        exit(1)
