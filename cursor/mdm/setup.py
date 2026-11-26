#!/usr/bin/env python3

import os
import random
import stat
import sys
import platform
import shutil
import shlex
import subprocess
import hashlib
import json
import re
import tempfile
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Tuple, List, Optional
try:
    import pwd
except ImportError:
    pwd = None

# On Windows, when this script runs as a child of the MDM onboard wrapper its
# stdout is a non-console pipe defaulting to the legacy code page (cp1252),
# which can't encode the emoji we print — the first such print raises
# UnicodeEncodeError and crashes the step. Force UTF-8 so output never fails.
# mac/linux stdout is already UTF-8, so they are intentionally left untouched.
if platform.system().lower() == "windows":
    for _stream in (sys.stdout, sys.stderr):
        try:
            _stream.reconfigure(encoding="utf-8", errors="replace")
        except Exception:
            pass
    del _stream

HOOKS_URL = "https://raw.githubusercontent.com/websentry-ai/setup/refs/heads/main/cursor/hooks.json"
SCRIPT_URL = "https://raw.githubusercontent.com/websentry-ai/setup/refs/heads/main/cursor/unbound.py"
DEFAULT_GATEWAY_URL = "https://api.getunbound.ai"
MDM_RETRY_JITTER_SECONDS = 30  # spreads a fleet-wide MDM push so retries do not re-synchronise


def normalize_url(value: str) -> str:
    value = (value or "").strip()
    if not value:
        return value
    if not (value.startswith("http://") or value.startswith("https://")):
        value = f"https://{value}"
    return value.rstrip("/")
DEBUG = False


def debug_print(message: str) -> None:
    """Print message only if DEBUG mode is enabled."""
    if DEBUG:
        print(f"[DEBUG] {message}")


def _run_as_user(username, fn, *args, **kwargs):
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
        while True:
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


def get_enterprise_hooks_dir() -> Path:
    """Get the enterprise-managed hooks directory based on OS."""
    system = platform.system().lower()

    if system == "darwin":
        return Path("/Library/Application Support/Cursor")
    elif system == "linux":
        return Path("/etc/cursor")
    elif system == "windows":
        program_data = os.environ.get("ProgramData", r"C:\ProgramData")
        return Path(program_data) / "Cursor"
    else:
        raise OSError(f"Unsupported operating system: {system}")


def check_admin_privileges() -> bool:
    """Check if the script is running with admin/root privileges."""
    system = platform.system().lower()

    try:
        if system in ["darwin", "linux"]:
            # Check if running as root (UID 0)
            return os.geteuid() == 0
        elif system == "windows":
            # Check if running as admin
            import ctypes
            try:
                return bool(ctypes.windll.shell32.IsUserAnAdmin())
            except Exception:
                return False
        return False
    except Exception as e:
        debug_print(f"Failed to check privileges: {e}")
        return False


def get_mac_serial_number() -> str:
    """Get the Mac serial number using ioreg.

    ioreg's IOPlatformSerialNumber key is locale-stable; system_profiler's
    "Serial Number" label is localized and fails on non-English macOS.
    """
    try:
        result = subprocess.run(
            ["/usr/sbin/ioreg", "-rd1", "-c", "IOPlatformExpertDevice"],
            capture_output=True,
            text=True,
            timeout=10
        )
        if result.returncode != 0:
            return None

        for line in result.stdout.split('\n'):
            if 'IOPlatformSerialNumber' in line:
                parts = line.split('=')
                if len(parts) >= 2:
                    return parts[1].strip().strip('"').strip()
        return None
    except Exception as e:
        debug_print(f"Failed to get serial number: {e}")
        return None


_PLACEHOLDER_SERIALS = {
    '', '0', '00000000', '000000000', '0000000000', '000000000000', 'none',
    'na', 'n/a', 'unknown', 'default', 'default string',
    'to be filled by o.e.m.', 'to be filled by oem', 'serialnumber',
    'system serial number', 'serial number', 'chassis serial number',
    'system manufacturer', 'not applicable', 'not specified',
    'not available', 'oem', 'o.e.m.', 'invalid', '123456789', 'xxxxxxxx',
    'xxxxxxxxxxxxxx',
}


def get_windows_device_identifier() -> str:
    """Windows BIOS serial only; None if unreadable or a placeholder value."""
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


def get_linux_device_identifier() -> str:
    """Get a stable device identifier on Linux.

    Tries dmidecode serial, then /etc/machine-id, then hostname.
    """
    try:
        result = subprocess.run(
            ["dmidecode", "-s", "system-serial-number"],
            capture_output=True,
            text=True,
            timeout=10,
            stderr=subprocess.DEVNULL,
        )
        _DMIDECODE_PLACEHOLDERS = {
            "", "0", "default string", "not applicable",
            "not specified", "system serial number",
            "to be filled by o.e.m.",
        }
        if result.returncode == 0:
            device_id = result.stdout.strip()
            if device_id and device_id.lower() not in _DMIDECODE_PLACEHOLDERS:
                return device_id
    except Exception:
        debug_print("dmidecode failed, trying machine-id")

    for path in ["/etc/machine-id", "/var/lib/dbus/machine-id"]:
        try:
            with open(path, "r", encoding="utf-8") as f:
                device_id = f.read().strip()
                if device_id:
                    return device_id
        except Exception:
            continue

    try:
        result = subprocess.run(["hostname"], capture_output=True, text=True, timeout=10)
        if result.returncode == 0 and result.stdout.strip():
            return result.stdout.strip()
    except Exception:
        pass

    return None


def get_device_identifier() -> str:
    """Dispatch device identifier lookup based on platform."""
    system = platform.system().lower()
    if system == "darwin":
        return get_mac_serial_number()
    if system == "linux":
        return get_linux_device_identifier()
    if system == "windows":
        return get_windows_device_identifier()
    return None


def get_shell_rc_file() -> Path:
    system = platform.system().lower()
    shell = os.environ.get("SHELL", "").lower()

    if system == "darwin":
        return Path.home() / ".zprofile" if "zsh" in shell else Path.home() / ".bash_profile"
    elif system == "linux":
        return Path.home() / ".zshrc" if "zsh" in shell else Path.home() / ".bashrc"
    elif system == "windows":
        return None
    else:
        raise OSError(f"Unsupported operating system: {system}")


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


def append_to_file(file_path: Path, line: str, var_name: str = None) -> bool:
    try:
        file_path.touch(exist_ok=True)

        with open(file_path, "r", encoding="utf-8") as f:
            lines = f.readlines()

        if var_name:
            export_prefix = f"export {var_name}="
            lines = [l for l in lines if not l.strip().startswith(export_prefix)]

        if line + "\n" not in lines and line not in [l.rstrip() for l in lines]:
            lines.append(f"{line}\n")

            with open(file_path, "w", encoding="utf-8") as f:
                f.writelines(lines)
            return True

        if var_name:
            with open(file_path, "w", encoding="utf-8") as f:
                f.writelines(lines)
            return True

        return True
    except Exception as e:
        print(f"❌ Failed to modify {file_path}: {e}")
        return False


def _repair_user_ownership(username: str, paths: List[Path]) -> None:
    """Root-context best-effort: reclaim ownership of any of `paths` that exist
    as a real, user-home file/dir owned by another user, so the upcoming
    privilege-dropped write can touch it. A prior root-context run can leave
    ~/.unbound root-owned, which the dropped user then can't write (EACCES).

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
    """Write API key to user's ~/.unbound/config.json (shared with unbound-cli).
    On Unix, drops privileges to the target user before any FS op — prevents
    symlink-following privilege escalation."""
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

    result = _run_as_user(username, _write)
    if not result:
        debug_print(f"Failed to write config for {username}")
        return False
    return True


def remove_user_level_hooks(username: str, home_dir: Path) -> bool:
    """Remove user-level Cursor hooks (from normal setup) to prevent duplicate execution."""
    hooks_json = home_dir / ".cursor" / "hooks.json"
    hooks_dir = home_dir / ".cursor" / "hooks"
    removed = False
    if hooks_json.exists():
        try:
            hooks_json.unlink()
            removed = True
        except Exception as e:
            debug_print(f"Failed to remove {hooks_json}: {e}")
    if hooks_dir.exists():
        try:
            import shutil
            shutil.rmtree(hooks_dir)
            removed = True
        except Exception as e:
            debug_print(f"Failed to remove {hooks_dir}: {e}")
    if removed:
        print(f"   Removed user-level hooks for {username} (replaced by enterprise hooks)")
    return removed


def remove_hook_logs_for_user(username: str, home_dir: Path) -> None:
    """Remove the hook's own logs (agent-audit.log, error.log) from a user's
    ~/.cursor/hooks. They exist only because of us, so a clear/nuke takes them.
    Privilege-drops to the user; unlink() drops the dir entry (a symlink, never
    its target)."""
    if home_dir is None:
        return  # Windows machine-wide placeholder — no per-user dir to clean
    hooks_dir = home_dir / ".cursor" / "hooks"

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


def set_env_var_windows(var_name: str, value: str) -> bool:
    # MDM setup runs elevated and provisions every user on the device, so
    # write machine-wide (HKLM) with /M — matches every other MDM script.
    try:
        subprocess.run(["setx", var_name, value, "/M"], check=True, capture_output=True)
        return True
    except (subprocess.CalledProcessError, FileNotFoundError) as e:
        print(f"❌ Failed to set {var_name} on Windows: {e}")
        return False


def remove_env_var_on_windows(var_name: str) -> str:
    """Remove the machine-wide (HKLM) environment variable on Windows.

    Returns "cleared", "not_found", or "failed".
    """
    reg_path = "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Environment"
    try:
        query = subprocess.run(
            ["reg", "query", reg_path, "/V", var_name],
            capture_output=True,
        )
        if query.returncode != 0:
            return "not_found"
        subprocess.run(
            ["reg", "delete", reg_path, "/F", "/V", var_name],
            check=True,
            capture_output=True,
        )
        debug_print(f"Removed {var_name} from Windows registry (HKLM)")
        return "cleared"
    except subprocess.CalledProcessError:
        return "failed"
    except FileNotFoundError:
        print("'reg' command not found. Please remove the variable manually.")
        return "failed"


def get_all_user_homes() -> List[Tuple[str, Path]]:
    """Get all real user home directories on the system (excluding system accounts)."""
    user_homes = []
    system = platform.system().lower()

    try:
        if system == "windows":
            system_drive = os.environ.get("SystemDrive", "C:")
            users_dir = Path(system_drive + r"\Users")
            if users_dir.exists():
                for user_dir in users_dir.iterdir():
                    if user_dir.is_dir() and user_dir.name not in [
                        "Public", "Default User", "Administrator",
                        "All Users",
                    ]:
                        user_homes.append((user_dir.name, user_dir))
                        debug_print(f"Found user: {user_dir.name} -> {user_dir}")
            return user_homes

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

        return user_homes
    except Exception as e:
        debug_print(f"Error enumerating users: {e}")
        return []


def set_env_var_system_wide_unix(var_name: str, value: str) -> Tuple[bool, bool]:
    """Set environment variable for all users on macOS/Linux via per-user shell rc files.
    Returns: (success, changed)"""
    try:
        system = platform.system().lower()
        user_homes = get_all_user_homes()

        if not user_homes:
            print("⚠️  No user home directories found")
            return False, False

        success_count = 0
        changed_count = 0
        export_line = f'export {var_name}="{value}"'

        for username, home_dir in user_homes:
            debug_print(f"Setting env var for user: {username}")

            if system == "linux":
                rc_files = [home_dir / ".zshrc", home_dir / ".bashrc"]
            else:
                rc_files = [home_dir / ".zprofile", home_dir / ".bash_profile"]
            debug_print(f"Writing to shell files: {[str(f) for f in rc_files]}")

            def _do_user_writes(_rc_files=rc_files):
                _success = False
                _changed = False
                for rc_file in _rc_files:
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

            result = _run_as_user(username, _do_user_writes)
            if result is None:
                debug_print(f"Could not set env var for {username}")
                continue
            user_success, user_changed = result

            if user_success:
                success_count += 1
            if user_changed:
                changed_count += 1

        if success_count > 0:
            print(f"   Set for {success_count} user(s)")
            return True, changed_count > 0
        else:
            print("⚠️  Failed to set environment variable for any users")
            return False, False

    except Exception as e:
        print(f"❌ Failed to set system-wide environment variable: {e}")
        return False, False


def remove_env_var_from_user(username: str, home_dir: Path, var_name: str) -> str:
    """Remove environment variable from a user's shell rc files.
    Privilege-drops to the user before any FS op.

    Returns "cleared", "not_found", or "failed".
    """
    system = platform.system().lower()
    if system == "linux":
        rc_files = [home_dir / ".zshrc", home_dir / ".bashrc"]
    else:
        rc_files = [home_dir / ".zprofile", home_dir / ".bash_profile"]
    export_prefix = f"export {var_name}="

    def _remove():
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

    result = _run_as_user(username, _remove)
    if result in ("cleared", "not_found", "failed"):
        return result
    return "failed"


def set_env_var_unix(var_name: str, value: str) -> Tuple[bool, bool]:
    if os.geteuid() == 0:
        return set_env_var_system_wide_unix(var_name, value)

    # Non-root fallback: write to current user's rc file only.
    rc_file = get_shell_rc_file()
    if rc_file is None:
        return False, False

    exists_already = check_env_var_exists(rc_file, var_name, value)
    export_line = f'export {var_name}="{value}"'
    success = append_to_file(rc_file, export_line, var_name)
    return success, success and not exists_already


def set_env_var(var_name: str, value: str) -> Tuple[bool, bool, str]:
    system = platform.system().lower()

    if system == "windows":
        success = set_env_var_windows(var_name, value)
        if success:
            debug_print(f"Environment variable {var_name} set on Windows")
        msg = "Set for new terminals" if success else "Failed"
        return (success, True, msg)
    elif system in ["darwin", "linux"]:
        success, changed = set_env_var_unix(var_name, value)
        if success:
            debug_print(f"Environment variable {var_name} set system-wide for all users")
            return True, changed, "Set system-wide for all users"
        return False, False, "Failed"
    else:
        return False, False, f"Unsupported OS: {system}"


def rewrite_hook_commands_for_windows(hooks_json_path: Path, script_path: Path) -> None:
    """Cursor's hook runner on Windows doesn't reliably execute bare `.py`
    paths (no shebang, depends on file associations). Replace every hook
    command with an explicit `py -3 "<abs path>"` invocation so Cursor hooks
    fire even on machines where .py isn't associated with the Python launcher.
    Mirrors the claude-code/codex hooks pattern in this repo.
    """
    try:
        with open(hooks_json_path, "r", encoding="utf-8") as f:
            data = json.load(f)
    except Exception as e:
        debug_print(f"Failed to parse hooks.json for Windows rewrite: {e}")
        return
    launcher = "py -3" if shutil.which("py") else "python"
    new_command = f'{launcher} "{script_path}"'
    hooks = data.get("hooks", {}) if isinstance(data, dict) else {}
    for event_hooks in hooks.values() if isinstance(hooks, dict) else []:
        if not isinstance(event_hooks, list):
            continue
        for entry in event_hooks:
            if isinstance(entry, dict) and "command" in entry:
                entry["command"] = new_command
    with open(hooks_json_path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)


def compare_hooks_json(hooks_json_path: Path, new_content: str) -> bool:
    if not hooks_json_path.exists():
        return True
    try:
        with open(hooks_json_path, 'r', encoding='utf-8') as f:
            existing_content = f.read()
        existing = json.loads(existing_content)
        new = json.loads(new_content)
        return existing != new
    except Exception:
        return True


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
        print(f"❌ Failed to download {url}: {e}")
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


def setup_hooks(gateway_url: str = DEFAULT_GATEWAY_URL) -> Tuple[bool, bool]:
    enterprise_dir = get_enterprise_hooks_dir()
    hooks_dir = enterprise_dir / "hooks"
    hooks_json = enterprise_dir / "hooks.json"
    script_path = hooks_dir / "unbound.py"
    temp_hooks_json = enterprise_dir / "hooks.json.tmp"

    debug_print(f"Enterprise hooks directory: {enterprise_dir}")
    debug_print(f"Hooks JSON path: {hooks_json}")
    debug_print(f"Script path: {script_path}")

    print("\n📥 Downloading hooks configuration...")
    if not download_file(HOOKS_URL, temp_hooks_json):
        return False, False

    # Windows: rewrite bare `.py` commands to an explicit Python launcher call.
    if platform.system().lower() == "windows":
        rewrite_hook_commands_for_windows(temp_hooks_json, script_path)

    hooks_changed = False
    try:
        with open(temp_hooks_json, 'r', encoding='utf-8') as f:
            new_hooks_content = f.read()
        hooks_changed = compare_hooks_json(hooks_json, new_hooks_content)
        hooks_json.parent.mkdir(parents=True, exist_ok=True)
        temp_hooks_json.replace(hooks_json)
    except Exception as e:
        debug_print(f"Failed to handle hooks.json: {e}")
        return False, False
    print("✅ hooks.json downloaded")

    print("📥 Downloading unbound.py script...")
    if not download_file(SCRIPT_URL, script_path, gateway_url):
        return False, hooks_changed
    print("✅ unbound.py downloaded")

    try:
        current_mode = script_path.stat().st_mode
        os.chmod(script_path, current_mode | 0o111)
        print("✅ Made unbound.py executable")
    except Exception as e:
        print(f"⚠️  Could not make script executable: {e}")

    # Set proper permissions for hooks directory (allow users to write logs)
    try:
        os.chmod(hooks_dir, 0o775)
        debug_print(f"Set hooks directory permissions to 775")
        print("✅ Set hooks directory permissions")
    except Exception as e:
        print(f"⚠️  Could not set directory permissions: {e}")

    return True, hooks_changed


def find_cursor_exe() -> Optional[str]:
    """Machine-wide Cursor.exe, or None. A bare name would make the shell pop an error dialog."""
    # Machine-wide only: this script runs elevated, and a per-user AppData path, a PATH
    # lookup or shutil.which (which prepends the CWD on Windows) would let any local user
    # plant a binary we then launch as SYSTEM. Cursor installed per-user is simply not
    # restarted here; the caller prints the manual line instead.
    system_drive = os.environ.get("SystemDrive", "C:")
    for base in ("Program Files", "Program Files (x86)"):
        candidate = Path(system_drive + "\\" + base) / "cursor" / "Cursor.exe"
        if candidate.is_file():
            return str(candidate)
    return None


def restart_cursor() -> bool:
    """Attempt to restart Cursor IDE."""
    system = platform.system().lower()

    try:
        if system == "darwin":
            print("\n🔄 Restarting Cursor IDE...")
            result = subprocess.run(["osascript", "-e", 'tell application "Cursor" to quit'],
                                    capture_output=True, timeout=5)
            if result.returncode != 0:
                subprocess.run(["killall", "Cursor"], capture_output=True, timeout=5)
            time.sleep(2)
            result = subprocess.run(["open", "-a", "Cursor"],
                                    capture_output=True, timeout=5)
            if result.returncode == 0:
                print("✅ Cursor restarted")
                return True
            else:
                print("Restart Cursor")
                return False

        elif system == "linux":
            print("\n🔄 Restarting Cursor IDE...")
            subprocess.run(["pkill", "-9", "cursor"], capture_output=True, timeout=5)
            time.sleep(1)
            proc = subprocess.Popen(["cursor"],
                                    stdout=subprocess.DEVNULL,
                                    stderr=subprocess.DEVNULL)
            time.sleep(0.5)
            if proc.poll() is None:
                print("✅ Cursor restarted")
                return True
            else:
                print("Restart Cursor")
                return False

        elif system == "windows":
            exe = find_cursor_exe()
            if exe is None:
                print("Restart Cursor")
                return False
            print("\n🔄 Restarting Cursor IDE...")
            subprocess.run(["taskkill", "/F", "/IM", "Cursor.exe"],
                           capture_output=True, timeout=5)
            time.sleep(1)
            proc = subprocess.Popen([exe],
                                    stdout=subprocess.DEVNULL,
                                    stderr=subprocess.DEVNULL)
            time.sleep(0.5)
            if proc.poll() is None:
                print("✅ Cursor restarted")
                return True
            else:
                print("Restart Cursor")
                return False

        return False

    except subprocess.TimeoutExpired:
        return False
    except Exception as e:
        print("Restart Cursor")
        return False


def _remove_env_var_for_all_users(var_name: str, keep=lambda home_dir: False) -> bool:
    """Removes var_name for every user except those keep() names; False when any removal failed."""
    if platform.system().lower() == "windows":
        # One machine-wide value: it stays if any user still needs it.
        # A planted hook file only keeps a value every user can already read; unbound-hook clear drops it regardless.
        if keep(None) or any(keep(home_dir) for _, home_dir in get_all_user_homes()):
            return True
        return remove_env_var_on_windows(var_name) in ("cleared", "not_found")
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
        _remove_env_var_for_all_users("UNBOUND_CURSOR_API_KEY")
        # Env copy goes only once config.json holds the key; the Default profile gets one too, so later Windows profiles inherit it.
        _remove_env_var_for_all_users("UNBOUND_DEVICE_TOKEN", keep=lambda home_dir: home_dir is not None and not _config_has_key(home_dir))
    except Exception:
        pass


# Other Unbound tools' hook dirs; the shared UNBOUND_DEVICE_TOKEN stays while any of them holds a hook.
OTHER_HOOK_DIRS = (
    "~/.claude", "~/.codex", "~/.copilot", "~/.augment",
    "/Library/Application Support/ClaudeCode", "/etc/claude-code", "%ProgramFiles%/ClaudeCode",
    "/etc/codex", "%ProgramData%/OpenAI/Codex", "/etc/augment", "%ProgramData%/Augment",
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
    """Remove hooks and environment variables set by the setup script."""
    print("=" * 60)
    print("Unbound Cursor Hooks - Clearing Setup")
    print("=" * 60)

    # Check admin privileges
    if not check_admin_privileges():
        print("❌ This script requires administrator/root privileges")
        print("   Please re-run with sudo.")
        return False

    teardown_failed = False
    # Remove enterprise hooks files (NOT the entire Cursor directory)
    print("\nClearing enterprise hooks...")
    enterprise_dir = get_enterprise_hooks_dir()
    hooks_json = enterprise_dir / "hooks.json"
    hooks_dir = enterprise_dir / "hooks"

    # Remove hooks.json
    if hooks_json.exists():
        try:
            hooks_json.unlink()
            print("Cleared enterprise hooks.json")
        except Exception as e:
            teardown_failed = True
            print(f"Failed to clear hooks.json: {e}")

    # Remove hooks directory
    if hooks_dir.exists():
        try:
            import shutil
            shutil.rmtree(hooks_dir)
            print("Cleared enterprise hooks directory")
        except Exception as e:
            teardown_failed = True
            print(f"Failed to clear hooks directory: {e}")

    # Remove environment variable from all users
    print("\nClearing environment variables...")
    system = platform.system().lower()
    if system == "windows":
        status = remove_env_var_on_windows("UNBOUND_CURSOR_API_KEY")
        if status == "cleared":
            print("Cleared")
        elif status == "not_found":
            print("API_KEY not set, nothing to clear")
        else:
            teardown_failed = True
            print("Failed to clear API_KEY")
    else:
        user_homes = get_all_user_homes()

        if not user_homes:
            print("   No user home directories found")
        else:
            cleared = 0
            not_found = 0
            failed = 0
            for username, home_dir in user_homes:
                status = remove_env_var_from_user(username, home_dir, "UNBOUND_CURSOR_API_KEY")
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

    # Per-user hook logs live in ~/.cursor/hooks on every platform; remove them
    # regardless of how env vars were cleared above (the Windows branch is
    # machine-wide and has no per-user loop).
    for username, home_dir in (get_all_user_homes() or []):
        remove_hook_logs_for_user(username, home_dir)

    if not _remove_env_var_for_all_users("UNBOUND_DEVICE_TOKEN", keep=device_token_in_use):
        teardown_failed = True
        print("Failed to clear UNBOUND_DEVICE_TOKEN")

    print("\n" + "=" * 60)
    print("Clear Complete!")
    print("=" * 60)

    # Restart Cursor
    restart_cursor()

    print("=" * 60)
    print("\nNote: Restart your terminal or log out/in for env var changes to take effect")
    print("=" * 60)
    return not teardown_failed


def fetch_api_key_from_mdm(base_url: str, app_name: str, auth_api_key: str, serial_number: str) -> str:
    """Fetch API key from MDM endpoint."""
    params = f"serial_number={serial_number}&app_type=cursor"
    if app_name:
        params = f"app_name={app_name}&{params}"
    url = f"{base_url.rstrip('/')}/api/v1/automations/mdm/get_application_api_key/?{params}"

    debug_print(f"Fetching API key from: {url}")

    try:
        time.sleep(random.uniform(0, MDM_RETRY_JITTER_SECONDS))
        result = subprocess.run(
            ["curl", "-fsSL", "-w", "\n%{http_code}", "--max-time", "30", "--retry", "7", "--retry-max-time", "180", "--retry-connrefused", "-H", f"Authorization: Bearer {auth_api_key}", url],
            capture_output=True,
            text=True,
            timeout=300
        )

        output_lines = result.stdout.strip().split('\n')
        if len(output_lines) < 2:
            print("❌ Invalid response from server")
            return None

        http_code = output_lines[-1]
        response_body = '\n'.join(output_lines[:-1])

        debug_print(f"HTTP status: {http_code}")
        debug_print(f"Response length: {len(response_body)}")

        if http_code != "200":
            print(f"❌ API request failed with status {http_code}")
            return None

        try:
            data = json.loads(response_body)
            api_key = data.get("api_key")
            if not api_key:
                print("❌ No api_key in response")
                return None
            user_email = data.get("email")
            first_name = data.get("first_name")
            last_name = data.get("last_name")
            print(f"User email: {user_email}")
            print(f"Name: {first_name} {last_name}")
            return api_key
        except json.JSONDecodeError:
            print("❌ Invalid JSON response from server")
            return None

    except subprocess.TimeoutExpired:
        print("❌ Request timed out")
        return None
    except Exception as e:
        debug_print(f"Request failed: {e}")
        print("❌ Failed to fetch API key")
        return None


def _is_unbound_hook_command(cmd, script_path) -> bool:
    """Ours when the command RUNS our hook or the /opt/unbound binary, not merely
    mentions one: a decoy like '/bin/true # <our path>' is not ours."""
    if not cmd or not isinstance(cmd, str):
        return False
    if "/opt/unbound/" in cmd and "unbound-hook" in cmd:
        return True
    try:
        # posix=False on Windows: shlex still groups a quoted argument, so a path
        # containing spaces stays one token; only the quotes it leaves are stripped.
        tokens = shlex.split(cmd, posix=(os.name != "nt"))
    except ValueError:
        return False
    tokens = [t for t in (t.strip().strip('"').strip("'") for t in tokens) if t]
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
    program = os.path.normcase(os.path.normpath(tokens[0]))
    # hooks.json ships the relative form; the Windows rewrite makes it absolute.
    return program in (os.path.normcase(os.path.normpath(str(script_path))),
                       os.path.normcase(os.path.normpath("./hooks/unbound.py")))


def _unbound_hooks_registered(hooks_path, script_path) -> Optional[bool]:
    """True when hooks.json registers OUR hook on any event. Any event, not the
    enforcing one alone: the install writes them together, and under-matching reports
    'fresh', which the backend counts as a removal, so demanding one named event would
    accuse every device whose cursor ships a different event set. False when it does
    not, None when it could not be read. Unparseable raises, because cursor refuses
    such a file too."""
    if not hooks_path.exists():
        return False
    try:
        with open(hooks_path, "r", encoding="utf-8") as f:
            data = json.load(f)
    except OSError as e:
        debug_print(f"Could not read {hooks_path}: {e}")
        return None
    events = data.get("hooks") if isinstance(data, dict) else None
    for entries in events.values() if isinstance(events, dict) else ():
        for item in entries if isinstance(entries, list) else []:
            if isinstance(item, dict) and _is_unbound_hook_command(
                    item.get("command", ""), script_path):
                return True
    return False


def detect_install_state() -> Optional[str]:
    """Inspect the enterprise hooks.json target BEFORE it gets overwritten.
    'fresh' (neither our hook entries nor the script), 'persisted' (both),
    'tampered' (one without the other), None when hooks.json was unreadable."""
    try:
        enterprise_dir = get_enterprise_hooks_dir()
        script_path = enterprise_dir / "hooks" / "unbound.py"
        # An enterprise hooks.json can be the org's own, so the file existing is
        # not our install; only our own hook entries are.
        try:
            registered = _unbound_hooks_registered(
                enterprise_dir / "hooks.json", script_path)
        except ValueError:
            # Cursor refuses a hooks.json it cannot parse, ours included, so
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


TOOL_NAME, TOOL_CLI = "Cursor", "cursor-agent"
HOOK_ERROR_LOG = (".cursor/hooks/error.log", "cursor")  # this tool's log under a home, and its hook_source
# Per OS: (machine-wide paths, paths under a home), beside the CLI's own folders.
TOOL_FOOTPRINTS = {
    "darwin": (("Applications/Cursor.app",), ("Applications/Cursor.app",)),
    "linux": (("opt/Cursor", "opt/cursor", "usr/share/cursor", "usr/bin/cursor", "usr/local/bin/cursor"),
              ("Applications/Cursor*.AppImage", "Applications/cursor*.AppImage", ".local/bin/cursor")),
    "windows": (("Program Files/Cursor",), ("AppData/Local/Programs/cursor",)),
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


def _read_user_file(path: Path) -> bytes:
    """A user's regular file, whole and within _USER_FILE_MAX_BYTES. Raises OSError for anything else."""
    fd = os.open(str(path), os.O_RDONLY | _USER_FILE_FLAGS)
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
    fd = os.open(str(path), os.O_RDONLY | _USER_FILE_FLAGS)
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
    if os.path.lexists(tmp):
        tmp.unlink()
    fd = os.open(str(tmp), os.O_WRONLY | os.O_CREAT | os.O_EXCL | _USER_FILE_FLAGS, 0o600)
    try:
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
    if _run_as_user(username, _writable_dir, log.parent) is not True:
        print(f"[errors] {log} skipped: its forwarded place can't be saved beside it")
        return 0, "sent", False
    entries = _run_as_user(username, _unsent_hook_errors, log)
    if entries is None:
        return 0, "sent", False
    for start in range(0, len(entries), HOOK_ERRORS_PER_REQUEST):
        batch = entries[start:start + HOOK_ERRORS_PER_REQUEST]
        verdict = send(batch)
        if verdict != "sent":
            return start, verdict, False
        if _run_as_user(username, _save_forwarded, log, batch[-1]["state"]) is not True:
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
            found = None if down else _run_as_user(username, _home_device_key, Path(home_dir))
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


# Cursor only: remove_user_level_hooks removes ~/.cursor/hooks, and the error.log in it. A log the gateway
# has not taken all of is moved out of that folder by rename (so any size moves) and put back after.
def _set_aside_name(path: Path) -> Path:
    return path.parent.parent / f".unbound-unsent-{path.parent.name}-{path.name}"


def _set_aside_unsent_log(log: Path) -> list:
    """Runs as the home's user: move the log and its forwarded place out of ~/.cursor/hooks. Returns the
    names moved."""
    moved = []
    for path in (log, log.with_name(FORWARDED_STATE_NAME)):
        try:
            if os.path.lexists(path):
                os.replace(path, _set_aside_name(path))
                moved.append(path.name)
        except OSError:
            continue
    return moved


def _append_user_file(path: Path, data: bytes) -> None:
    """Runs as the home's user: add data to the end of a regular file, on a line of its own."""
    fd = os.open(str(path), os.O_RDWR | os.O_APPEND | _USER_FILE_FLAGS)
    try:
        size = os.fstat(fd).st_size
        if size:
            os.lseek(fd, size - 1, os.SEEK_SET)
            if os.read(fd, 1) != b"\n":
                data = b"\n" + data
        view = memoryview(data)
        while view:
            view = view[os.write(fd, view):]
    finally:
        os.close(fd)


def _restore_unsent_log(log: Path, names: list) -> bool:
    """Runs as the home's user: move a set-aside log and its place back for the next run. A hook can write
    a new log while the old one is aside: its entries go after the set-aside ones, so both are kept."""
    log.parent.mkdir(mode=0o700, exist_ok=True)
    for name in names:
        path = log.with_name(name)
        if os.path.lexists(path):
            if name != log.name:
                continue  # setup writes the forwarded place, never a hook
            _append_user_file(_set_aside_name(path), _read_user_file(path))
        os.replace(_set_aside_name(path), path)
    return True


def _recover_set_aside_log(log: Path) -> bool:
    """Runs as the home's user: put back a log an earlier run set aside and could not restore."""
    return _restore_unsent_log(log, [p.name for p in (log, log.with_name(FORWARDED_STATE_NAME))
                                     if os.path.lexists(_set_aside_name(p))])


def recover_set_aside_hook_logs(user_homes) -> None:
    """Before forwarding: a log an earlier run set aside and could not put back goes back, so it is sent.
    Never raises."""
    for username, home_dir in user_homes:
        try:
            log = Path(home_dir) / HOOK_ERROR_LOG[0]
            if os.path.lexists(_set_aside_name(log)):
                _run_as_user(username, _recover_set_aside_log, log)
        except Exception as e:
            print(f"[errors] set-aside hook errors in {home_dir} not put back: {e}")


def keep_unsent_hook_logs(unsent) -> list:
    """Set aside each (username, log) not fully sent: [(username, log, names moved)]. Never raises."""
    try:
        return [(username, log, _run_as_user(username, _set_aside_unsent_log, log)) for username, log in unsent]
    except Exception as e:
        print(f"[errors] unsent hook errors not set aside: {e}")
        return []


def restore_unsent_hook_logs(kept) -> None:
    """Put back what keep_unsent_hook_logs set aside. Never raises."""
    for username, log, names in kept:
        try:
            if names and _run_as_user(username, _restore_unsent_log, log, names) is not True and not os.path.lexists(log):
                print(f"[errors] {log}: unsent hook errors could not be kept for the next run")
        except Exception as e:
            print(f"[errors] {log}: unsent hook errors could not be kept for the next run: {e}")


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

    # Check for --clear flag first
    clear_mode = "--clear" in sys.argv

    debug_mode = "--debug" in sys.argv
    if debug_mode:
        DEBUG = True
        debug_print("Debug mode enabled")

    if "--backfill" in sys.argv:
        print("[backfill] Cursor backfill is not supported — no historical transcript data is available on disk.")

    # If clear mode, run cleanup and exit
    if clear_mode:
        return clear_setup()

    print("=" * 60)
    print("Unbound Cursor Hooks - MDM Setup")
    print("=" * 60)

    system = platform.system().lower()

    if not check_admin_privileges():
        if system == "windows":
            sys.exit(
                "Error: MDM setup requires an elevated shell on Windows. "
                "Right-click PowerShell \u2192 Run as Administrator, then rerun."
            )
        print("❌ This script requires administrator/root privileges")
        print("   Please re-run with sudo.")
        return False

    # Parse arguments
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
        print("\n❌ Missing required argument: --api-key")
        print("Usage: sudo python3 setup.py --api-key <api_key> [--backend-url <url>] [--app_name <app_name>] [--debug]")
        print("   Or: sudo python3 setup.py --clear [--debug]")
        return False

    # Before this run changes anything, with the key each home's hooks already report with. A log not
    # fully sent is kept across remove_user_level_hooks below, which removes ~/.cursor/hooks.
    homes = get_all_user_homes()
    recover_set_aside_hook_logs(homes)
    unsent_logs = forward_hook_errors(homes, gateway_url, get_enterprise_hooks_dir() / "hooks" / "unbound.py")

    # Get device identifier
    print("\n🔍 Getting device serial number...")
    serial_number = get_device_identifier()
    if not serial_number:
        print("❌ Failed to get device serial number")
        return False
    debug_print(f"Serial number: {serial_number}")
    print("✅ Serial number retrieved")

    # Fetch API key from MDM endpoint
    print("\n🔑 Fetching API key from MDM...")
    cursor_api_key = fetch_api_key_from_mdm(base_url, app_name, auth_api_key, serial_number)
    if not cursor_api_key:
        return False
    print("✅ API key received")

    tool_present = tool_installed(get_all_user_homes())  # before this run writes anything

    def report(status, reason=None, **fields):
        """This tool's setup/complete for the run, whatever happened (WEB-6392). Configured on a device
        without the tool reads skipped: its config is written all the same."""
        if status == "configured" and not tool_present:
            status, reason = "skipped", f"{TOOL_NAME} is not installed"
        notify_setup_complete(cursor_api_key, "cursor", backend_url=base_url, serial_number=serial_number,
                              install_mode="mdm", status=status, reason=reason, **fields)

    url_ok, _, url_message = set_env_var("UNBOUND_BACKEND_URL", base_url)
    if not url_ok:
        print(f"❌ Failed to set UNBOUND_BACKEND_URL: {url_message}")
        report("deferred", f"Failed to set UNBOUND_BACKEND_URL: {url_message}")
        return False

    # Write API key to ~/.unbound/config.json for each user and remove user-level hooks
    print("\n📝 Writing config for all users...")
    user_homes = get_all_user_homes()
    config_count = 0
    kept_logs = keep_unsent_hook_logs(unsent_logs)
    try:
        for username, home_dir in user_homes:
            if write_unbound_config_for_user(username, home_dir, cursor_api_key, urls={"base_url": base_url, "gateway_url": gateway_url, "frontend_url": frontend_url}):
                config_count += 1
                remove_user_level_hooks(username, home_dir)
            else:
                print(f"⚠️  Skipping hook removal for {username}: config write failed")
    finally:
        restore_unsent_hook_logs(kept_logs)
    if config_count > 0:
        print(f"✅ Config written for {config_count} user(s)")
    remove_legacy_key_env()

    state = detect_install_state()

    # Setup hooks
    debug_print("Setting up hooks...")
    hooks_success, hooks_changed = setup_hooks(gateway_url=gateway_url)
    if not hooks_success:
        print("\n❌ Failed to setup hooks")
        report("deferred", "Failed to setup hooks")
        return False
    debug_print("Hooks setup complete")

    if config_count < len(user_homes):
        print("Could not write ~/.unbound/config.json for every user")
        report("deferred", "Could not write ~/.unbound/config.json for every user")
        return False

    print("\n" + "=" * 60)
    print("Setup Complete!")
    print("=" * 60)

    report("configured", install_state=state, hook_hash=hook_script_hash(get_enterprise_hooks_dir() / "hooks" / "unbound.py"),
           written_to=str(get_enterprise_hooks_dir() / "hooks.json"))

    if hooks_changed:
        debug_print("Restart needed: hooks changed")
        restart_cursor()
    else:
        debug_print("No changes detected, skipping restart")

    print("=" * 60)
    print("\n")

    return True


if __name__ == "__main__":
    try:
        ok = main()
    except KeyboardInterrupt:
        print("\n\n⚠️  Setup cancelled.")
        sys.exit(1)
    except Exception as e:
        print(f"\n❌ Error: {e}")
        sys.exit(1)
    sys.exit(0 if ok else 1)
