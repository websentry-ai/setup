#!/usr/bin/env python3

import os
import stat
import re
import shutil
import sys
import time
import platform
import subprocess
import json
import shlex
from pathlib import Path
from typing import Tuple, List, Optional, Dict
try:
    import pwd
except ImportError:
    pwd = None

DEBUG = False
SCRIPT_URL = "https://raw.githubusercontent.com/websentry-ai/setup/refs/heads/main/codex/hooks/unbound.py"
DEFAULT_GATEWAY_URL = "https://api.getunbound.ai"

BACKFILL_CHUNK_BYTES = 14 * 1024 * 1024
BACKFILL_TOOL_TYPE = "codex"
BACKFILL_MAX_FILE_BYTES = 50 * 1024 * 1024
BACKFILL_MAX_LINES_PER_FILE = 50000
BACKFILL_MAX_SESSIONS_PER_RUN = 5000
BACKFILL_MAX_AGE_DAYS = 30
BACKFILL_STATE_FILE = '.unbound_last_backfill'
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
    params = f"serial_number={device_id}&app_type=codex"
    if app_name:
        params = f"app_name={app_name}&{params}"
    url = f"{base_url.rstrip('/')}/api/v1/automations/mdm/get_application_api_key/?{params}"

    debug_print(f"Fetching API key from: {url}")

    try:
        result = subprocess.run(
            ["curl", "-fsSL", "-w", "\n%{http_code}",
             "--max-time", "30", "--retry", "3", "--retry-delay", "2", "--retry-connrefused",
             "-H", f"Authorization: Bearer {auth_api_key}", url],
            capture_output=True,
            text=True,
            timeout=140
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


def remove_gateway_artifacts_for_user(username: str, home_dir: Path) -> None:
    """Remove OPENAI_API_KEY env var and openai_base_url from ~/.codex/config.toml.
    Privilege-drops to the target user before any FS op."""
    # remove_env_var_from_user already privilege-drops internally.
    remove_env_var_from_user(username, home_dir, "OPENAI_API_KEY")

    config_path = home_dir / ".codex" / "config.toml"
    if not config_path.exists():
        return

    def _strip():
        with open(config_path, 'r', encoding='utf-8') as f:
            lines = f.readlines()
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
    if not command:
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
    hooks are preserved. The codex_hooks feature flag in config.toml is left
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
    """Get the system-wide managed settings directory for Codex."""
    system = platform.system().lower()
    if system == "darwin":
        return Path("/Library/Application Support/Codex")
    elif system == "linux":
        return Path("/etc/codex")
    elif system == "windows":
        program_files = os.environ.get("ProgramFiles", r"C:\Program Files")
        return Path(program_files) / "Codex"
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
        if not download_file(SCRIPT_URL, script_path):
            print("Failed to download unbound.py")
            return False
        debug_print(f"Downloaded hook script: {script_path}")
        rewrite_gateway_url_in_file(script_path, gateway_url)

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

        settings["hooks"] = hooks_config
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
        if not download_file(SCRIPT_URL, script_path):
            return False
        rewrite_gateway_url_in_file(script_path, gateway_url)
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
            if event in config["hooks"]:
                existing_config = config["hooks"][event]
                our_hook_exists = False
                for existing_item in existing_config:
                    if isinstance(existing_item, dict):
                        for hook in existing_item.get("hooks", []):
                            existing_cmd = hook.get("command", "")
                            if _command_targets_hook(existing_cmd, script_path):
                                our_hook_exists = True
                                break
                if not our_hook_exists:
                    config["hooks"][event].extend(new_config)
            else:
                config["hooks"][event] = new_config

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
    if not cmd:
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


def enable_codex_hooks_feature_for_user(username: str, home_dir: Path) -> None:
    """Enable codex_hooks feature flag in user's ~/.codex/config.toml.
    Privilege-drops to the target user before any FS op."""
    config_path = home_dir / ".codex" / "config.toml"

    def _enable():
        config_path.parent.mkdir(parents=True, exist_ok=True)
        lines = []
        if config_path.exists():
            with open(config_path, 'r', encoding='utf-8') as f:
                lines = f.readlines()
        if 'codex_hooks = true' in ''.join(lines):
            return False  # already enabled

        features_idx = next((i for i, l in enumerate(lines) if l.strip() == '[features]'), None)
        if features_idx is not None:
            lines.insert(features_idx + 1, 'codex_hooks = true\n')
        else:
            if lines and not lines[-1].endswith('\n'):
                lines.append('\n')
            lines.append('\n[features]\ncodex_hooks = true\n')

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


def disable_codex_hooks_feature_for_user(username: str, home_dir: Path) -> None:
    """Remove only the codex_hooks line from user's ~/.codex/config.toml.
    Privilege-drops to the target user before any FS op."""
    config_path = home_dir / ".codex" / "config.toml"
    if not config_path.exists():
        return

    def _disable():
        with open(config_path, 'r', encoding='utf-8') as f:
            lines = f.readlines()
        new_lines = [line for line in lines if not line.strip().startswith('codex_hooks')]
        if len(new_lines) == len(lines):
            return False
        flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC | getattr(os, 'O_NOFOLLOW', 0)
        fd = os.open(str(config_path), flags, 0o600)
        with os.fdopen(fd, 'w', encoding='utf-8') as f:
            f.writelines(new_lines)
        return True

    if _run_as_user(username, _disable):
        debug_print(f"Removed codex_hooks feature for {username}")


def clear_setup():
    print("=" * 60)
    print("Codex Hooks - Clearing MDM Setup")
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
                disable_codex_hooks_feature_for_user(username, home_dir)

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


def _backfill_collect_sessions(home_dir: Path) -> Tuple[List[Dict], bool]:
    # Returns (sessions, capped); capped=True means the per-run cap was hit and
    # older files remain unprocessed, so this home's cutoff must not advance.
    sessions_root = home_dir / '.codex' / 'sessions'
    if not sessions_root.exists():
        return [], False
    cutoff_mtime = _backfill_read_cutoff(home_dir)
    sessions = []
    capped = False
    for transcript_path in sorted(_backfill_iter_transcripts(sessions_root, cutoff_mtime)):
        if len(sessions) >= BACKFILL_MAX_SESSIONS_PER_RUN:
            capped = True
            break
        session = _backfill_collect_session(transcript_path)
        if session:
            sessions.append(session)
    return sessions, capped


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
    cmd = ["curl", "-sS", "-X", method, "-w", "\n%{http_code}",
           "--max-time", str(timeout), "--retry", "3", "--retry-delay", "2", "--retry-connrefused"]
    for header_name, header_value in headers.items():
        cmd += ["-H", f"{header_name}: {header_value}"]
    if body is not None:
        cmd += ["--data-binary", "@-"]
    cmd += ["--", url]  # -- stops option parsing so a '-'-leading URL can't be read as a flag
    try:
        result = subprocess.run(cmd, input=body, capture_output=True, timeout=timeout * 4 + 20)
    except (subprocess.TimeoutExpired, OSError) as e:
        debug_print(f"HTTP request failed: {e}")
        return 0, b''
    if result.returncode != 0:
        # curl transport error (DNS/TLS/refused); -sS keeps the message on stderr.
        debug_print(f"curl exit {result.returncode}: {(result.stderr or b'').decode('utf-8', 'replace').strip()}")
    out = result.stdout or b''
    # curl appended "\n<http_code>" after the response body; split it off.
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

        started_at = time.time()
        sessions = []
        collected_homes: List[Tuple[str, Path]] = []
        for username, home_dir in user_homes:
            result = _run_as_user(username, _backfill_collect_sessions, home_dir)
            if result is None:
                # Could not read this user's home (fork/perms) — don't advance its
                # cutoff, or we'd permanently skip its history on the next run.
                continue
            user_sessions, capped = result
            if user_sessions:
                debug_print(f"Found {len(user_sessions)} sessions for user: {username}")
                sessions.extend(user_sessions)
            # Capped homes still have unprocessed files — leave their cutoff so the
            # overflow stays eligible on the next run.
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
    """Inspect the managed hooks.json target BEFORE it gets overwritten.
    Existence-based: the self-update rewrites these files, so content checks
    are unreliable — only file existence is trustworthy.
    'fresh' (config absent), 'persisted' (config + unbound.py both present),
    'tampered' (config present but hook script missing), or None on any error."""
    try:
        managed_dir = get_managed_settings_dir()
        config_path = managed_dir / "hooks.json"
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
    # Remove leftover gateway setup env vars
    for username, home_dir in get_all_user_homes():
        remove_env_var_from_user(username, home_dir, "OPENAI_API_KEY")

    success, _ = set_env_var_system_wide("UNBOUND_CODEX_API_KEY", api_key)
    if not success:
        print("Failed to set UNBOUND_CODEX_API_KEY")
        return
    debug_print("UNBOUND_CODEX_API_KEY set successfully")

    # codex 0.125 discovers hooks from ~/.codex/hooks.json (user layer), not the
    # managed dir — so remove gateway artifacts, write unbound config, enable the
    # codex_hooks feature flag, and register the hook per-user (the install IS the
    # user registration; no managed write and no user-level strip).
    state = detect_install_state()

    print("\nConfiguring Codex user hooks...")
    installed = 0
    user_homes = get_all_user_homes()
    for username, home_dir in user_homes:
        remove_gateway_artifacts_for_user(username, home_dir)
        write_unbound_config_for_user(username, home_dir, api_key, urls={"base_url": base_url, "gateway_url": gateway_url, "frontend_url": frontend_url})
        enable_codex_hooks_feature_for_user(username, home_dir)
        if configure_codex_hooks_for_user(username, home_dir, gateway_url):
            print(f"Registered codex hooks for {username}")
            installed += 1

    if user_homes and installed == 0:
        print("Failed to configure codex hooks for any user")
        return

    print("\n" + "=" * 60)
    print("Setup Complete!")
    print("=" * 60)

    notify_setup_complete(api_key, "codex", backend_url=base_url, install_state=state, serial_number=device_id)

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
