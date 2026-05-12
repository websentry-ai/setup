#!/usr/bin/env python3

import os
import shutil
import sys
import platform
import subprocess
import json
import urllib.request
import urllib.error
from pathlib import Path
from typing import Tuple, List, Optional, Dict
try:
    import pwd
except ImportError:
    pwd = None

DEBUG = False
SCRIPT_URL = "https://raw.githubusercontent.com/websentry-ai/setup/refs/heads/main/claude-code/hooks/unbound.py"
DEFAULT_GATEWAY_URL = "https://api.getunbound.ai"

BACKFILL_CHUNK_BYTES = 14 * 1024 * 1024
BACKFILL_TOOL_TYPE = "claude-code"
BACKFILL_MAX_FILE_BYTES = 50 * 1024 * 1024
BACKFILL_MAX_LINES_PER_FILE = 50000
BACKFILL_MAX_SESSIONS_PER_RUN = 5000
BACKFILL_FIELD_MAX_BYTES = 64 * 1024


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
            result = subprocess.run(
                ["system_profiler", "SPHardwareDataType"],
                capture_output=True,
                text=True,
                timeout=10
            )
            if result.returncode == 0:
                for line in result.stdout.split('\n'):
                    if 'Serial Number' in line:
                        parts = line.split(': ')
                        if len(parts) >= 2:
                            serial = parts[1].strip()
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
    params = f"serial_number={device_id}&app_type=claude-code"
    if app_name:
        params = f"app_name={app_name}&{params}"
    url = f"{base_url.rstrip('/')}/api/v1/automations/mdm/get_application_api_key/?{params}"

    debug_print(f"Fetching API key from: {url}")

    try:
        result = subprocess.run(
            ["curl", "-fsSL", "-w", "\n%{http_code}",
             "-H", f"Authorization: Bearer {auth_api_key}", url],
            capture_output=True,
            text=True,
            timeout=30
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


def remove_env_var_from_user(username: str, home_dir: Path, var_name: str) -> bool:
    """Remove env var from user's shell rc files. Privilege-drops on Unix."""
    system = platform.system().lower()

    if system == "windows":
        try:
            subprocess.run(
                ["reg", "delete", "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Environment", "/F", "/V", var_name],
                check=False, capture_output=True, timeout=10,
            )
            debug_print(f"Removed {var_name} from system environment")
            return True
        except Exception as e:
            debug_print(f"Failed to remove {var_name}: {e}")
            return False

    if system == "darwin":
        rc_files = [home_dir / ".zprofile", home_dir / ".bash_profile"]
    elif system == "linux":
        rc_files = [home_dir / ".zshrc", home_dir / ".bashrc"]
    else:
        return False

    export_prefix = f"export {var_name}="

    def _do():
        success = False
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
                    success = True
            except Exception as e:
                debug_print(f"Failed to update {rc_file}: {e}")
        return success

    return bool(_run_as_user(username, _do))


def write_unbound_config_for_user(username: str, home_dir: Path, api_key: str) -> None:
    """Write API key to ~/.unbound/config.json for a given user.
    Privilege-drops to the target user before any FS op."""
    config_dir = home_dir / ".unbound"
    config_file = config_dir / "config.json"

    def _write():
        config_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
        if platform.system().lower() != "windows":
            os.chmod(config_dir, 0o700)
        config = {}
        if config_file.exists():
            try:
                with open(config_file, 'r', encoding='utf-8') as f:
                    config = json.loads(f.read())
            except (json.JSONDecodeError, OSError):
                config = {}
        config['api_key'] = api_key
        flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC | getattr(os, 'O_NOFOLLOW', 0)
        fd = os.open(str(config_file), flags, 0o600)
        with os.fdopen(fd, 'w', encoding='utf-8') as f:
            f.write(json.dumps(config, indent=2))

    if _run_as_user(username, _write) is None and platform.system().lower() != "windows":
        debug_print(f"Could not write config for {username}")


def remove_gateway_artifacts_for_user(username: str, home_dir: Path) -> None:
    """Remove ~/.claude/anthropic_key.sh for a given user (leftover from gateway setup).
    Privilege-drops to the target user — `unlink` against an attacker-planted
    symlink would otherwise let a non-root user delete root-owned files."""
    key_helper_path = home_dir / ".claude" / "anthropic_key.sh"
    if not key_helper_path.exists():
        return

    def _unlink():
        try:
            key_helper_path.unlink()
            return True
        except Exception:
            return False

    if _run_as_user(username, _unlink):
        debug_print(f"Removed {key_helper_path} for {username}")


def get_managed_settings_dir() -> Path:
    """Get the system-wide managed settings directory for Claude Code."""
    system = platform.system().lower()
    if system == "darwin":
        return Path("/Library/Application Support/ClaudeCode")
    elif system == "linux":
        return Path("/etc/claude-code")
    elif system == "windows":
        program_files = os.environ.get("ProgramFiles", r"C:\Program Files")
        return Path(program_files) / "ClaudeCode"
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
    Set up system-wide managed hooks for Claude Code.
    Downloads unbound.py and configures managed-settings.json with hooks.
    """
    system = platform.system().lower()
    try:
        managed_dir = get_managed_settings_dir()
        hooks_dir = managed_dir / "hooks"
        script_path = hooks_dir / "unbound.py"

        # On Windows, prefer the drop-in directory to avoid clobbering an
        # existing admin-managed settings file; fall back if we can't create it.
        if system == "windows":
            dropin_dir = managed_dir / "managed-settings.d"
            try:
                dropin_dir.mkdir(parents=True, exist_ok=True)
                settings_path = dropin_dir / "unbound.json"
            except Exception as e:
                debug_print(f"Could not create drop-in dir, falling back: {e}")
                managed_dir.mkdir(parents=True, exist_ok=True)
                settings_path = managed_dir / "managed-settings.json"
        else:
            managed_dir.mkdir(parents=True, exist_ok=True)
            settings_path = managed_dir / "managed-settings.json"

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

        # Configure hooks - quote the path to handle spaces. On Windows, invoke
        # via `py -3` (falling back to `python`) and tell Claude to run each
        # hook through PowerShell so the quoted launcher parses correctly.
        is_windows = system == "windows"
        if is_windows:
            launcher = "py -3" if shutil.which("py") else "python"
            hook_command = f'{launcher} "{script_path}"'
        else:
            hook_command = f'"{script_path}"'

        def _hook(entry: dict) -> dict:
            if is_windows:
                entry = {**entry, "shell": "powershell"}
            return entry
        hooks_config = {
            "PreToolUse": [
                {
                    "matcher": "*",
                    "hooks": [
                        _hook({
                            "type": "command",
                            "command": hook_command,
                            "timeout": 15000
                        })
                    ]
                }
            ],
            "PostToolUse": [
                {
                    "matcher": "*",
                    "hooks": [
                        _hook({
                            "type": "command",
                            "command": hook_command,
                            "async": True,
                            "timeout": 60
                        })
                    ]
                }
            ],
            "UserPromptSubmit": [
                {
                    "hooks": [
                        _hook({
                            "type": "command",
                            "command": hook_command,
                            "timeout": 60
                        })
                    ]
                }
            ],
            "Stop": [
                {
                    "hooks": [
                        _hook({
                            "type": "command",
                            "command": hook_command,
                            "timeout": 60
                        })
                    ]
                }
            ],
            "SessionStart": [
                {
                    "matcher": "*",
                    "hooks": [
                        _hook({
                            "type": "command",
                            "command": hook_command,
                            "async": True,
                            "timeout": 60
                        })
                    ]
                }
            ],
            "SessionEnd": [
                {
                    "hooks": [
                        _hook({
                            "type": "command",
                            "command": hook_command,
                            "async": True,
                            "timeout": 60
                        })
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


def clear_managed_hooks() -> bool:
    """Remove the hooks script and hooks setting from managed Claude config."""
    try:
        managed_dir = get_managed_settings_dir()
        hooks_dir = managed_dir / "hooks"
        script_path = hooks_dir / "unbound.py"

        settings_candidates = [
            managed_dir / "managed-settings.d" / "unbound.json",
            managed_dir / "managed-settings.json",
        ]

        removed_any = False

        # Remove the hook script
        if script_path.exists():
            try:
                script_path.unlink()
                debug_print(f"Removed {script_path}")
                removed_any = True
            except Exception as e:
                debug_print(f"Failed to remove {script_path}: {e}")

        # Try to remove hooks directory if empty
        if hooks_dir.exists():
            try:
                if not any(hooks_dir.iterdir()):
                    hooks_dir.rmdir()
                    debug_print(f"Removed empty directory {hooks_dir}")
            except Exception as e:
                debug_print(f"Could not remove directory {hooks_dir}: {e}")

        for settings_path in settings_candidates:
            if not settings_path.exists():
                continue
            try:
                with open(settings_path, "r", encoding="utf-8") as f:
                    settings = json.load(f)
                if "hooks" in settings:
                    del settings["hooks"]
                    if (settings_path.name == "unbound.json"
                            and settings_path.parent.name == "managed-settings.d"
                            and not settings):
                        settings_path.unlink()
                        debug_print(f"Removed empty drop-in {settings_path}")
                    else:
                        with open(settings_path, "w", encoding="utf-8") as f:
                            json.dump(settings, f, indent=2)
                        debug_print(f"Removed hooks from {settings_path}")
                    removed_any = True
            except Exception as e:
                debug_print(f"Failed to update {settings_path}: {e}")

        return removed_any

    except Exception as e:
        debug_print(f"Error clearing managed hooks: {e}")
        return False


def clear_setup():
    print("=" * 60)
    print("Claude Code Hooks - Clearing MDM Setup")
    print("=" * 60)

    if not check_admin_privileges():
        print("This script requires administrator/root privileges")
        print("   Please re-run with sudo.")
        return

    print("\nRemoving environment variables...")
    # Windows `reg delete HKLM\...` is machine-wide; fall through with a
    # placeholder so the removal runs even if C:\Users has no profiles.
    user_homes = get_all_user_homes() or ([(None, None)] if platform.system().lower() == "windows" else [])

    if not user_homes:
        print("   No user home directories found")
    else:
        removed_count = 0
        for username, home_dir in user_homes:
            if remove_env_var_from_user(username, home_dir, "UNBOUND_CLAUDE_API_KEY"):
                removed_count += 1

        if removed_count > 0:
            print(f"Removed environment variables from {removed_count} user(s)")
        else:
            print("   No environment variables found to remove")

    # Remove managed hooks
    print("\nRemoving managed hooks...")
    if clear_managed_hooks():
        managed_dir = get_managed_settings_dir()
        print(f"Removed managed hooks from {managed_dir}")
    else:
        print("   No managed hooks found to remove")

    print("\n" + "=" * 60)
    print("Clear Complete!")
    print("=" * 60)


def _backfill_truncate(value, limit: int = BACKFILL_FIELD_MAX_BYTES):
    if isinstance(value, str):
        encoded = value.encode('utf-8', errors='replace')
        if len(encoded) <= limit:
            return value
        return encoded[:limit].decode('utf-8', errors='ignore')
    if isinstance(value, dict):
        return {k: _backfill_truncate(v, limit) for k, v in value.items()}
    if isinstance(value, list):
        return [_backfill_truncate(v, limit) for v in value]
    return value


def _backfill_parse_transcript(transcript_path: Path) -> Optional[Dict]:
    session_id = None
    permission_mode = None
    model = None
    earliest_ts = None
    user_prompts = []
    assistant_texts = []
    assistant_tool_uses = []
    usage = {'input_tokens': 0, 'output_tokens': 0, 'cache_read_input_tokens': 0, 'cache_creation_input_tokens': 0}

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

                entry_ts = entry.get('timestamp')
                if entry_ts and (earliest_ts is None or entry_ts < earliest_ts):
                    earliest_ts = entry_ts

                if not session_id:
                    session_id = entry.get('sessionId') or entry.get('session_id')

                entry_type = entry.get('type', '')
                message = entry.get('message') or {}

                if entry_type == 'user' and message.get('role') == 'user':
                    content = message.get('content', '')
                    if isinstance(content, str):
                        if content:
                            user_prompts.append(_backfill_truncate(content))
                    elif isinstance(content, list):
                        for item in content:
                            if isinstance(item, dict) and item.get('type') == 'tool_result':
                                tool_use_id = item.get('tool_use_id')
                                output = item.get('content', '')
                                for tu in assistant_tool_uses:
                                    if tu.get('_tool_use_id') == tool_use_id:
                                        if isinstance(output, dict):
                                            tu['tool_response'] = _backfill_truncate(output)
                                        else:
                                            tu['tool_response'] = {'content': _backfill_truncate(output)}
                                        break

                elif entry_type == 'assistant' and message.get('role') == 'assistant':
                    if not model:
                        model = message.get('model')
                    for content_item in message.get('content', []) or []:
                        if not isinstance(content_item, dict):
                            continue
                        item_type = content_item.get('type')
                        if item_type == 'text':
                            text = content_item.get('text', '')
                            if text:
                                assistant_texts.append(_backfill_truncate(text))
                        elif item_type == 'tool_use':
                            assistant_tool_uses.append({
                                'type': 'PostToolUse',
                                'tool_name': content_item.get('name', ''),
                                'tool_input': _backfill_truncate(content_item.get('input', {}) or {}),
                                'tool_response': {},
                                '_tool_use_id': content_item.get('id', ''),
                            })
                    msg_usage = message.get('usage') or {}
                    if msg_usage:
                        for k in usage:
                            try:
                                usage[k] += int(msg_usage.get(k) or 0)
                            except (TypeError, ValueError):
                                pass

                if not permission_mode:
                    permission_mode = entry.get('permission_mode')
    except (OSError, UnicodeDecodeError):
        return None
    except Exception:
        return None

    # No filename-stem fallback — corrupted files are skipped.
    if not session_id:
        return None

    if not (user_prompts or assistant_texts or assistant_tool_uses):
        return None

    messages = []
    if user_prompts:
        messages.append({'role': 'user', 'content': '\n\n'.join(user_prompts)})
    if assistant_texts or assistant_tool_uses:
        assistant_msg = {'role': 'assistant', 'content': '\n\n'.join(assistant_texts)}
        if assistant_tool_uses:
            for tu in assistant_tool_uses:
                tu.pop('_tool_use_id', None)
            assistant_msg['tool_use'] = assistant_tool_uses
        messages.append(assistant_msg)

    if len(messages) < 2:
        return None

    record = {
        'conversation_id': session_id,
        'model': model or 'auto',
        'messages': messages,
        'permission_mode': permission_mode or 'default',
        'timestamp': earliest_ts or '',
    }
    if any(usage.values()):
        record['usage'] = {**usage, 'total_tokens': sum(usage.values())}

    return {'session_id': session_id, 'records': [record]}


def _backfill_iter_transcripts(root: Path):
    # Skip hidden, symlinked, or oversized files (50MB cap).
    for p in root.rglob('*.jsonl'):
        if p.name.startswith('.'):
            continue
        if not p.is_file() or p.is_symlink():
            continue
        try:
            if p.stat().st_size > BACKFILL_MAX_FILE_BYTES:
                continue
        except OSError:
            continue
        yield p


def _backfill_collect_sessions(home_dir: Path) -> List[Dict]:
    # Must run inside _run_as_user (reads transcripts as the target user).
    projects_root = home_dir / '.claude' / 'projects'
    if not projects_root.exists():
        return []
    sessions = []
    for transcript_path in sorted(_backfill_iter_transcripts(projects_root)):
        if len(sessions) >= BACKFILL_MAX_SESSIONS_PER_RUN:
            break
        session = _backfill_parse_transcript(transcript_path)
        if session:
            sessions.append(session)
    return sessions


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
    req = urllib.request.Request(url, data=body, method=method, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.getcode(), resp.read()
    except urllib.error.HTTPError as e:
        try:
            error_body = e.read()
        except Exception:
            error_body = b''
        return e.code, error_body
    except (urllib.error.URLError, OSError) as e:
        print(f"[backfill] HTTP request failed: {e}", file=sys.stderr)
        return 0, b''


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
        print(f"[backfill] upload-url request failed: HTTP {code}", file=sys.stderr)
        return False
    try:
        url_resp = json.loads(body.decode('utf-8'))
    except (ValueError, UnicodeDecodeError):
        print("[backfill] upload-url response was not JSON", file=sys.stderr)
        return False

    upload_url = url_resp.get('upload_url')
    object_key = url_resp.get('object_key')
    if not upload_url or not object_key:
        print("[backfill] upload-url response missing fields", file=sys.stderr)
        return False

    code, _ = _backfill_http_request(
        upload_url,
        method='PUT',
        headers=_backfill_edr_headers({'Content-Type': 'application/json'}),
        body=payload_bytes,
        timeout=30,
    )
    if code < 200 or code >= 300:
        print(f"[backfill] S3 PUT failed: HTTP {code}", file=sys.stderr)
        return False

    code, _ = _backfill_http_request(
        f"{backend_url.rstrip('/')}/api/v1/coding-tools/backfill/from-s3/",
        method='POST',
        headers=auth_headers,
        body=json.dumps({'tool_type': BACKFILL_TOOL_TYPE, 'object_key': object_key}).encode('utf-8'),
        timeout=30,
    )
    if code < 200 or code >= 300:
        print(f"[backfill] from-s3 request failed: HTTP {code}", file=sys.stderr)
        return False

    return True


def _backfill_send_sessions(api_key: str, backend_url: str, sessions: List[Dict]) -> Tuple[int, int]:
    chunks_total = 0
    chunks_sent = 0
    sessions_sent = 0
    current_chunk: List[Dict] = []
    current_size = 2

    def _flush():
        nonlocal current_chunk, current_size, chunks_total, chunks_sent, sessions_sent
        if not current_chunk:
            return
        chunks_total += 1
        chunk_size = current_size
        print(f"[backfill] Uploading chunk {chunks_total} ({chunk_size} bytes)...", flush=True)
        if _backfill_upload_chunk(api_key, backend_url, current_chunk):
            chunks_sent += 1
            sessions_sent += len(current_chunk)
            print(f"[backfill] Chunk {chunks_total} ok ({len(current_chunk)} sessions)")
        else:
            print(f"[backfill] Chunk {chunks_total} upload failed, continuing", file=sys.stderr)
        current_chunk = []
        current_size = 2

    for session in sessions:
        try:
            session_bytes = len(json.dumps(session).encode('utf-8'))
        except (TypeError, ValueError):
            continue
        if session_bytes > BACKFILL_CHUNK_BYTES:
            print(f"[backfill] Skipped oversized session {session.get('session_id')}", file=sys.stderr)
            continue
        if current_chunk and current_size + session_bytes + 1 > BACKFILL_CHUNK_BYTES:
            _flush()
        current_chunk.append(session)
        current_size += session_bytes + 1

    _flush()
    return sessions_sent, chunks_sent


def run_backfill(api_key: str, backend_url: str, user_homes: List[Tuple[str, Path]]) -> None:
    """Walk each user's ~/.claude/projects and seed historical sessions.

    MDM /get_application_api_key/ returns one per-device key with no `home_user`
    param, so backfilling every user with that key would mis-attribute history.
    Only run when exactly one user home is present."""
    if os.environ.get('UNBOUND_BACKFILL_DISABLED') == '1':
        debug_print("UNBOUND_BACKFILL_DISABLED=1 — skipping backfill")
        return

    try:
        if not user_homes:
            print("[backfill] No user homes found — skipping backfill.")
            return

        if len(user_homes) > 1:
            print(f"[backfill] Skipped: MDM device key cannot be attributed across {len(user_homes)} user homes. Re-run --backfill at the user level per account.", file=sys.stderr)
            return

        username, home_dir = user_homes[0]
        print(f"[backfill] Scanning {home_dir}/.claude/projects for transcripts...")
        sessions = _run_as_user(username, _backfill_collect_sessions, home_dir)
        if sessions is None:
            sessions = []

        print(f"[backfill] Found {len(sessions)} sessions")

        if not sessions:
            print("[backfill] No transcripts found.")
            return

        sessions_sent, chunks_sent = _backfill_send_sessions(api_key, backend_url, sessions)

        if sessions_sent == 0:
            print("[backfill] No sessions queued.")
        else:
            print(f"[backfill] Done. Queued {sessions_sent} sessions across {chunks_sent} chunks for processing.")
    except Exception as e:
        print(f"[backfill] Skipped due to error: {e}", file=sys.stderr)


def notify_setup_complete(api_key: str, tool_type: str, backend_url: str = "https://backend.getunbound.ai"):
    """Notify backend that tool setup completed. Never fails the setup."""
    try:
        url = f"{backend_url.rstrip('/')}/api/v1/setup/complete/"
        data = json.dumps({"tool_type": tool_type})
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
    print("Claude Code Hooks - MDM Setup")
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
        remove_env_var_from_user(username, home_dir, "UNBOUND_API_KEY")
        remove_env_var_from_user(username, home_dir, "ANTHROPIC_BASE_URL")

    success, _ = set_env_var_system_wide("UNBOUND_CLAUDE_API_KEY", api_key)
    if not success:
        print("Failed to set UNBOUND_CLAUDE_API_KEY")
        return
    debug_print("UNBOUND_CLAUDE_API_KEY set successfully")

    # Remove gateway artifacts and write unbound config for all users
    for username, home_dir in get_all_user_homes():
        remove_gateway_artifacts_for_user(username, home_dir)
        write_unbound_config_for_user(username, home_dir, api_key)

    print("\nConfiguring Claude managed hooks...")
    if setup_managed_hooks(gateway_url=gateway_url):
        managed_dir = get_managed_settings_dir()
        print(f"Created managed hooks in {managed_dir}")
    else:
        print("Failed to configure managed hooks")
        return

    print("\n" + "=" * 60)
    print("Setup Complete!")
    print("=" * 60)

    notify_setup_complete(api_key, "claude-code", backend_url=base_url)

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
