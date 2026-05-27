#!/usr/bin/env python3

import os
import shutil
import sys
import time
import platform
import subprocess
import json
import tempfile
import urllib.request
import urllib.error
from pathlib import Path
from typing import Tuple, List, Optional, Dict
try:
    import pwd
except ImportError:
    pwd = None

DEBUG = False
SCRIPT_URL = "https://raw.githubusercontent.com/websentry-ai/setup/refs/heads/main/copilot/hooks/unbound.py"
DEFAULT_GATEWAY_URL = "https://api.getunbound.ai"

BACKFILL_CHUNK_BYTES = 14 * 1024 * 1024
BACKFILL_TOOL_TYPE = "copilot"
BACKFILL_MAX_FILE_BYTES = 50 * 1024 * 1024
BACKFILL_MAX_LINES_PER_FILE = 50000
BACKFILL_MAX_SESSIONS_PER_RUN = 5000
BACKFILL_MAX_AGE_DAYS = 30


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
    params = f"serial_number={device_id}&app_type=copilot"
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


def _copilot_hooks_config(script_path: Path) -> Dict:
    """Build the ~/.copilot/hooks/unbound.json config for the 5 Copilot events.
    Copilot delivers hook_event_name in the payload, so no per-event env is needed."""
    bash_cmd = f'"{script_path}"'
    launcher = "py -3" if shutil.which("py") else "python"
    powershell_cmd = f'{launcher} "{script_path}"'

    event_timeouts = {
        "SessionStart": 30,
        "UserPromptSubmit": 60,
        "PreToolUse": 600,
        "PostToolUse": 30,
        "Stop": 60,
    }

    hooks = {}
    for event_name, timeout_sec in event_timeouts.items():
        hooks[event_name] = [
            {
                "type": "command",
                "command": bash_cmd,
                "bash": bash_cmd,
                "powershell": powershell_cmd,
                "timeout": timeout_sec,
                "timeoutSec": timeout_sec,
            }
        ]

    return {"version": 1, "hooks": hooks}


def install_hooks_for_user(username: str, home_dir: Path, gateway_url: str, source_script: Path) -> bool:
    """Install unbound.py and unbound.json into a user's ~/.copilot/hooks.
    Privilege-drops to the target user before any FS op — curl already ran as
    root to fetch source_script; the per-user write happens post-drop."""
    hooks_dir = home_dir / ".copilot" / "hooks"
    script_path = hooks_dir / "unbound.py"
    hooks_json = hooks_dir / "unbound.json"
    system = platform.system().lower()

    def _install():
        hooks_dir.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(str(source_script), str(script_path))
        if system in ["darwin", "linux"]:
            os.chmod(script_path, 0o755)
        rewrite_gateway_url_in_file(script_path, gateway_url)

        config = _copilot_hooks_config(script_path)
        flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC | getattr(os, 'O_NOFOLLOW', 0)
        fd = os.open(str(hooks_json), flags, 0o644)
        with os.fdopen(fd, 'w', encoding='utf-8') as f:
            json.dump(config, f, indent=2)
        return True

    ok = bool(_run_as_user(username, _install))
    debug_print(f"{'Installed' if ok else 'Failed to install'} Copilot hooks for {username}")
    return ok


def clear_hooks_for_user(username: str, home_dir: Path) -> str:
    """Remove unbound.py and unbound.json from a user's ~/.copilot/hooks.
    Privilege-drops to the target user before any FS op.

    Returns "cleared", "not_found", or "failed".
    """
    hooks_dir = home_dir / ".copilot" / "hooks"
    script_path = hooks_dir / "unbound.py"
    hooks_json = hooks_dir / "unbound.json"

    def _clear():
        cleared = False
        had_error = False
        any_existed = False
        for path in (script_path, hooks_json):
            try:
                if path.exists():
                    any_existed = True
                    path.unlink()
                    debug_print(f"Removed {path}")
                    cleared = True
            except Exception as e:
                debug_print(f"Failed to remove {path}: {e}")
                had_error = True
        if cleared:
            return "cleared"
        if had_error or any_existed:
            return "failed"
        return "not_found"

    result = _run_as_user(username, _clear)
    if result in ("cleared", "not_found", "failed"):
        return result
    return "failed"


def _backfill_session_id_from_path(transcript_path: Path) -> Optional[str]:
    # CLI: <home>/.copilot/session-state/<id>/events.jsonl → parent dir name.
    # VS Code: .../GitHub.copilot-chat/transcripts/<id>.jsonl → file stem.
    name = transcript_path.parent.name if transcript_path.stem == 'events' else transcript_path.stem
    return name or None


def _backfill_collect_session(transcript_path: Path) -> Optional[Dict]:
    """Read a transcript and return {session_id, entries} for server-side parsing.
    The client only JSON-decodes lines and resolves a session id (preferring the
    session.start payload, falling back to the path). All semantic parsing
    happens server-side in webapp.services.coding_tools_backfill_service."""
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
                if not session_id and isinstance(entry, dict):
                    if entry.get('type') == 'session.start':
                        sid = (entry.get('data') or {}).get('sessionId')
                        if sid:
                            session_id = sid
    except (OSError, UnicodeDecodeError):
        return None
    except Exception:
        return None

    if not session_id:
        session_id = _backfill_session_id_from_path(transcript_path)

    if not session_id or not entries:
        return None
    return {'session_id': session_id, 'entries': entries}


def _backfill_vscode_workspace_roots(home_dir: Path) -> List[Path]:
    # VS Code stores Copilot transcripts under workspaceStorage; the base differs
    # by OS and by stable/Insiders build.
    system = platform.system().lower()
    editors = ('Code', 'Code - Insiders')
    bases: List[Path] = []
    if system == 'darwin':
        for editor in editors:
            bases.append(home_dir / 'Library' / 'Application Support' / editor / 'User' / 'workspaceStorage')
    elif system == 'windows':
        for editor in editors:
            bases.append(home_dir / 'AppData' / 'Roaming' / editor / 'User' / 'workspaceStorage')
    else:
        for editor in editors:
            bases.append(home_dir / '.config' / editor / 'User' / 'workspaceStorage')
    return bases


def _backfill_should_include(p: Path, cutoff_mtime: float) -> bool:
    # Skip hidden, symlinked, oversized (50MB cap), or stale (>30 day) files.
    if p.name.startswith('.'):
        return False
    if not p.is_file() or p.is_symlink():
        return False
    try:
        st = p.stat()
        if st.st_size > BACKFILL_MAX_FILE_BYTES:
            return False
        if st.st_mtime < cutoff_mtime:
            return False
    except OSError:
        return False
    return True


def _backfill_iter_transcripts(home_dir: Path):
    cutoff_mtime = time.time() - (BACKFILL_MAX_AGE_DAYS * 86400)
    cli_root = home_dir / '.copilot' / 'session-state'
    if cli_root.exists():
        for p in cli_root.glob('*/events.jsonl'):
            if _backfill_should_include(p, cutoff_mtime):
                yield p
    for base in _backfill_vscode_workspace_roots(home_dir):
        if not base.exists():
            continue
        for p in base.glob('*/GitHub.copilot-chat/transcripts/*.jsonl'):
            if _backfill_should_include(p, cutoff_mtime):
                yield p


def _backfill_collect_sessions(home_dir: Path) -> List[Dict]:
    # Must run inside _run_as_user (reads transcripts as the target user).
    sessions = []
    for transcript_path in sorted(_backfill_iter_transcripts(home_dir)):
        if len(sessions) >= BACKFILL_MAX_SESSIONS_PER_RUN:
            break
        session = _backfill_collect_session(transcript_path)
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
        debug_print(f"HTTP request failed: {e}")
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


def _backfill_is_user_message(entry) -> bool:
    # Mirror server-side parse_copilot_session: a new exchange starts on a
    # user.message with non-empty data.content.
    if not isinstance(entry, dict) or entry.get('type') != 'user.message':
        return False
    content = (entry.get('data') or {}).get('content')
    return bool(content and str(content).strip())


def _backfill_exchange_boundaries(entries: List[Dict]) -> List[int]:
    return [i for i, entry in enumerate(entries) if _backfill_is_user_message(entry)]


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
    """Walk each user's Copilot CLI + VS Code transcripts and seed historical sessions.

    MDM /get_application_api_key/ returns one per-device key with no `home_user`
    param, so backfilling every user with that key would mis-attribute history.
    Only run when exactly one user home is present."""
    if os.environ.get('UNBOUND_BACKFILL_DISABLED') == '1':
        debug_print("UNBOUND_BACKFILL_DISABLED=1 — skipping backfill")
        return

    try:
        if not user_homes:
            debug_print("no user homes found — skipping backfill")
            return

        if len(user_homes) > 1:
            print(f"[backfill] Skipped: MDM device key can't span {len(user_homes)} user homes; run --backfill per account.", file=sys.stderr)
            return

        username, home_dir = user_homes[0]
        sessions = _run_as_user(username, _backfill_collect_sessions, home_dir) or []
        if not sessions:
            print("[backfill] No past sessions found.")
            return

        print(f"[backfill] Found {len(sessions)} past sessions. Uploading (this may take a few minutes)...")
        sessions_sent, _, chunks_failed = _backfill_send_sessions(api_key, backend_url, sessions)

        if sessions_sent == 0:
            print(f"[backfill] No sessions queued (all {chunks_failed} uploads failed).")
        elif chunks_failed:
            print(f"[backfill] Done — queued {sessions_sent} past sessions ({chunks_failed} chunks failed).")
        else:
            print(f"[backfill] Done — queued {sessions_sent} past sessions for processing.")
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


def clear_setup():
    print("=" * 60)
    print("Copilot Hooks - Clearing MDM Setup")
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
        env_cleared = 0
        env_not_found = 0
        env_failed = 0
        hooks_cleared = 0
        hooks_not_found = 0
        hooks_failed = 0
        for username, home_dir in user_homes:
            status = remove_env_var_from_user(username, home_dir, "UNBOUND_COPILOT_API_KEY")
            if status == "cleared":
                env_cleared += 1
            elif status == "not_found":
                env_not_found += 1
            else:
                env_failed += 1
            # Per-user copilot hooks — skip when falling through on Windows.
            if home_dir is not None:
                hstatus = clear_hooks_for_user(username, home_dir)
                if hstatus == "cleared":
                    hooks_cleared += 1
                elif hstatus == "not_found":
                    hooks_not_found += 1
                else:
                    hooks_failed += 1

        if env_cleared:
            print(f"Cleared for {env_cleared} user(s)")
        elif env_not_found:
            print(f"API_KEY not set, nothing to clear for {env_not_found} user(s)")
        if env_failed:
            print(f"Failed to clear API_KEY for {env_failed} user(s)")

        if hooks_cleared:
            print(f"Cleared Copilot hooks for {hooks_cleared} user(s)")
        if hooks_failed:
            print(f"Failed to clear Copilot hooks for {hooks_failed} user(s)")

    print("\n" + "=" * 60)
    print("Clear Complete!")
    print("=" * 60)


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
    print("Copilot Hooks - MDM Setup")
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
    success, _ = set_env_var_system_wide("UNBOUND_COPILOT_API_KEY", api_key)
    if not success:
        print("Failed to set UNBOUND_COPILOT_API_KEY")
        return
    debug_print("UNBOUND_COPILOT_API_KEY set successfully")

    # Download unbound.py once as root into a private root-owned temp dir.
    # mkdtemp gives an unpredictable name so a local user cannot pre-create or
    # symlink the path the root curl writes to. The dir is then widened to
    # 0o711 (traverse, still no listing) and the file to 0o644 so the per-user
    # installs — which run after privilege-drop — can read the script.
    print("\nDownloading hook script...")
    staging_dir = Path(tempfile.mkdtemp(prefix="unbound-copilot-"))
    source_script = staging_dir / "unbound.py"
    if not download_file(SCRIPT_URL, source_script):
        print("Failed to download unbound.py")
        shutil.rmtree(staging_dir, ignore_errors=True)
        return
    try:
        os.chmod(staging_dir, 0o711)
        os.chmod(source_script, 0o644)
    except OSError:
        pass

    print("\nInstalling Copilot hooks for all users...")
    user_homes = get_all_user_homes()
    installed_count = 0
    for username, home_dir in user_homes:
        write_unbound_config_for_user(username, home_dir, api_key)
        if install_hooks_for_user(username, home_dir, gateway_url, source_script):
            installed_count += 1

    shutil.rmtree(staging_dir, ignore_errors=True)

    if not user_homes:
        print("No user home directories found")
    elif installed_count == len(user_homes):
        print(f"Installed Copilot hooks for {installed_count} user(s)")
    else:
        print(f"Installed Copilot hooks for {installed_count} of {len(user_homes)} user(s) — {len(user_homes) - installed_count} failed")

    print("\n" + "=" * 60)
    print("Setup Complete!")
    print("=" * 60)

    notify_setup_complete(api_key, "copilot", backend_url=base_url)

    if backfill_mode:
        run_backfill(api_key, base_url, user_homes)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\nSetup cancelled.")
    except Exception as e:
        print(f"\nError: {e}")
        exit(1)
