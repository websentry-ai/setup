#!/usr/bin/env python3

import os
import random
import stat
import shutil
import sys
import time
import platform
import subprocess
import hashlib
import json
import shlex
from pathlib import Path
from typing import Tuple, List, Optional, Dict
try:
    import pwd
except ImportError:
    pwd = None

DEBUG = False
SCRIPT_URL = "https://raw.githubusercontent.com/websentry-ai/setup/refs/heads/main/claude-code/hooks/unbound.py"
DEFAULT_GATEWAY_URL = "https://api.getunbound.ai"
MDM_RETRY_JITTER_SECONDS = 30  # spreads a fleet-wide MDM push so retries do not re-synchronise

BACKFILL_CHUNK_BYTES = 14 * 1024 * 1024
BACKFILL_TOOL_TYPE = "claude-code"
BACKFILL_MAX_FILE_BYTES = 50 * 1024 * 1024
BACKFILL_MAX_LINES_PER_FILE = 50000
BACKFILL_MAX_SESSIONS_PER_RUN = 5000
BACKFILL_MAX_AGE_DAYS = 30
BACKFILL_STATE_FILE = '.unbound_last_backfill'


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


def fetch_api_key_from_mdm(base_url: str, app_name: str, auth_api_key: str, device_id: str,
                           app_type: str = "claude-code") -> Optional[str]:
    params = f"serial_number={device_id}&app_type={app_type}"
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


def remove_env_var_on_windows_machine(var_name: str, only_if=None) -> str:
    """Remove machine-wide (HKLM) env var on Windows. With only_if, removes it only when
    the recorded value is accepted.

    Returns "cleared", "not_found", or "failed".
    """
    reg_path = "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Environment"
    try:
        query = subprocess.run(
            ["reg", "query", reg_path, "/V", var_name],
            capture_output=True, text=True, timeout=10,
        )
        if query.returncode != 0:
            return "not_found"
        if only_if is not None:
            recorded = _registry_value(query.stdout, var_name)
            if recorded is None:
                debug_print(f"Could not read {var_name} from the registry")
                return "failed"
            if not only_if(recorded):
                debug_print(f"{var_name} left in place: not set by this setup")
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


UNBOUND_GATEWAY_URL = "https://api.getunbound.ai"
UNBOUND_KEY_HELPER_BODY = "echo $UNBOUND_API_KEY"


def _is_unbound_base_url(value) -> bool:
    """Whether ANTHROPIC_BASE_URL is the default Unbound gateway.

    Device-wide scope, so it consults no per-account record on purpose: this decides what
    comes out of managed settings the whole device shares, and one user's config must not
    be able to authorise that. A --gateway-url endpoint is still recognised, per user and
    only for that user's own export, by _unbound_base_url_matcher; and the drop-in this
    setup writes is identified by being that file rather than by the value inside it."""
    return isinstance(value, str) and value.strip().rstrip("/") == UNBOUND_GATEWAY_URL


def _recorded_gateway_url_for_user(username, home_dir) -> str:
    """The gateway URL this install recorded for one user, read as that user. It says
    which endpoint we pointed *them* at, so it authorises removing *their* export and
    nothing else. Never consulted for the system-wide managed settings: one account's
    record must not decide what comes out of a file the whole device shares.

    Windows falls back to a single (None, None) entry when it finds no user profiles, so
    there may be no home to read; that answers "no record", not an error."""
    if home_dir is None:
        return ""
    config_file = home_dir / ".unbound" / "config.json"

    def _read():
        try:
            fd = os.open(str(config_file), os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0))
            with os.fdopen(fd, 'r', encoding='utf-8') as handle:
                config = json.loads(handle.read())
        except (OSError, ValueError):
            return ""
        # A config that is not an object has no gateway to report; .get would raise, and
        # this runs on the install path where anything raising aborts the setup.
        if not isinstance(config, dict):
            return ""
        recorded = config.get("gateway_url")
        return recorded.strip().rstrip("/") if isinstance(recorded, str) else ""

    result = _run_as_user(username, _read) if username else _read()
    return result or ""


def _machine_env_is_set(var_name: str) -> bool:
    """Whether the machine-wide environment holds this variable. UNBOUND_API_KEY is
    written by nothing but this setup, so its presence is proof the setup ran on this
    device -- device-level evidence, unlike a per-account record."""
    reg_path = "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Environment"
    try:
        result = subprocess.run(["reg", "query", reg_path, "/V", var_name],
                                capture_output=True, timeout=10)
    except Exception:
        return False
    return result.returncode == 0


_OWNERSHIP_EVIDENCE = {}


def _freeze_ownership_evidence(managed_dir=None) -> None:
    """Freeze what teardown judges ownership by, before teardown removes the very things
    that evidence consists of. Clearing sweeps UNBOUND_API_KEY out of the machine
    environment and unlinks the drop-in part-way through its own run, so reading either
    one live means the same file gets a different verdict depending on when it is asked.

    The first freeze of a run wins. A later call would re-read state this run has already
    changed -- hooks mode freezes, deletes the key, then enters the managed-settings step
    and would freeze again from a machine it has just altered."""
    if _OWNERSHIP_EVIDENCE:
        return
    try:
        if managed_dir is None:
            managed_dir = get_managed_settings_dir()
    except OSError:
        return
    _OWNERSHIP_EVIDENCE["installed_here"] = _machine_env_is_set("UNBOUND_API_KEY")
    _OWNERSHIP_EVIDENCE["dropin_present"] = (
        managed_dir / "managed-settings.d" / "unbound.json").exists()
    _OWNERSHIP_EVIDENCE["gateway_url"] = _read_managed_gateway_url()


def _installed_here() -> bool:
    if "installed_here" in _OWNERSHIP_EVIDENCE:
        return _OWNERSHIP_EVIDENCE["installed_here"]
    return _machine_env_is_set("UNBOUND_API_KEY")


def _dropin_present(managed_dir) -> bool:
    if "dropin_present" in _OWNERSHIP_EVIDENCE:
        return _OWNERSHIP_EVIDENCE["dropin_present"]
    return (managed_dir / "managed-settings.d" / "unbound.json").exists()


def _managed_settings_is_exactly_ours(settings, managed_dir) -> bool:
    """Whether a managed settings file is the one this setup writes on the fallback path.

    Three things have to hold, because the shape alone proves nothing: an env block
    holding just the token and the base URL is also the ordinary env-only managed layout
    an organisation writes for Bedrock or their own gateway.

    The drop-in must be absent. The install prefers managed-settings.d/unbound.json
    exactly so it does not touch a sibling flat file, so a drop-in on disk means the flat
    file beside it belongs to somebody else whatever it contains.

    And this setup must actually have run on the device, which UNBOUND_API_KEY in the
    machine environment proves because nothing else writes it. That is what lets a custom
    gateway be recognised here without the endpoint vouching for itself: an organisation's
    own Bedrock settings sit on a device that has no such key. This shape only ever occurs
    on Windows; the Unix install writes an apiKeyHelper, not an env block."""
    if _dropin_present(managed_dir):
        return False
    if not isinstance(settings, dict) or set(settings) != {"env"}:
        return False
    env = settings.get("env")
    if not (isinstance(env, dict)
            and set(env) == {"ANTHROPIC_AUTH_TOKEN", "ANTHROPIC_BASE_URL"}):
        return False
    return _installed_here()


def _managed_settings_gateway_url(path) -> str:
    """The base URL in a managed settings file's env block, or ""."""
    try:
        fd = os.open(str(path), os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0))
        with os.fdopen(fd, 'r', encoding='utf-8') as handle:
            settings = json.loads(handle.read())
    except (OSError, ValueError):
        return ""
    if not isinstance(settings, dict):
        return ""
    env = settings.get("env")
    if not isinstance(env, dict):
        return ""
    recorded = env.get("ANTHROPIC_BASE_URL")
    return recorded.strip().rstrip("/") if isinstance(recorded, str) else ""



def _read_managed_gateway_url() -> str:
    """The gateway URL this setup recorded on the device. Device-level state we own, so
    unlike a per-account record it can authorise removing the machine-wide route, which
    matters on a Windows device that has no user profiles to read.

    The drop-in first: nothing else writes that file. The install falls back to the shared
    managed-settings.json when it cannot create the drop-in directory, and there it writes
    the whole file, so that one counts only when its entire content is what the install
    produces -- an administrator's own settings carry other keys and stay theirs."""
    try:
        managed_dir = get_managed_settings_dir()
    except OSError:
        return ""
    dropin = _managed_settings_gateway_url(
        managed_dir / "managed-settings.d" / "unbound.json")
    if dropin:
        return dropin
    # The install writes the flat file instead when it cannot create the drop-in
    # directory. It counts only under the same proof teardown uses for that file.
    flat = managed_dir / "managed-settings.json"
    try:
        settings = json.loads(flat.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return ""
    if not _managed_settings_is_exactly_ours(settings, managed_dir):
        return ""
    return _managed_settings_gateway_url(flat)

def _recorded_managed_gateway_url() -> str:
    """The recorded gateway, from the snapshot when teardown has frozen one. The record
    lives in files this run also clears, so reading it live afterwards loses it."""
    if "gateway_url" in _OWNERSHIP_EVIDENCE:
        return _OWNERSHIP_EVIDENCE["gateway_url"]
    return _read_managed_gateway_url()


def _unbound_base_url_matcher(username, home_dir):
    """Accepts our default gateway, or the one recorded for this user. The record is read
    here rather than inside the predicate: the removal runs under a privilege drop, and a
    second drop nested in the first cannot call setgroups."""
    # On Windows this removal is not per user at all: remove_env_var_from_user deletes the
    # machine-wide HKLM value, which the whole device shares. A record any account can
    # write must not authorise that, so there it is ignored and only the default gateway
    # and the drop-in this setup owns count. On Unix the removal edits that user's own rc
    # files, where their own record is exactly the right authority.
    recorded = ("" if platform.system().lower() == "windows"
                else _recorded_gateway_url_for_user(username, home_dir))
    # Read before the managed settings are cleared: teardown sweeps the environment first,
    # and afterwards the drop-in holding this record is gone.
    managed = _recorded_managed_gateway_url()

    def _matches(value):
        if _is_unbound_base_url(value):
            return True
        if not isinstance(value, str):
            return False
        candidate = value.strip().rstrip("/")
        return ((bool(recorded) and candidate == recorded)
                or (bool(managed) and candidate == managed))

    return _matches


def _export_value(line: str, prefix: str) -> str:
    return line.strip()[len(prefix):].strip().strip('"').strip("'")


def _is_unbound_key_helper_body(text) -> bool:
    """Exact against the body the gateway writer emits, apart from surrounding whitespace,
    so a CRLF or a trailing newline still matches but a script carrying anything else is
    somebody else's."""
    return isinstance(text, str) and text.strip() == UNBOUND_KEY_HELPER_BODY


def _registry_value(output: str, var_name: str):
    """The value `reg query` printed for var_name, or None when its output held no line
    for it. None is "could not tell", not "not ours" -- the caller reports failure rather
    than silently leaving our own value behind."""
    for line in (output or "").splitlines():
        parts = line.split(None, 2)
        if len(parts) >= 2 and parts[0].lower() == var_name.lower():
            return parts[2].strip() if len(parts) == 3 else ""
    return None


def _read_text_or_none(path):
    try:
        return path.read_text(encoding="utf-8")
    except (OSError, ValueError):
        return None


def _is_our_dropin(settings_path) -> bool:
    """Whether this settings file is the drop-in this setup creates. Nothing else writes
    it, so everything in it is ours -- including a self-hosted gateway URL, which no
    value check could recognise."""
    return (settings_path is not None
            and settings_path.name == "unbound.json"
            and settings_path.parent.name == "managed-settings.d")


def _is_unbound_key_helper_setting(value, managed_dir) -> bool:
    """Whether settings.json's apiKeyHelper is one this setup writes: the per-user script
    or the managed one. Judged on the value alone, so a helper that has already been
    deleted cannot make somebody else's setting look like ours."""
    if not isinstance(value, str):
        return False
    if value.strip() != str(managed_dir / "anthropic_key.sh"):
        return False
    # The path is a name anyone could choose, so the script there decides. Nothing there
    # means our own removal already ran; a dangling helper is broken either way.
    path = managed_dir / "anthropic_key.sh"
    return not path.exists() or _is_unbound_key_helper_body(_read_text_or_none(path))


def remove_env_var_from_user(username: str, home_dir: Path, var_name: str,
                             only_if=None) -> str:
    """Remove env var from user's shell rc files. Privilege-drops on Unix.
    With only_if, removes just the exports whose value it accepts -- a user may have their
    own export of the same variable in the other startup file.

    Returns "cleared", "not_found", or "failed".
    """
    system = platform.system().lower()

    if system == "windows":
        return remove_env_var_on_windows_machine(var_name, only_if)

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
                new_lines = [l for l in lines
                             if not (l.strip().startswith(export_prefix)
                                     and (only_if is None
                                          or only_if(_export_value(l, export_prefix))))]
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
    """Remove ~/.claude/anthropic_key.sh for a given user (leftover from gateway setup).
    Privilege-drops to the target user — `unlink` against an attacker-planted
    symlink would otherwise let a non-root user delete root-owned files."""
    key_helper_path = home_dir / ".claude" / "anthropic_key.sh"
    if not key_helper_path.exists():
        return

    def _unlink():
        try:
            # Read and unlink as the user: a helper of this name that we did not write
            # belongs to whoever did.
            if not _is_unbound_key_helper_body(
                    key_helper_path.read_text(encoding="utf-8")):
                return False
            key_helper_path.unlink()
            return True
        except Exception:
            return False

    if _run_as_user(username, _unlink):
        debug_print(f"Removed {key_helper_path} for {username}")


def _command_targets_hook(command: str, target: Path) -> bool:
    if not command:
        return False
    # Binary install: command invokes the /opt/unbound hook binary (require both
    # the prefix and the binary name so a foreign hook merely mentioning the path
    # isn't matched). Mirrors the managed _is_unbound_hook_command matcher.
    if "/opt/unbound/" in command and "unbound-hook" in command:
        return True
    try:
        # posix=False on Windows: shlex still groups a quoted argument, so a home
        # directory containing spaces stays one token; only the quotes it leaves behind
        # are stripped below.
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
    """Strip Unbound's hook entries from ~/.claude/settings.json and delete
    ~/.claude/hooks/unbound.py for a given user. Without this, MDM-managed
    hooks fire alongside leftover user-level ones and every event runs twice.
    Only entries pointing to our own unbound.py are removed; unrelated user
    hooks are preserved. Privilege-drops to the target user."""
    settings_path = home_dir / ".claude" / "settings.json"
    script_path = home_dir / ".claude" / "hooks" / "unbound.py"

    def _is_unbound(cmd: str) -> bool:
        return _command_targets_hook(cmd, script_path)

    def _clean():
        # safe_to_unlink stays True only if the JSON no longer references
        # script_path. If the read/write fails partway, we leave the script
        # in place so a dangling hook entry doesn't point at a missing file.
        safe_to_unlink = True
        if settings_path.exists():
            try:
                with open(settings_path, 'r', encoding='utf-8') as f:
                    settings = json.load(f)
                if isinstance(settings, dict) and isinstance(settings.get("hooks"), dict):
                    hooks_block = settings["hooks"]
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
                        del settings["hooks"]
                        modified = True
                    if modified:
                        flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC | getattr(os, 'O_NOFOLLOW', 0)
                        fd = os.open(str(settings_path), flags, 0o644)
                        with os.fdopen(fd, 'w', encoding='utf-8') as f:
                            json.dump(settings, f, indent=2)
                        debug_print(f"Stripped Unbound hooks from {settings_path}")
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
    ~/.claude/hooks on CLEAR/nuke — they exist only because of us. Kept separate
    from remove_user_level_hooks_for_user (which also runs at setup) so logs are
    dropped ONLY on clear. Privilege-drops to the user; unlink() removes the dir
    entry (a symlink, never its target)."""
    if home_dir is None:
        return  # Windows machine-wide placeholder — no per-user dir to clean
    hooks_dir = home_dir / ".claude" / "hooks"

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


def setup_managed_hooks(gateway_url: str = DEFAULT_GATEWAY_URL, skip_settings: bool = False) -> bool:
    """Set up system-wide managed hooks for Claude Code: download unbound.py and
    configure managed-settings.json. With skip_settings, install only the script."""
    system = platform.system().lower()
    try:
        managed_dir = get_managed_settings_dir()
        hooks_dir = managed_dir / "hooks"
        script_path = hooks_dir / "unbound.py"
        # Before this run removes the gateway's leftovers, which are what its ownership
        # checks read.
        _freeze_ownership_evidence(managed_dir)

        if skip_settings:
            settings_path = None
        # On Windows, prefer the drop-in directory to avoid clobbering an
        # existing admin-managed settings file; fall back if we can't create it.
        elif system == "windows":
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

        # No hook config of our own: the remote policy owns it, and stale local
        # hooks would let the device enforce from two places at once.
        if skip_settings:
            stripped, strip_error = _strip_unbound_hooks_from_settings(
                managed_dir, script_path, delete_when_empty=False)
            if stripped:
                print("Removed Unbound hooks left behind in the local managed settings")
            if strip_error:
                print(f"Warning: could not strip existing Unbound hooks from {managed_dir}; check it by hand")
            if system in ["darwin", "linux"]:
                os.chmod(managed_dir, 0o755)
                os.chmod(hooks_dir, 0o755)
            debug_print("Installed hook script only; wrote no managed settings")
            return True

        # Read existing settings or create new
        settings = {}
        if settings_path.exists():
            try:
                with open(settings_path, 'r', encoding='utf-8') as f:
                    settings = json.load(f) or {}
            except Exception:
                settings = {}

        # Drop gateway MDM setup from the same file — leaving its apiKeyHelper
        # behind makes Claude Code run anthropic_key.sh, which echoes the now
        # removed UNBOUND_API_KEY and fails with "did not return a valid value".
        # One verdict per file: the env sweep already treats a flat file of exactly this
        # shape as ours, and stripping it must agree or the base URL stays behind while
        # its credential goes.
        ours = (_is_our_dropin(settings_path)
                or _managed_settings_is_exactly_ours(settings, get_managed_settings_dir()))
        if (ours or _is_unbound_key_helper_setting(settings.get("apiKeyHelper"),
                                                   get_managed_settings_dir())):
            settings.pop("apiKeyHelper", None)
        env = settings.get("env") if isinstance(settings.get("env"), dict) else None
        if env:
            # The gateway writes the token and the base URL together, so they go
            # together, and only out of a file that setup wrote or a pair it recognises.
            # A token in somebody else's file is their credential, not ours to delete.
            # Inside our own file the URL may since have been repointed; the credential
            # still comes out, because it would otherwise be sent to whatever that URL
            # now names.
            if ours or _is_unbound_base_url(env.get("ANTHROPIC_BASE_URL")):
                env.pop("ANTHROPIC_AUTH_TOKEN", None)
                env.pop("ANTHROPIC_BASE_URL", None)
            if not env:
                del settings["env"]

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

        # Delete the gateway key helper only after the hooks settings are
        # written, so a failed write never strands managed-settings.json
        # pointing at a now-missing apiKeyHelper script.
        gateway_key_helper = managed_dir / "anthropic_key.sh"
        if gateway_key_helper.exists() and _is_unbound_key_helper_body(
                _read_text_or_none(gateway_key_helper)):
            try:
                gateway_key_helper.unlink()
                debug_print(f"Removed gateway key helper {gateway_key_helper}")
            except Exception as e:
                debug_print(f"Failed to remove {gateway_key_helper}: {e}")

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


def _is_unbound_hook_command(cmd: str, script_path: Path) -> bool:
    """A hook command is ours if it points at OUR managed python hook
    (script_path) or the /opt/unbound hook binary. Both forms are recognized so a
    binary-install hook is stripped on clear instead of being orphaned. Matches the
    specific script path (NOT a bare 'unbound.py' substring) and requires both the
    install prefix and the binary name, so a foreign hook in a shared/Enterprise
    config that merely references some other unbound.py / mentions /opt/unbound/
    isn't stripped."""
    # A non-string command is never ours; matching one raises and would abandon
    # every remaining entry in the file.
    if not cmd or not isinstance(cmd, str):
        return False
    return str(script_path) in cmd or ("/opt/unbound/" in cmd and "unbound-hook" in cmd)


def _strip_unbound_hooks_from_settings(managed_dir: Path, script_path: Path,
                                       delete_when_empty: bool = True) -> Tuple[bool, bool]:
    """Remove ONLY our hook entries from the managed Claude config, preserving
    foreign content; managed-settings.json is shared with org/Enterprise policy.

    delete_when_empty removes a file that held nothing but our hooks — right for
    teardown, wrong mid-install. Returns (stripped_any, had_error). Leaves the
    hook script itself alone.
    """
    stripped_any = False
    had_error = False
    settings_candidates = [
        managed_dir / "managed-settings.d" / "unbound.json",
        managed_dir / "managed-settings.json",
    ]

    for settings_path in settings_candidates:
        if not settings_path.exists():
            continue
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
                # Delete the file only when nothing foreign remains (our
                # drop-in, or a managed-settings.json that held only our
                # hooks); otherwise rewrite in place so org policy survives.
                if delete_when_empty and isinstance(settings, dict) and not settings:
                    settings_path.unlink()
                    debug_print(f"Removed empty settings {settings_path}")
                else:
                    # tmp + os.replace so a crash never truncates org policy; the
                    # mode carries over so a tight umask cannot hide the file from
                    # the non-root users whose Claude Code has to read it.
                    try:
                        mode = stat.S_IMODE(settings_path.stat().st_mode)
                    except OSError:
                        mode = 0o644
                    tmp = settings_path.parent / f"{settings_path.name}.{os.getpid()}.tmp"
                    try:
                        tmp.write_text(json.dumps(settings, indent=2), encoding="utf-8")
                        os.chmod(tmp, mode)
                        os.replace(tmp, settings_path)
                    except Exception:
                        tmp.unlink(missing_ok=True)
                        raise
                    debug_print(f"Stripped our hooks from {settings_path}")
                stripped_any = True
        except Exception as e:
            debug_print(f"Failed to update {settings_path}: {e}")
            had_error = True

    return stripped_any, had_error


def clear_managed_hooks() -> str:
    """Strip ONLY our hook entries from the managed Claude config, preserving
    foreign content; managed-settings.json is shared with org/Enterprise policy.

    Returns "cleared", "not_found", or "failed".
    """
    try:
        managed_dir = get_managed_settings_dir()
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

        stripped, strip_error = _strip_unbound_hooks_from_settings(managed_dir, script_path)
        cleared_any = cleared_any or stripped
        had_error = had_error or strip_error

        if cleared_any:
            return "cleared"
        if had_error:
            return "failed"
        return "not_found"

    except Exception as e:
        debug_print(f"Error clearing managed hooks: {e}")
        return "failed"


def clear_setup() -> bool:
    print("=" * 60)
    print("Claude Code Hooks - Clearing MDM Setup")
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
            status = remove_env_var_from_user(username, home_dir, "UNBOUND_CLAUDE_API_KEY")
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

    print("\n" + "=" * 60)
    print("Clear Complete!")
    print("=" * 60)
    return not teardown_failed


def _backfill_collect_session(transcript_path: Path) -> Optional[Dict]:
    """Read a transcript and return {session_id, entries} for server-side parsing.
    The client only JSON-decodes lines and pulls a session id — all semantic
    parsing happens server-side in
    webapp.services.coding_tools_backfill_service."""
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
    return home / '.claude' / 'hooks' / BACKFILL_STATE_FILE


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


def _backfill_is_real_user_prompt(content) -> bool:
    # Mirror server-side parse_claude_code_session._is_real_user_prompt so the
    # client splits exactly where the server starts a new exchange.
    if isinstance(content, str):
        return bool(content.strip())
    if isinstance(content, list):
        for block in content:
            if not isinstance(block, dict):
                continue
            btype = block.get('type')
            if btype in ('text', 'input_text'):
                if (block.get('text') or '').strip():
                    return True
            elif btype == 'image':
                return True
    return False


def _backfill_exchange_boundaries(entries: List[Dict]) -> List[int]:
    boundaries = []
    for i, entry in enumerate(entries):
        if not isinstance(entry, dict):
            continue
        if entry.get('isSidechain'):
            continue
        if entry.get('type') != 'user':
            continue
        msg = entry.get('message') or {}
        if msg.get('role') != 'user':
            continue
        if _backfill_is_real_user_prompt(msg.get('content')):
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
    # A slice is a fresh dict, so the identity has to be carried over explicitly or
    # an oversized session silently loses the attribution the whole change is for.
    identity = {k: session[k] for k in ('device_serial', 'user_email') if session.get(k)}
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
            **identity,
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

        slice_payload = {
            'session_id': session_id,
            'record_index_base': record_index_base,
            'entries': entries[start_idx:last_fit_end],
        }
        slice_payload.update(identity)
        yield slice_payload
        record_index_base += last_fit_base_count
        start_idx = last_fit_end


_DESKTOP_SESSION_MAX_BYTES = 512 * 1024
_IS_JUNCTION = getattr(os.path, 'isjunction', None)


def _is_reparse_point(path: Path) -> bool:
    """Symlink, or a Windows directory junction. os.path.islink reports False for
    junctions and os.path.isjunction only exists on 3.12+, so both are checked and
    an unreadable path is treated as suspect."""
    try:
        if path.is_symlink():
            return True
        return bool(_IS_JUNCTION and _IS_JUNCTION(path))
    except OSError:
        return True


def _claude_desktop_support_dirs(home: Path) -> List[Path]:
    r"""Claude Desktop app support dir(s) for a home. Team/SSO desktop sessions
    cache the active account's oauthAccount under local-agent-mode-sessions/ here.

    Taken from unbound.py, keyed off `home` instead of Path.home()/APPDATA: MDM
    backfill walks every profile, so per-process paths would resolve to the
    admin's for all of them. On Windows APPDATA is that user's
    <home>\AppData\Roaming.
    """
    system = platform.system().lower()
    if system == 'darwin':
        return [home / 'Library' / 'Application Support' / 'Claude']
    if system == 'windows':
        # MSIX/Store installs never write %APPDATA%\Claude — Windows redirects it
        # to a per-package LocalCache. Verified on a Windows Server 2022 box where
        # only the second path existed. Both are listed; missing ones are skipped.
        appdata = home / 'AppData'
        return [
            appdata / 'Roaming' / 'Claude',
            appdata / 'Local' / 'Packages' / 'Claude_pzs8sxrjxfjjc' / 'LocalCache' / 'Roaming' / 'Claude',
        ]
    return [home / '.config' / 'Claude']


def _desktop_session_email(home: Path) -> Optional[str]:
    """Fallback for Team/SSO Claude Desktop, where the desktop app doesn't hydrate
    oauthAccount into ~/.claude.json (anthropics/claude-code#57026) but does write
    the active account's oauthAccount (with emailAddress) into each per-session
    sandbox config. These configs are sandbox-writable and thus untrusted, so the
    email is returned only when every session that carries one agrees on a single
    address; any disagreement (multiple accounts, or a forged/injected config) or
    failure yields None, so backfill sends a blank email rather than a wrong one.
    Best effort — never raises. Copied from unbound.py, keyed off `home`."""
    timed = []
    try:
        bases = _claude_desktop_support_dirs(home)
    except Exception:
        return None
    for base in bases:
        # These live under a user-writable AppData. On Windows _run_as_user cannot
        # fork, so the MDM script globs every profile while still elevated; a planted
        # junction would otherwise walk SYSTEM out of the profile. Transcript
        # collection already skips symlinks, this mirrors that.
        if _is_reparse_point(base):
            debug_print("skipping reparse-point desktop support dir")
            continue
        try:
            base_real = base.resolve(strict=True)
        except OSError:
            continue
        try:
            # list() forces the lazy glob traversal to happen inside this guard —
            # a mid-iteration traversal error (e.g. an unreadable subdir) then only
            # skips this base instead of aborting the whole scan.
            candidates = list((base / 'local-agent-mode-sessions').glob('*/*/local_*/.claude/.claude.json'))
        except Exception:
            continue
        for path in candidates:
            # stat per file so one unreadable/vanished entry can't poison the sort.
            try:
                if not path.is_file() or _is_reparse_point(path):
                    continue
                # Resolving and re-containing catches a junction at any level of the
                # globbed path, not just the leaf.
                path.resolve(strict=True).relative_to(base_real)
                timed.append((path.stat().st_mtime, path))
            except (OSError, ValueError):
                continue
    timed.sort(key=lambda t: t[0], reverse=True)
    found = None
    found_key = None
    for _, path in timed:
        # A session that exists but can't be read (oversized, IO/parse error) is a
        # blind spot — it could belong to a different account, so we can't verify
        # agreement. Return blank rather than fall through to a possibly-stale email.
        # Bound the read itself (read MAX+1 bytes) rather than trusting a separate
        # stat(): a rewrite-after-stat race can't feed an unbounded file into read.
        try:
            with open(path, 'rb') as f:
                data = f.read(_DESKTOP_SESSION_MAX_BYTES + 1)
            if len(data) > _DESKTOP_SESSION_MAX_BYTES:
                return None
            oauth = json.loads(data.decode('utf-8')).get('oauthAccount')
        except Exception:
            return None
        if not isinstance(oauth, dict):
            continue
        raw = oauth.get('emailAddress')
        email = raw.strip() if isinstance(raw, str) else ''
        if not email:
            continue
        key = email.lower()
        if found_key is None:
            found, found_key = email, key
        elif key != found_key:
            return None  # accounts disagree — blank over wrong
    return found


def _backfill_account_email(home: Path) -> Optional[str]:
    """Signed-in email for a home, in the same order read_account_identity uses:
    oauthAccount in ~/.claude.json first, then the Team/SSO desktop session cache.

    Team/SSO desktop never hydrates oauthAccount, so skipping the fallback would
    leave exactly those users unattributed — the case this change exists to fix.
    """
    email = None
    try:
        account_file = home / '.claude.json'
        # Same reason the desktop-session scan is guarded: on Windows _run_as_user
        # cannot fork, so this read happens as SYSTEM across every profile. A link
        # planted here would otherwise pull another user's address into this
        # profile's sessions. Containment rather than refusal, so a dotfiles symlink
        # inside the same home still resolves.
        if _is_reparse_point(account_file):
            account_file.resolve(strict=True).relative_to(home.resolve(strict=True))
        config = json.loads(account_file.read_text(encoding='utf-8'))
        oauth = config.get('oauthAccount')
        if isinstance(oauth, dict):
            raw = oauth.get('emailAddress')
            if isinstance(raw, str) and raw.strip():
                email = raw.strip()
    except FileNotFoundError:
        debug_print("no .claude.json for this home")
    except Exception as e:
        debug_print(f"could not read oauthAccount: {e!r}")
    if not email:
        try:
            email = _desktop_session_email(home)
        except Exception as e:
            debug_print(f"desktop session email lookup failed: {e!r}")
            email = None
    if not email:
        debug_print("no signed-in email resolved; backfill will send none")
    return email


def _backfill_attach_identity(sessions: List[Dict], serial: Optional[str], email: Optional[str]) -> None:
    """Carry the device serial and signed-in email alongside the sessions.

    Without them the server attributes replayed history to whichever application
    owns the upload key, which under MDM is the admin's rather than the person who
    actually ran the session. Either field may be absent; the server maps on what
    it gets.
    """
    for session in sessions:
        if serial:
            session['device_serial'] = serial
        if email:
            session['user_email'] = email


def _backfill_collect_sessions(home_dir: Path, force_epoch=None,
                               force_days=None) -> Tuple[List[Dict], bool, bool]:
    # Must run inside _run_as_user (reads transcripts as the target user).
    # Returns (sessions, capped, forced); capped=True means the per-run cap was hit and
    # older files remain unprocessed, so this home's cutoff must not advance.
    projects_root = home_dir / '.claude' / 'projects'
    if not projects_root.exists():
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
    for transcript_path in sorted(_backfill_iter_transcripts(projects_root, cutoff_mtime)):
        if len(sessions) >= BACKFILL_MAX_SESSIONS_PER_RUN:
            capped = True
            break
        session = _backfill_collect_session(transcript_path)
        if session:
            sessions.append(session)
    # Read here rather than in run_backfill: this runs privilege-dropped as the
    # owner, so another user's home is never read as root.
    _backfill_attach_identity(sessions, None, _backfill_account_email(home_dir))
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


def _backfill_upload_chunk(api_key: str, backend_url: str, sessions: List[Dict],
                           force: bool = False) -> bool:
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
        chunks_total += 1
        if _backfill_upload_chunk(api_key, backend_url, current_chunk, forced):
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
    """Walk every user's ~/.claude/projects and seed historical sessions.

    MDM /get_application_api_key/ returns one per-device key, so the upload is
    shared. Each session carries its own home's signed-in email plus the machine
    serial, which is what lets the server attribute a profile's history to the
    person who ran it rather than to the key's owner."""
    if os.environ.get('UNBOUND_BACKFILL_DISABLED') == '1':
        debug_print("UNBOUND_BACKFILL_DISABLED=1 — skipping backfill")
        return

    try:
        if not user_homes:
            debug_print("no user homes found — skipping backfill")
            return

        started_at = time.time()
        device_serial = get_device_identifier()
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
                # One serial for the machine; the email was attached per home above.
                _backfill_attach_identity(user_sessions, device_serial, None)
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
        for batch, forced in ((forced_sessions, True), (sessions, False)):
            if not batch:
                continue
            sent, _, failed = _backfill_send_sessions(api_key, backend_url, batch, forced)
            sessions_sent += sent
            chunks_failed += failed

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


def detect_install_state(skip_settings: bool = False) -> Optional[str]:
    """Inspect the managed-settings target BEFORE it gets overwritten.
    Existence-based: these files change across versions, so content checks
    are unreliable — only file existence is trustworthy.
    'fresh' (config absent), 'persisted' (config + unbound.py both present),
    'tampered' (config present but hook script missing), or None on any error.
    With skip_settings no config is written, so the hook script is the marker."""
    try:
        managed_dir = get_managed_settings_dir()
        config_path = managed_dir / "managed-settings.json"
        script_path = managed_dir / "hooks" / "unbound.py"
        if skip_settings:
            return 'persisted' if script_path.exists() else 'fresh'
        if not config_path.exists():
            return 'fresh'
        return 'persisted' if script_path.exists() else 'tampered'
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


def notify_setup_complete(api_key: str, tool_type: str, backend_url: str = "https://backend.getunbound.ai", install_state: Optional[str] = None, serial_number: Optional[str] = None,
                          hook_hash: Optional[str] = None, install_mode: Optional[str] = None):
    """Notify backend that tool setup completed. Never fails the setup."""
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
        return clear_setup()

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
        return False

    base_url = "https://backend.getunbound.ai"
    gateway_url = DEFAULT_GATEWAY_URL
    frontend_url = None
    app_name = None
    auth_api_key = None
    backfill_mode = False
    skip_managed_settings = False

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
        elif args[i] == "--skip-managed-settings":
            skip_managed_settings = True
            i += 1
        else:
            i += 1

    if not auth_api_key:
        print("\nMissing required argument: --api-key")
        print("Usage: sudo python3 setup.py --api-key <api_key> [--backend-url <url>] [--app_name <app_name>] [--debug] [--backfill] [--skip-managed-settings]")
        print("   Or: sudo python3 setup.py --clear [--debug]")
        return False

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

    print("\nSetting environment variables system-wide...")
    _freeze_ownership_evidence()

    # Remove leftover gateway setup env vars. Runs before write_unbound_config_for_user
    # below, which rewrites the recorded gateway_url the ownership check reads --
    # afterwards it would answer for this install, not the one being removed.
    for username, home_dir in get_all_user_homes():
        remove_env_var_from_user(username, home_dir, "UNBOUND_API_KEY")
        remove_env_var_from_user(username, home_dir, "ANTHROPIC_BASE_URL",
                                 _unbound_base_url_matcher(username, home_dir))

    success, _ = set_env_var_system_wide("UNBOUND_CLAUDE_API_KEY", api_key)
    if not success:
        print("Failed to set UNBOUND_CLAUDE_API_KEY")
        return False
    debug_print("UNBOUND_CLAUDE_API_KEY set successfully")

    url_ok, _ = set_env_var_system_wide("UNBOUND_BACKEND_URL", base_url)
    if not url_ok:
        print("Failed to set UNBOUND_BACKEND_URL")
        return False

    # Remove gateway artifacts, strip leftover user-level Unbound hooks
    # (so managed hooks don't fire twice), and write unbound config.
    for username, home_dir in get_all_user_homes():
        remove_gateway_artifacts_for_user(username, home_dir)
        remove_user_level_hooks_for_user(username, home_dir)
        write_unbound_config_for_user(username, home_dir, api_key, urls={"base_url": base_url, "gateway_url": gateway_url, "frontend_url": frontend_url})

    state = detect_install_state(skip_settings=skip_managed_settings)

    print("\nInstalling Claude hook script..." if skip_managed_settings else "\nConfiguring Claude managed hooks...")
    if setup_managed_hooks(gateway_url=gateway_url, skip_settings=skip_managed_settings):
        managed_dir = get_managed_settings_dir()
        if skip_managed_settings:
            print(f"Installed hook script at {managed_dir / 'hooks' / 'unbound.py'}")
            print("Skipped managed-settings.json - point your remote Claude Code policy at that path.")
        else:
            print(f"Created managed hooks in {managed_dir}")
    else:
        print("Failed to configure managed hooks")
        return False

    print("\n" + "=" * 60)
    print("Setup Complete!")
    print("=" * 60)

    notify_setup_complete(api_key, "claude-code", backend_url=base_url, install_state=state, serial_number=device_id,
                          hook_hash=hook_script_hash(get_managed_settings_dir() / "hooks" / "unbound.py"),
                          install_mode="mdm-skip" if skip_managed_settings else "mdm")

    if backfill_mode:
        run_backfill(api_key, base_url, get_all_user_homes())

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
