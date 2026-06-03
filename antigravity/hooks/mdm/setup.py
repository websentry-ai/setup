#!/usr/bin/env python3
"""MDM (device-wide) Unbound hooks installer for Antigravity 2.0.

Mirrors ``claude-code/hooks/mdm/setup.py``: enumerates user homes, drops
privileges to each user, and runs the same user-level install logic against
``~<user>/.antigravity/settings.json``.

  --api-key <key>          MDM admin API key, used to fetch a per-device key.
  --backend-url <url>      Backend host (default https://backend.getunbound.ai).
  --gateway-url <url>      Unbound gateway base URL (baked into hook scripts).
  --app_name <name>        Optional MDM application identifier.
  --clear                  Uninstall — surgically remove our entries for every
                           user, delete our scripts, drop the policy marker.
  --backfill               No-op for Antigravity. Accepted for CLI parity.
  --debug                  Always on for MDM; flag accepted for parity.

Drops a marker at ``/etc/unbound/antigravity.policy.json`` (Unix) or
``%ProgramFiles%\\Unbound\\antigravity.policy.json`` (Windows) so reruns are
idempotent.
"""

import json
import os
import platform
import shutil
import subprocess
import sys
import urllib.error
import urllib.request
from pathlib import Path
from typing import Dict, List, Optional, Tuple

try:
    import pwd
except ImportError:
    pwd = None


DEFAULT_GATEWAY_URL = "https://api.getunbound.ai"
DEFAULT_BACKEND_URL = "https://backend.getunbound.ai"
UNBOUND_APP_LABEL = "antigravity"

HOOK_EVENT_SCRIPTS: List[Tuple[str, str]] = [
    ("PreToolUse", "unbound_pre_tool_use.py"),
    ("PostToolUse", "unbound_post_tool_use.py"),
    ("UserPromptSubmit", "unbound_user_prompt_submit.py"),
    ("SessionStart", "unbound_session_start.py"),
]

# Catch-all matchers for tool-scoped events. A regex allowlist here silently
# bypasses our hook for any tool not in the list (WebFetch, WebSearch,
# MultiEdit, NotebookEdit, TodoWrite, future tools...). Server-side filtering
# (gateway's APP_NATIVE_FILE_TOOLS / tools_to_check) is the right gate; the
# matcher is the wrong place to defang.
HOOK_EVENT_MATCHERS: Dict[str, Optional[str]] = {
    "PreToolUse": "*",
    "PostToolUse": "*",
    "UserPromptSubmit": None,
    "SessionStart": None,
}

HOOK_TIMEOUT_SECONDS = 15
TELEMETRY_TIMEOUT_SECONDS = 60

# MDM scripts always run with debug logging on — administrators need full
# diagnostic output for troubleshooting across managed devices.
DEBUG = True


def debug_print(message: str) -> None:
    if DEBUG:
        print(f"[DEBUG] {message}")


def normalize_url(value: str) -> str:
    value = (value or "").strip()
    if not value:
        return value
    if not (value.startswith("http://") or value.startswith("https://")):
        value = f"https://{value}"
    return value.rstrip("/")


def check_admin_privileges() -> bool:
    try:
        system = platform.system().lower()
        if system in ("darwin", "linux"):
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


def get_policy_marker_path() -> Path:
    """Where we drop the install marker so reruns are idempotent."""
    system = platform.system().lower()
    if system == "windows":
        program_files = os.environ.get("ProgramFiles", r"C:\Program Files")
        return Path(program_files) / "Unbound" / "antigravity.policy.json"
    return Path("/etc/unbound/antigravity.policy.json")


# -----------------------------------------------------------------------------
# User enumeration (mirrors claude-code/hooks/mdm/setup.py)
# -----------------------------------------------------------------------------

def get_all_user_homes() -> List[Tuple[str, Path]]:
    user_homes: List[Tuple[str, Path]] = []
    system = platform.system().lower()
    try:
        if system == "darwin" and pwd is not None:
            for user in pwd.getpwall():
                uid = user.pw_uid
                username = user.pw_name
                home_dir = Path(user.pw_dir)
                if uid >= 500 and home_dir.exists() and home_dir.is_dir():
                    if str(home_dir).startswith("/Users/") and username not in ("Shared", "Guest"):
                        user_homes.append((username, home_dir))
                        debug_print(f"Found user: {username} -> {home_dir}")
        elif system == "linux" and pwd is not None:
            for user in pwd.getpwall():
                uid = user.pw_uid
                username = user.pw_name
                home_dir = Path(user.pw_dir)
                if uid >= 1000 and home_dir.exists() and home_dir.is_dir():
                    if str(home_dir).startswith("/home/"):
                        user_homes.append((username, home_dir))
                        debug_print(f"Found user: {username} -> {home_dir}")
        elif system == "windows":
            system_drive = os.environ.get("SystemDrive", "C:")
            users_dir = Path(system_drive + r"\Users")
            if users_dir.exists():
                for user_dir in users_dir.iterdir():
                    if user_dir.is_dir() and user_dir.name not in (
                        "Public", "Default", "Default User", "Administrator", "All Users",
                    ):
                        user_homes.append((user_dir.name, user_dir))
                        debug_print(f"Found user: {user_dir.name} -> {user_dir}")
        return user_homes
    except Exception as e:
        debug_print(f"Error enumerating users: {e}")
        return []


def _run_as_user(username: Optional[str], fn, *args, **kwargs):
    """Fork+exec fn as the unprivileged user `username`. Returns whatever fn
    returns on success, or None on failure.

    Security-critical: any FS op that touches a user-controlled path must go
    through this to avoid symlink-following privilege escalation. Mirrors
    claude-code/hooks/mdm/setup.py::_run_as_user."""
    if platform.system().lower() == "windows":
        try:
            return fn(*args, **kwargs)
        except Exception:
            return None
    if pwd is None or username is None:
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


# -----------------------------------------------------------------------------
# MDM API key fetch (mirrors claude-code MDM)
# -----------------------------------------------------------------------------

def get_device_identifier() -> Optional[str]:
    system = platform.system().lower()
    try:
        if system == "darwin":
            result = subprocess.run(
                ["system_profiler", "SPHardwareDataType"],
                capture_output=True, text=True, timeout=10,
            )
            if result.returncode == 0:
                for line in result.stdout.split("\n"):
                    if "Serial Number" in line:
                        parts = line.split(": ")
                        if len(parts) >= 2 and parts[1].strip():
                            return parts[1].strip()
            return None
        if system == "linux":
            try:
                result = subprocess.run(
                    ["dmidecode", "-s", "system-serial-number"],
                    capture_output=True, text=True, timeout=10, stderr=subprocess.DEVNULL,
                )
                if result.returncode == 0 and result.stdout.strip():
                    return result.stdout.strip()
            except Exception:
                pass
            for p in ("/etc/machine-id", "/var/lib/dbus/machine-id"):
                try:
                    with open(p, "r", encoding="utf-8") as f:
                        v = f.read().strip()
                        if v:
                            return v
                except Exception:
                    continue
            try:
                import socket
                return socket.gethostname()
            except Exception:
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
        debug_print(f"Failed to get device identifier: {e}")
        return None


def fetch_api_key_from_mdm(
    base_url: str, app_name: Optional[str], auth_api_key: str, device_id: str
) -> Optional[str]:
    # Use stdlib urllib instead of shelling out to curl: passing the bearer
    # token via curl's argv leaks it through ``ps auxe`` /
    # ``/proc/<pid>/cmdline`` to any other user on the device. urllib sets the
    # header inside our own process — argv stays secret-free.
    params = f"serial_number={device_id}&app_type={UNBOUND_APP_LABEL}"
    if app_name:
        params = f"app_name={app_name}&{params}"
    url = f"{base_url.rstrip('/')}/api/v1/automations/mdm/get_application_api_key/?{params}"
    debug_print(f"Fetching API key from: {url}")
    try:
        req = urllib.request.Request(
            url,
            method="GET",
            headers={"Authorization": f"Bearer {auth_api_key}"},
        )
        try:
            with urllib.request.urlopen(req, timeout=30) as resp:
                http_code = resp.getcode()
                body = resp.read().decode("utf-8")
        except urllib.error.HTTPError as e:
            try:
                err_body = e.read().decode("utf-8", errors="replace")
            except Exception:
                err_body = ""
            debug_print(f"HTTP {e.code} body: {err_body[:200]}")
            print(f"API request failed with status {e.code}")
            return None
        except urllib.error.URLError as e:
            debug_print(f"URL error: {e}")
            print("Failed to reach backend")
            return None

        if http_code != 200:
            print(f"API request failed with status {http_code}")
            return None
        data = json.loads(body)
        api_key = data.get("api_key")
        if not api_key:
            print("No api_key in response")
            return None
        return api_key
    except (json.JSONDecodeError, ValueError):
        print("Invalid JSON response from server")
        return None
    except Exception as e:
        debug_print(f"Request failed: {e}")
        return None


# -----------------------------------------------------------------------------
# Per-user install logic — runs inside the privilege-dropped fork.
# -----------------------------------------------------------------------------

def _script_source_dir() -> Path:
    """Templates live next to this file at install time, two levels up
    (``antigravity/hooks/scripts/``)."""
    return Path(__file__).resolve().parent.parent / "scripts"


SCRIPT_BASE_URL = (
    "https://raw.githubusercontent.com/websentry-ai/setup/refs/heads/main/"
    "antigravity/hooks/scripts"
)


def _read_script_template(filename: str) -> Optional[bytes]:
    """Read a script template either from the local checkout or by fetching
    from GitHub. Run as root *before* the privilege drop so we don't need
    network/FS access inside the unprivileged child."""
    src = _script_source_dir() / filename
    if src.exists():
        try:
            return src.read_bytes()
        except OSError as e:
            print(f"Failed to read {src}: {e}")
            return None
    url = f"{SCRIPT_BASE_URL}/{filename}"
    try:
        result = subprocess.run(
            ["curl", "-fsSL", url], capture_output=True, timeout=30,
        )
        if result.returncode == 0:
            return result.stdout
        return None
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return None


def _build_hook_command(script_path: Path) -> Tuple[str, bool]:
    is_windows = platform.system().lower() == "windows"
    if is_windows:
        launcher = "py -3" if shutil.which("py") else "python"
        return f'{launcher} "{script_path}"', True
    return str(script_path), False


def _build_event_entry(event: str, script_path: Path) -> Dict:
    command, is_windows = _build_hook_command(script_path)
    matcher = HOOK_EVENT_MATCHERS.get(event)
    inner: Dict = {
        "type": "command",
        "command": command,
        "timeout": TELEMETRY_TIMEOUT_SECONDS if event != "PreToolUse" else HOOK_TIMEOUT_SECONDS,
    }
    if event in ("PostToolUse", "UserPromptSubmit", "SessionStart"):
        inner["async"] = True
    if is_windows:
        inner["shell"] = "powershell"
    if matcher is not None:
        return {"matcher": matcher, "hooks": [inner]}
    return {"hooks": [inner]}


def _is_our_hook_command(command: str, install_prefix: str, is_windows: bool) -> bool:
    if not command:
        return False
    if is_windows:
        return install_prefix in command and "unbound_" in command
    try:
        path = Path(command)
        return (
            str(path.parent) == install_prefix
            and path.name.startswith("unbound_")
            and path.name.endswith(".py")
        )
    except (ValueError, OSError):
        return False


def _atomic_write_json(path: Path, data: Dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)
        f.write("\n")
    os.replace(tmp, path)


def _write_unbound_config_payload(home_dir: Path, api_key: str, gateway_url: str, backend_url: str) -> bool:
    """Body of the per-user ~/.unbound/config.json write. Runs inside the
    privilege-dropped fork so attacker-planted symlinks in $HOME can't
    redirect a root write. Mirrors claude-code/hooks/mdm/setup.py's
    write_unbound_config_for_user pattern: tighten perms, atomic write,
    O_NOFOLLOW + 0o600.

    This is what the runtime hook scripts read in
    ``scripts/_common.py::load_credentials`` to authenticate to the gateway —
    without it every PreToolUse silently fail-opens and the org policy is
    never enforced."""
    try:
        config_dir = home_dir / ".unbound"
        config_file = config_dir / "config.json"
        config_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
        if platform.system().lower() != "windows":
            try:
                os.chmod(config_dir, 0o700)
            except OSError:
                pass

        # Preserve unrelated fields a previous tool's setup may have written
        # (e.g. claude-code writes the same file). Only api_key/gateway_url/
        # backend_url are owned by us.
        config: Dict = {}
        if config_file.exists():
            try:
                with open(config_file, "r", encoding="utf-8") as f:
                    config = json.loads(f.read())
                if not isinstance(config, dict):
                    config = {}
            except (json.JSONDecodeError, OSError):
                config = {}

        config["api_key"] = api_key
        if gateway_url:
            config["gateway_url"] = gateway_url
        if backend_url:
            config["backend_url"] = backend_url

        # Atomic write via tmp + rename. O_NOFOLLOW on both the tmp open AND
        # the rename target so a symlink at either path is refused. 0o600 so
        # only the target user can read the secret.
        flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC | getattr(os, "O_NOFOLLOW", 0)
        tmp = config_file.with_suffix(config_file.suffix + ".tmp")
        if tmp.exists():
            try:
                tmp.unlink()
            except OSError:
                pass
        fd = os.open(str(tmp), flags, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(json.dumps(config, indent=2))
        os.replace(str(tmp), str(config_file))
        # os.replace preserves the source's mode, but be defensive in case the
        # rename target pre-existed with a wider mode and somehow survives.
        if platform.system().lower() != "windows":
            try:
                os.chmod(config_file, 0o600)
            except OSError:
                pass
        return True
    except Exception as e:
        debug_print(f"per-user config write failed in {home_dir}: {e}")
        return False


def install_for_user_payload(home_dir: Path, gateway_url: str, backend_url: str, api_key: str, script_templates: Dict[str, bytes]) -> bool:
    """Body of the per-user install. Runs inside the privilege-dropped fork.
    Arguments are inherited from the parent via copy-on-write (os.fork), so
    script bytes are passed by value (we already read them as root before
    dropping). Only the return value is pickled back to the parent over the
    write end of the pipe.

    Order matters: write ~/.unbound/config.json BEFORE settings.json so a
    settings.json failure never leaves the user with an entry-point hook
    that can't authenticate (which would fail-open every call)."""
    try:
        antigravity_dir = home_dir / ".antigravity"
        hooks_dir = antigravity_dir / "hooks"
        settings_path = antigravity_dir / "settings.json"

        antigravity_dir.mkdir(parents=True, exist_ok=True)
        hooks_dir.mkdir(parents=True, exist_ok=True)

        # 0. Write the credentials file FIRST. Hook scripts read this at
        # runtime via _common.py::load_credentials; without it the PreToolUse
        # gate silently fail-opens on every call.
        if not _write_unbound_config_payload(home_dir, api_key, gateway_url, backend_url):
            return False

        # 1. Write the shared helper, with the gateway URL baked in.
        common_bytes = script_templates["_common.py"]
        common_text = common_bytes.decode("utf-8")
        if gateway_url and gateway_url != DEFAULT_GATEWAY_URL:
            common_text = common_text.replace(
                f'"{DEFAULT_GATEWAY_URL}"', f'"{gateway_url}"'
            )
        common_dest = hooks_dir / "_common.py"
        flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC | getattr(os, "O_NOFOLLOW", 0)
        fd = os.open(str(common_dest), flags, 0o644)
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(common_text)

        # 2. Write the four event scripts.
        for _event, installed_name in HOOK_EVENT_SCRIPTS:
            src_name = installed_name.replace("unbound_", "", 1)
            script_bytes = script_templates[src_name]
            dest = hooks_dir / installed_name
            fd = os.open(str(dest), flags, 0o755)
            with os.fdopen(fd, "wb") as f:
                f.write(script_bytes)

        # 3. Non-destructive settings.json merge.
        if settings_path.exists():
            try:
                # O_NOFOLLOW so an attacker-planted symlink at this path can't
                # redirect our read (and the subsequent write) to a file outside
                # the user's home. Matches the write side and the script-write
                # loop above.
                read_flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
                fd = os.open(str(settings_path), read_flags)
                with os.fdopen(fd, "r", encoding="utf-8") as f:
                    settings = json.load(f)
                if not isinstance(settings, dict):
                    return False
            except (json.JSONDecodeError, OSError):
                return False
        else:
            settings = {}

        if "hooks" not in settings or not isinstance(settings["hooks"], dict):
            settings["hooks"] = {}

        for event, installed_name in HOOK_EVENT_SCRIPTS:
            script_path = hooks_dir / installed_name
            our_entry = _build_event_entry(event, script_path)
            our_command = our_entry["hooks"][0]["command"]
            existing = settings["hooks"].get(event)
            if not isinstance(existing, list):
                settings["hooks"][event] = [our_entry]
                continue
            already_present = False
            for item in existing:
                if not isinstance(item, dict):
                    continue
                hooks_list = item.get("hooks", [])
                if not isinstance(hooks_list, list):
                    continue
                for h in hooks_list:
                    if isinstance(h, dict) and h.get("command") == our_command:
                        already_present = True
                        break
                if already_present:
                    break
            if not already_present:
                existing.append(our_entry)

        _atomic_write_json(settings_path, settings)
        return True
    except Exception as e:
        debug_print(f"per-user install failed in {home_dir}: {e}")
        return False


def clear_for_user_payload(home_dir: Path) -> str:
    """Body of the per-user clear. Mirrors install_for_user_payload. Returns
    "cleared" | "not_found" | "failed"."""
    try:
        antigravity_dir = home_dir / ".antigravity"
        hooks_dir = antigravity_dir / "hooks"
        settings_path = antigravity_dir / "settings.json"
        install_prefix = str(hooks_dir)
        is_windows = platform.system().lower() == "windows"

        any_cleared = False
        any_failed = False

        # 1. Remove our hook entries from settings.json.
        if settings_path.exists():
            try:
                with open(settings_path, "r", encoding="utf-8") as f:
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
                            if not isinstance(item, dict):
                                new_event_config.append(item)
                                continue
                            hooks_list = item.get("hooks", [])
                            if not isinstance(hooks_list, list):
                                new_event_config.append(item)
                                continue
                            new_hooks = [
                                h for h in hooks_list
                                if not (
                                    isinstance(h, dict)
                                    and _is_our_hook_command(
                                        h.get("command", ""), install_prefix, is_windows,
                                    )
                                )
                            ]
                            if len(new_hooks) == len(hooks_list):
                                new_event_config.append(item)
                                continue
                            modified = True
                            if new_hooks:
                                item["hooks"] = new_hooks
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
                        _atomic_write_json(settings_path, settings)
                        any_cleared = True
            except (json.JSONDecodeError, OSError) as e:
                debug_print(f"Failed to clean {settings_path}: {e}")
                any_failed = True

        # 2. Delete the installed scripts.
        if hooks_dir.exists():
            for _event, installed_name in HOOK_EVENT_SCRIPTS:
                p = hooks_dir / installed_name
                if p.exists():
                    try:
                        p.unlink()
                        any_cleared = True
                    except OSError:
                        any_failed = True
            common = hooks_dir / "_common.py"
            if common.exists():
                try:
                    common.unlink()
                    any_cleared = True
                except OSError:
                    any_failed = True
            # Best-effort: drop the hooks dir if empty.
            try:
                if not any(hooks_dir.iterdir()):
                    hooks_dir.rmdir()
            except OSError:
                pass

        if any_cleared:
            return "cleared"
        if any_failed:
            return "failed"
        return "not_found"
    except Exception as e:
        debug_print(f"per-user clear failed in {home_dir}: {e}")
        return "failed"


# -----------------------------------------------------------------------------
# Policy marker (idempotency)
# -----------------------------------------------------------------------------

def write_policy_marker(api_key_present: bool, device_id: Optional[str]) -> None:
    marker = get_policy_marker_path()
    payload = {
        "tool_type": UNBOUND_APP_LABEL,
        "api_key_set": bool(api_key_present),
        "device_id": device_id or "",
    }
    try:
        marker.parent.mkdir(parents=True, exist_ok=True)
        _atomic_write_json(marker, payload)
        debug_print(f"Wrote policy marker {marker}")
    except OSError as e:
        debug_print(f"Could not write policy marker {marker}: {e}")


def remove_policy_marker() -> None:
    marker = get_policy_marker_path()
    if marker.exists():
        try:
            marker.unlink()
            debug_print(f"Removed policy marker {marker}")
        except OSError as e:
            debug_print(f"Could not remove policy marker {marker}: {e}")


def notify_setup_complete(api_key: str, backend_url: str, device_id: Optional[str]) -> None:
    # Use stdlib urllib so the API key never appears on the curl argv —
    # see fetch_api_key_from_mdm above for the same reason.
    try:
        url = f"{backend_url.rstrip('/')}/api/v1/setup/complete/"
        body: Dict = {"tool_type": UNBOUND_APP_LABEL}
        if device_id:
            body["serial_number"] = device_id
        data = json.dumps(body).encode("utf-8")
        req = urllib.request.Request(
            url,
            data=data,
            method="POST",
            headers={
                "X-API-KEY": api_key,
                "Content-Type": "application/json",
            },
        )
        try:
            with urllib.request.urlopen(req, timeout=10):
                pass
        except urllib.error.HTTPError as e:
            debug_print(f"Setup-complete returned HTTP {e.code}")
        debug_print("Setup completion notification sent")
    except Exception as e:
        debug_print(f"Could not notify backend: {e}")


# -----------------------------------------------------------------------------
# Top-level orchestration
# -----------------------------------------------------------------------------

def run_install(api_key: str, gateway_url: str, backend_url: str, device_id: Optional[str]) -> None:
    user_homes = get_all_user_homes()
    if not user_homes:
        print("No user home directories found")
        return

    print(f"\nInstalling hooks for {len(user_homes)} user(s)...")

    # Read all script templates once as root, before any privilege drop.
    templates: Dict[str, bytes] = {}
    needed = ["_common.py"] + [name.replace("unbound_", "", 1) for _e, name in HOOK_EVENT_SCRIPTS]
    for filename in needed:
        data = _read_script_template(filename)
        if data is None:
            print(f"Failed to read hook script template {filename}")
            return
        templates[filename] = data

    success_count = 0
    for username, home_dir in user_homes:
        ok = _run_as_user(
            username, install_for_user_payload,
            home_dir, gateway_url, backend_url, api_key, templates,
        )
        if ok:
            success_count += 1
            debug_print(f"Installed for {username}")
        else:
            print(f"Failed to install for {username}")

    if success_count > 0:
        print(f"Installed for {success_count} user(s)")
        write_policy_marker(api_key_present=True, device_id=device_id)
        notify_setup_complete(api_key, backend_url, device_id)
    else:
        print("Install failed for all users")


def run_clear() -> None:
    print("\nClearing Antigravity hooks for all users...")
    user_homes = get_all_user_homes()
    if not user_homes:
        print("No user home directories found")

    cleared = 0
    not_found = 0
    failed = 0
    for username, home_dir in user_homes:
        status = _run_as_user(username, clear_for_user_payload, home_dir)
        if status == "cleared":
            cleared += 1
        elif status == "not_found":
            not_found += 1
        else:
            failed += 1

    if cleared:
        print(f"Cleared for {cleared} user(s)")
    if not_found:
        print(f"Not installed for {not_found} user(s)")
    if failed:
        print(f"Failed to clear for {failed} user(s)")

    remove_policy_marker()


def _arg_value(name: str, argv: List[str]) -> Optional[str]:
    for i, arg in enumerate(argv):
        if arg == name and i + 1 < len(argv):
            return argv[i + 1]
    return None


def main() -> None:
    argv = sys.argv[1:]
    clear_mode = "--clear" in argv

    print("=" * 60)
    print("Antigravity Hooks - MDM Setup")
    print("=" * 60)

    if not check_admin_privileges():
        if platform.system().lower() == "windows":
            sys.exit(
                "Error: MDM setup requires an elevated shell on Windows. "
                "Right-click PowerShell -> Run as Administrator, then rerun."
            )
        print("This script requires administrator/root privileges")
        print("   Please re-run with sudo.")
        sys.exit(1)

    if clear_mode:
        run_clear()
        print("\n" + "=" * 60)
        print("Clear Complete!")
        print("=" * 60)
        return

    backend_url = normalize_url(_arg_value("--backend-url", argv) or DEFAULT_BACKEND_URL)
    gateway_url = normalize_url(_arg_value("--gateway-url", argv) or DEFAULT_GATEWAY_URL)
    app_name = _arg_value("--app_name", argv)
    auth_api_key = _arg_value("--api-key", argv)

    if not auth_api_key:
        print("\nMissing required argument: --api-key")
        print("Usage: sudo python3 setup.py --api-key <api_key> [--backend-url <url>] "
              "[--gateway-url <url>] [--app_name <app_name>] [--debug] [--backfill]")
        print("   Or: sudo python3 setup.py --clear [--debug]")
        sys.exit(1)

    print("\nGetting device identifier...")
    device_id = get_device_identifier()
    if not device_id:
        print("Failed to get device identifier")
        sys.exit(1)
    debug_print(f"Device identifier: {device_id}")

    print("\nFetching API key from MDM...")
    api_key = fetch_api_key_from_mdm(backend_url, app_name, auth_api_key, device_id)
    if not api_key:
        sys.exit(1)
    print("API key received")

    run_install(api_key, gateway_url, backend_url, device_id)

    print("\n" + "=" * 60)
    print("Setup Complete!")
    print("=" * 60)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\nSetup cancelled.")
    except Exception as e:
        print(f"\nError: {e}")
        sys.exit(1)
