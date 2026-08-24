#!/usr/bin/env python3
"""
Claude Code - Environment Setup Script
"""

import os
import shlex
import sys
import platform
import subprocess
import urllib.request
import urllib.error
import urllib.parse
import json
from pathlib import Path
from typing import Tuple, Optional, Dict
import argparse
import threading
import http.server
import socketserver
import socket
import webbrowser


DEBUG = False


def debug_print(message: str) -> None:
    """Print message only if DEBUG mode is enabled."""
    if DEBUG:
        print(f"[DEBUG] {message}")


def normalize_url(domain: str) -> str:
    """Normalize domain to proper URL format."""
    domain = domain.strip()

    if domain.startswith("http://") or domain.startswith("https://"):
        url = domain
    else:
        url = f"https://{domain}"

    return url.rstrip('/')

def get_shell_rc_file() -> Path:
    """
    Determine the appropriate shell configuration file based on the OS and shell.
    
    Returns:
        Path: Path to the shell configuration file
    """
    system = platform.system().lower()
    shell = os.environ.get("SHELL", "").lower()
    
    if system == "darwin":
        # macOS - default shell is zsh
        if "zsh" in shell:
            return Path.home() / ".zprofile"
        else:
            return Path.home() / ".bash_profile"
    
    elif system == "linux":
        # Linux
        if "zsh" in shell:
            return Path.home() / ".zshrc"
        else:
            return Path.home() / ".bashrc"
    
    elif system == "windows":
        # Windows - uses registry, no rc file
        return None
    
    else:
        raise OSError(f"Unsupported operating system: {system}")


def append_to_file(file_path: Path, line: str) -> bool:
    """
    Append a line to a file only if it's not already present.
    
    Args:
        file_path: Path to the file to append to
        line: Line to append (without newline)
    
    Returns:
        bool: True if line was added, False if it already existed
    """
    try:
        file_path.touch(exist_ok=True)
        
        with open(file_path, "r", encoding="utf-8") as f:
            content = f.read()
        
        if line not in content:
            with open(file_path, "a", encoding="utf-8") as f:
                f.write(f"{line}\n")
            return True
        else:
            return False
    except Exception as e:
        print(f"❌ Failed to modify {file_path}: {e}")
        return False


def set_env_var_on_windows(var_name: str, value: str) -> bool:
    """
    Set environment variable permanently on Windows using setx.

    Args:
        var_name: Name of the environment variable
        value: Value to set

    Returns:
        bool: True if successful, False otherwise
    """
    debug_print(f"Writing to user environment registry (Windows)")
    try:
        subprocess.run(["setx", var_name, value], check=True, capture_output=True)
        return True
    except subprocess.CalledProcessError as e:
        print(f"❌ Failed to set {var_name} on Windows: {e}")
        if e.stderr:
            print(f"   Error details: {e.stderr.decode()}")
        return False
    except FileNotFoundError:
        print(f"❌ 'setx' command not found. Please set {var_name} manually.")
        return False


def set_env_var_on_unix(var_name: str, value: str) -> bool:
    """
    Set environment variable permanently on Unix-like systems (macOS, Linux).

    Args:
        var_name: Name of the environment variable
        value: Value to set

    Returns:
        bool: True if successful, False otherwise
    """
    rc_file = get_shell_rc_file()
    if rc_file is None:
        return False

    debug_print(f"Writing to shell file: {rc_file}")
    export_line = f'export {var_name}="{value}"'
    
    append_to_file(rc_file, export_line)

    try:
        return any(line.strip() == export_line for line in rc_file.read_text(encoding="utf-8").splitlines())
    except Exception:
        return False


def set_env_var(var_name: str, value: str) -> Tuple[bool, str]:
    """
    Set an environment variable permanently across all OS platforms.
    
    Args:
        var_name: Name of the environment variable
        value: Value to set
    
    Returns:
        Tuple[bool, str]: (success, message)
    """
    system = platform.system().lower()
    
    if system == "windows":
        success = set_env_var_on_windows(var_name, value)
        if success:
            return True, "Environment variable set for new terminals"
        else:
            return False, "Failed to set environment variable"
    
    elif system in ["darwin", "linux"]:
        success = set_env_var_on_unix(var_name, value)
        if success:
            shell_name = "zsh" if "zsh" in os.environ.get("SHELL", "") else "bash"
            return True, f"Run 'source ~/.{shell_name}rc' or restart terminal"
        else:
            return False, "Failed to set environment variable"
    
    else:
        return False, f"Unsupported OS: {system}"


def _registry_value(output: str, var_name: str):
    """The value `reg query` printed for var_name, or None when its output held no line
    for it. None is "could not tell", not "not ours" -- the caller reports failure rather
    than silently leaving our own value behind."""
    for line in (output or "").splitlines():
        parts = line.split(None, 2)
        if len(parts) >= 2 and parts[0].lower() == var_name.lower():
            return parts[2].strip() if len(parts) == 3 else ""
    return None


UNBOUND_GATEWAY_URL = "https://api.getunbound.ai"
UNBOUND_KEY_HELPER_BODY = "echo $UNBOUND_API_KEY"
UNBOUND_KEY_HELPER_SETTING = "~/.claude/anthropic_key.sh"


def _recorded_gateway_url() -> str:
    """The gateway URL this install recorded for the current user, or "". Read from the
    user's own config as that user -- it says which endpoint we pointed them at, so it
    can authorise removing their own export and nothing else."""
    try:
        text = (Path.home() / ".unbound" / "config.json").read_text(encoding="utf-8")
        config = json.loads(text)
    except (OSError, ValueError):
        return ""
    # A config that is not an object has no gateway to report; .get would raise, and this
    # runs on the install path where anything raising aborts the setup.
    if not isinstance(config, dict):
        return ""
    recorded = config.get("gateway_url")
    return recorded.strip().rstrip("/") if isinstance(recorded, str) else ""


def _is_unbound_base_url(value) -> bool:
    """Whether ANTHROPIC_BASE_URL holds the gateway this setup writes. Anything else is
    the customer's own endpoint and is left alone.

    Our default gateway, or the one this install recorded for this user. A URL that is
    neither is the customer's and stays: guessing wrong removes an endpoint they
    configured, which is the failure this check exists to prevent."""
    if not isinstance(value, str):
        return False
    candidate = value.strip().rstrip("/")
    if candidate == UNBOUND_GATEWAY_URL:
        return True
    recorded = _recorded_gateway_url()
    return bool(recorded) and candidate == recorded


def _export_value(line: str, prefix: str) -> str:
    return line.strip()[len(prefix):].strip().strip('"').strip("'")


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


def _is_unbound_hook_command(command) -> bool:
    """Whether a settings.json hook entry runs the Unbound hook. The hooks installer
    writes the interpreter, quoting and separators of the platform it ran on, so the
    command is tokenised and the path compared rather than matched as a substring."""
    return isinstance(command, str) and _command_targets_hook(
        command, Path.home() / ".claude" / "hooks" / "unbound.py")


def _strip_unbound_hooks(settings: dict) -> None:
    """Drop the Unbound entries from settings["hooks"], leaving every other hook in place
    and removing only the groups and the block our entries emptied."""
    hooks = settings.get("hooks")
    if not isinstance(hooks, dict):
        return
    for event, groups in list(hooks.items()):
        if not isinstance(groups, list):
            continue
        kept_groups = []
        for group in groups:
            if not isinstance(group, dict):
                kept_groups.append(group)
                continue
            entries = group.get("hooks")
            if not isinstance(entries, list):
                kept_groups.append(group)
                continue
            kept = [e for e in entries
                    if not (isinstance(e, dict) and _is_unbound_hook_command(e.get("command")))]
            if not kept:
                continue
            group["hooks"] = kept
            kept_groups.append(group)
        if kept_groups:
            hooks[event] = kept_groups
        else:
            del hooks[event]
    if not hooks:
        del settings["hooks"]


def _is_unbound_key_helper_setting(value) -> bool:
    """Whether settings.json's apiKeyHelper is the one this setup writes. The expanded
    form counts too: the setup writes the ~ form, but a device may already carry the
    expanded one."""
    if not isinstance(value, str):
        return False
    candidate = value.strip()
    if candidate not in (UNBOUND_KEY_HELPER_SETTING,
                         str(Path.home() / ".claude" / "anthropic_key.sh")):
        return False
    # The path is a name anyone could choose, so the script there decides. Nothing there
    # means our own removal already ran; a dangling helper is broken either way.
    path = Path.home() / ".claude" / "anthropic_key.sh"
    return not path.exists() or _is_unbound_key_helper_file(path)


def _is_unbound_key_helper_file(path: Path) -> bool:
    """Whether an anthropic_key.sh is the one this setup writes. The compare is exact
    against the body the gateway writer emits, apart from surrounding whitespace, so a
    CRLF or a trailing newline still matches but a script with a shebang or an extra line
    is somebody else's."""
    try:
        return path.read_text(encoding="utf-8").strip() == UNBOUND_KEY_HELPER_BODY
    except (OSError, ValueError):
        return False


def remove_env_var_on_unix(var_name: str, only_if=None) -> str:
    """Remove an environment variable export line from the user's shell rc file.
    With only_if, removes just the exports whose value it accepts.

    Returns "cleared", "not_found", or "failed".
    """
    rc_file = get_shell_rc_file()
    if rc_file is None:
        return "failed"
    try:
        if not rc_file.exists():
            return "not_found"
        with open(rc_file, "r", encoding="utf-8") as f:
            lines = f.readlines()
        new_lines = []
        removed = False
        export_prefix = f"export {var_name}="
        for line in lines:
            if line.strip().startswith(export_prefix):
                if only_if is not None and not only_if(_export_value(line, export_prefix)):
                    new_lines.append(line)
                    continue
                removed = True
                debug_print(f"Removing {var_name} from {rc_file}")
                continue
            new_lines.append(line)
        if removed:
            with open(rc_file, "w", encoding="utf-8") as f:
                f.writelines(new_lines)
            return "cleared"
        return "not_found"
    except Exception as e:
        print(f"Failed to modify {rc_file}: {e}")
        return "failed"


def remove_env_var_on_windows(var_name: str, only_if=None) -> str:
    """Remove a user environment variable on Windows.

    Returns "cleared", "not_found", or "failed".
    """
    try:
        query = subprocess.run(
            ["reg", "query", "HKCU\\Environment", "/V", var_name],
            capture_output=True, text=True,
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
            ["reg", "delete", "HKCU\\Environment", "/F", "/V", var_name],
            check=True,
            capture_output=True,
        )
        debug_print(f"Removed {var_name} from Windows registry")
        return "cleared"
    except subprocess.CalledProcessError:
        return "failed"
    except FileNotFoundError:
        print("'reg' command not found. Please remove the variable manually.")
        return "failed"


def remove_env_var(var_name: str, only_if=None) -> Tuple[str, str]:
    """Remove an environment variable permanently across OS platforms.

    Returns (status, message) where status is "cleared", "not_found", "failed",
    or "unsupported".
    """
    system = platform.system().lower()
    if system == "windows":
        return remove_env_var_on_windows(var_name, only_if), ""
    elif system in ["darwin", "linux"]:
        return remove_env_var_on_unix(var_name, only_if), ""
    else:
        return "unsupported", f"Unsupported OS: {system}"


def write_unbound_config(api_key: str, urls: dict = None) -> bool:
    """Write API key to ~/.unbound/config.json (shared with unbound-cli)."""
    config_dir = Path.home() / ".unbound"
    config_file = config_dir / "config.json"
    try:
        config_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
        os.chmod(config_dir, 0o700)
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
        fd = os.open(str(config_file), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, 'w', encoding='utf-8') as f:
            f.write(json.dumps(config, indent=2))
        return True
    except Exception as e:
        print(f"⚠️  Could not write config: {e}")
        return False


def _resolve_claude_config_dir(config_dir_arg: Optional[str] = None) -> Path:
    """Resolve Claude Code's config dir: $CLAUDE_CONFIG_DIR (env wins), else the
    --config-dir arg the CLI forwards, else the default ~/.claude."""
    value = (os.environ.get("CLAUDE_CONFIG_DIR") or "").strip() or None
    if not value and config_dir_arg:
        value = config_dir_arg.strip() or None
    if not value:
        return Path.home() / ".claude"
    # Verbatim, as Claude Code reads it: a literal "~" must not be expanded.
    return Path(os.path.abspath(value))


def remove_hooks_unbound_script(config_dir: Path = None) -> None:
    """Remove <config_dir>/hooks/unbound.py if present (leftover from hooks setup)."""
    config_dir = config_dir or (Path.home() / ".claude")
    script_path = config_dir / "hooks" / "unbound.py"
    if script_path.exists():
        try:
            script_path.unlink()
            debug_print(f"Removed {script_path}")
        except Exception as e:
            debug_print(f"Failed to remove {script_path}: {e}")


def setup_claude_key_helper(config_dir: Path = None) -> bool:
    """
    Create <config_dir>/anthropic_key.sh that echoes UNBOUND_API_KEY and
    update <config_dir>/settings.json with apiKeyHelper pointing to that script.
    """
    claude_dir = config_dir or (Path.home() / ".claude")
    settings_path = claude_dir / "settings.json"
    key_helper_path = claude_dir / "anthropic_key.sh"

    try:
        claude_dir.mkdir(parents=True, exist_ok=True)

        # Write anthropic_key.sh
        # This body is what identifies the script as ours at removal time.
        key_helper_path.write_text("echo $UNBOUND_API_KEY", encoding="utf-8")
        try:
            current_mode = key_helper_path.stat().st_mode
            os.chmod(key_helper_path, current_mode | 0o111)
        except Exception:
            pass

        # Read existing settings.json if present
        settings: Dict[str, any] = {}
        if settings_path.exists():
            try:
                settings = json.loads(settings_path.read_text(encoding="utf-8")) or {}
            except Exception:
                settings = {}

        # Our hook and the gateway cannot both drive Claude Code, so ours goes before
        # apiKeyHelper is added. Only ours: a hook the user installed is not ours to drop.
        _strip_unbound_hooks(settings)

        if claude_dir.resolve() == (Path.home() / ".claude").resolve():
            settings["apiKeyHelper"] = "~/.claude/anthropic_key.sh"
        else:
            settings["apiKeyHelper"] = str(key_helper_path)

        settings_path.write_text(json.dumps(settings, indent=2), encoding="utf-8")
        return True
    except Exception as e:
        print(f"❌ Failed to configure Claude Code key helper: {e}")
        return False


def run_one_shot_callback_server(frontend_url: str) -> Optional[Dict[str, any]]:
    """
    Start a local HTTP server that waits for a single callback request and returns its contents.
    Returns a dict with method, path, query, headers, and body; or None on failure.
    """
    result: Dict[str, any] = {"method": None, "path": None, "query": None, "headers": None, "body": None}
    done_evt = threading.Event()

    class CallbackHandler(http.server.BaseHTTPRequestHandler):
        def _finish(self, code: int = 200, message: bytes = b"Logged in successfully! You can close this tab and return to the terminal.") -> None:
            try:
                self.send_response(code)
                self.send_header("Content-Type", "text/plain; charset=utf-8")
                self.send_header("Content-Length", str(len(message)))
                self.end_headers()
                self.wfile.write(message)
            except Exception:
                pass

        def do_GET(self) -> None:
            parsed = urllib.parse.urlparse(self.path)
            result["method"] = "GET"
            result["path"] = self.path
            result["query"] = dict(urllib.parse.parse_qsl(parsed.query))
            result["headers"] = {k: v for k, v in self.headers.items()}
            result["body"] = None
            self._finish()
            done_evt.set()

        def do_POST(self) -> None:
            length = int(self.headers.get("Content-Length", "0") or 0)
            body = self.rfile.read(length) if length > 0 else b""
            parsed = urllib.parse.urlparse(self.path)
            result["method"] = "POST"
            result["path"] = self.path
            result["query"] = dict(urllib.parse.parse_qsl(parsed.query))
            result["headers"] = {k: v for k, v in self.headers.items()}
            result["body"] = body.decode("utf-8", errors="replace") if body else None
            self._finish()
            done_evt.set()

        def log_message(self, format: str, *args) -> None:
            return

    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.bind(("127.0.0.1", 0))
            host, port = s.getsockname()
        callback_url = f"http://127.0.0.1:{port}/callback"

        httpd = socketserver.TCPServer(("127.0.0.1", port), CallbackHandler)
        httpd.allow_reuse_address = True

        thread = threading.Thread(target=httpd.serve_forever, daemon=True)
        thread.start()

        encoded_callback = urllib.parse.quote(callback_url, safe="")
        target_url = f"{frontend_url.rstrip('/')}/automations/api-key-callback?callback_url={encoded_callback}&app_type=default"
        webbrowser.open(target_url)
        print("🌐 Opening browser...")
        print("If browser doesn't open automatically, open this link:")
        print(target_url)
        print("Waiting for authentication...")

        try:
            done_evt.wait()
        finally:
            try:
                httpd.shutdown()
                httpd.server_close()
            except Exception:
                pass

        return result
    except Exception as e:
        print(f"❌ Failed to run callback server: {e}")
        return None



def _clear_path(path: Path, label: str) -> str:
    if not path.exists():
        return "not_found"
    try:
        path.unlink()
        debug_print(f"Removed {path}")
        return "cleared"
    except Exception as e:
        print(f"Failed to clear {label}: {e}")
        return "failed"


def remove_api_key_helper_setting(config_dir: Path = None) -> str:
    """Remove apiKeyHelper from settings.json.

    Returns "cleared", "not_found", or "failed".
    """
    config_dir = config_dir or (Path.home() / ".claude")
    settings_path = config_dir / "settings.json"
    if not settings_path.exists():
        return "not_found"
    try:
        with open(settings_path, "r", encoding="utf-8") as f:
            settings = json.load(f)
        if not _is_unbound_key_helper_setting(settings.get("apiKeyHelper")):
            return "not_found"
        del settings["apiKeyHelper"]
        with open(settings_path, "w", encoding="utf-8") as f:
            json.dump(settings, f, indent=2)
        debug_print("Removed apiKeyHelper from settings.json")
        return "cleared"
    except Exception as e:
        print(f"Failed to update settings.json: {e}")
        return "failed"


def clear_setup(config_dir: Path = None) -> bool:
    """Undo all changes made by the setup script."""
    config_dir = config_dir or (Path.home() / ".claude")
    print("=" * 60)
    print("Claude Code - Clearing Setup")
    print("=" * 60)

    any_cleared = False
    any_failed = False

    for var, label in {"UNBOUND_API_KEY": "API_KEY", "ANTHROPIC_BASE_URL": "BASE_URL"}.items():
        # ANTHROPIC_BASE_URL goes only when it holds our gateway.
        status, _ = remove_env_var(
            var, _is_unbound_base_url if var == "ANTHROPIC_BASE_URL" else None)
        if status == "cleared":
            any_cleared = True
        elif status not in ("cleared", "not_found"):
            print(f"Failed to clear {label}")
            any_failed = True

    key_helper = config_dir / "anthropic_key.sh"
    _r = (_clear_path(key_helper, "Claude anthropic_key.sh")
          if _is_unbound_key_helper_file(key_helper) else "not_found")
    if _r == "cleared":
        any_cleared = True
    elif _r == "failed":
        any_failed = True

    settings_status = remove_api_key_helper_setting(config_dir)
    if settings_status == "cleared":
        any_cleared = True
    elif settings_status == "failed":
        print("Failed to clear apiKeyHelper in settings.json")
        any_failed = True

    # When the config dir was relocated, also strip enforcement left behind in the
    # default ~/.claude so clearing leaves nothing that fires if Claude later runs
    # without CLAUDE_CONFIG_DIR set.
    default_dir = Path.home() / ".claude"
    if config_dir.resolve() != default_dir.resolve():
        if _clear_path(default_dir / "anthropic_key.sh", "Claude anthropic_key.sh (~/.claude)") == "cleared":
            any_cleared = True
        if remove_api_key_helper_setting(default_dir) == "cleared":
            any_cleared = True

    if any_cleared:
        print("Cleared")
    elif not any_failed:
        print("API_KEY not set, nothing to clear")

    print("\n" + "=" * 60)
    print("Clear Complete!")
    print("=" * 60)

    return not any_failed


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


def detect_install_state(config_dir: Path = None) -> str:
    """User-level install state (informational): 'persisted' if this tool's
    Unbound setup already exists on this device, else 'fresh'. User-level setups
    are never tamper-eligible, so 'tampered' is never reported."""
    config_dir = config_dir or (Path.home() / ".claude")
    try:
        return "persisted" if (config_dir / "anthropic_key.sh").exists() else "fresh"
    except Exception as e:
        debug_print(f"detect_install_state failed: {e}")
        return "fresh"


def get_managed_settings_dir() -> Path:
    """System-wide managed (MDM) settings directory for Claude Code. Mirrors the
    path the MDM setup writes to; keep this in sync with mdm/setup.py."""
    system = platform.system().lower()
    if system == "darwin":
        return Path("/Library/Application Support/ClaudeCode")
    elif system == "linux":
        return Path("/etc/claude-code")
    elif system == "windows":
        program_files = os.environ.get("ProgramFiles", r"C:\Program Files")
        return Path(program_files) / "ClaudeCode"
    raise OSError(f"Unsupported operating system: {system}")


def check_enterprise_hooks_conflict() -> bool:
    """True if an Unbound MDM (managed) setup already exists for Claude Code on
    this device. User-level setup must not run alongside it — the managed config
    already enforces Unbound for every user, so a second user-level install would
    make every hook fire twice. Read-only; fails open (False) on any error."""
    try:
        managed_dir = get_managed_settings_dir()
        markers = [
            managed_dir / "hooks" / "unbound.py",
            managed_dir / "anthropic_key.sh",
            managed_dir / "managed-settings.d" / "unbound.json",
        ]
        return any(marker.exists() for marker in markers)
    except Exception as e:
        print(f"Warning: could not check for an MDM install ({e!r}); continuing with user-level setup.")
        return False


def notify_setup_complete(api_key: str, tool_type: str, backend_url: str = "https://backend.getunbound.ai", install_state: Optional[str] = None, serial_number: Optional[str] = None):
    """Notify backend that tool setup completed. Never fails the setup."""
    try:
        url = f"{backend_url.rstrip('/')}/api/v1/setup/complete/"
        body = {"tool_type": tool_type}
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
    """Main setup function."""
    global DEBUG

    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("--domain", dest="domain", help="Base frontend URL (e.g., gateway.getunbound.ai)")
    parser.add_argument("--backend-url", dest="backend_url", default="https://backend.getunbound.ai", help="Override backend URL for local/staging testing (default: https://backend.getunbound.ai)")
    parser.add_argument("--gateway-url", dest="gateway_url", default="https://api.getunbound.ai", help="Override AI gateway URL written to ANTHROPIC_BASE_URL (default: https://api.getunbound.ai)")
    parser.add_argument("--clear", action="store_true", help="Undo all changes made by the setup script")
    parser.add_argument("--debug", action="store_true", help="Show detailed debug information")
    parser.add_argument("--api-key", dest="api_key", help="API key (skip browser auth)")
    parser.add_argument("--config-dir", dest="config_dir", help="Claude Code config dir (defaults to $CLAUDE_CONFIG_DIR or ~/.claude)")
    args, _ = parser.parse_known_args()
    args.gateway_url = normalize_url(args.gateway_url)
    args.backend_url = normalize_url(args.backend_url)

    config_dir = _resolve_claude_config_dir(args.config_dir)
    # Claude Code resolves CLAUDE_CONFIG_DIR against the current directory when it
    # is set but empty, instead of falling back to ~/.claude, so installing to the
    # default would be invisible to it.
    _raw_cfg = os.environ.get("CLAUDE_CONFIG_DIR")
    if _raw_cfg is not None and not _raw_cfg.strip():
        print("\n\u26a0\ufe0f  CLAUDE_CONFIG_DIR is set but empty. Claude Code reads that as a path "
              "relative to the current directory, not as ~/.claude, so it will not load this "
              "install. Unset the variable, or point it at a real directory.")

    if args.debug:
        DEBUG = True
        debug_print("Debug mode enabled")

    if args.clear:
        return clear_setup(config_dir)

    if check_enterprise_hooks_conflict():
        print("\n❌ Skipped — Claude Code is managed by your organization (MDM).")
        raise SystemExit(3)

    print("=" * 60)
    print("Claude Code - Environment Setup")
    print("=" * 60)

    # Flush previously set environment variables at start (including hooks setup var).
    # ANTHROPIC_BASE_URL is unconditional here and deliberately so: gateway mode exists to
    # route Claude Code through us and sets this variable to our gateway a few lines
    # below, so whatever it held is being replaced either way. Every other place that
    # removes it is a teardown, and those take it only when it is ours.
    for var_name in [
        "ANTHROPIC_BASE_URL",
        "UNBOUND_API_KEY",
        "UNBOUND_CLAUDE_API_KEY",
    ]:
        try:
            remove_env_var(var_name)
        except Exception:
            pass

    # Remove leftover hooks setup artifacts
    remove_hooks_unbound_script(config_dir)

    api_key = args.api_key
    if not api_key:
        if not args.domain:
            print("\n❌ Missing required argument: --domain or --api-key")
            return False

        auth_url = normalize_url(args.domain)
        cb_response = run_one_shot_callback_server(auth_url)
        if cb_response is None:
            print("\n❌ Failed to receive callback response. Exiting.")
            return False

        try:
            api_key = (cb_response.get("query") or {}).get("api_key")
        except Exception:
            api_key = None

        if not api_key:
            print("\n❌ No api_key found in callback. Exiting.")
            return False

    print("API Key Verified ✅")
    debug_print("API key verification successful")

    # Record the endpoint before anything is written to the machine. Clearing this setup
    # identifies a non-default gateway by the URL recorded here, so installing first and
    # failing to record would leave a route teardown cannot tell from the customer's own.
    # Nothing has been set at this point, so refusing here leaves the device untouched
    # rather than holding a key with no route to use it on.
    _config_written = write_unbound_config(api_key, urls={"base_url": args.backend_url, "gateway_url": args.gateway_url, "frontend_url": normalize_url(args.domain) if args.domain else None})
    if not _config_written and args.gateway_url != UNBOUND_GATEWAY_URL:
        print(f"❌ Could not record the gateway URL in {Path.home() / '.unbound' / 'config.json'}.")
        print(f"   Nothing was installed: clearing this setup could not have removed "
              f"ANTHROPIC_BASE_URL={args.gateway_url} afterwards.")
        return False

    debug_print("Setting UNBOUND_API_KEY environment variable...")
    success, message = set_env_var("UNBOUND_API_KEY", api_key)
    if not success:
        print(f"❌ Failed to configure UNBOUND_API_KEY: {message}")
        return False
    debug_print("UNBOUND_API_KEY set successfully")

    debug_print("Setting ANTHROPIC_BASE_URL environment variable...")
    success, message = set_env_var("ANTHROPIC_BASE_URL", args.gateway_url)
    if not success:
        print(f"❌ Failed to configure ANTHROPIC_BASE_URL: {message}")
        return False
    debug_print("ANTHROPIC_BASE_URL set successfully")

    _install_state = detect_install_state(config_dir)
    _device_id = get_device_identifier()

    # Configure Claude Code helper files
    debug_print("Setting up Claude key helper...")
    if not setup_claude_key_helper(config_dir):
        return False
    debug_print("Claude key helper configured")
    
    # Final instructions
    print("\n" + "=" * 60)
    print("Setup Complete!")
    print("=" * 60)

    notify_setup_complete(api_key, "unbound-claude-code", backend_url=args.backend_url, install_state=_install_state, serial_number=_device_id)

    rc_path = get_shell_rc_file()
    if rc_path is not None:
        print(f"\nTo apply changes in your current terminal, run:\n  source {rc_path}\n\nOr open a new terminal.")

    return True

if __name__ == "__main__":
    try:
        ok = main()
    except KeyboardInterrupt:
        print("\n\n⚠️  Setup cancelled by user.")
        sys.exit(1)
    except Exception as e:
        print(f"\n❌ An error occurred: {e}")
        sys.exit(1)
    sys.exit(0 if ok else 1)
