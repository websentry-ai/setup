
#!/usr/bin/env python3

import os
import re
import shutil
import sys
import time
import platform
import subprocess
import urllib.parse
import webbrowser
from pathlib import Path
from typing import Tuple, Optional, Dict, List
import threading
import http.server
import socketserver
import socket
import json
import shlex


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

DEBUG = False


def debug_print(message: str) -> None:
    """Print message only if DEBUG mode is enabled."""
    if DEBUG:
        print(f"[DEBUG] {message}")


def install_macos_certificates():
    """Run Python certificate installation command on macOS."""
    if platform.system().lower() != "darwin":
        return
    py_version = f"{sys.version_info.major}.{sys.version_info.minor}"
    cert_path = f"/Applications/Python {py_version}/Install Certificates.command"
    if os.path.exists(cert_path):
        subprocess.run([cert_path], capture_output=True)


def normalize_url(domain: str) -> str:
    domain = domain.strip()

    if domain.startswith("http://") or domain.startswith("https://"):
        url = domain
    else:
        url = f"https://{domain}"

    return url.rstrip('/')


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

        if var_name and line not in [l.rstrip() for l in lines]:
            lines.append(f"{line}\n")
            with open(file_path, "w", encoding="utf-8") as f:
                f.writelines(lines)
            return True

        return True
    except Exception as e:
        print(f"Failed to modify {file_path}: {e}")
        return False


def set_env_var_windows(var_name: str, value: str) -> bool:
    debug_print(f"Writing to user environment registry (Windows)")
    try:
        subprocess.run(["setx", var_name, value], check=True, capture_output=True)
        return True
    except (subprocess.CalledProcessError, FileNotFoundError) as e:
        print(f"Failed to set {var_name} on Windows: {e}")
        return False


def set_env_var_unix(var_name: str, value: str) -> bool:
    rc_file = get_shell_rc_file()
    if rc_file is None:
        return False

    debug_print(f"Writing to shell file: {rc_file}")
    export_line = f'export {var_name}="{value}"'
    return append_to_file(rc_file, export_line, var_name)


def set_env_var(var_name: str, value: str) -> Tuple[bool, str]:
    system = platform.system().lower()

    if system == "windows":
        success = set_env_var_windows(var_name, value)
        return (True, "Set for new terminals") if success else (False, "Failed")
    elif system in ["darwin", "linux"]:
        success = set_env_var_unix(var_name, value)
        if success:
            shell_name = "zsh" if "zsh" in os.environ.get("SHELL", "") else "bash"
            return True, f"Run 'source ~/.{shell_name}rc' or restart terminal"
        return False, "Failed"
    else:
        return False, f"Unsupported OS: {system}"


def remove_env_var_on_unix(var_name: str) -> str:
    """Remove an environment variable export line from the user's shell rc file.

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


def remove_env_var_on_windows(var_name: str) -> str:
    """Remove a user environment variable on Windows.

    Returns "cleared", "not_found", or "failed".
    """
    try:
        query = subprocess.run(
            ["reg", "query", "HKCU\\Environment", "/V", var_name],
            capture_output=True,
        )
        if query.returncode != 0:
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


def remove_env_var(var_name: str) -> Tuple[str, str]:
    """Remove an environment variable permanently across OS platforms.

    Returns (status, message) where status is "cleared", "not_found", "failed",
    or "unsupported".
    """
    system = platform.system().lower()
    if system == "windows":
        return remove_env_var_on_windows(var_name), ""
    elif system in ["darwin", "linux"]:
        return remove_env_var_on_unix(var_name), ""
    else:
        return "unsupported", f"Unsupported OS: {system}"


def run_callback_server(frontend_url: str) -> Optional[Dict[str, any]]:
    result: Dict[str, any] = {"method": None, "path": None, "query": None, "headers": None, "body": None}
    done_evt = threading.Event()

    class CallbackHandler(http.server.BaseHTTPRequestHandler):
        def _finish(self, code: int = 200, message: bytes = b"Logged in successfully! You can close this tab.") -> None:
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
            query = result["query"]
            if "error" in query:
                self._finish(code=400, message=f"Setup failed: {query['error'][:200]}\nPlease try again or contact support.".encode())
            else:
                self._finish()
            done_evt.set()

        def log_message(self, format: str, *args) -> None:
            return

    class _CallbackServer(socketserver.TCPServer):
        allow_reuse_address = True

    try:
        httpd = _CallbackServer(("127.0.0.1", 0), CallbackHandler)
        port = httpd.server_address[1]
        callback_url = f"http://127.0.0.1:{port}/callback"

        thread = threading.Thread(target=httpd.serve_forever, daemon=True)
        thread.start()

        encoded_callback = urllib.parse.quote(callback_url, safe="")
        target_url = f"{frontend_url.rstrip('/')}/automations/api-key-callback?callback_url={encoded_callback}&app_type=codex"
        webbrowser.open(target_url)
        print("Opening browser...")
        print("If browser doesn't open automatically, open this link:")
        print(target_url)
        print("Waiting for authentication...")

        try:
            if not done_evt.wait(timeout=300):
                print("Timed out waiting for authentication (5 minutes). Please re-run setup.")
                return None
        finally:
            try:
                httpd.shutdown()
                httpd.server_close()
            except Exception:
                pass

        return result
    except Exception as e:
        print(f"Failed to run callback server: {e}")
        return None


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
        print(f"Could not write config: {e}")
        return False


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


def remove_gateway_artifacts() -> None:
    """Remove OPENAI_API_KEY env var and openai_base_url from ~/.codex/config.toml (leftover from gateway setup)."""
    # Remove OPENAI_API_KEY env var
    try:
        remove_env_var("OPENAI_API_KEY")
        debug_print("Removed OPENAI_API_KEY env var")
    except Exception as e:
        debug_print(f"Failed to remove OPENAI_API_KEY: {e}")

    # Remove openai_base_url from config.toml
    config_path = Path.home() / ".codex" / "config.toml"
    if config_path.exists():
        try:
            with open(config_path, 'r', encoding='utf-8') as f:
                lines = f.readlines()
            new_lines = [l for l in lines if not l.strip().startswith('openai_base_url')]
            if len(new_lines) != len(lines):
                with open(config_path, 'w', encoding='utf-8') as f:
                    f.writelines(new_lines)
                debug_print(f"Removed openai_base_url from {config_path}")
        except Exception as e:
            debug_print(f"Failed to update {config_path}: {e}")


def rewrite_gateway_url_in_file(path: Path, gateway_url: str) -> None:
    """Replace the hardcoded default gateway URL inside a downloaded unbound.py."""
    if not gateway_url or gateway_url == DEFAULT_GATEWAY_URL:
        return
    try:
        text = path.read_text(encoding="utf-8")
        new_text = text.replace(f'"{DEFAULT_GATEWAY_URL}"', f'"{gateway_url}"')
        if new_text != text:
            path.write_text(new_text, encoding="utf-8")
    except Exception:
        pass


def setup_hooks(gateway_url: str = DEFAULT_GATEWAY_URL):
    hooks_dir = Path.home() / ".codex" / "hooks"
    script_path = hooks_dir / "unbound.py"

    if not download_file(SCRIPT_URL, script_path):
        return False
    rewrite_gateway_url_in_file(script_path, gateway_url)

    try:
        current_mode = script_path.stat().st_mode
        os.chmod(script_path, current_mode | 0o111)
    except Exception:
        pass

    return True


def _command_targets_hook(command: str, target: Path) -> bool:
    if not command:
        return False
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


def configure_codex_hooks() -> bool:
    hooks_path = Path.home() / ".codex" / "hooks.json"

    try:
        if hooks_path.exists():
            with open(hooks_path, 'r', encoding='utf-8') as f:
                config = json.load(f)
        else:
            config = {}
            hooks_path.parent.mkdir(parents=True, exist_ok=True)

        script_path = Path.home() / ".codex" / "hooks" / "unbound.py"
        is_windows = platform.system().lower() == "windows"

        # On Windows, invoke via `py -3` (falling back to `python`) and quote
        # the path so spaces in C:\Users\<name>\ paths don't break parsing.
        if is_windows:
            launcher = "py -3" if shutil.which("py") else "python"
            hook_command = f'{launcher} "{script_path}"'
        else:
            hook_command = str(script_path)

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
                        existing_hooks = existing_item.get("hooks", [])
                        for hook in existing_hooks:
                            existing_cmd = hook.get("command", "")
                            if _command_targets_hook(existing_cmd, script_path):
                                our_hook_exists = True
                                break

                if not our_hook_exists:
                    config["hooks"][event].extend(new_config)
            else:
                config["hooks"][event] = new_config

        with open(hooks_path, 'w', encoding='utf-8') as f:
            json.dump(config, f, indent=2)

        return True

    except json.JSONDecodeError as e:
        print(f"Failed to parse existing hooks.json: {e}")
        print("   Please check your hooks.json file for syntax errors")
        return False
    except Exception as e:
        print(f"Failed to configure hooks: {e}")
        return False


def remove_hooks_from_config() -> str:
    """Remove the unbound hooks from hooks.json.

    Returns "cleared", "not_found", or "failed".
    """
    hooks_path = Path.home() / ".codex" / "hooks.json"
    script_path = Path.home() / ".codex" / "hooks" / "unbound.py"

    if not hooks_path.exists():
        return "not_found"

    def _is_unbound(cmd: str) -> bool:
        return _command_targets_hook(cmd, script_path)

    try:
        with open(hooks_path, 'r', encoding='utf-8') as f:
            config = json.load(f)

        if "hooks" not in config:
            return "not_found"

        modified = False
        for event in list(config["hooks"].keys()):
            event_config = config["hooks"][event]
            new_config = []
            for item in event_config:
                if isinstance(item, dict):
                    hooks = item.get("hooks", [])
                    new_hooks = [h for h in hooks if not _is_unbound(h.get("command", ""))]
                    if new_hooks != hooks:
                        modified = True
                        debug_print(f"Removed unbound hook from {event}")
                    if new_hooks:
                        item["hooks"] = new_hooks
                        new_config.append(item)
                else:
                    new_config.append(item)
            if new_config:
                config["hooks"][event] = new_config
            else:
                del config["hooks"][event]
                modified = True

        if not config["hooks"]:
            del config["hooks"]

        if modified:
            with open(hooks_path, 'w', encoding='utf-8') as f:
                json.dump(config, f, indent=2)
            return "cleared"
        return "not_found"
    except Exception as e:
        print(f"Failed to update hooks.json: {e}")
        return "failed"


def disable_codex_hooks_feature_status() -> str:
    """Remove the codex_hooks line from ~/.codex/config.toml.

    Returns "cleared", "not_found", or "failed".
    """
    config_path = Path.home() / ".codex" / "config.toml"
    if not config_path.exists():
        return "not_found"
    try:
        with open(config_path, 'r', encoding='utf-8') as f:
            lines = f.readlines()
        new_lines = [line for line in lines if not line.strip().startswith('codex_hooks')]
        if len(new_lines) == len(lines):
            return "not_found"
        with open(config_path, 'w', encoding='utf-8') as f:
            f.writelines(new_lines)
        debug_print("Removed codex_hooks feature flag from config.toml")
        return "cleared"
    except Exception as e:
        print(f"Failed to remove codex_hooks feature: {e}")
        return "failed"



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


def clear_setup() -> None:
    """Undo all changes made by the setup script."""
    print("=" * 60)
    print("Codex Hooks - Clearing Setup")
    print("=" * 60)

    any_cleared = False
    any_failed = False

    status, _ = remove_env_var("UNBOUND_CODEX_API_KEY")
    if status == "cleared":
        any_cleared = True
    elif status not in ("cleared", "not_found"):
        print("Failed to clear API_KEY")
        any_failed = True

    _r = _clear_path(Path.home() / ".codex" / "hooks" / "unbound.py", "Codex unbound.py hook")
    if _r == "cleared":
        any_cleared = True
    elif _r == "failed":
        any_failed = True

    for extra in (
        Path.home() / ".codex" / "hooks" / "unbound-setup.py",
        Path.home() / ".codex" / "hooks" / ".last_updated",
    ):
        _r = _clear_path(extra, str(extra))
        if _r == "cleared":
            any_cleared = True
        elif _r == "failed":
            any_failed = True

    hooks_status = remove_hooks_from_config()
    if hooks_status == "cleared":
        any_cleared = True
    elif hooks_status == "failed":
        print("Failed to clear Unbound hooks in hooks.json")
        any_failed = True

    feature_status = disable_codex_hooks_feature_status()
    if feature_status == "cleared":
        any_cleared = True
    elif feature_status == "failed":
        print("Failed to clear codex_hooks feature flag")
        any_failed = True

    if any_cleared:
        print("Cleared")
    elif not any_failed:
        print("API_KEY not set, nothing to clear")

    print("\n" + "=" * 60)
    print("Clear Complete!")
    print("=" * 60)


def enable_codex_hooks_feature() -> bool:
    """Enable the codex_hooks feature flag in ~/.codex/config.toml.
    If [features] section exists, adds the key under it.
    Otherwise appends a new [features] section at the end of the file."""
    config_path = Path.home() / ".codex" / "config.toml"
    try:
        config_path.parent.mkdir(parents=True, exist_ok=True)

        lines = []
        if config_path.exists():
            with open(config_path, 'r', encoding='utf-8') as f:
                lines = f.readlines()

        # Check if already enabled
        content = ''.join(lines)
        if 'codex_hooks = true' in content:
            debug_print("codex_hooks feature flag already enabled")
            return True

        # Check if [features] section already exists
        features_idx = None
        for i, line in enumerate(lines):
            if line.strip() == '[features]':
                features_idx = i
                break

        if features_idx is not None:
            # Insert codex_hooks = true right after [features] header
            lines.insert(features_idx + 1, 'codex_hooks = true\n')
        else:
            # Append new [features] section at the end
            if lines and not lines[-1].endswith('\n'):
                lines.append('\n')
            lines.append('\n[features]\ncodex_hooks = true\n')

        with open(config_path, 'w', encoding='utf-8') as f:
            f.writelines(lines)

        debug_print("Enabled codex_hooks feature flag in config.toml")
        return True
    except Exception as e:
        debug_print(f"Failed to enable codex_hooks feature: {e}")
        return False


def disable_codex_hooks_feature() -> None:
    """Remove only the codex_hooks line from ~/.codex/config.toml.
    Preserves the [features] section and any other flags within it."""
    config_path = Path.home() / ".codex" / "config.toml"
    if not config_path.exists():
        return
    try:
        with open(config_path, 'r', encoding='utf-8') as f:
            lines = f.readlines()

        new_lines = [line for line in lines if not line.strip().startswith('codex_hooks')]
        if len(new_lines) != len(lines):
            with open(config_path, 'w', encoding='utf-8') as f:
                f.writelines(new_lines)
            debug_print("Removed codex_hooks feature flag from config.toml")
    except Exception as e:
        debug_print(f"Failed to remove codex_hooks feature: {e}")


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


def detect_install_state() -> str:
    """User-level install state (informational): 'persisted' if this tool's
    Unbound setup already exists on this device, else 'fresh'. User-level setups
    are never tamper-eligible, so 'tampered' is never reported."""
    try:
        return "persisted" if (Path.home() / ".codex" / "hooks" / "unbound.py").exists() else "fresh"
    except Exception as e:
        debug_print(f"detect_install_state failed: {e}")
        return "fresh"


def get_managed_settings_dir() -> Path:
    """System-wide managed (MDM) settings directory for Codex. Mirrors the path
    the MDM setup writes to; keep this in sync with mdm/setup.py."""
    system = platform.system().lower()
    if system == "darwin":
        return Path("/Library/Application Support/Codex")
    elif system == "linux":
        return Path("/etc/codex")
    elif system == "windows":
        program_files = os.environ.get("ProgramFiles", r"C:\Program Files")
        return Path(program_files) / "Codex"
    raise OSError(f"Unsupported operating system: {system}")


def check_enterprise_hooks_conflict() -> bool:
    """True if an Unbound MDM (managed) setup already exists for Codex on this
    device. User-level setup must not run alongside it — the managed config
    already enforces Unbound for every user, so a second user-level install would
    make every hook fire twice. Read-only; fails open (False) on any error."""
    try:
        managed_dir = get_managed_settings_dir()
        markers = [
            managed_dir / "hooks" / "unbound.py",
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


def _backfill_session_id_from_filename(transcript_path: Path) -> Optional[str]:
    # Only `rollout-<isots>-<uuid>.jsonl` — never a generic stem fallback.
    m = ROLLOUT_FILENAME_RE.match(transcript_path.stem)
    return m.group(1) if m else None


def _backfill_collect_session(transcript_path: Path) -> Optional[Dict]:
    """Read a transcript and return {session_id, entries} for server-side parsing.
    The client only JSON-decodes lines and resolves a session id (preferring
    the session_meta payload, falling back to the rollout filename UUID). All
    semantic parsing happens server-side in
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


def run_backfill(api_key: str, backend_url: str) -> None:
    """Walk ~/.codex/sessions and seed historical sessions. Never raises."""
    if os.environ.get('UNBOUND_BACKFILL_DISABLED') == '1':
        debug_print("UNBOUND_BACKFILL_DISABLED=1 — skipping backfill")
        return

    try:
        home = Path.home()
        started_at = time.time()
        cutoff_mtime = _backfill_read_cutoff(home)
        sessions_root = home / '.codex' / 'sessions'
        sessions: List[Dict] = []
        capped = False
        if sessions_root.exists():
            for transcript_path in sorted(_backfill_iter_transcripts(sessions_root, cutoff_mtime)):
                if len(sessions) >= BACKFILL_MAX_SESSIONS_PER_RUN:
                    # Hit the per-run cap with files still unprocessed — don't advance
                    # the cutoff, or those older files would be skipped permanently.
                    capped = True
                    debug_print(f"reached session cap {BACKFILL_MAX_SESSIONS_PER_RUN}; remaining skipped")
                    break
                session = _backfill_collect_session(transcript_path)
                if session:
                    sessions.append(session)
        if not sessions:
            _backfill_write_cutoff(home, started_at)
            print("[backfill] No past sessions found.")
            return

        print(f"[backfill] Found {len(sessions)} past sessions. Uploading (this may take a few minutes)...")

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

        failed = chunks_total - chunks_sent
        sessions_sent = len(sessions_sent_ids)
        if sessions_sent == 0:
            print(f"[backfill] No sessions queued (all {chunks_total} uploads failed).")
        elif failed:
            print(f"[backfill] Done — queued {sessions_sent} past sessions ({failed} chunks failed).")
        else:
            if not capped:
                _backfill_write_cutoff(home, started_at)
            print(f"[backfill] Done — queued {sessions_sent} past sessions for processing.")
    except Exception as e:
        print(f"[backfill] Skipped due to error: {e}", file=sys.stderr)


def main():
    global DEBUG

    # Parse arguments
    clear_mode = "--clear" in sys.argv
    debug_mode = "--debug" in sys.argv
    backfill_mode = "--backfill" in sys.argv

    if debug_mode:
        DEBUG = True
        debug_print("Debug mode enabled")

    if clear_mode:
        clear_setup()
        return

    if check_enterprise_hooks_conflict():
        print("\n❌ Skipped — Codex is managed by your organization (MDM).")
        raise SystemExit(3)

    install_macos_certificates()

    print("=" * 60)
    print("Codex Setup for Unbound Gateway")
    print("=" * 60)

    domain = None
    for i, arg in enumerate(sys.argv):
        if arg == "--domain" and i + 1 < len(sys.argv):
            domain = sys.argv[i + 1]
            break

    backend_url = "https://backend.getunbound.ai"
    for i, arg in enumerate(sys.argv):
        if arg == "--backend-url" and i + 1 < len(sys.argv):
            backend_url = normalize_url(sys.argv[i + 1])
            break

    gateway_url = DEFAULT_GATEWAY_URL
    for i, arg in enumerate(sys.argv):
        if arg == "--gateway-url" and i + 1 < len(sys.argv):
            gateway_url = normalize_url(sys.argv[i + 1])
            break

    api_key_arg = None
    for i, arg in enumerate(sys.argv):
        if arg == "--api-key" and i + 1 < len(sys.argv):
            api_key_arg = sys.argv[i + 1]
            break

    api_key = api_key_arg
    if not api_key:
        if not domain:
            print("Missing required argument: --domain or --api-key")
            return

        auth_url = normalize_url(domain)

        cb_response = run_callback_server(auth_url)
        if cb_response is None:
            print("Failed to receive callback. Exiting.")
            return

        try:
            api_key = (cb_response.get("query") or {}).get("api_key")
        except Exception:
            pass

        if not api_key:
            error_msg = (cb_response.get("query") or {}).get("error")
            if error_msg:
                safe_error = re.sub(r'[\x00-\x1f\x7f]', '', error_msg)[:200]
                print(f"Setup failed: {safe_error}")
            else:
                print("No API key received. Exiting.")
            return

    debug_print("API key received from callback")

    _install_state = detect_install_state()
    _device_id = get_device_identifier()

    # Remove gateway setup env vars and artifacts
    remove_gateway_artifacts()

    debug_print("Setting UNBOUND_CODEX_API_KEY environment variable...")
    success, message = set_env_var("UNBOUND_CODEX_API_KEY", api_key)
    if not success:
        print(f"Failed to set environment variable: {message}")
        return
    debug_print("UNBOUND_CODEX_API_KEY set successfully")

    write_unbound_config(api_key, urls={"base_url": backend_url, "gateway_url": gateway_url, "frontend_url": normalize_url(domain) if domain else None})

    debug_print("Setting up hooks...")
    if not setup_hooks(gateway_url=gateway_url):
        print("Failed to setup hooks")
        return
    debug_print("Hooks downloaded successfully")

    debug_print("Configuring Codex hooks...")
    if not configure_codex_hooks():
        print("Failed to configure Codex hooks")
        return
    debug_print("Codex hooks configured successfully")

    debug_print("Enabling codex_hooks feature flag...")
    enable_codex_hooks_feature()

    print("API key verified and added")
    print("Setup complete")
    print("=" * 60)

    notify_setup_complete(api_key, "codex", backend_url=backend_url, install_state=_install_state, serial_number=_device_id)

    if backfill_mode:
        run_backfill(api_key, backend_url)

    rc_path = get_shell_rc_file()
    if rc_path is not None:
        print(f"\nTo apply changes in your current terminal, run:\n  source {rc_path}\n\nOr open a new terminal.")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\nSetup cancelled.")
    except Exception as e:
        print(f"\nError: {e}")
        exit(1)
